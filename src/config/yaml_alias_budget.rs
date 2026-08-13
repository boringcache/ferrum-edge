//! Bounded YAML alias/anchor admission for file-mode config documents.
//!
//! `serde_yaml` 0.9.34 materializes aliases by replaying events (`jump`) and
//! only caps the number of jumps at `events.len() * 100`. That is not a
//! memory budget: a small source document can still expand far past the 64 MiB
//! read ceiling before the jump cap fires. This module is the YAML trust
//! boundary for gateway and mesh file documents.
//!
//! Admission walks libyaml events (so comments, quoted scalars, tags, and
//! escaped text cannot be confused with anchors/aliases), composes an
//! alias-preserving graph only when an alias event is present, and charges
//! expansion against depth / alias-reference / expanded-byte / work budgets.
//! Documents without alias events return immediately after the event probe.
//!
//! Diagnostics are fixed strings and never echo scalar payloads, anchor names,
//! or file contents.

use crate::config::stable_file::MAX_GATEWAY_CONFIG_FILE_BYTES;
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::slice;
#[allow(clippy::unsafe_removed_from_name)]
use unsafe_libyaml as sys;

/// Nesting depth while composing and expanding. Matches `serde_yaml` 0.9.34's
/// `remaining_depth` of 128.
pub const MAX_YAML_DEPTH: usize = 128;

/// Maximum number of alias edges followed during expansion.
pub const MAX_YAML_ALIAS_REFERENCES: usize = 500_000;

/// Fail-closed ceiling on scalar bytes visited during expansion, including
/// bytes revisited through aliases. Twice the 64 MiB read ceiling so a unique
/// document at the file cap can still reuse a modest anchored fragment.
pub const MAX_YAML_EXPANDED_BYTES: usize =
    (MAX_GATEWAY_CONFIG_FILE_BYTES as usize).saturating_mul(2);

/// Extra expansion visits beyond the composed node count.
pub const MAX_YAML_EXTRA_EXPANSION_WORK: usize = 2_000_000;

/// Fail-closed outcomes. Display text is field-oriented and must not include
/// attacker-controlled scalar or anchor text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlAliasBudgetError {
    DepthExceeded,
    AliasReferenceLimitExceeded,
    ExpandedByteLimitExceeded,
    WorkLimitExceeded,
    UndefinedAlias,
    Cycle,
}

impl std::fmt::Display for YamlAliasBudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for YamlAliasBudgetError {}

impl YamlAliasBudgetError {
    fn message(self) -> &'static str {
        match self {
            Self::DepthExceeded => "YAML document exceeds nesting depth limit",
            Self::AliasReferenceLimitExceeded => {
                "YAML document exceeds alias reference limit; reduce alias reuse"
            }
            Self::ExpandedByteLimitExceeded => {
                "YAML document exceeds expanded byte limit; reduce alias reuse or document size"
            }
            Self::WorkLimitExceeded => {
                "YAML document exceeds expansion work limit; reduce alias reuse or nesting"
            }
            Self::UndefinedAlias => "undefined YAML alias",
            Self::Cycle => "YAML alias cycle detected during expansion",
        }
    }
}

/// Admit `content` as YAML at the file-config trust boundary.
///
/// Parser failures are not reported here: `serde_yaml` remains the diagnostic
/// authority for malformed documents. Alias-expansion budget failures are
/// fail-closed and redacted.
pub fn admit_yaml_alias_expansion(content: &str) -> Result<(), YamlAliasBudgetError> {
    admit_yaml_alias_expansion_bytes(content.as_bytes())
}

fn admit_yaml_alias_expansion_bytes(body: &[u8]) -> Result<(), YamlAliasBudgetError> {
    match probe_alias_event(body) {
        Probe::NoAlias | Probe::Malformed => Ok(()),
        Probe::HasAlias => {
            let document = match compose_document(body) {
                Ok(document) => document,
                // Malformed YAML is reported by serde_yaml, not this budget.
                Err(ComposeError::Parse) => return Ok(()),
                Err(ComposeError::Budget(err)) => return Err(err),
            };
            let Some(root) = document.root else {
                return Ok(());
            };
            let mut budgets = Budgets {
                depth: 0,
                max_depth: MAX_YAML_DEPTH,
                alias_refs: 0,
                max_alias_refs: MAX_YAML_ALIAS_REFERENCES,
                bytes: 0,
                max_bytes: MAX_YAML_EXPANDED_BYTES,
                work: 0,
                max_work: document
                    .nodes
                    .len()
                    .saturating_add(MAX_YAML_EXTRA_EXPANSION_WORK),
            };
            let mut expanding = HashSet::new();
            expand_node(&document, root, &mut budgets, &mut expanding)
        }
    }
}

enum Probe {
    NoAlias,
    HasAlias,
    Malformed,
}

fn probe_alias_event(body: &[u8]) -> Probe {
    let mut parser = match Parser::new(body) {
        Ok(parser) => parser,
        Err(()) => return Probe::Malformed,
    };
    loop {
        match parser.next_type() {
            Ok(sys::YAML_ALIAS_EVENT) => return Probe::HasAlias,
            Ok(sys::YAML_STREAM_END_EVENT) => return Probe::NoAlias,
            Ok(_) => {}
            Err(()) => return Probe::Malformed,
        }
    }
}

struct Budgets {
    depth: usize,
    max_depth: usize,
    alias_refs: usize,
    max_alias_refs: usize,
    bytes: usize,
    max_bytes: usize,
    work: usize,
    max_work: usize,
}

impl Budgets {
    fn charge_work(&mut self) -> Result<(), YamlAliasBudgetError> {
        self.work = self.work.saturating_add(1);
        if self.work > self.max_work {
            return Err(YamlAliasBudgetError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn enter_depth(&mut self) -> Result<(), YamlAliasBudgetError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.max_depth {
            return Err(YamlAliasBudgetError::DepthExceeded);
        }
        Ok(())
    }

    fn leave_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn charge_bytes(&mut self, n: usize) -> Result<(), YamlAliasBudgetError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.max_bytes {
            return Err(YamlAliasBudgetError::ExpandedByteLimitExceeded);
        }
        Ok(())
    }

    fn charge_alias(&mut self) -> Result<(), YamlAliasBudgetError> {
        self.alias_refs = self.alias_refs.saturating_add(1);
        if self.alias_refs > self.max_alias_refs {
            return Err(YamlAliasBudgetError::AliasReferenceLimitExceeded);
        }
        Ok(())
    }
}

enum NodeKind {
    Scalar {
        bytes: usize,
    },
    Sequence(Vec<usize>),
    Mapping(Vec<(usize, usize)>),
    Alias {
        target: usize,
    },
}

struct Document {
    nodes: Vec<NodeKind>,
    anchors: HashMap<String, usize>,
    root: Option<usize>,
}

enum Frame {
    Sequence {
        node: usize,
    },
    Mapping {
        node: usize,
        pending_key: Option<usize>,
    },
}

enum ComposeError {
    Parse,
    Budget(YamlAliasBudgetError),
}

enum Event {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias {
        name: String,
    },
    Scalar {
        anchor: Option<String>,
        bytes: usize,
    },
    SequenceStart {
        anchor: Option<String>,
    },
    SequenceEnd,
    MappingStart {
        anchor: Option<String>,
    },
    MappingEnd,
}

fn compose_document(body: &[u8]) -> Result<Document, ComposeError> {
    let mut parser = Parser::new(body).map_err(|()| ComposeError::Parse)?;
    let mut document = Document {
        nodes: Vec::new(),
        anchors: HashMap::new(),
        root: None,
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut seen_document = false;
    let mut finished_document = false;

    loop {
        if stack.len() > MAX_YAML_DEPTH {
            return Err(ComposeError::Budget(YamlAliasBudgetError::DepthExceeded));
        }
        let event = parser.next_event().map_err(|()| ComposeError::Parse)?;
        match event {
            Event::StreamStart => {}
            Event::DocumentStart => {
                if seen_document {
                    return Err(ComposeError::Parse);
                }
                seen_document = true;
            }
            Event::StreamEnd => {
                if !stack.is_empty() || (seen_document && !finished_document) {
                    return Err(ComposeError::Parse);
                }
                break;
            }
            Event::DocumentEnd => {
                if !stack.is_empty() {
                    return Err(ComposeError::Parse);
                }
                finished_document = true;
            }
            Event::Alias { name } => {
                if finished_document {
                    return Err(ComposeError::Parse);
                }
                let target = document
                    .anchors
                    .get(&name)
                    .copied()
                    .ok_or(ComposeError::Budget(YamlAliasBudgetError::UndefinedAlias))?;
                let id = alloc_node(&mut document, NodeKind::Alias { target });
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::Scalar { anchor, bytes } => {
                if finished_document {
                    return Err(ComposeError::Parse);
                }
                let id = alloc_node(&mut document, NodeKind::Scalar { bytes });
                register_anchor(&mut document, anchor, id);
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::SequenceStart { anchor } => {
                if finished_document {
                    return Err(ComposeError::Parse);
                }
                let id = alloc_node(&mut document, NodeKind::Sequence(Vec::new()));
                register_anchor(&mut document, anchor, id);
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Sequence { node: id });
            }
            Event::SequenceEnd => match stack.pop() {
                Some(Frame::Sequence { .. }) => {}
                _ => return Err(ComposeError::Parse),
            },
            Event::MappingStart { anchor } => {
                if finished_document {
                    return Err(ComposeError::Parse);
                }
                let id = alloc_node(&mut document, NodeKind::Mapping(Vec::new()));
                register_anchor(&mut document, anchor, id);
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Mapping {
                    node: id,
                    pending_key: None,
                });
            }
            Event::MappingEnd => match stack.pop() {
                Some(Frame::Mapping {
                    pending_key: None, ..
                }) => {}
                _ => return Err(ComposeError::Parse),
            },
        }
    }
    Ok(document)
}

fn alloc_node(document: &mut Document, kind: NodeKind) -> usize {
    let id = document.nodes.len();
    document.nodes.push(kind);
    id
}

fn register_anchor(document: &mut Document, anchor: Option<String>, id: usize) {
    let Some(name) = anchor else {
        return;
    };
    // YAML allows redefining an anchor; later events win, matching serde_yaml.
    document.anchors.insert(name, id);
}

fn attach_child(
    document: &mut Document,
    stack: &mut [Frame],
    child: usize,
) -> Result<(), ComposeError> {
    let Some(frame) = stack.last_mut() else {
        if document.root.is_some() {
            return Err(ComposeError::Parse);
        }
        document.root = Some(child);
        return Ok(());
    };
    match frame {
        Frame::Sequence { node } => {
            let node = *node;
            match document.nodes.get_mut(node) {
                Some(NodeKind::Sequence(items)) => {
                    items.push(child);
                    Ok(())
                }
                _ => Err(ComposeError::Parse),
            }
        }
        Frame::Mapping { node, pending_key } => {
            if let Some(key) = *pending_key {
                let node = *node;
                match document.nodes.get_mut(node) {
                    Some(NodeKind::Mapping(pairs)) => {
                        pairs.push((key, child));
                        *pending_key = None;
                        Ok(())
                    }
                    _ => Err(ComposeError::Parse),
                }
            } else {
                *pending_key = Some(child);
                Ok(())
            }
        }
    }
}

fn expand_node(
    document: &Document,
    id: usize,
    budgets: &mut Budgets,
    expanding: &mut HashSet<usize>,
) -> Result<(), YamlAliasBudgetError> {
    budgets.charge_work()?;
    if !expanding.insert(id) {
        return Err(YamlAliasBudgetError::Cycle);
    }
    let result = expand_node_inner(document, id, budgets, expanding);
    expanding.remove(&id);
    result
}

fn expand_node_inner(
    document: &Document,
    id: usize,
    budgets: &mut Budgets,
    expanding: &mut HashSet<usize>,
) -> Result<(), YamlAliasBudgetError> {
    let kind = document
        .nodes
        .get(id)
        .ok_or(YamlAliasBudgetError::WorkLimitExceeded)?;
    match kind {
        NodeKind::Alias { target } => {
            budgets.charge_alias()?;
            if expanding.contains(target) {
                return Err(YamlAliasBudgetError::Cycle);
            }
            expand_node(document, *target, budgets, expanding)
        }
        NodeKind::Scalar { bytes } => budgets.charge_bytes(*bytes),
        NodeKind::Sequence(items) => {
            budgets.enter_depth()?;
            for child in items {
                expand_node(document, *child, budgets, expanding)?;
            }
            budgets.leave_depth();
            Ok(())
        }
        NodeKind::Mapping(pairs) => {
            budgets.enter_depth()?;
            for (key, value) in pairs {
                expand_node(document, *key, budgets, expanding)?;
                expand_node(document, *value, budgets, expanding)?;
            }
            budgets.leave_depth();
            Ok(())
        }
    }
}

struct Parser {
    /// Heap-resident foreign parser. `yaml_parser_set_input_string` stores
    /// `read_handler_data = parser`, so the C object is self-referential and
    /// must not move after input setup.
    sys: Box<sys::yaml_parser_t>,
    /// Owned input bytes. The heap buffer must stay alive for the parser
    /// lifetime.
    _input: Vec<u8>,
}

impl Parser {
    fn new(input: &[u8]) -> Result<Self, ()> {
        let input = input.to_vec();
        let mut sys = Box::<sys::yaml_parser_t>::new_uninit();
        unsafe {
            if sys::yaml_parser_initialize(sys.as_mut_ptr()).fail {
                return Err(());
            }
            let mut sys = sys.assume_init();
            let parser_ptr = &mut *sys as *mut sys::yaml_parser_t;
            sys::yaml_parser_set_encoding(parser_ptr, sys::YAML_UTF8_ENCODING);
            sys::yaml_parser_set_input_string(parser_ptr, input.as_ptr(), input.len() as u64);
            Ok(Self { sys, _input: input })
        }
    }

    fn next_type(&mut self) -> Result<sys::yaml_event_type_t, ()> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = &mut *self.sys as *mut sys::yaml_parser_t;
            let event_ptr = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event_ptr).fail {
                sys::yaml_event_delete(event_ptr);
                return Err(());
            }
            let kind = (*event_ptr).type_;
            sys::yaml_event_delete(event_ptr);
            Ok(kind)
        }
    }

    fn next_event(&mut self) -> Result<Event, ()> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = &mut *self.sys as *mut sys::yaml_parser_t;
            let event_ptr = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event_ptr).fail {
                sys::yaml_event_delete(event_ptr);
                return Err(());
            }
            let converted = convert_event(&*event_ptr);
            sys::yaml_event_delete(event_ptr);
            converted
        }
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        unsafe {
            sys::yaml_parser_delete(&mut *self.sys);
        }
    }
}

unsafe fn convert_event(event: &sys::yaml_event_t) -> Result<Event, ()> {
    match event.type_ {
        sys::YAML_STREAM_START_EVENT => Ok(Event::StreamStart),
        sys::YAML_STREAM_END_EVENT => Ok(Event::StreamEnd),
        sys::YAML_DOCUMENT_START_EVENT => Ok(Event::DocumentStart),
        sys::YAML_DOCUMENT_END_EVENT => Ok(Event::DocumentEnd),
        sys::YAML_ALIAS_EVENT => {
            let name = unsafe { optional_cstr(event.data.alias.anchor) }?.ok_or(())?;
            Ok(Event::Alias { name })
        }
        sys::YAML_SCALAR_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.scalar.anchor) }?;
            let bytes = event.data.scalar.length as usize;
            Ok(Event::Scalar { anchor, bytes })
        }
        sys::YAML_SEQUENCE_START_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.sequence_start.anchor) }?;
            Ok(Event::SequenceStart { anchor })
        }
        sys::YAML_SEQUENCE_END_EVENT => Ok(Event::SequenceEnd),
        sys::YAML_MAPPING_START_EVENT => {
            let anchor = unsafe { optional_cstr(event.data.mapping_start.anchor) }?;
            Ok(Event::MappingStart { anchor })
        }
        sys::YAML_MAPPING_END_EVENT => Ok(Event::MappingEnd),
        _ => Err(()),
    }
}

unsafe fn optional_cstr(ptr: *const u8) -> Result<Option<String>, ()> {
    let Some(nn) = NonNull::new(ptr as *mut i8) else {
        return Ok(None);
    };
    let s = unsafe { cstr_to_string(nn.as_ptr()) }.ok_or(())?;
    if s.is_empty() { Ok(None) } else { Ok(Some(s)) }
}

unsafe fn cstr_to_string(ptr: *const i8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len = len.saturating_add(1);
            if len > 1_048_576 {
                return None;
            }
        }
        let bytes = slice::from_raw_parts(ptr as *const u8, len);
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}
