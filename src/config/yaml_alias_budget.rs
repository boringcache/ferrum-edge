//! Bounded YAML alias/anchor admission for file-backed config documents.
//!
//! `serde_yaml` 0.9.34 materializes aliases by replaying events (`jump`) and
//! only caps the number of jumps at `events.len() * 100`. That is not a
//! memory budget: a small source document can still expand far past the 64 MiB
//! read ceiling before the jump cap fires. This module is the YAML trust
//! boundary for gateway, mesh, and config-migration file documents.
//!
//! Admission first walks the complete libyaml event stream (so comments,
//! quoted scalars, tags, and escaped text cannot be confused with
//! anchors/aliases). Documents without alias events return after that bounded
//! preflight. Alias-bearing documents are parsed a second time into a compact,
//! alias-preserving graph and charged against cumulative event / composition
//! node / expansion node / depth / alias-reference / expanded-scalar-byte /
//! work budgets before `serde_yaml` is allowed to materialize them.
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

/// Maximum events accepted in either the preflight or composition pass.
pub const MAX_YAML_EVENTS_PER_PASS: usize = 1_000_000;

/// Maximum nodes retained in the alias-preserving composition graph. Alias
/// nodes count, and every anchored value must already occupy one of these
/// slots; live anchor-table entries are separately capped at the same value.
pub const MAX_YAML_COMPOSITION_NODES: usize = 500_000;

/// Maximum scalar/sequence/mapping values that `serde_yaml` would materialize
/// after following aliases. Alias edges themselves are charged separately.
pub const MAX_YAML_EXPANDED_NODES: usize = 500_000;

/// Maximum YAML source bytes admitted by this trust boundary.
pub const MAX_YAML_SOURCE_BYTES: usize = MAX_GATEWAY_CONFIG_FILE_BYTES as usize;

/// Fail-closed ceiling on scalar bytes visited during expansion, including
/// bytes revisited through aliases. This deliberately matches the 64 MiB
/// source-file read ceiling: alias reuse may rearrange or repeat a document,
/// but may not authorize more scalar payload than the largest source document.
pub const MAX_YAML_EXPANDED_BYTES: usize = MAX_YAML_SOURCE_BYTES;

/// Maximum live bytes retained for unique anchor identifiers during
/// composition. The source-byte ceiling already makes this unreachable for a
/// valid stream, but keeping it explicit protects the foreign-data boundary.
const MAX_YAML_ANCHOR_BYTES: usize = MAX_YAML_SOURCE_BYTES;

/// Maximum cumulative work across the complete preflight, alias composition,
/// and expansion traversal. This matches the hardened API-spec YAML parser's
/// composition/expansion ceiling while also charging this module's preflight.
pub const MAX_YAML_WORK: usize = 2_000_000;

/// Fail-closed outcomes. Display text is field-oriented and must not include
/// attacker-controlled scalar or anchor text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlAliasBudgetError {
    SourceByteLimitExceeded,
    EventLimitExceeded,
    CompositionNodeLimitExceeded,
    AnchorLimitExceeded,
    ExpandedNodeLimitExceeded,
    DepthExceeded,
    AliasReferenceLimitExceeded,
    ExpandedByteLimitExceeded,
    WorkLimitExceeded,
    AdmissionFailure,
    InvalidAliasDocument,
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
            Self::SourceByteLimitExceeded => "YAML document exceeds source byte limit",
            Self::EventLimitExceeded => "YAML document exceeds event limit",
            Self::CompositionNodeLimitExceeded => "YAML document exceeds composition node limit",
            Self::AnchorLimitExceeded => "YAML document exceeds anchor bookkeeping limit",
            Self::ExpandedNodeLimitExceeded => {
                "YAML document exceeds expanded node limit; reduce alias reuse or nesting"
            }
            Self::DepthExceeded => "YAML document exceeds nesting depth limit",
            Self::AliasReferenceLimitExceeded => {
                "YAML document exceeds alias reference limit; reduce alias reuse"
            }
            Self::ExpandedByteLimitExceeded => {
                "YAML document exceeds expanded byte limit; reduce alias reuse or document size"
            }
            Self::WorkLimitExceeded => {
                "YAML document exceeds admission work limit; reduce alias reuse or nesting"
            }
            Self::AdmissionFailure => "YAML document could not be safely preflighted",
            Self::InvalidAliasDocument => {
                "YAML document containing aliases is malformed or unsupported"
            }
            Self::UndefinedAlias => "undefined YAML alias",
            Self::Cycle => "YAML alias cycle detected during expansion",
        }
    }
}

/// Admit `content` as YAML at the file-config trust boundary.
///
/// A malformed stream with no observed alias is left to `serde_yaml` so its
/// ordinary syntax diagnostic remains authoritative. Once an alias event has
/// been observed, an incomplete, malformed, multi-document, or unsupported
/// stream fails closed here with a fixed redacted diagnostic.
pub fn admit_yaml_alias_expansion(content: &str) -> Result<(), YamlAliasBudgetError> {
    admit_yaml_alias_expansion_bytes(content.as_bytes())
}

fn admit_yaml_alias_expansion_bytes(body: &[u8]) -> Result<(), YamlAliasBudgetError> {
    if body.len() > MAX_YAML_SOURCE_BYTES {
        return Err(YamlAliasBudgetError::SourceByteLimitExceeded);
    }

    let mut budgets = Budgets::new();
    match probe_alias_event(body, &mut budgets)? {
        Probe::NoAlias | Probe::MalformedWithoutAlias => Ok(()),
        Probe::HasAlias => {
            let document = compose_document(body, &mut budgets)?;
            let root = document
                .root
                .ok_or(YamlAliasBudgetError::InvalidAliasDocument)?;
            let mut expanding = HashSet::new();
            expand_node(&document, root, &mut budgets, &mut expanding)
        }
    }
}

enum Probe {
    NoAlias,
    HasAlias,
    MalformedWithoutAlias,
}

fn probe_alias_event(body: &[u8], budgets: &mut Budgets) -> Result<Probe, YamlAliasBudgetError> {
    let mut parser = Parser::new(body).map_err(|()| YamlAliasBudgetError::AdmissionFailure)?;
    let mut events = 0usize;
    let mut saw_alias = false;
    loop {
        charge_event(&mut events, budgets)?;
        match parser.next_type() {
            Ok(sys::YAML_ALIAS_EVENT) => saw_alias = true,
            Ok(sys::YAML_STREAM_END_EVENT) => {
                return Ok(if saw_alias {
                    Probe::HasAlias
                } else {
                    Probe::NoAlias
                });
            }
            Ok(_) => {}
            Err(()) if saw_alias => {
                return Err(YamlAliasBudgetError::InvalidAliasDocument);
            }
            Err(()) => return Ok(Probe::MalformedWithoutAlias),
        }
    }
}

struct Budgets {
    depth: usize,
    alias_refs: usize,
    bytes: usize,
    expanded_nodes: usize,
    work: usize,
}

impl Budgets {
    fn new() -> Self {
        Self {
            depth: 0,
            alias_refs: 0,
            bytes: 0,
            expanded_nodes: 0,
            work: 0,
        }
    }

    fn charge_work(&mut self) -> Result<(), YamlAliasBudgetError> {
        let next = self
            .work
            .checked_add(1)
            .ok_or(YamlAliasBudgetError::WorkLimitExceeded)?;
        if next > MAX_YAML_WORK {
            return Err(YamlAliasBudgetError::WorkLimitExceeded);
        }
        self.work = next;
        Ok(())
    }

    fn enter_depth(&mut self) -> Result<(), YamlAliasBudgetError> {
        if self.depth >= MAX_YAML_DEPTH {
            return Err(YamlAliasBudgetError::DepthExceeded);
        }
        self.depth += 1;
        Ok(())
    }

    fn leave_depth(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
    }

    fn charge_bytes(&mut self, n: usize) -> Result<(), YamlAliasBudgetError> {
        let next = self
            .bytes
            .checked_add(n)
            .ok_or(YamlAliasBudgetError::ExpandedByteLimitExceeded)?;
        if next > MAX_YAML_EXPANDED_BYTES {
            return Err(YamlAliasBudgetError::ExpandedByteLimitExceeded);
        }
        self.bytes = next;
        Ok(())
    }

    fn charge_alias(&mut self) -> Result<(), YamlAliasBudgetError> {
        let next = self
            .alias_refs
            .checked_add(1)
            .ok_or(YamlAliasBudgetError::AliasReferenceLimitExceeded)?;
        if next > MAX_YAML_ALIAS_REFERENCES {
            return Err(YamlAliasBudgetError::AliasReferenceLimitExceeded);
        }
        self.alias_refs = next;
        Ok(())
    }

    fn charge_expanded_node(&mut self) -> Result<(), YamlAliasBudgetError> {
        let next = self
            .expanded_nodes
            .checked_add(1)
            .ok_or(YamlAliasBudgetError::ExpandedNodeLimitExceeded)?;
        if next > MAX_YAML_EXPANDED_NODES {
            return Err(YamlAliasBudgetError::ExpandedNodeLimitExceeded);
        }
        self.expanded_nodes = next;
        Ok(())
    }
}

fn charge_event(events: &mut usize, budgets: &mut Budgets) -> Result<(), YamlAliasBudgetError> {
    budgets.charge_work()?;
    let next = events
        .checked_add(1)
        .ok_or(YamlAliasBudgetError::EventLimitExceeded)?;
    if next > MAX_YAML_EVENTS_PER_PASS {
        return Err(YamlAliasBudgetError::EventLimitExceeded);
    }
    *events = next;
    Ok(())
}

enum NodeKind {
    Scalar { bytes: usize },
    Sequence(Vec<usize>),
    Mapping(Vec<(usize, usize)>),
    Alias { target: usize },
}

struct Document {
    nodes: Vec<NodeKind>,
    anchors: HashMap<String, usize>,
    anchor_bytes: usize,
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

fn compose_document(body: &[u8], budgets: &mut Budgets) -> Result<Document, YamlAliasBudgetError> {
    let mut parser = Parser::new(body).map_err(|()| YamlAliasBudgetError::InvalidAliasDocument)?;
    let mut document = Document {
        nodes: Vec::new(),
        anchors: HashMap::new(),
        anchor_bytes: 0,
        root: None,
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut events = 0usize;
    let mut seen_stream = false;
    let mut seen_document = false;
    let mut finished_document = false;

    loop {
        charge_event(&mut events, budgets)?;
        let event = parser
            .next_event()
            .map_err(|()| YamlAliasBudgetError::InvalidAliasDocument)?;
        match event {
            Event::StreamStart => {
                if seen_stream || seen_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                seen_stream = true;
            }
            Event::DocumentStart => {
                if !seen_stream || seen_document || finished_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                seen_document = true;
            }
            Event::StreamEnd => {
                if !seen_stream
                    || !seen_document
                    || !finished_document
                    || !stack.is_empty()
                    || document.root.is_none()
                {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                break;
            }
            Event::DocumentEnd => {
                if !seen_document || finished_document || !stack.is_empty() {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                finished_document = true;
            }
            Event::Alias { name } => {
                if !seen_document || finished_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                // The alias node is covered by the composition-node ceiling;
                // charge the anchor-table lookup as cumulative work too.
                budgets.charge_work()?;
                let target = document
                    .anchors
                    .get(&name)
                    .copied()
                    .ok_or(YamlAliasBudgetError::UndefinedAlias)?;
                let id = alloc_node(&mut document, NodeKind::Alias { target })?;
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::Scalar { anchor, bytes } => {
                if !seen_document || finished_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                let id = alloc_node(&mut document, NodeKind::Scalar { bytes })?;
                register_anchor(&mut document, anchor, id, budgets)?;
                attach_child(&mut document, &mut stack, id)?;
            }
            Event::SequenceStart { anchor } => {
                if !seen_document || finished_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                if stack.len() >= MAX_YAML_DEPTH {
                    return Err(YamlAliasBudgetError::DepthExceeded);
                }
                let id = alloc_node(&mut document, NodeKind::Sequence(Vec::new()))?;
                register_anchor(&mut document, anchor, id, budgets)?;
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Sequence { node: id });
            }
            Event::SequenceEnd if !seen_document || finished_document => {
                return Err(YamlAliasBudgetError::InvalidAliasDocument);
            }
            Event::SequenceEnd => match stack.pop() {
                Some(Frame::Sequence { .. }) => {}
                _ => return Err(YamlAliasBudgetError::InvalidAliasDocument),
            },
            Event::MappingStart { anchor } => {
                if !seen_document || finished_document {
                    return Err(YamlAliasBudgetError::InvalidAliasDocument);
                }
                if stack.len() >= MAX_YAML_DEPTH {
                    return Err(YamlAliasBudgetError::DepthExceeded);
                }
                let id = alloc_node(&mut document, NodeKind::Mapping(Vec::new()))?;
                register_anchor(&mut document, anchor, id, budgets)?;
                attach_child(&mut document, &mut stack, id)?;
                stack.push(Frame::Mapping {
                    node: id,
                    pending_key: None,
                });
            }
            Event::MappingEnd if !seen_document || finished_document => {
                return Err(YamlAliasBudgetError::InvalidAliasDocument);
            }
            Event::MappingEnd => match stack.pop() {
                Some(Frame::Mapping {
                    pending_key: None, ..
                }) => {}
                _ => return Err(YamlAliasBudgetError::InvalidAliasDocument),
            },
        }
    }
    Ok(document)
}

fn alloc_node(document: &mut Document, kind: NodeKind) -> Result<usize, YamlAliasBudgetError> {
    if document.nodes.len() >= MAX_YAML_COMPOSITION_NODES {
        return Err(YamlAliasBudgetError::CompositionNodeLimitExceeded);
    }
    let id = document.nodes.len();
    document.nodes.push(kind);
    Ok(id)
}

fn register_anchor(
    document: &mut Document,
    anchor: Option<String>,
    id: usize,
    budgets: &mut Budgets,
) -> Result<(), YamlAliasBudgetError> {
    let Some(name) = anchor else {
        return Ok(());
    };
    // Anchor insertion/redefinition is distinct bookkeeping beyond the node's
    // event and is included in the one cumulative work counter.
    budgets.charge_work()?;
    // YAML allows redefining an anchor; later events win, matching serde_yaml.
    if !document.anchors.contains_key(&name) {
        if document.anchors.len() >= MAX_YAML_COMPOSITION_NODES {
            return Err(YamlAliasBudgetError::AnchorLimitExceeded);
        }
        let next = document
            .anchor_bytes
            .checked_add(name.len())
            .ok_or(YamlAliasBudgetError::AnchorLimitExceeded)?;
        if next > MAX_YAML_ANCHOR_BYTES {
            return Err(YamlAliasBudgetError::AnchorLimitExceeded);
        }
        document.anchor_bytes = next;
    }
    document.anchors.insert(name, id);
    Ok(())
}

fn attach_child(
    document: &mut Document,
    stack: &mut [Frame],
    child: usize,
) -> Result<(), YamlAliasBudgetError> {
    let Some(frame) = stack.last_mut() else {
        if document.root.is_some() {
            return Err(YamlAliasBudgetError::InvalidAliasDocument);
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
                _ => Err(YamlAliasBudgetError::InvalidAliasDocument),
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
                    _ => Err(YamlAliasBudgetError::InvalidAliasDocument),
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
        .ok_or(YamlAliasBudgetError::InvalidAliasDocument)?;
    match kind {
        NodeKind::Alias { target } => {
            budgets.charge_alias()?;
            if expanding.contains(target) {
                return Err(YamlAliasBudgetError::Cycle);
            }
            expand_node(document, *target, budgets, expanding)
        }
        NodeKind::Scalar { bytes } => {
            budgets.charge_expanded_node()?;
            budgets.charge_bytes(*bytes)
        }
        NodeKind::Sequence(items) => {
            budgets.enter_depth()?;
            budgets.charge_expanded_node()?;
            for child in items {
                expand_node(document, *child, budgets, expanding)?;
            }
            budgets.leave_depth();
            Ok(())
        }
        NodeKind::Mapping(pairs) => {
            budgets.enter_depth()?;
            budgets.charge_expanded_node()?;
            for (key, value) in pairs {
                expand_node(document, *key, budgets, expanding)?;
                expand_node(document, *value, budgets, expanding)?;
            }
            budgets.leave_depth();
            Ok(())
        }
    }
}

struct Parser<'input> {
    /// Heap-resident foreign parser. `yaml_parser_set_input_string` stores
    /// `read_handler_data = parser`, so the C object is self-referential and
    /// must not move after input setup.
    sys: Box<sys::yaml_parser_t>,
    /// Borrowed input keeps the source allocation alive for every raw pointer
    /// retained by libyaml. The parser never outlives this borrow, and the
    /// caller cannot mutate or free the bytes while it exists.
    _input: &'input [u8],
}

impl<'input> Parser<'input> {
    fn new(input: &'input [u8]) -> Result<Self, ()> {
        let input_len = u64::try_from(input.len()).map_err(|_| ())?;
        let mut sys = Box::<sys::yaml_parser_t>::new_uninit();
        unsafe {
            if sys::yaml_parser_initialize(sys.as_mut_ptr()).fail {
                // Initialization failure does not establish a deletable parser.
                return Err(());
            }
            // `Box::assume_init` preserves the allocation address. The private
            // field is never moved out, so only the Box handle moves afterward.
            let mut sys = sys.assume_init();
            let parser_ptr = &mut *sys as *mut sys::yaml_parser_t;
            sys::yaml_parser_set_encoding(parser_ptr, sys::YAML_UTF8_ENCODING);
            // The Box keeps the self-referential parser address stable; the
            // lifetime parameter keeps the borrowed input pointer valid.
            sys::yaml_parser_set_input_string(parser_ptr, input.as_ptr(), input_len);
            Ok(Self { sys, _input: input })
        }
    }

    fn next_type(&mut self) -> Result<sys::yaml_event_type_t, ()> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = &mut *self.sys as *mut sys::yaml_parser_t;
            let event_ptr = event.as_mut_ptr();
            // unsafe-libyaml zero-initializes the event before parsing. Delete
            // it on both success and failure so partial allocations cannot
            // escape either path.
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
            // Conversion borrows event-owned fields only until it has copied
            // bounded identifiers/counts. Delete the event for every result.
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

impl Drop for Parser<'_> {
    fn drop(&mut self) {
        // Teardown runs while `_input` is still borrowed and alive; Rust drops
        // fields only after this custom Drop implementation returns.
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
            let bytes = usize::try_from(unsafe { event.data.scalar.length }).map_err(|_| ())?;
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
            if len == 1_048_576 {
                return None;
            }
            len += 1;
        }
        let bytes = slice::from_raw_parts(ptr as *const u8, len);
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}
