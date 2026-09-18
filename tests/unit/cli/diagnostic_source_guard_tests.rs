//! Producer/emitter parity for #5591. This is a source contract, not a substitute
//! for rendered-output tests: bare document values cannot be inferred by a lexer.
use std::path::{Path, PathBuf};

const ROOTS: &[&str] = &[
    "src/config",
    "src/modes",
    "src/cli.rs",
    "src/startup.rs",
    "src/gateway_entry.rs",
    "src/config_sources",
    "src/grpc",
    "src/plugins/waf",
];

// Exact exceptions only; adding one requires a producer/consumer justification.
// These are SQL queries, not diagnostics. `table` comes from the migration's
// fixed schema table inventory. SQL single-quote syntax must remain unchanged.
const SINGLE_QUOTE_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = '{table}' LIMIT 1",
    ),
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '{table}' LIMIT 1",
    ),
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{table}' LIMIT 1",
    ),
];

#[derive(Debug)]
struct Token<'a> {
    text: &'a str,
    offset: usize,
    string: bool,
}

// Lex enough Rust to keep comments, escaped quotes, raw strings, char literals,
// lifetimes and nested macro arguments distinct. No line-based macro matching:
// a sanitizer in a neighbor statement must never bless an unsafe emission.
fn tokens(source: &str) -> Vec<Token<'_>> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if source[pos..].starts_with("//") {
            pos += source[pos..].find('\n').unwrap_or(bytes.len() - pos);
            continue;
        }
        if source[pos..].starts_with("/*") {
            pos += 2;
            let mut depth = 1;
            while pos < bytes.len() && depth > 0 {
                if source[pos..].starts_with("/*") {
                    depth += 1;
                    pos += 2;
                } else if source[pos..].starts_with("*/") {
                    depth -= 1;
                    pos += 2;
                } else {
                    pos += source[pos..].chars().next().unwrap().len_utf8();
                }
            }
            assert_eq!(depth, 0, "unterminated source comment");
            continue;
        }
        // Byte/C strings share the same quote rules as ordinary strings.
        let raw_start = if source[pos..].starts_with("br") || source[pos..].starts_with("cr") {
            pos + 1
        } else {
            pos
        };
        if bytes[raw_start] == b'r' {
            let mut quote = raw_start + 1;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let end_marker = format!("\"{}", "#".repeat(quote - raw_start - 1));
                let body = quote + 1;
                let end = body + source[body..].find(&end_marker).expect("raw string end");
                pos = end + end_marker.len();
                result.push(Token {
                    text: &source[body..end],
                    offset: start,
                    string: true,
                });
                continue;
            }
        }
        let quote = if matches!(bytes[pos], b'b' | b'c') && bytes.get(pos + 1) == Some(&b'"') {
            pos + 1
        } else {
            pos
        };
        if bytes[quote] == b'"' {
            pos = quote + 1;
            let body = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                if bytes[pos] == b'\\' {
                    pos += 1;
                }
                pos += source[pos..].chars().next().unwrap().len_utf8();
            }
            assert!(pos < bytes.len(), "unterminated source string");
            result.push(Token {
                text: &source[body..pos],
                offset: start,
                string: true,
            });
            pos += 1;
            continue;
        }
        if bytes[pos] == b'\'' {
            let mut end = pos + 1;
            if bytes.get(end) == Some(&b'\\') {
                end += 2;
                if bytes.get(end) == Some(&b'{') {
                    end += source[end..].find('}').expect("unicode character end") + 1;
                }
            } else if end < bytes.len() {
                end += source[end..].chars().next().unwrap().len_utf8();
            }
            if bytes.get(end) == Some(&b'\'') {
                pos = end + 1;
                continue;
            }
        }
        if bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_' {
            pos += 1;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
        } else {
            pos += source[pos..].chars().next().unwrap().len_utf8();
        }
        result.push(Token {
            text: &source[start..pos],
            offset: start,
            string: false,
        });
    }
    result
}

fn violations(path: &str, source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let error_capture = regex::Regex::new(r"\{(?:error|e|err|cause|message)(?::[^}]*)?\}").unwrap();
    let mut failures = Vec::new();
    for index in 0..tokens.len().saturating_sub(2) {
        let name = &tokens[index];
        if name.string
            || !matches!(
                name.text,
                "format"
                    | "anyhow"
                    | "bail"
                    | "warn"
                    | "error"
                    | "info"
                    | "debug"
                    | "trace"
                    | "eprintln"
                    | "event"
            )
            || tokens[index + 1].text != "!"
            || !matches!(tokens[index + 2].text, "(" | "[" | "{")
        {
            continue;
        }
        let mut depth = 1;
        let mut end = index + 3;
        while end < tokens.len() && depth > 0 {
            if !tokens[end].string {
                match tokens[end].text {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => depth -= 1,
                    _ => {}
                }
            }
            end += 1;
        }
        assert_eq!(depth, 0, "unbalanced macro in {path}");
        let body = &tokens[index + 3..end - 1];
        let sanitized = body.windows(2).any(|pair| {
            !pair[0].string
                && matches!(pair[0].text, "sanitize_startup_cause" | "redact_error_text")
                && pair[1].text == "("
        });
        for literal in body.iter().filter(|token| token.string) {
            let line = source[..literal.offset]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1;
            if literal.text.contains("'{")
                && !SINGLE_QUOTE_EXCEPTIONS.contains(&(path, literal.text))
            {
                failures.push(format!(
                    "{path}:{line}: {}!: single-quoted interpolation",
                    name.text
                ));
            }
            if matches!(name.text, "warn" | "error")
                && error_capture.is_match(literal.text)
                && !sanitized
            {
                failures.push(format!(
                    "{path}:{line}: {}!: unsanitized diagnostic",
                    name.text
                ));
            }
        }
    }
    failures
}

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            rust_files(&entry.unwrap().path(), files);
        }
    } else if path.extension().is_some_and(|extension| extension == "rs") {
        files.push(path.to_path_buf());
    }
}

#[test]
fn in_scope_diagnostic_producers_and_emitters_obey_the_source_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for relative in ROOTS {
        rust_files(&root.join(relative), &mut files);
    }
    files.sort();
    let mut failures = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).unwrap();
        failures.extend(violations(&relative, &source));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn diagnostic_guard_recognizes_multiline_raw_and_nested_macros() {
    for source in [
        r#"format!("invalid '{value}'")"#,
        r##"anyhow::bail!(r#"invalid '{value}'"#)"##,
        "tracing::warn!(\n field = 1,\n \"rejected: {error:#}\"\n);",
        r#"error!("{e}"); sanitize_startup_cause(e, &[]);"#,
        r#"warn!("{err}"); // sanitize_startup_cause(err, &[])"#,
        r#"warn!("{cause}", label = "sanitize_startup_cause(");"#,
        r#"error!("{message}");"#,
    ] {
        assert!(!violations("fixture.rs", source).is_empty(), "{source}");
    }
    for source in [
        r#"format!("invalid {value:?}")"#,
        r#"warn!("{}", sanitize_startup_cause(format!("{error:#}"), &[]));"#,
        r#"error!("{err}", err = redact_error_text(err, &urls));"#,
        r#"// warn!("{error}")
            let example = "format!(\"'{value}'\")";"#,
        r#"let character = '"'; let lifetime: &'a str; format!("`{field}` is invalid");"#,
    ] {
        assert!(violations("fixture.rs", source).is_empty(), "{source}");
    }
}
