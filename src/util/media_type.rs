//! Pure HTTP media-type syntax helpers shared by config admission boundaries.

/// Return `true` when `value` is a concrete RFC 9110 media type.
///
/// The caller remains responsible for validating the value as an HTTP field
/// value when it needs to distinguish control-byte errors from media-type
/// syntax errors.
pub fn is_concrete_http_media_type(value: &str) -> bool {
    let (base, parameters) = value
        .split_once(';')
        .map_or((value, None), |(base, parameters)| (base, Some(parameters)));
    let base = base.trim_end_matches([' ', '\t']);
    let Some((type_, subtype)) = base.split_once('/') else {
        return false;
    };
    if type_ == "*" || subtype == "*" || !is_http_token(type_) || !is_http_token(subtype) {
        return false;
    }
    parameters.is_none_or(valid_media_type_parameters)
}

fn valid_media_type_parameters(parameters: &str) -> bool {
    let bytes = parameters.as_bytes();
    let mut index = 0;
    loop {
        skip_ows(bytes, &mut index);
        if index == bytes.len() {
            return false;
        }
        let name_start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| is_http_token_byte(*byte))
        {
            index += 1;
        }
        if index == name_start {
            return false;
        }
        if bytes.get(index) != Some(&b'=') {
            return false;
        }
        index += 1;
        if bytes.get(index) == Some(&b'"') {
            index += 1;
            if !consume_quoted_string(bytes, &mut index) {
                return false;
            }
        } else {
            let value_start = index;
            while bytes
                .get(index)
                .is_some_and(|byte| is_http_token_byte(*byte))
            {
                index += 1;
            }
            if index == value_start {
                return false;
            }
        }
        skip_ows(bytes, &mut index);
        if index == bytes.len() {
            return true;
        }
        if bytes.get(index) != Some(&b';') {
            return false;
        }
        index += 1;
    }
}

fn consume_quoted_string(bytes: &[u8], index: &mut usize) -> bool {
    while let Some(byte) = bytes.get(*index).copied() {
        match byte {
            b'"' => {
                *index += 1;
                return true;
            }
            b'\\' => {
                *index += 1;
                let Some(escaped) = bytes.get(*index).copied() else {
                    return false;
                };
                if !is_quoted_pair_byte(escaped) {
                    return false;
                }
                *index += 1;
            }
            byte if is_qdtext_byte(byte) => *index += 1,
            _ => return false,
        }
    }
    false
}

fn skip_ows(bytes: &[u8], index: &mut usize) {
    while bytes
        .get(*index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *index += 1;
    }
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_http_token_byte)
}

fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn is_qdtext_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff
    )
}

fn is_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}
