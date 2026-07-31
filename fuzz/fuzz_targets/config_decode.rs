#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(data) = ferrum_edge::fuzz_support::enforce_input_budget(data) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ferrum_edge::fuzz_support::fuzz_decode_config_document(text);
});
