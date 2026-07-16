// SPDX-License-Identifier: Apache-2.0 OR MIT
// The canonical encoder must never panic; on any parseable JSON it returns canonical bytes or a typed Canon error.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = ainra_core::canon::canonicalize_value(&v);
        }
    }
});
