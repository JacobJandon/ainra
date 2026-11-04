// SPDX-License-Identifier: Apache-2.0 OR MIT
// Root-signed directories (with epochs, D-083), gates over them (D-073) and currency gates (D-086) must never panic
// on arbitrary bytes. Seeded from vectors/v1-directory, v1-directory-epoch, v1-gate and v1-currency by
// tools/fuzz-smoke.sh.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = ainra_adapter::accredit_json(s, s);
    let _ = ainra_adapter::accredit_json_at_least(s, s, 1);
    let _ = ainra_adapter::run_gate_vector_json(s);
    let _ = ainra_adapter::run_currency_vector_json(s);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        let _ = ainra_adapter::directory_result(&v);
        let _ = ainra_adapter::directory_epoch_vector_result(&v);
    }
});
