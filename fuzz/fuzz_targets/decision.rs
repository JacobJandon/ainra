// SPDX-License-Identifier: Apache-2.0 OR MIT
// Decision records and logged heads (D-079, D-081) must never panic on arbitrary bytes: one record line, one head
// statement line, a chain of lines checked against a gate key, and the whole vector path (receipts included).
// Seeded from vectors/v1-decision by tools/fuzz-smoke.sh.
#![no_main]
use libfuzzer_sys::fuzz_target;

const GATE_KEY: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fuzz_target!(|data: &[u8]| {
    let _ = ainra_core::decision::DecisionRecord::parse_checked(data);
    let _ = ainra_core::decision::HeadStatement::parse_checked(data);
    let _ = ainra_core::decision::HeadStatement::verify(data, &[7u8; 32]);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ainra_adapter::run_decision_vector_json(s);
        let _ = ainra_adapter::decision_chain_json(GATE_KEY, s, "null");
    }
});
