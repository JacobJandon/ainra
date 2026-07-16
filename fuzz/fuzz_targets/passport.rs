// SPDX-License-Identifier: Apache-2.0 OR MIT
// The SD-JWT-VC claim parser must never panic on arbitrary bytes — it returns a Reason or a Passport.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ainra_core::passport::Passport::parse_checked(data);
});
