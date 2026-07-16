// SPDX-License-Identifier: Apache-2.0 OR MIT
// The Token Status List codec must never panic on arbitrary compressed bytes / declared lengths, and must bound its
// allocation (M5/D-020 cap + M6 bomb bound): a declared length across and ABOVE MAX_STATUS_BITS must be rejected
// without OOM. The first 4 bytes derive a declared bit length that can span below, at, and far above the 2^24 cap;
// the remainder is the (arbitrary) compressed body.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (head, body) = data.split_at(core::cmp::min(4, data.len()));
    let mut raw = [0u8; 4];
    raw[..head.len()].copy_from_slice(head);
    // scale into a range that reaches ~2× the cap, so the reject-without-allocating path is exercised
    let len = (u32::from_le_bytes(raw) as usize) % ((1usize << 25) + 7);
    let _ = ainra_core::status::StatusList::decode(body, len);
});
