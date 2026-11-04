// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Inputs the fuzz targets found (PLAN-M51 step 5), kept as tests so the panics cannot come back. Each was a vector
//! runner calling `expect` on a field it did not check; each must now answer with a refusal.

use std::path::Path;

fn vector(dir: &str) -> serde_json::Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(dir);
    let mut names: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json") && !p.ends_with("manifest.json"))
        .collect();
    names.sort();
    serde_json::from_str(&std::fs::read_to_string(&names[0]).unwrap()).unwrap()
}

#[test]
fn a_directory_vector_without_a_directory_is_refused_not_a_panic() {
    // The first crash: the corpus manifest itself, fed as a vector, has no `directory` field.
    let manifest = serde_json::json!({ "accept": 3, "count": 9, "version": "v1-directory" });
    assert_eq!(
        ainra_adapter::directory_result(&manifest),
        serde_json::json!({ "accept": false })
    );
    let mut v = vector("v1-directory");
    v["root_slh"] = serde_json::json!("not base64url!");
    assert_eq!(
        ainra_adapter::directory_result(&v),
        serde_json::json!({ "accept": false })
    );
}

#[test]
fn a_delta_vector_with_a_malformed_field_is_a_schema_violation_not_a_panic() {
    let mut v = vector("v1-delta");
    v["cert"]["sig_slh"] = serde_json::json!("not base64url!");
    let w: ainra_adapter::WireDeltaVector = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(
        ainra_adapter::delta_verify(&w),
        Err(ainra_core::Reason::SchemaViolation)
    );
    v["root_pub_slh"] = serde_json::json!("%%%");
    let w: ainra_adapter::WireDeltaVector = serde_json::from_value(v).unwrap();
    assert_eq!(
        ainra_adapter::delta_verify(&w),
        Err(ainra_core::Reason::SchemaViolation)
    );
}
