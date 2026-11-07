// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A change of owner (PLAN-M53 step 8, D-103): the Standard §1's "logged event that resets assurance evidence while
//! preserving the historical record", at one real registrar with real keys, log and status list.
//!
//! WITNESS: the old owner gives a lineage away with its logged operator key; after the public window the new owner's
//! passport verifies with the tier the registrar set for the NEW owner (not the old one's), carries the old passport
//! in its signed history, and its operator key is logged so it can move the lineage on; the old passport is revoked.
//! An agent key cannot give a lineage away; the old operator key stops a change; and each other rule refuses by name.

use ainra_core::{b64, crypto, Reason, Verdict};
use ainra_services::registrar::transfer::{
    contest_message, operator_key_message, ownership_message, sign_b64, wire_of, NewOwnerAssurance,
    OwnershipRequest, TransferState, CONTEST_WINDOW_SECS, TRANSFER_LOCK_SECS,
};
use ainra_services::registrar::{
    holder_pop_message, verify_record_offline, IssueSpec, IssuedRecord, RegistrarBox,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::Value;

const NBF: u64 = 1_775_865_600;
const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;
const T0: u64 = NBF + 86_400;

fn registrar(tag: &str) -> RegistrarBox {
    let d = std::env::temp_dir().join(format!("ainra-ownership-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    RegistrarBox::create_seeded(&d, "registrar-07", 64, 71, NBF - 1000, NBF, EXP).unwrap()
}

struct World {
    rb: RegistrarBox,
    agent: crypto::HybridKeypair,
    old_operator: crypto::HybridKeypair,
    new_operator: crypto::HybridKeypair,
    new_agent: crypto::HybridKeypair,
    old: IssuedRecord,
}

fn world(tag: &str) -> World {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD1_03);
    let mut rb = registrar(tag);
    let [agent, old_operator, new_operator, new_agent] =
        [(); 4].map(|_| crypto::HybridKeypair::generate(&mut rng));
    let key = wire_of(&agent.public());
    let pop = sign_b64(&agent, &holder_pop_message("registrar-07", &key).unwrap()).unwrap();
    let old = rb
        .issue(
            &IssueSpec {
                operator: "acme".into(),
                lineage: "billing".into(),
                version: "1.0.0".into(),
                tier: "L2".into(),
                auth_class: "A2".into(),
                principal_proof: "deadbeef".into(),
                capabilities: vec!["read:invoices".into(), "sign:invoice".into()],
                scope_ceiling: vec!["read:invoices".into(), "sign:invoice".into()],
                hops: vec![],
                audit: None,
                holder_key: Some(key),
                holder_pop: Some(pop),
                principal_evidence: None,
            },
            &[],
            &mut rng,
        )
        .unwrap();
    let okey = wire_of(&old_operator.public());
    let opop = sign_b64(
        &old_operator,
        &operator_key_message("registrar-07", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    rb.register_operator_key("acme", "billing", &okey, &opop)
        .unwrap();
    World {
        rb,
        agent,
        old_operator,
        new_operator,
        new_agent,
        old,
    }
}

/// A request to give `acme:billing` to `globex`, signed by `signer` (the old operator key, unless a test says not).
fn request(w: &World, signer: &crypto::HybridKeypair, at: u64) -> OwnershipRequest {
    let nok = wire_of(&w.new_operator.public());
    let nop = sign_b64(
        &w.new_operator,
        &operator_key_message("registrar-07", "globex", "billing", &nok).unwrap(),
    )
    .unwrap();
    let nhk = wire_of(&w.new_agent.public());
    let nhp = sign_b64(
        &w.new_agent,
        &holder_pop_message("registrar-07", &nhk).unwrap(),
    )
    .unwrap();
    let msg = ownership_message(&w.old.sub, "globex", at, &nok, &nhk).unwrap();
    OwnershipRequest {
        from_sub: w.old.sub.clone(),
        new_operator: "globex".into(),
        requested_at: at,
        new_operator_key: nok,
        new_operator_pop: nop,
        new_holder_key: nhk,
        new_holder_pop: nhp,
        old_operator_sig: sign_b64(signer, &msg).unwrap(),
    }
}

fn assurance() -> NewOwnerAssurance {
    NewOwnerAssurance {
        tier: "L1".into(),
        auth_class: "A3".into(),
        principal_proof: "c0ffee".into(),
        capabilities: vec!["read:invoices".into()],
        scope_ceiling: vec!["read:invoices".into()],
        audit: None,
        principal_evidence: None,
    }
}

fn verdict(rb: &RegistrarBox, rec: &IssuedRecord, now: u64) -> Verdict {
    let p = rb.publish_status(now);
    let list = ainra_core::status::StatusList::decode(
        &b64::decode(&p.status_list_b64).unwrap(),
        p.bit_len as usize,
    )
    .unwrap();
    verify_record_offline(
        rec,
        &rb.trust_anchors(),
        list,
        p.issued_at,
        now,
        ainra_core::status::Freshness::F2,
    )
}

#[test]
fn the_old_owner_gives_a_lineage_away_and_assurance_starts_again() {
    let mut w = world("ok");
    let req = request(&w, &w.old_operator, T0);
    let id = w.rb.ownership_open(req, T0).unwrap().id;
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let e =
        w.rb.ownership_complete(&id, &assurance(), T0 + CONTEST_WINDOW_SECS - 1, &mut rng)
            .unwrap_err();
    assert!(e.to_string().contains("open to contest"), "{e}");
    let now = T0 + CONTEST_WINDOW_SECS;
    let new =
        w.rb.ownership_complete(&id, &assurance(), now, &mut rng)
            .unwrap();
    assert_eq!(new.sub, "ainra:registrar-07:globex:billing@1.0.0");

    let claims: Value = serde_json::from_str(&new.claims).unwrap();
    assert_eq!(
        claims["tier"], "L1",
        "the tier is the one set for the NEW owner, not the old L2"
    );
    assert_eq!(claims["authority"]["class"], "A3");
    assert_eq!(claims["capabilities"], serde_json::json!(["read:invoices"]));
    let h = &claims["transfer_history"][0];
    assert_eq!(h["kind"], "ownership");
    assert_eq!(h["from"], w.old.sub.as_str());
    assert_eq!(h["leaf_index"], w.old.leaf_index);
    assert_eq!(h["assurance_reset"], true);
    assert_eq!(
        claims["keys"][0]["ed25519"],
        b64::encode(&w.new_agent.public().ed25519)
    );

    assert_eq!(
        verdict(&w.rb, &new, now + 60),
        Verdict::Valid,
        "the new owner's passport verifies"
    );
    assert_eq!(
        verdict(&w.rb, &w.old, now + 60).reason(),
        Some(Reason::Revoked),
        "the old owner's passport ended in the same step"
    );
    assert!(
        w.rb.operator_key_receipt("globex", "billing").is_some(),
        "the new owner's operator key is logged, so it can move or give away the lineage in turn"
    );
    assert_eq!(
        w.rb.ownerships()[0].state,
        TransferState::Completed {
            sub: new.sub.clone()
        }
    );

    // The record survives a restart.
    w.rb.save().unwrap();
    let back = RegistrarBox::load(
        &std::env::temp_dir().join(format!("ainra-ownership-ok-{}", std::process::id())),
    )
    .unwrap();
    assert_eq!(back.ownerships().len(), 1);
}

#[test]
fn an_agent_key_cannot_give_a_lineage_away_and_the_owner_can_stop_a_change() {
    // The agent's own key is not the operator key.
    let mut w = world("agent");
    let req = request(&w, &w.agent, T0);
    let e = w.rb.ownership_open(req, T0).unwrap_err().to_string();
    assert!(e.contains("not signed by the operator key"), "{e}");
    assert!(w.rb.ownerships().is_empty(), "nothing was opened or logged");

    // The old operator key stops a change during the window; a forged stop is refused and leaves no record.
    let mut w = world("stop");
    let req = request(&w, &w.old_operator, T0);
    let id = w.rb.ownership_open(req, T0).unwrap().id;
    let forged = sign_b64(
        &w.agent,
        &contest_message(&id, "operator", "stolen").unwrap(),
    )
    .unwrap();
    assert!(w
        .rb
        .ownership_contest(&id, "stolen", &forged, T0 + 60)
        .is_err());
    assert!(w.rb.ownerships()[0].contests.is_empty());
    let sig = sign_b64(
        &w.old_operator,
        &contest_message(&id, "operator", "stolen").unwrap(),
    )
    .unwrap();
    let o =
        w.rb.ownership_contest(&id, "stolen", &sig, T0 + 60)
            .unwrap();
    assert!(matches!(o.state, TransferState::Refused { .. }));
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let e =
        w.rb.ownership_complete(&id, &assurance(), T0 + CONTEST_WINDOW_SECS, &mut rng)
            .unwrap_err();
    assert!(e.to_string().contains("no longer open"), "{e}");
    assert_eq!(
        verdict(&w.rb, &w.old, T0 + CONTEST_WINDOW_SECS),
        Verdict::Valid,
        "the old passport stands"
    );
}

#[test]
fn every_other_rule_refuses_by_name() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    // The new owner did not prove it holds its operator key.
    let mut w = world("rules-pop");
    let mut req = request(&w, &w.old_operator, T0);
    req.new_operator_pop = req.new_holder_pop.clone();
    assert!(w
        .rb
        .ownership_open(req, T0)
        .unwrap_err()
        .to_string()
        .contains("did not prove"));
    // A request too old.
    let req = request(&w, &w.old_operator, T0);
    assert!(w
        .rb
        .ownership_open(req, T0 + 2 * 86_400)
        .unwrap_err()
        .to_string()
        .contains("too old"));
    // The new name is taken here.
    let mut w = world("rules-taken");
    let spec = IssueSpec {
        operator: "globex".into(),
        lineage: "billing".into(),
        version: "3.0.0".into(),
        tier: "L1".into(),
        auth_class: "A2".into(),
        principal_proof: "x".into(),
        capabilities: vec![],
        scope_ceiling: vec![],
        hops: vec![],
        audit: None,
        holder_key: None,
        holder_pop: None,
        principal_evidence: None,
    };
    w.rb.issue(&spec, &[], &mut rng).unwrap();
    let req = request(&w, &w.old_operator, T0);
    assert!(w
        .rb
        .ownership_open(req, T0)
        .unwrap_err()
        .to_string()
        .contains("cannot merge two lineages"));
    // A revoked passport does not change hands.
    let mut w = world("rules-revoked");
    let sub = w.old.sub.clone();
    w.rb.revoke(&sub, T0 - 60).unwrap();
    let req = request(&w, &w.old_operator, T0);
    assert!(w
        .rb
        .ownership_open(req, T0)
        .unwrap_err()
        .to_string()
        .contains("revoked"));
    // Only the current head changes hands: after a renewal the superseded passport cannot.
    let mut w = world("rules-head");
    let sub = w.old.sub.clone();
    w.rb.reissue(&sub, Some("1.1.0"), T0 - 60, None, &mut rng)
        .unwrap();
    let req = request(&w, &w.old_operator, T0);
    assert!(w
        .rb
        .ownership_open(req, T0)
        .unwrap_err()
        .to_string()
        .contains("current passport"));
    // Two changes at once.
    let mut w = world("rules-busy");
    let req = request(&w, &w.old_operator, T0);
    w.rb.ownership_open(req, T0).unwrap();
    let req = request(&w, &w.old_operator, T0 + 1);
    assert!(w
        .rb
        .ownership_open(req, T0 + 1)
        .unwrap_err()
        .to_string()
        .contains("already open"));
    // A lineage that just changed hands is locked: the new owner cannot pass it on at once.
    let mut w = world("rules-lock");
    let req = request(&w, &w.old_operator, T0);
    let id = w.rb.ownership_open(req, T0).unwrap().id;
    let now = T0 + CONTEST_WINDOW_SECS;
    let new =
        w.rb.ownership_complete(&id, &assurance(), now, &mut rng)
            .unwrap();
    let third = crypto::HybridKeypair::generate(&mut rng);
    let tok = wire_of(&third.public());
    let top = sign_b64(
        &third,
        &operator_key_message("registrar-07", "initech", "billing", &tok).unwrap(),
    )
    .unwrap();
    let thk = wire_of(&third.public());
    let thp = sign_b64(&third, &holder_pop_message("registrar-07", &thk).unwrap()).unwrap();
    let again = |at: u64| {
        let msg = ownership_message(&new.sub, "initech", at, &tok, &thk).unwrap();
        OwnershipRequest {
            from_sub: new.sub.clone(),
            new_operator: "initech".into(),
            requested_at: at,
            new_operator_key: tok.clone(),
            new_operator_pop: top.clone(),
            new_holder_key: thk.clone(),
            new_holder_pop: thp.clone(),
            old_operator_sig: sign_b64(&w.new_operator, &msg).unwrap(),
        }
    };
    let e =
        w.rb.ownership_open(again(now + 86_400), now + 86_400)
            .unwrap_err()
            .to_string();
    assert!(e.contains("locked until"), "{e}");
    w.rb.ownership_open(again(now + TRANSFER_LOCK_SECS), now + TRANSFER_LOCK_SECS)
        .expect("after the lock, the new owner can pass it on with ITS operator key");
}
