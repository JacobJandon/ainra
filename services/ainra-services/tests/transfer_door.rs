// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The transfer door (PLAN-M53 step 7, D-102): a lineage moves from one registrar to another, history intact, with no
//! part for the root. Three real registrars in-process, real keys, real logs, real status lists.
//!
//! WITNESS: a move asked for with a stolen agent key alone, contested by the operator, is refused; the same move,
//! never signed by the operator, is refused when its window closes. A passport issued after the cutoff at a
//! distrusted registrar is refused, while the one moved out of it verifies. Each other rule is asserted by the
//! refusal it causes: the window, the lock, the losing registrar's contest (counted in good standing, ignored once
//! distrusted), a forged contest (refused and not recorded), a revoked passport, a request for another registrar.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ainra_core::verify::TrustAnchors;
use ainra_core::{b64, crypto, Reason, Verdict};
use ainra_services::registrar::transfer::{
    operator_key_message, request_message, sign_b64, wire_of, PeerRegistrar, TransferRequest,
    TransferState, CONTEST_WINDOW_SECS, TRANSFER_LOCK_SECS,
};
use ainra_services::registrar::{
    holder_pop_message, verify_record_offline, HybridB64, IssueSpec, IssuedRecord, RegistrarBox,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::Value;

const NBF: u64 = 1_775_865_600;
const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;
const T0: u64 = NBF + 86_400; // the day the move is asked for
static NO_REVOKED: BTreeSet<[u8; 32]> = BTreeSet::new();

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ainra-transfer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn registrar(tag: &str, id: &str, seed: u64) -> RegistrarBox {
    RegistrarBox::create_seeded(
        &dir(&format!("{tag}-{id}")),
        id,
        64,
        seed,
        NBF - 1000,
        NBF,
        EXP,
    )
    .unwrap()
}

fn spec(op: &str, lineage: &str) -> IssueSpec {
    IssueSpec {
        operator: op.into(),
        lineage: lineage.into(),
        version: "1.0.0".into(),
        tier: "L2".into(),
        auth_class: "A2".into(),
        principal_proof: "deadbeef".into(),
        capabilities: vec!["read:invoices".into()],
        scope_ceiling: vec!["read:invoices".into(), "sign:invoice".into()],
        hops: vec![],
        audit: None,
        holder_key: None,
        holder_pop: None,
        principal_evidence: None,
    }
}

/// A holder key and its proof of possession for `registrar` (D-063).
fn csr(kp: &crypto::HybridKeypair, registrar: &str) -> (HybridB64, HybridB64) {
    let key = wire_of(&kp.public());
    let pop = sign_b64(kp, &holder_pop_message(registrar, &key).unwrap()).unwrap();
    (key, pop)
}

fn directory(of: &[&RegistrarBox], distrust: Option<(&str, u64)>) -> TrustAnchors {
    let mut a = TrustAnchors {
        registrars: Default::default(),
    };
    for r in of {
        a.registrars.extend(r.trust_anchors().registrars);
    }
    if let Some((id, cut)) = distrust {
        a.registrars.get_mut(id).unwrap().distrust_from_leaf = Some(cut);
    }
    a
}

fn verdict(rec: &IssuedRecord, at: &RegistrarBox, anchors: &TrustAnchors, now: u64) -> Verdict {
    let p = at.publish_status(now);
    let list = ainra_core::status::StatusList::decode(
        &b64::decode(&p.status_list_b64).unwrap(),
        p.bit_len as usize,
    )
    .unwrap();
    verify_record_offline(
        rec,
        anchors,
        list,
        p.issued_at,
        now,
        ainra_core::status::Freshness::F2,
    )
}

/// One lineage at `from`, its agent key, its operator key logged there.
struct World {
    from: RegistrarBox,
    to: RegistrarBox,
    agent: crypto::HybridKeypair,
    operator: crypto::HybridKeypair,
    old: IssuedRecord,
    rng: ChaCha20Rng,
}

fn world(tag: &str) -> World {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD1_02);
    let mut from = registrar(tag, "registrar-07", 71);
    let to = registrar(tag, "registrar-08", 81);
    let agent = crypto::HybridKeypair::generate(&mut rng);
    let operator = crypto::HybridKeypair::generate(&mut rng);
    let mut s = spec("acme", "billing");
    let (k, p) = csr(&agent, "registrar-07");
    s.holder_key = Some(k);
    s.holder_pop = Some(p);
    let old = from.issue(&s, &[], &mut rng).unwrap();
    let okey = wire_of(&operator.public());
    let pop = sign_b64(
        &operator,
        &operator_key_message("registrar-07", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    from.register_operator_key("acme", "billing", &okey, &pop)
        .unwrap();
    World {
        from,
        to,
        agent,
        operator,
        old,
        rng,
    }
}

/// A request to move `w.old` to `to`, signed by the agent key, and by the operator if `operator_signs`.
fn request(w: &World, to: &str, at: u64, operator_signs: bool) -> TransferRequest {
    let (new_key, new_pop) = csr(&w.agent, to);
    let msg = request_message(&w.old.sub, to, at, &new_key).unwrap();
    TransferRequest {
        from_sub: w.old.sub.clone(),
        to_registrar: to.into(),
        requested_at: at,
        new_holder_key: new_key,
        new_holder_pop: new_pop,
        holder_sig: sign_b64(&w.agent, &msg).unwrap(),
        operator_sig: operator_signs.then(|| sign_b64(&w.operator, &msg).unwrap()),
    }
}

fn open(w: &mut World, anchors: &TrustAnchors, operator_signs: bool) -> String {
    let req = request(w, "registrar-08", T0, operator_signs);
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let (sk, st) = (w.from.status_public(), w.from.publish_status(T0));
    let side = PeerRegistrar {
        anchors,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    w.to.transfer_in(req, &w.old, &receipt, &side, T0)
        .unwrap()
        .id
}

fn complete(
    w: &mut World,
    id: &str,
    anchors: &TrustAnchors,
    now: u64,
) -> Result<IssuedRecord, String> {
    let (sk, st) = (w.from.status_public(), w.from.publish_status(now));
    let side = PeerRegistrar {
        anchors,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    let old = w.old.clone();
    let mut rng = w.rng.clone();
    w.to.transfer_complete(id, &old, &side, None, None, now, &mut rng)
        .map_err(|e| e.to_string())
}

fn state(w: &World, id: &str) -> TransferState {
    w.to.transfers()
        .iter()
        .find(|t| t.id == id)
        .unwrap()
        .state
        .clone()
}

#[test]
fn a_stolen_agent_key_alone_does_not_move_a_lineage() {
    let mut w = world("stolen");
    let dir_a = directory(&[&w.from], None);
    // The thief holds the agent key, not the operator key. The door opens the move in public …
    let id = open(&mut w, &dir_a, false);
    // … and the operator, watching, stops it.
    let sig = sign_b64(
        &w.operator,
        &ainra_services::registrar::transfer::contest_message(&id, "operator", "not_mine").unwrap(),
    )
    .unwrap();
    let t =
        w.to.transfer_contest(&id, "operator", "not_mine", &sig, &dir_a, T0 + 3600)
            .unwrap();
    assert!(
        matches!(t.state, TransferState::Refused { .. }),
        "the operator's contest must stop the move"
    );
    let e = complete(&mut w, &id, &dir_a, T0 + CONTEST_WINDOW_SECS + 1).unwrap_err();
    assert!(
        e.contains("no longer open"),
        "a stopped move never completes: {e}"
    );

    // The same theft with nobody watching: the window closes, and the operator never signed.
    let mut w = world("stolen-quiet");
    let id = open(&mut w, &dir_a, false);
    let e = complete(&mut w, &id, &dir_a, T0 + CONTEST_WINDOW_SECS + 1).unwrap_err();
    assert!(e.contains("operator never signed"), "{e}");
    assert!(matches!(state(&w, &id), TransferState::Refused { .. }));
    assert_eq!(w.to.len(), 0, "nothing was issued");

    // The agent asks, the operator agrees during the window: that move completes.
    let mut w = world("consent");
    let id = open(&mut w, &dir_a, false);
    let req = request(&w, "registrar-08", T0, true);
    w.to.transfer_consent(&id, req.operator_sig.as_ref().unwrap(), T0 + 60)
        .unwrap();
    complete(&mut w, &id, &dir_a, T0 + CONTEST_WINDOW_SECS + 1)
        .expect("an operator-signed move completes");
}

#[test]
fn an_operator_signed_move_completes_after_the_window_with_its_history() {
    let mut w = world("ok");
    let dir_a = directory(&[&w.from], None);
    let id = open(&mut w, &dir_a, true);
    let e = complete(&mut w, &id, &dir_a, T0 + CONTEST_WINDOW_SECS - 1).unwrap_err();
    assert!(
        e.contains("open to contest"),
        "not before the window closes: {e}"
    );
    let now = T0 + CONTEST_WINDOW_SECS;
    let new = complete(&mut w, &id, &dir_a, now).unwrap();
    assert_eq!(new.sub, "ainra:registrar-08:acme:billing@1.0.0");
    assert_eq!(
        state(&w, &id),
        TransferState::Completed {
            sub: new.sub.clone()
        }
    );

    // The history is in the SIGNED claims and names the old passport's place in the old log.
    let claims: Value = serde_json::from_str(&new.claims).unwrap();
    let h = &claims["transfer_history"][0];
    assert_eq!(h["from"], w.old.sub.as_str());
    assert_eq!(h["log_origin"], "ainra-log/registrar-07");
    assert_eq!(h["leaf_index"], w.old.leaf_index);
    assert_eq!(h["at"], now);
    // The old leaf is still provable in the old log: the trail is unbroken.
    let old_root = w.from.root_public();
    ainra_services::registrar::verify_log_inclusion(&w.old, &old_root, now)
        .expect("old leaf still in the old log");

    let both = directory(&[&w.from, &w.to], None);
    assert_eq!(
        verdict(&new, &w.to, &both, now + 60),
        Verdict::Valid,
        "the moved passport verifies"
    );
    // Until the losing registrar is shown the new passport, the old one still verifies: the overlap is stated.
    assert_eq!(verdict(&w.old, &w.from, &both, now + 60), Verdict::Valid);
    let (sk, st) = (w.to.status_public(), w.to.publish_status(now + 120));
    let asked = w.to.transfers()[0].request.clone();
    w.from
        .transfer_out(
            &new,
            &asked,
            &PeerRegistrar {
                anchors: &both,
                revoked_delegates: &NO_REVOKED,
                status_key: &sk,
                status: &st,
            },
            now + 120,
        )
        .expect("the losing registrar revokes the old passport");
    assert_eq!(
        verdict(&w.old, &w.from, &both, now + 180).reason(),
        Some(Reason::Revoked),
        "after transfer-out the old passport is revoked"
    );
    assert_eq!(
        verdict(&new, &w.to, &both, now + 180),
        Verdict::Valid,
        "and the new one is not"
    );

    // The record survives a restart (D-080: every write persists).
    w.to.save().unwrap();
    let back = RegistrarBox::load(&std::env::temp_dir().join(format!(
        "ainra-transfer-ok-registrar-08-{}",
        std::process::id()
    )))
    .unwrap();
    assert_eq!(back.transfers().len(), 1);
    assert_eq!(
        back.transfers()[0].state,
        TransferState::Completed {
            sub: new.sub.clone()
        }
    );
}

#[test]
fn the_losing_registrar_may_contest_only_in_good_standing() {
    // In good standing, with a listed reason: counted, the move stops.
    let mut w = world("rc-good");
    let dir_a = directory(&[&w.from], None);
    let id = open(&mut w, &dir_a, true);
    let bad = w
        .from
        .sign_transfer_contest(&id, "we_want_to_keep_them")
        .unwrap();
    let e =
        w.to.transfer_contest(
            &id,
            "registrar",
            "we_want_to_keep_them",
            &bad,
            &dir_a,
            T0 + 60,
        )
        .unwrap_err();
    assert!(
        e.to_string().contains("needs one of"),
        "a reason outside the closed list is refused: {e}"
    );
    let sig = w.from.sign_transfer_contest(&id, "fraud_evidence").unwrap();
    let t =
        w.to.transfer_contest(&id, "registrar", "fraud_evidence", &sig, &dir_a, T0 + 60)
            .unwrap();
    assert!(matches!(t.state, TransferState::Refused { .. }));

    // A forged contest (some other registrar's key) is refused and not recorded.
    let mut w = world("rc-forged");
    let id = open(&mut w, &dir_a, true);
    let stranger = registrar("rc-forged", "registrar-09", 91);
    let forged = stranger
        .sign_transfer_contest(&id, "fraud_evidence")
        .unwrap();
    assert!(w
        .to
        .transfer_contest(&id, "registrar", "fraud_evidence", &forged, &dir_a, T0 + 60)
        .is_err());
    assert!(
        w.to.transfers()[0].contests.is_empty(),
        "a forged contest leaves no trace in the record"
    );
    assert_eq!(state(&w, &id), TransferState::Open);

    // Distrusted: the contest is recorded, not counted, and the move completes.
    let mut w = world("rc-distrusted");
    let cut = w.old.leaf_index + 2; // after the passport and the operator key
    let dir_d = directory(&[&w.from], Some(("registrar-07", cut)));
    let id = open(&mut w, &dir_d, true);
    let sig = w.from.sign_transfer_contest(&id, "fraud_evidence").unwrap();
    let t =
        w.to.transfer_contest(&id, "registrar", "fraud_evidence", &sig, &dir_d, T0 + 60)
            .unwrap();
    assert_eq!(
        t.state,
        TransferState::Open,
        "a distrusted registrar cannot keep its customers"
    );
    assert!(!t.contests[0].counted && t.contests[0].note.contains("distrusts"));
    complete(&mut w, &id, &dir_d, T0 + CONTEST_WINDOW_SECS).expect("the move completes");
}

#[test]
fn after_the_cutoff_the_distrusted_registrar_is_refused_and_the_moved_passport_verifies() {
    let mut w = world("cutoff");
    let cut = w.old.leaf_index + 2; // the passport, then the operator key; everything later is past the cutoff
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let late = w.from.issue(&spec("acme", "late"), &[], &mut rng).unwrap();
    assert!(late.leaf_index >= cut);
    let dir_d = directory(&[&w.from], Some(("registrar-07", cut)));
    let id = open(&mut w, &dir_d, true);
    let now = T0 + CONTEST_WINDOW_SECS;
    let moved = complete(&mut w, &id, &dir_d, now).unwrap();
    let all = directory(&[&w.from, &w.to], Some(("registrar-07", cut)));
    assert_eq!(
        verdict(&late, &w.from, &all, now).reason(),
        Some(Reason::RegistrarDistrusted),
        "issued after the cutoff at the distrusted registrar: refused"
    );
    assert_eq!(
        verdict(&moved, &w.to, &all, now),
        Verdict::Valid,
        "the moved passport verifies"
    );
}

#[test]
fn every_other_rule_refuses_by_name() {
    let mut w = world("rules");
    let dir_a = directory(&[&w.from], None);
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let try_in = |w: &mut World, req: TransferRequest, now: u64, anchors: &TrustAnchors| {
        let (sk, st) = (w.from.status_public(), w.from.publish_status(now));
        let side = PeerRegistrar {
            anchors,
            revoked_delegates: &NO_REVOKED,
            status_key: &sk,
            status: &st,
        };
        let old = w.old.clone();
        w.to.transfer_in(req, &old, &receipt, &side, now)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    // For another registrar.
    let req = request(&w, "registrar-09", T0, true);
    assert!(try_in(&mut w, req, T0, &dir_a)
        .unwrap_err()
        .contains("not this registrar"));
    // Too old.
    let req = request(&w, "registrar-08", T0, true);
    assert!(try_in(&mut w, req, T0 + 2 * 86_400, &dir_a)
        .unwrap_err()
        .contains("too old"));
    // Not signed by the passport's key.
    let mut req = request(&w, "registrar-08", T0, true);
    req.holder_sig = req.operator_sig.clone().unwrap();
    assert!(try_in(&mut w, req, T0, &dir_a)
        .unwrap_err()
        .contains("own key did not sign"));
    // Operator signature from some other key.
    let mut req = request(&w, "registrar-08", T0, true);
    req.operator_sig = Some(req.holder_sig.clone());
    assert!(try_in(&mut w, req, T0, &dir_a)
        .unwrap_err()
        .contains("operator signature"));
    // A receipt whose operator key is logged after the cutoff.
    let dir_cut = directory(&[&w.from], Some(("registrar-07", w.old.leaf_index + 1)));
    let req = request(&w, "registrar-08", T0, true);
    assert!(try_in(&mut w, req, T0, &dir_cut)
        .unwrap_err()
        .contains("after the registrar's distrust cutoff"));
    // Two moves of one lineage at once.
    let req = request(&w, "registrar-08", T0, true);
    try_in(&mut w, req, T0, &dir_a).unwrap();
    let req = request(&w, "registrar-08", T0 + 1, true);
    assert!(try_in(&mut w, req, T0 + 1, &dir_a)
        .unwrap_err()
        .contains("already open"));

    // A revoked passport cannot move.
    let mut w = world("rules-revoked");
    let sub = w.old.sub.clone();
    w.from.revoke(&sub, T0 - 60).unwrap();
    let req = request(&w, "registrar-08", T0, true);
    assert!(try_in(&mut w, req, T0, &dir_a)
        .unwrap_err()
        .contains("revoked"));
}

#[test]
fn a_lineage_that_moved_is_locked() {
    let mut w = world("lock");
    let dir_a = directory(&[&w.from], None);
    let id = open(&mut w, &dir_a, true);
    let at = T0 + CONTEST_WINDOW_SECS;
    let moved = complete(&mut w, &id, &dir_a, at).unwrap();
    // The operator logs its key at the new registrar and asks to move again, to a third one.
    let okey = wire_of(&w.operator.public());
    let pop = sign_b64(
        &w.operator,
        &operator_key_message("registrar-08", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    let receipt =
        w.to.register_operator_key("acme", "billing", &okey, &pop)
            .unwrap();
    let mut third = registrar("lock", "registrar-09", 91);
    let both = directory(&[&w.from, &w.to], None);
    let again = |third: &mut RegistrarBox, w: &World, now: u64| {
        let (new_key, new_pop) = csr(&w.agent, "registrar-09");
        let msg = request_message(&moved.sub, "registrar-09", now, &new_key).unwrap();
        let req = TransferRequest {
            from_sub: moved.sub.clone(),
            to_registrar: "registrar-09".into(),
            requested_at: now,
            new_holder_key: new_key,
            new_holder_pop: new_pop,
            holder_sig: sign_b64(&w.agent, &msg).unwrap(),
            operator_sig: Some(sign_b64(&w.operator, &msg).unwrap()),
        };
        let (sk, st) = (w.to.status_public(), w.to.publish_status(now));
        third
            .transfer_in(
                req,
                &moved,
                &receipt,
                &PeerRegistrar {
                    anchors: &both,
                    revoked_delegates: &NO_REVOKED,
                    status_key: &sk,
                    status: &st,
                },
                now,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let e = again(&mut third, &w, at + 10 * 86_400).unwrap_err();
    assert!(e.contains("locked until"), "{e}");
    again(&mut third, &w, at + TRANSFER_LOCK_SECS).expect("the lock ends");
}

/// One attack per hole the adversarial pass over this door found (2026-11-07). Each must be refused.
#[test]
fn attacks_on_the_door_are_refused() {
    use ainra_core::checkpoint::CheckpointSig;
    let dir_a = |w: &World| directory(&[&w.from], None);

    // A checkpoint signed by a delegate the directory revoked (a stolen delegate key could otherwise forge an
    // operator-key receipt): refused.
    let mut w = world("atk-delegate");
    let anchors = dir_a(&w);
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let fp = match receipt.checkpoint_sig.to_core().unwrap() {
        CheckpointSig::Delegate { cert, .. } => cert.fingerprint(),
        CheckpointSig::Root { .. } => {
            panic!("the reference registrar signs checkpoints in delegate mode")
        }
    };
    let revoked: BTreeSet<[u8; 32]> = [fp].into();
    let (sk, st) = (w.from.status_public(), w.from.publish_status(T0));
    let side = PeerRegistrar {
        anchors: &anchors,
        revoked_delegates: &revoked,
        status_key: &sk,
        status: &st,
    };
    let (req, old) = (request(&w, "registrar-08", T0, true), w.old.clone());
    let e =
        w.to.transfer_in(req, &old, &receipt, &side, T0)
            .unwrap_err()
            .to_string();
    assert!(
        e.contains("checkpoint_invalid") || e.contains("revoked"),
        "{e}"
    );

    // An edited status index: the record's unsigned copy points at a clear bit while the signed claims name the
    // revoked one. Refused, read from the signed claims.
    let mut w = world("atk-idx");
    let anchors = dir_a(&w);
    let sub = w.old.sub.clone();
    w.from.revoke(&sub, T0 - 60).unwrap();
    w.old.status_idx += 7;
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let (sk, st) = (w.from.status_public(), w.from.publish_status(T0));
    let side = PeerRegistrar {
        anchors: &anchors,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    let (req, old) = (request(&w, "registrar-08", T0, true), w.old.clone());
    let e =
        w.to.transfer_in(req, &old, &receipt, &side, T0)
            .unwrap_err()
            .to_string();
    assert!(e.contains("revoked"), "{e}");

    // A name already taken at the gaining registrar: a move would merge two owners' lineages under one status bit.
    let mut w = world("atk-name");
    let anchors = dir_a(&w);
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut someone_else = spec("acme", "billing");
    someone_else.version = "0.9.0".into();
    w.to.issue(&someone_else, &[], &mut rng).unwrap();
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let (sk, st) = (w.from.status_public(), w.from.publish_status(T0));
    let side = PeerRegistrar {
        anchors: &anchors,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    let (req, old) = (request(&w, "registrar-08", T0, true), w.old.clone());
    let e =
        w.to.transfer_in(req, &old, &receipt, &side, T0)
            .unwrap_err()
            .to_string();
    assert!(e.contains("cannot merge two lineages"), "{e}");

    // A completed move, then: transfer-out without the customer's own signed request (what a hostile registrar
    // holding only a passport it issued could send), and shedding the lock with a fresh version.
    let mut w = world("atk-out");
    let anchors = dir_a(&w);
    let id = open(&mut w, &anchors, true);
    let now = T0 + CONTEST_WINDOW_SECS;
    let new = complete(&mut w, &id, &anchors, now).unwrap();
    let both = directory(&[&w.from, &w.to], None);
    let asked = w.to.transfers()[0].request.clone();
    let (sk, st) = (w.to.status_public(), w.to.publish_status(now + 60));
    let gaining = PeerRegistrar {
        anchors: &both,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    let mut no_operator = asked.clone();
    no_operator.operator_sig = None;
    let mut forged_holder = asked.clone();
    forged_holder.holder_sig = asked.operator_sig.clone().unwrap();
    let mut another = asked.clone();
    another.requested_at += 1;
    for (bad, why) in [
        (no_operator, "operator key logged here"),
        (forged_holder, "old passport's key"),
        (another, "history records"),
    ] {
        let e = w
            .from
            .transfer_out(&new, &bad, &gaining, now + 60)
            .unwrap_err()
            .to_string();
        assert!(e.contains(why), "{why}: {e}");
    }
    assert_eq!(
        verdict(&w.old, &w.from, &both, now + 90),
        Verdict::Valid,
        "nothing was revoked by a refused transfer-out"
    );
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let mut v2 = spec("acme", "billing");
    v2.version = "2.0.0".into();
    let fresh = w.to.issue(&v2, &[], &mut rng).unwrap();
    let claims: Value = serde_json::from_str(&fresh.claims).unwrap();
    assert_eq!(
        claims["transfer_history"][0]["from"],
        w.old.sub.as_str(),
        "a fresh version keeps the moves, so the lock and the trail cannot be shed"
    );
}

/// The 2026-11-07 review (D-104): a distrusted registrar cannot strand a customer through its status list — not by
/// revoking during the window, not by going dark — and another registrar's genuine list cannot stand in for the
/// passport's own.
#[test]
fn a_distrusted_registrar_cannot_strand_a_customer_through_its_status() {
    let mut w = world("strand");
    let cut = w.old.leaf_index + 2;
    let dir_d = directory(&[&w.from], Some(("registrar-07", cut)));
    let id = open(&mut w, &dir_d, true);
    // The distrusted registrar revokes its customer during the window, and then publishes nothing at all.
    let sub = w.old.sub.clone();
    w.from.revoke(&sub, T0 + 3600).unwrap();
    let dark = ainra_services::status::SignedStatusList {
        uri: String::new(),
        status_list_b64: String::new(),
        bit_len: 0,
        issued_at: 0,
        sig_ed25519: String::new(),
        sig_mldsa65: String::new(),
    };
    let sk = w.from.status_public();
    let side = PeerRegistrar {
        anchors: &dir_d,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &dark,
    };
    let old = w.old.clone();
    let mut rng = w.rng.clone();
    let new =
        w.to.transfer_complete(
            &id,
            &old,
            &side,
            None,
            None,
            T0 + CONTEST_WINDOW_SECS,
            &mut rng,
        )
        .expect("the move completes: a distrusted registrar's status counts for nothing");
    assert_eq!(new.sub, "ainra:registrar-08:acme:billing@1.0.0");

    // In good standing, another registrar's genuine, fresh list cannot stand in for the passport's own.
    let mut w = world("substitute");
    let dir_a = directory(&[&w.from], None);
    let stranger = registrar("substitute", "registrar-09", 91);
    let receipt = w.from.operator_key_receipt("acme", "billing").unwrap();
    let (sk, st) = (stranger.status_public(), stranger.publish_status(T0));
    let side = PeerRegistrar {
        anchors: &dir_a,
        revoked_delegates: &NO_REVOKED,
        status_key: &sk,
        status: &st,
    };
    let (req, old) = (request(&w, "registrar-08", T0, true), w.old.clone());
    let e =
        w.to.transfer_in(req, &old, &receipt, &side, T0)
            .unwrap_err()
            .to_string();
    assert!(e.contains("not the one the passport names"), "{e}");
}
