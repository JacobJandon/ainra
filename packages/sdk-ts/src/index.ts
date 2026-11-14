// SPDX-License-Identifier: Apache-2.0 OR MIT
// @ainra/sdk — the package root: everything an integrator uses to DECIDE, and nothing that only replays a vector.
//
// The implementation lives in engine.ts. This file names what the root exports, one by one, because since 0.7.0 the
// corpus runners (runVector and the other run*Vector, expectedVerdict) are not among them: they believe a vector's own
// clock, freshness class and status list, so they must never be how anyone decides trust (D-074). They live in
// `@ainra/sdk/conformance`. test/root-exports.test.mjs fails if anything engine.ts exports is missing here, other
// than those runners — so a new export cannot silently stay internal.

export {
  applyGatePolicy, canonicalize, contentDigest, coveredComponents, createDecisionLog, createDirectoryHolder, DECISION_V, denyMatches,
  decisionRequestDigest, decisionSigningBytes, decodeInstance, HEAD_V, headHash, headSigningBytes,
  INSTANCE_CRED_DEFAULT_SECS, instanceCredDigest, instanceSigningBytes, isPresentationRef, joinPresentation,
  jwkThumbprintEd25519, jwkThumbprintEs256, jwkThumbprintEs256k, linkFromIndex, linkPopSigningBytes, MAX_AGE_SECS, MAX_CAPABILITIES,
  MAX_FUTURE_SECS, MAX_IID_LEN, mintInstanceCredential, mintWit, numberFromName, PASSPORT_VALIDITY_DEFAULT_SECS,
  POP_HEADER, POP_MAX_FUTURE_SECS, POP_MAX_SKEW_SECS, popSigningBytes, PRESENTATION_HEADER, presentationRef,
  presentedKeyAlg, presentedKeyThumbprint, PRIME_PATH, proveInstancePossession, RENEWAL_LEAD_SECS, renewalDue, serializeVerdictEvent,
  SIG_ALG, SIG_LABEL, signatureBase, signDecision, signHeadStatement, signPresentation, signWimseRequest,
  splitPresentation, strictB64u, trustDomainOf, verdictEvent, Verifier, verify, verifyDecisionChain,
  verifyDecisionChainToHead, verifyDelta, verifyDirectory, verifyDirectoryAtLeast, verifyFreshHead,
  verifyHeadStatement, verifyLogCheckpoint, verifyPresentation, verifyWimseRequest, WIMSE_SIG_MAX_SECS, WIMSE_TAG,
  wimseIdentifier, WIT_HEADER, WIT_MAX_SECS, WIT_TYP,
} from "./engine.js";

export type {
  AccreditedSet, ChainAnchor, ChainProblem, ChainResult, CheckpointSig, DecisionInput, DecisionLog, DecisionRecord,
  DelegateCert, DirectoryAcceptance, DirectoryEpochResult, DirectoryHolder, DirectoryRefusal, FreshHead,
  FreshnessClass, GatePolicy, HeadChainResult, HeadStatement, HeadVerdict, HopLogProof, HybridSigner, InstanceCredential,
  InstancePop, LinkAttribution, LinkIndex, LinkVerdict, MandateInclusion, Presentation, PresentationBundle,
  PresentationCheck, PresentationReason, PresentedBundle, Reason, RegistrarInfo, SignableRequest, SigParams,
  StatusDelta, StatusPublication, TrustAnchors, Verdict, VerdictEvent, WireDeltaVector, WireDirectory,
  WireDirectoryEntry, WireDirectoryEpochVector, WireDirectoryVector, WireHeadReceipt, WireLink, WireVector,
} from "./engine.js";
