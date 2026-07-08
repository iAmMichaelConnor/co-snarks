# Chapter 4 — `monty-hall-aztec`: the Aztec ↔ co-SNARK integration pattern

*Facts verified 2026-07-08 against `~/monty-hall-aztec` (Taceo demo, README:
"small demo … not yet finished"). Read chapters 01–02 first.*

## 1. What it is

A proof-of-concept of **"Private Shared State" (PSS) on Aztec**, using the
Monty Hall game as the toy app: an MPC network collectively holds private state
that *no single party — not even the user's PXE — can see*, produces
collaborative UltraHonk proofs of correct state transitions, and an Aztec
contract verifies those proofs inside **private functions** and anchors the
state as note commitments. This is the closest existing artifact to the
PLAN.md end-goal ("co-snarkified UH proofs using an Aztec user's secret data
from their PXE"), so its architecture is the reference pattern — but it is
**unfinished and pinned to a mid-2025 stack**.

Layout: `contract/` (Aztec contract), `noir_logic/` (circuits the MPC proves),
`mpc/` (Rust services).

## 2. Architecture (the part we'd reuse conceptually)

```
User ──HTTP──▶ Orchestrator (axum, :3000)
                   │  fan-out gRPC (tonic), parallel to all 3
                   ▼
        ┌── mpc-node 0 (:8000) ──┐
        │── mpc-node 1 (:8001) ──│──── mpc-net TLS mesh (:10000-2)
        └── mpc-node 2 (:8002) ──┘     (REP3 protocol runs here)
              │ each node: Postgres (state shares), CryptoDevice (X25519 key)
              ▼
   co-noir library calls: generate_witness_rep3 → generate_proving_key_rep3
                          → Rep3CoUltraHonk::<_,_,Poseidon2Sponge>::prove
              │
              ▼
   Orchestrator: asserts all 3 returned proofs byte-identical,
   verifies with UltraHonk::verify against Barretenberg VK + G2 CRS,
   then (TODO, stubbed) submits on-chain
              │
              ▼
   Aztec: proof+VK pushed into PXE **capsules** → contract private function
   pops them and calls std::verify_proof_with_type(vk, proof, public_inputs,
   vk_hash, HONK_IDENTIFIER=1)  → recursive UH verification in-circuit
   → state stored as TACEONote / PrivateSharedMutable
```

Key mechanisms worth internalizing:

- **Two separate networks**: orchestrator→nodes control plane (gRPC) vs
  node↔node MPC data plane (mpc-net TLS mesh). Clean separation we should keep.
- **Proof "recombination" is byte-equality**: the MPC protocol opens the proof
  elements internally, so every party emits the same complete proof. There is
  no shard-stitching step (a common misconception the PLAN.md wording implies —
  worth correcting: nothing needs to "recombine proof shards").
- **User→MPC encryption**: each node derives an X25519 `crypto_box` key from a
  seed phrase (HKDF-SHA256); intended for users to encrypt input shares
  per-node. **Instantiated but not yet wired to anything.** In-circuit
  counterparts (Poseidon2 authenticated encryption, ECDH on Grumpkin) live in
  `noir_logic/pss_utils/{ae,dh}.nr`.
- **Private Shared State on Aztec**: `TACEONote` is a custom note whose hash
  *is* the MPC-produced commitment (PXE never learns the preimage) and which
  can only be nullified with an MPC-computed nullifier;
  `PrivateSharedMutable` is a fork of `PrivateMutable` taking the nullifier as
  input. `NUMBER_OF_VK_HASHES` per-phase VK hashes are stored on-chain and
  checked (`poseidon2::hash(vk, 128)`).
- **In-contract proof verification**: `PROOF_SIZE = 463` fields,
  `VK_SIZE = 128` fields, `HONK_IDENTIFIER = 1`, Poseidon2 transcript — these
  constants are the bb-version-coupled surface.

## 3. Version pins — everything is ~1 year stale

| Component | Pin |
|---|---|
| co-snarks | git rev `5395f991…` (co-noir 0.5.0, mpc-core 0.8.0 era) |
| Noir | v1.0.0-beta.3 |
| Barretenberg | 0.72.1 (compare scripts) |
| aztec-nr | v0.80.0 |

So monty-hall-aztec is pinned ~1 year back even though co-snarks itself is
current. Upgrading it is a separate (later) workstream from upgrading co-noir.

## 4. What breaks when we upgrade the proving stack

- **Contract side (hardest)**: `PROOF_SIZE`/`VK_SIZE`/public-input layout all
  changed in newer bb (public-input handling, pairing-point aggregation, ZK
  transcript). Every `verify_proof_with_type` call site and the VK-hash
  computation need recomputation. aztec-nr v0.80.0 APIs (custom_note traits,
  capsule oracles) have churned heavily since.
- **Rust side**: co-noir's API churned (network/IoContext refactor in
  `5d6bd19e`, proving-key builder signatures); all `mpc/mpc-node/src/mpc.rs`
  call sites need updating. Hardcoded witness-index extraction
  (`witness_share[4]`, indices 11–15) is fragile and flagged in-code.
- **Known pre-existing defects** (correct during upgrade): node proves with
  `ZeroKnowledge::No` but orchestrator verifies with `ZeroKnowledge::Yes`
  (`mpc.rs:148` vs `routes/user.rs:60`); `finish_game` checks `vk_hash[2]` but
  passes `vk_hash[1]` (`contract/src/main.nr:201,217`); `TACEONote::pack`
  duplicates `.x` (`taceo_note.nr:55`); Postgres table-name mismatch
  (`data_store.rs:122`); `reveal_door` is `todo!()`; on-chain submission
  stubbed ("TODO SEND THIS ON CHAIN", `routes/user.rs:31,67`).

## 5. VERIFIED (2026-07-08): the in-contract verification recipe on `v5-next`

This supersedes the demo's obsolete constants (463/128, HONK_IDENTIFIER=1
from bb 0.72). Traced through noir stdlib → ACIR → bb dsl on `origin/v5-next`
(spot-verified in `recursion_constraint.hpp` and `constants.nr`):

- Entry point: `std::verify_proof_with_type(vk, proof, public_inputs,
  vk_hash, proof_type)` (`noir_stdlib/src/lib.nr:82`; there is no plain
  `verify_proof` on this fork). Lowers to the ACIR `RecursiveAggregation`
  blackbox; in a private (Mega) circuit bb instantiates an **in-circuit
  UltraHonk recursive verifier** — the co-snark proof and VK enter as
  *private witnesses* and are **never published**; the final pairing defers
  into the pairing-point accumulator carried through the kernel folding.
- Proof types (`dsl/acir_format/recursion_constraint.hpp:32`): **HONK = 0**
  (non-ZK Ultra), **HONK_ZK = 6** (ZK Ultra). Both recursive verifiers exist
  and are tested on Mega. Noir-side constants in
  `noir-protocol-circuits/.../constants.nr:1308+` — note `PROOF_TYPE_HONK_ZK`
  is *not exported* (upstream TODO); use the literal 6.
- Sizes (constant, padded to virtual log-n 25): proof **410 fields** non-ZK /
  **458 fields** ZK; VK **115 fields** (`RECURSIVE_PROOF_LENGTH=410`,
  `ULTRA_VK_LENGTH_IN_FIELDS=115`). The `proof` array includes the 8
  pairing-point fields but NOT user public inputs (passed separately).
- **Poseidon2 transcript is mandatory** — keccak flavors have no in-circuit
  recursive path. `vk_hash` is constrained in-circuit (Poseidon2 re-hash of
  the VK), so use bb's `write_vk` output hash.
- bb CLI note: `bb prove --scheme ultra_honk --oracle_hash poseidon2`
  produces the **ZK flavor by default**; non-ZK needs `--disable_zk`.
- ZK choice: since the inner proof stays witness data, ZK-ness matters only
  vs whoever *sees the raw proof* (MPC parties, orchestrator, the user, the
  tx assembler). For the PSS pattern (user must not learn MPC state) that
  means **ZK (HONK_ZK=6) is required**; for pure self-delegation non-ZK
  (HONK=0) is acceptable and slightly cheaper in-circuit.
- v6 divergence (FYI): enum shifts CHONK to 8 (HN_TAIL removed); HONK=0 and
  HONK_ZK=6, 410/458/115 all unchanged.

## 6. Critique — hackathon shortcuts we must NOT inherit

*(Context from Mike: this was built as a hackathon project in a couple of
days. It's a valuable pattern demo, but as a design it has real problems.
Each item below is a design input for our phase-5 architecture, beyond the
plain defects listed in §4.)*

**Protocol/privacy design**
1. **Proving non-ZK in a privacy-critical pattern.** The nodes prove with
   `ZeroKnowledge::No`. In PSS, the *user* must not learn the MPC-held state,
   yet they receive the proof — a non-ZK proof of a known circuit can leak
   witness information to exactly the party it must hide from. Our design:
   ZK flavor mandatory for PSS (ch. 04 §5, decision 3).
2. **Byte-equality as the only fault check.** The orchestrator asserts all 3
   returned proofs identical, with no story for divergence: no fault
   attribution (which node deviated?), no retry, no logging of a mismatch as
   a security event. Acceptable for semi-honest demos; a real deployment
   needs at least divergence handling and alerting, even before considering
   malicious-secure MPC.
3. **Nullifier and state flow trusts implicit conventions.** Witness values
   are extracted by **hardcoded indices** into the witness vector
   (`witness_share[4]`, `[11..15]` — flagged "THIS SHOULD NOT HAPPEN" in
   their own comments). Any recompilation can silently reorder these. Proper
   approach: bind outputs via the circuit ABI / declared public inputs, never
   positional witness indices.

**Orchestration/operations**
4. **Single orchestrator, fully trusted for liveness and flow.** It fans out
   jobs, is the only verifier before chain submission, and holds the only
   copy of the control state. No user-side verification of *which* nodes ran,
   no node identity attestation beyond self-signed certs listed in a TOML.
5. **State handling is single-tenant and destructive**: one global game per
   deployment; `init` TRUNCATEs the state table (with a table-name mismatch); no
   job/session IDs, no concurrency, no idempotency. Every request
   re-establishes the whole MPC TCP mesh (`spawn_blocking` + fresh network
   per call) — enormous per-request setup cost, no session reuse.
6. **HTTP GETs with side effects** (`GET /api/sample_rand` mutates state) —
   plus permissive CORS, no auth on any route, no rate limiting.
7. **Key management is placeholder-grade**: node secret keys derived from
   literal phrases `node0/1/2` in a committed `dev.env`; the `crypto_box`
   user-encryption device is instantiated and *never used*; no rotation,
   registration, or attestation story.

**Aztec integration**
8. **Version-frozen constants** (PROOF_SIZE=463, VK_SIZE=128,
   HONK_IDENTIFIER=1) hardcoded in the contract with "iirc" comments — the
   integration breaks silently on any bb bump. Ours should import
   protocol-constants (`RECURSIVE_PROOF_LENGTH`, `ULTRA_VK_LENGTH_IN_FIELDS`)
   and assert against them.
9. **Capsule coupling**: proof/VK delivery depends on implicit capsule stack
   *ordering* (pop order must mirror push order with no tags) — works, but
   fragile; newer capsule APIs allow keyed slots.
10. **`PrivateSharedMutable` is a hand-fork** of aztec-nr's `PrivateMutable`
    that will silently drift from upstream note-lifecycle changes; and
    `TACEONote.compute_nullifier` = `assert(false)` is a blunt way to say
    "MPC-only nullification". A real PSS note abstraction (nullifier as
    input, validated against an MPC key registered in the note) deserves a
    designed API, potentially worth proposing upstream *later*.
11. **Unfinished core loop**: on-chain submission stubbed, `reveal_door`
    `todo!()` — the pattern was demoed to "verify locally" and no further.
    Plus floating git dependencies (no rev pins in Cargo.toml; only the
    lockfile pins), and a Noir-tag/circuit-version mismatch risk.

**What it still gets right** (credit where due): clean two-plane separation
(gRPC control vs mpc-net data), per-node isolated state, parallel fan-out,
orchestrator-side re-verification before submission, and the
capsule→`verify_proof_with_type` in-contract pattern itself — all worth
keeping in our design.

## 7. Takeaways for our project

1. The **pattern** (orchestrator + 3 nodes + capsule-delivered proofs +
   MPC-nullifiable notes) is sound and demonstrably compiles end-to-end to the
   "verify locally" step; on-chain submission was never finished.
2. The demo confirms the **integration seam** is small: one file
   (`mpc/mpc-node/src/mpc.rs`) contains every co-noir call.
3. It validates that **Aztec private functions can verify UH proofs produced
   by MPC** via the standard recursion path — no Aztec protocol changes needed,
   only correct constants (proof size, VK layout, Honk identifier).
4. Its user-side encryption layer is embryonic — building the real
   PXE-integrated share-submission channel is genuinely new work.
