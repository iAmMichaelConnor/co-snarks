# Chapter 17 — monty-hall-aztec quality backlog (reviews of 2026-07-13)

*Sources: two exhaustive read-only reviews (Rust workspace; Noir code vs
current aztec-nr idioms in `~/ap-next` v5-next) + Mike's design write-up
(hackmd.io/@mike-connor/ByZ6tymhyl). Statuses maintained in place.
Tags: effort S/M/L × impact H/M/L. The hackathon origin showed: the worst
finds were in the *original* code, not the modernization.*

## 0. Design context from the HackMD write-up (feeds A5/5.1b/5.0)

- The pattern's core trick: a co-Noir program that adheres to Aztec's
  `PrivateCircuitPublicInputs` layout (read requests / nullifiers / note
  hashes) "is effectively an Aztec smart contract function". The OS
  (orchestrator) executes the contract side and must NEVER see preimages —
  only commitments/nullifiers (this is why PrivateShared* exist).
- MPC-held nullifier secret key = the network's identity; could extend to
  a full MPC-held Aztec address (not implemented).
- Wish-list overlapping our plan: PXE `add_note_hash()` endpoint (→ add to
  ch. 09 scope); PXE secret-sharing (= PLAN 5.0); ZK recursive verifier
  (SOLVED on v5-next: HONK_ZK=6); UH kernel circuits (long-term);
  `SharedMutable` rename (upstream naming note only).
- Known-acknowledged hacks: secure data sharing hand-waved; MPC identity
  is a bare keypair.

## 1. Confirmed bugs — FIXED 2026-07-13 (commit pending on mc/modernize)

1. ✅ **F0 `GameState::choose_door` broken for winning==chosen ∈ {1,2}**
   [S×H — live soundness/liveness bug in the original code]. Noir
   evaluates both branch blocks eagerly: (a) winning==chosen==1 → the
   "equal" branch opened the WINNING (= chosen) door ~half the time;
   (b) winning==chosen==2 → the discarded `3-w-d` underflowed u8 →
   circuit PANICS (game unprovable). All 6 original tests used seed 123
   (winning door 0) and could not see it. FIXED: branch restructured
   (both blocks total + panic-free for all inputs; comment explains the
   eager-evaluation rule); tests: exhaustive (winning,chosen) sweep +
   coin-flip coverage + 3 state-machine negatives (11 tests green).
2. ✅ **Orchestrator returned HTTP 200 on proof-verification failure**
   [S×H]. Now: `ApiErrors::VerificationFailed` → 502; error taxonomy
   rewritten (NodesDiverged names the diverging field — also fixes the
   copy-pasted "seed_commitment differ!" message); all handler
   unwrap/expect removed; VK parsed once at startup; e2e.sh now asserts
   the real signal.
3. ✅ **Side-effecting GETs** [S×H] → POST (+ TraceLayer request logging).
4. ✅ **No session guard on nodes** [M×H]: fixed mesh port meant a second
   concurrent MPC session → EADDRINUSE via an accidental client-side
   queue. Now an explicit per-node `session_lock` (Mutex) + a
   `run_mpc_session` helper (dedupes both handlers, maps failures to
   distinct gRPC statuses; `init_game` without prior randomness →
   FAILED_PRECONDITION; `reveal_door` → UNIMPLEMENTED not `todo!()`).
5. ✅ **Non-transactional TRUNCATE+INSERT** [S×M] → singleton-row atomic
   upserts (migration `20260713140000`); DB deserialization now fallible
   (TryFrom) instead of `.expect` panics.
6. ✅ **Dead `CryptoDevice`** [S×M]: deleted (with the `--key-phrase`
   config + crypto deps); its hidden side effect is now an explicit
   `install_rustls_provider()` (needed by sqlx). NOTE: 5.2's envelope
   encryption will be designed fresh; the crypto_box sketch lives in git
   history (`main`).
7. ✅ Cleanups: orchestrator startup validates `mpc_nodes.len()==3` +
   loads VK/CRS with context errors; node validates circuit ABI param
   names at startup (fail-fast, replaces silent convention); network
   config parsed once (was per-RPC + unwrap); phase-timing log bug fixed
   (delta-vs-cumulative) + `{:.3}`s format; orphaned
   `monty-hall-orchestration/data/` (stale VK/keys, unreferenced)
   deleted; compose postgres image pinned 16-alpine; start_nodes.sh
   header + `set -euo pipefail`; clippy 0 warnings; both gates re-run
   PASS (check.sh + e2e.sh).

## 2. Open — Rust workspace (priority order)

1. **In-process 3-party integration test** [M×H — the big lever]:
   genericize `sample_root_rand`/`init_game`/`commit` over `N: Network`,
   dev-dep `mpc_net` with feature `local`, then a `LocalNetwork`-based
   3-thread test asserting byte-identical proofs + `UltraHonk::verify`
   true + flipped-byte false — the co-snarks `rep3.rs` tests are the
   model. Gives sub-second `cargo test` coverage of what e2e.sh needs
   docker+bb for. (Blocker: `local` feature not in the dep graph yet.)
2. **Unit tests** [S×H]: `extract_public_returns` (happy/shared/out-of-
   range, driving witness index from a real artifact's `return_values`);
   `data_store` serialization round-trips + corrupted-buffer → Err;
   orchestrator handler negatives (mocked divergent responses → 502).
3. **Transport security — DECIDED (Mike 2026-07-13): wire it properly (TLS mesh + gRPC security)** [M×H]: party TOMLs carry key/cert paths that
   mpc-net's `NetworkConfigFile` silently IGNORES (wrong TOML shape → 
   `tls: None`) and the code hardcodes `TcpNetwork` anyway; gRPC plane
   has no TLS/auth either. Decide: wire `TlsNetwork` + tonic mTLS, or
   delete the pretense (certs/keys) and document "plaintext, localhost
   demo only". Upstream note: mpc-net could `deny_unknown_fields`.
4. **CI** [M×H]: nothing runs cargo check/clippy/tests/gates on commit
   (local-only repo → a git hook or a local script convention).
5. Smaller: node-connect retry/backoff at orchestrator startup [S×M];
   committed dev TLS keys under `noir_logic/network/data` — regenerate
   or README-mark as loopback-only [S×L]; MSRV claim vs 1.90 toolchain
   [S×L]; `mpc/README.md` (architecture, port table 8000-2/10000-2/
   8080-2/3000, run paths) [S×H for onboarding].

## 3. Open — Noir (priority order)

1. **pss_utils test coverage** [S/M×H]: `private_state.nr` has ZERO
   tests (verify/verify_and_nullify/compute_nullifier — the soundness
   core): happy paths + tampered commitment/meta + wrong sk/pk
   negatives + KATs pinning commit/nullifier outputs (they're
   chain-visible values; a silent hash change must turn a test red).
   `prng.nr` zero tests (determinism, wrap at position 3, KAT).
   `ae.nr`: add wrong-key, direct tag-tamper, single-slot tamper
   negatives + KATs. `dh.nr`: KAT + non-square-address negative.
2. **F1 `to_address_point` panics for ~half of addresses** [M×H]:
   `sqrt().unwrap()` (upstream TODO aztec-packages #8970). Affects
   `verify_and_nullify`'s pk-binding path. Options: negate-y retry
   (address points are constructed to have square y², so real inputs
   may be fine — VERIFY the caller contract's guarantee) or propagate
   Option.
3. **F2 — DECIDED (Mike 2026-07-13): option (b), full DOM_SEP rework** [M×H]:
   GENERATOR_INDEX__{NOTE_HASH=1,NOTE_NULLIFIER=53} no longer exist on
   v5-next — replaced by `DOM_SEP__NOTE_HASH=116501019` /
   `DOM_SEP__NOTE_NULLIFIER=50789342` + `poseidon2_hash_with_separator`
   with a different preimage shape. Decide: true bit-compat (redo the
   scheme, feeds 5.1b's TACEONote whose hash is the raw commitment) or
   fix the comment to "structurally inspired". KATs first either way.
4. **F3 player-input commitments not tied to on-chain notes** [L×H —
   the known TODO from the demo's last commit]: nothing constrains the
   MPC circuits' `door`/`switch` inputs to equal the user's on-chain
   `UintNote` commitment (whose real hash is a 2-stage domain-separated
   construction now). This is exactly the A5/5.1b integration seam —
   fold into ch. 16 A5 design.
5. Style batch [S×M]: copy `noirfmt.toml` from ap-next + `nargo fmt`;
   `///` docs on all pub items (aztec-nr AGENTS.md structure);
   normalize `// Safety:` and replace the contract's 12
   "This is normal Aztec practice?" placeholders with real
   justifications; `compiler_version` pin in taceo_commit;
   `commit_field_array`+`absorb` are DEAD CODE (delete or test+use);
   fold `monty_hall_test`/`dh_test` bins into lib `#[test]`s (keep
   `taceo_commit` — operational circuit); F4: document (+negative-test)
   the `from_field_unsafe` repurposing in verify_and_nullify; F6 PRNG
   always advances comment (DONE in the F0 fix comment).

## 4. Open — contract (fold into ch. 16 5.1b when it starts)

- **F7 `TACEONote::unpack` second bug** [S×H]: beyond the known
  pack-duplicate-`.x`, unpack reads `packed[1]` (y) as the commitment —
  never `packed[3]`. Round-trip through PXE storage silently corrupts
  the note. Port fix: `#[derive(Packable)]` makes the class impossible.
- **F8 `game_phase` is write-only** [M×H]: no function ever reads or
  asserts it — the phase machine enforces nothing; call order is
  unconstrained (beyond per-note single-init). Port: assert phase (or
  drive the machine from the private state note).
- **F9 no access control** [L×H]: anyone can init (first-caller claims
  the game), choose/switch (first-caller claims the slot), open/finish
  (maybe intentional — proof is the gate — but must become an explicit
  design decision). Port: Map-per-player storage + stored operator
  address where identity matters.
- **F10** (= ch. 16 §5.0 delta table; the review independently
  confirmed it, adding: `compute_nullifier_unconstrained -> Option<Field>`
  is the DESIGNED way to express TACEONote's "no individual party can
  nullify" — replaces the `assert(false)` hack; and
  `SinglePrivateMutable` now has an upstream non-leaky initialization
  nullifier scheme our fork should inherit).
- **F11** [M×M]: consider `PartialUintNote` (partial notes) for
  `opened_door`/`win` delivery — first-class primitive for "value not
  known until later" — instead of the claim-function pattern.

## 5. Suggested execution order

1. §2.1+§2.2 (Rust tests incl. LocalNetwork harness) — locks in 5.1a.
2. §3.1 (pss_utils tests+KATs) + §3.2/§3.3 decisions — locks the crypto
   primitives before A5 builds on them.
3. ch. 16 A5 (open_door round) with §3.4/F3 as part of its design.
4. 5.1b contract port with §4 folded in.
5. §2.3 transport security + §2.5/§3.5 hygiene batches — before anything
   leaves localhost.

## 6. DESIGN OPTION — generic PSS-note primitives + shared hashing library
### (proposed 2026-07-13 with Mike; supersedes the §"learning curve" proposals in the write-up)

*Status: PROPOSED, not built. This is the direction to evaluate when we
next touch `private_shared_state.nr`. It reshapes the contract-side PSS
abstraction from a state-variable fork into a small set of composable
primitives, driven by three realisations from the TXE work + Mike's
review. Written to be self-contained for a future session.*

### 6.1 The three realisations that motivate it

1. **Nobody discovers a PSS (TACEO) note.** Its "contents" (e.g. the
   winning door) are the MPC network's secret shares; the note on-chain
   is only a commitment. The MPC network already knows the preimage; the
   orchestrator knows the note *hash* (a public proof output) but not the
   preimage and doesn't need it; the player only handles their own
   ordinary notes. So **no message delivery is required for TACEONotes** —
   the current `deliver()`/`get_note()` path is dead weight bolted on to
   satisfy `get_note`, and it is exactly what fails ("Failed to get a
   note") because there is no preimage to discover. This is the same gap
   Taceo's HackMD flagged as wanting an `add_note_hash` PXE endpoint.

2. **Inclusion proofs are STILL required (Mike, firm).** Dropping
   discovery must NOT mean dropping the read constraint that the old note
   is actually in the tree — that is a core soundness surface. A PSS
   note's "read" can live in one of three places:
   - **(a) Merkle-membership constraints inside the co-noir circuit** —
     the co-snark itself takes the note-hash-tree root + a membership
     path and verifies inclusion. Heavy (Merkle proof in the co-snark),
     and it couples the circuit to per-block tree state (the root becomes
     a public input that changes every block).
   - **(b) a read of the note_hash within the Aztec private function**
     (no preimage) — the function reads/asserts the hash directly.
   - **(c) a read request from the private function to the kernel for the
     note_hash** — the function pushes a note-hash read request; the
     KERNEL performs the inclusion proof (its standard, audited job),
     keyed on the hash alone, no preimage. **Mike leans (c); we adopt
     (c).** Rationale: reuses the kernel's existing note-hash-inclusion
     machinery; keeps the co-noir circuit completely tree-agnostic (it
     only does pure hashing — see §6.4); cleanest separation of concerns:
     **co-snark proves the state transition; kernel proves inclusion;
     contract binds them.**

   VERIFIED 2026-07-13: the primitive for (c) exists —
   `PrivateContext::assert_note_exists(NoteExistenceRequest)`
   (`~/ap-next/.../aztec/src/context/private_context.nr:662`). It takes a
   `note_hash` (+ optional contract address) and pushes to
   `note_hash_read_requests`; **no preimage**. The orchestrator supplies
   the (public) old note hash as a call input.

3. **The state-variable mould is the wrong PRIMARY abstraction for PSS.**
   Stock aztec-nr state vars (`SinglePrivateMutable`, etc.) *own* the note
   lifecycle and compute nullifiers *locally* from the caller's keys. In
   PSS the co-snark does all of that (opens the old note, computes the
   transition, computes the new commitment, computes the nullifier from
   the MPC-held key); the contract is a thin conduit that reads a hash,
   pushes a nullifier, pushes a new hash, and verifies the proof. Forcing
   that into an `initialize/replace` state-var API (and a monolithic
   `verify_pss_transition` helper) bakes in a single-old-note /
   single-new-note / single-nullifier shape that a generic PSS transition
   (N old notes read, M new emitted, K nullifiers) does not have.

### 6.2 The proposed generic core — composable primitives

Free functions the contract composes in whatever multiplicity its circuit
needs, instead of a stateful wrapper:

```
// inclusion proof of an old PSS note, hash-only (option c)
read_pss_note(context, note_hash)              -> assert_note_exists(note_hash)

// spend an old PSS note with the MPC-proven nullifier, bound to the note
nullify_pss_note(context, note_hash_for_nullification, nullifier)

// anchor a new PSS note (contract has the public hash; no preimage)
emit_pss_note(context, note_hash)              -> push_note_hash(hash) via a TACEONote

// verify the co-snark over its public inputs, with the vk-hash pin
verify_co_snark(context, vk, vk_hash, public_inputs)
```

A per-app convenience like `verify_pss_transition(...)` may still exist,
built ON TOP of these, for a contract whose circuit has exactly one
old/new/nullifier — but it is app-level sugar, not the abstraction. The
generic pattern is: for each old note the circuit declares →
`read_pss_note` + `nullify_pss_note`; for each new note → `emit_pss_note`;
then one `verify_co_snark`; and the contract asserts the proof's public
`nhfn`/hash outputs against the values it read/emitted (the binding that
ties the MPC-supplied nullifier to the actual on-chain note).

**Current-commitment anchoring.** Something must still stop the MPC from
advancing from a stale/forged old state. The chain is anchored by: the
seed note committed at `init` + the nullifier chain (an already-spent old
note cannot be re-advanced — duplicate nullifier is rejected) + the
inclusion proof from (c) (the old hash is really in the tree) + the
`npk_m_hash` binding (the nullifier was produced by the registered MPC
identity). Writing out the exact soundness argument — what a malicious
minority vs. a fully-colluding network could attempt — is a REQUIRED
task before calling this done (Mike flagged it; it is the contract's core
soundness surface).

### 6.3 Reassessment of the four original proposals (from the write-up)

- **#1 `verify_pss_transition` mega-helper → DEMOTE.** Too rigid for the
  generic case (fixes one-old/one-new/one-nullifier). Keep only as
  optional per-app sugar over §6.2's primitives. The primitives are the
  core.
- **#2 typed / ABI-checked public-inputs builder → KEEP, higher value
  generically.** Every co-snark has its own public-input layout; a
  builder checked against the circuit's ABI (we already run `aztec
  codegen`; the Rust side already has a startup ABI-name check) prevents
  the contract's `public_inputs` array from silently drifting from the
  circuit — the single most error-prone line in the contract.
- **#3 no `NoteMessage` returned from PSS methods → KEEP.** Now that
  nothing discovers a TACEONote, returning a `#[must_use]` message you
  must sink is pure noise. The primitives never return one.
- **#4 `PrivateSharedSet`/state-var family → SECONDARY.** Given §6.1(3),
  a `Set`/`Mutable` wrapper is optional sugar over the primitives for apps
  that want per-slot bookkeeping, not the primary abstraction.

### 6.4 Library sharing with aztec smart contracts (Mike's ask)

Goal: co-noir circuits should leverage the same libraries as aztec
contracts. Current state and the gap:

- **ALREADY SHARED:** `pss_utils::aztec_note` depends on the *real*
  `protocol_types` crate (`noir-protocol-circuits/crates/types`, pinned
  to the same tag), using its `poseidon2_hash_with_separator`, the
  siloing/uniquify helpers, `compute_app_siloed_secret_key`, and the
  `DOM_SEP__*` constants directly. So a co-noir circuit and an aztec-nr
  contract compute note/nullifier hashes with the **same primitives and
  constants → bit-identical commitments**, pinned by a KAT (ch. 18 §2).
- **CANNOT be shared:** full aztec-nr — its note helpers are wrapped in
  contract macros / oracles / `context`, none of which exist in a plain
  proving circuit (co-noir circuits are plain Noir, proven as UltraHonk,
  not `#[aztec]` Mega contracts).
- **THE GAP:** the note-hash *composition* — which fields in which order
  (`P2(DOM_SEP__NOTE_HASH, slot, packed…, owner, randomness)`) — is
  expressed twice: once by aztec-nr's `#[note]` macro + `note/utils.nr`
  (contract side), once in `pss_utils::aztec_note` (circuit side). They
  agree today and the KAT enforces it, but it is two definitions that
  must be kept in step.
- **PROPOSED FIX:** factor the *pure* composition (no context/oracles)
  into a plain-Noir library that BOTH the aztec-nr `#[note]` machinery and
  the co-noir circuits import — one definition. Option (c) makes this
  clean: because inclusion is the kernel's job, the co-noir circuit needs
  only pure hashing, which is exactly the shareable part; nothing
  tree- or context-bound leaks into the circuit. (Whether this lib lives
  in our tree, or is proposed upstream into aztec-packages so `note/
  utils.nr` and the macro consume it too, is an open call — upstreaming
  is the drift-proof version but needs their buy-in.)

### 6.5 Scope of the rework (so a future session can size it)

- `contract/montyhall/src/private_shared_state.nr`: replace the
  `PrivateSharedImmutable/Mutable` state-var fork with the §6.2
  primitives (or keep thin `Single*`-style wrappers as sugar over them).
  Drop `deliver()`/`get_note`; read via `assert_note_exists(hash)` with
  the hash supplied by the orchestrator as a call input.
- `contract/montyhall/src/main.nr`: each round passes the old note hash
  as an input, calls `read_pss_note` + `nullify_pss_note` +
  `emit_pss_note` + `verify_co_snark`, and asserts the proof's public
  `nhfn`/hashes against them.
- Co-noir circuits (`noir_logic/monty_hall_*`): essentially unchanged —
  they already compute the right hashes/nullifiers via `aztec_note`.
- Tests: this should let the FULL-game flow go green in TXE (the
  discovery dependency is gone). ⚠ VERIFY first that `assert_note_exists`
  works in TXE for a settled note hash the test supplies without the note
  being in the PXE note store — i.e. whether the kernel/TXE needs a
  membership-witness hint and whether the orchestrator/test can provide
  it. If TXE still can't prove inclusion of an un-discovered settled note,
  the full flow remains a local-network-only gate (but the primitives are
  still the right shape).

### 6.6 Open sub-questions to settle when picking this up

1. Does `assert_note_exists` in TXE (and on the local network) prove
   inclusion of a settled note hash the caller supplies *without* the note
   being in the PXE note store — or does the kernel need a
   membership-witness hint that only discovery would populate? (This is
   the crux of whether (c) fully removes the `add_note_hash` need.)
2. Where does the shared note-hash-composition library live — our tree,
   or upstreamed into aztec-packages so the macro consumes it too?
3. The §6.2 soundness write-up (malicious minority vs. full collusion).
4. Multiplicity: confirm the primitives compose cleanly for a circuit
   that reads/emits more than one note (not exercised by monty-hall,
   which is 1-old/1-new per round, but the generic pattern must support
   it — this is the whole reason to prefer primitives over the mega-helper).
