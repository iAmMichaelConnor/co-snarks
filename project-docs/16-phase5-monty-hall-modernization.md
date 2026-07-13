# Chapter 16 — PLAN 5.1 workplan: modernizing monty-hall-aztec

*Created 2026-07-13 (Phase-5 kickoff). Facts verified against
`~/monty-hall-aztec` @ `d333404` (Taceo demo, unchanged since ch. 04's
survey) and `~/co-snarks` branch `mc/update-co-noir` @ `d8970588` (our
synced co-noir, at parity with bb `v5.0.0-nightly.20260708`). Ch. 04 is
the WHAT/WHY (architecture, critique, the verified v5-next in-contract
recipe); this chapter is the HOW. Sequencing decision (Mike, 2026-07-13):
Phase 5 starts with 5.1; **Rust modernization first, TypeScript
orchestration re-implementation after the Rust path works end-to-end.***

## 0. Goal and definition of done

Bring the monty-hall-aztec pattern from its mid-2025 pins (co-noir 0.5.0 /
Noir beta.3 / bb 0.72.1 / aztec-nr v0.80.0) to our stack: the **local
synced co-noir** (bb `v5.0.0-nightly.20260708` parity) + nargo beta.22 +
v5-next aztec-nr. Done (Rust phase) =

1. The 3-node + orchestrator flow (`sample_rand` → `init_game`) runs
   against our co-noir: all parties emit byte-identical proofs, the
   orchestrator verifies them, **and the source-built bb oracle
   (`~/.bb-target-src/bb`) verifies them too** (the true parity gate —
   "our verifier accepts" alone is a weak oracle, ch. 11 postscript).
2. The Aztec contract compiles against v5-next aztec-nr with the correct
   constants (proof 458 fields ZK / VK 115 / `HONK_ZK = 6`) and its
   `verify_proof_with_type` calls pass in TXE tests fed by MPC-produced
   proofs.
3. The known defects (§2.3) are fixed, and none of the ch. 04 §6
   hackathon shortcuts are silently inherited.

On-chain submission (the part the demo always stubbed) and the TS
orchestration port are 5.1c/5.1d (§6–7) — after the above.

## 1. Ground rules (inherited + new)

- **Confidentiality rail**: work happens on a local branch
  (`mc/modernize`) in `~/monty-hall-aztec`; **disable the origin push URL
  first** (same rail as co-snarks, ch. 14 §12 — this is Taceo's repo and
  our changes embed knowledge of the private target). Local commits only
  when Mike asks. PLAN.md lists `~/monty-hall-aztec` as a read-only
  reference; that designation is superseded by 5.1 for this branch only —
  `main` stays untouched.
- **Dependency direction**: the demo's Cargo git-deps float on
  `TaceoLabs/co-snarks` main with **no rev pin** (only the lockfile pins
  `5395f991`). Our synced co-noir exists ONLY as a local branch, so the
  modernized workspace must use **`path` dependencies into
  `~/co-snarks`** (which also means the mpc workspace inherits our
  `rust-toolchain.toml` 1.90 pin, vs its current edition-2024/1.85 —
  compatible).
- **ZK flavor**: decision 3 (PLAN) says ZK is the default, and PSS is
  exactly the pattern where non-ZK leaks (the user receives a proof over
  witness data they must not learn — ch. 04 §6.1). The demo proves
  non-ZK and verifies ZK (a bug, §2.3). We standardize on
  **`ZeroKnowledge::Yes` everywhere**; the contract-side comment "later
  on with ZK once the recursion is allowed" is moot — `HONK_ZK = 6`
  exists on v5-next (ch. 04 §5).
- **Never guess API shapes**: every "current signature" in §3 was read
  from the working tree on 2026-07-13; re-verify at implementation time
  if the co-snarks branch has moved.

## 2. As-is inventory (verified 2026-07-13)

### 2.1 Layout

```
contract/                Aztec contract (aztec-nr v0.80.0, Noir >=0.25)
  src/main.nr            5 phases; verify_proof_with_type; consts 463/128/1
  src/taceo_note.nr      custom note, hash = MPC commitment
  src/private_shared_mutable.nr   hand-fork of PrivateMutable
  src/pop_capsule.nr     capsule oracle shim (old API)
noir_logic/              plain Noir circuits the MPC proves (beta.3)
  pss_utils/             ae.nr, commit.nr, dh.nr, prng.nr, private_state.nr
  monty_hall/            game_state lib
  monty_hall_{init,choose,switch,test}/, taceo_commit/, dh_test/  bins
  compare.sh, compare_mpc.sh    pinned to bb 0.72.1 / bbup
mpc/                     Rust workspace (edition 2024, rust 1.85)
  mpc-node/              tonic gRPC service; THE co-noir seam = src/mpc.rs
  monty-hall-orchestration/  axum HTTP; verify in src/routes/user.rs
  protos/                gRPC definitions
```

### 2.2 The co-noir seam (every call site, old shape)

`mpc/mpc-node/src/mpc.rs` (all of it) plus one verify block in
`monty-hall-orchestration/src/routes/user.rs:53-60`:

| Site | Old call |
|---|---|
| mpc.rs:40 | `CrsParser::<Bn254>::get_crs_g1(path, CRS_SIZE=4096, ZK::Yes)` |
| mpc.rs:45,50 | `Utils::get_program_artifact_from_file` |
| mpc.rs:80,103 | `IoContext::init(network)` + `io_context.random_fes::<Fr>()` (randomness sampling) |
| mpc.rs:110 | `Utils::get_constraint_system_from_artifact(&artifact, true)` |
| mpc.rs:130,209 | `co_noir::generate_witness_rep3(input_share, circuit, network) -> (witness, net)` |
| mpc.rs:134,216 | output extraction by **hardcoded witness index** (`witness_share[4]`, `[2]`; `[11..15]` in the `todo!()` `extract_game_state`) |
| mpc.rs:142 | `co_noir::generate_proving_key_rep3(net, &cs, witness, false) -> (pk, net)` |
| mpc.rs:148 | `Rep3CoUltraHonk::<_, _, Poseidon2Sponge>::prove(net, pk, &crs, ZeroKnowledge::No) -> (proof, _)` |
| mpc.rs:240,282 | `Rep3MpcNet::new(network_config)` (one network object, moved through calls) |
| user.rs:54-60 | `VerifyingKeyBarretenberg::from_buffer` → `VerifyingKey::from_barrettenberg_and_crs(vk, crs)` → `UltraHonk::<_, Poseidon2Sponge>::verify(proof, vk, ZK::Yes)` |

### 2.3 Defects to fix during the port (re-verified in source today)

1. **ZK mismatch**: proves `ZeroKnowledge::No` (mpc.rs:148), verifies
   `Yes` (user.rs:60) — the demo's verify can only have "passed" by
   accident or never ran. → ZK everywhere (§1).
2. **Hardcoded witness indices** for outputs (mpc.rs:134,216,186-194;
   self-flagged "THIS SHOULD NOT HAPPEN"). → extract via the circuit ABI
   (noirc-abi return-value decoding from the witness stack), never
   positional indices.
3. **Postgres table mismatch**: `init_monty_hall` TRUNCATEs
   `monty_hall_game` but INSERTs into `monty_hall_game_init_state`
   (data_store.rs:122,125) — second init would violate the demo's
   one-row assumption.
4. **`finish_game` vk-hash bug**: asserts against `vk_hash[2]` but passes
   `vk_hash[1]` to `verify_proof_with_type` (contract main.nr:201,217).
5. **`TACEONote::pack` duplicates `.x`** (taceo_note.nr:55).
6. **Stubs**: `reveal_door` `todo!()` (both layers); on-chain submission
   "TODO SEND THIS ON CHAIN" (user.rs:31,67). The `monty_hall_choose` /
   `monty_hall_switch` circuits exist but nothing calls them.
7. Contract constants `PROOF_SIZE=463 / VK_SIZE=128 / HONK_IDENTIFIER=1`
   ("iirc" comments, main.nr:21-23) — bb-0.72-era; see §5.
8. `GAME_OPENED_DOOR` and `GAME_DONE` are both `4` (main.nr:28-29).

### 2.4 What we deliberately keep (ch. 04 §6 "gets right" list)

Two-plane separation (gRPC control / mpc-net data), per-node isolated
state, parallel fan-out, orchestrator re-verification before submission,
capsule → `verify_proof_with_type` in-contract pattern.

## 3. API delta table (old demo call → current co-noir, read from tree 2026-07-13)

| Concern | Old (demo) | Current (`mc/update-co-noir`) |
|---|---|---|
| Network | `Rep3MpcNet::new(config)`, one object threaded through calls | **`Rep3MpcNet` no longer exists.** `mpc_net::tcp::TcpNetwork::networks::<2>(config)` → REP3 uses two parallel `&N` handles (`net0`, `net1`); nothing is consumed/returned |
| Randomness sampling | `IoContext::init(net)` + `random_fes()` | `IoContext` is gone. `Rep3State::new(net, A2BType::default())` owns the correlated RNG (`rngs.rand.random_fes()`); confirm exact accessor at implementation time |
| Witness gen | `generate_witness_rep3(input, circuit, net) -> (witness, net)` | `generate_witness_rep3(input: Rep3SharedInput<Fr>, program, net0: &N, net1: &N) -> Rep3SharedWitness<Fr>` (lib.rs:82) |
| Proving key | `generate_proving_key_rep3(net, &cs, witness, false) -> (pk, net)` | `generate_proving_key_rep3(&cs, witness, net0, net1, prover_crs) -> Rep3ProvingKey` (lib.rs:200) — takes the CRS now; recursion circuits need the real CRS |
| Prove | `Rep3CoUltraHonk::<_,_,H>::prove(net, pk, &crs, zk) -> (proof, _)` (3 generics) | `Rep3CoUltraHonk::<C,H>::prove(net, pk, crs, has_zk, &vk_bb) -> (HonkProof, Vec<public_inputs>)` (co_ultra_prover.rs:96) — 2 generics, **takes the bb-format VK** (ZK masking derives from it), and **returns proof and public inputs separated** |
| Verify | `UltraHonk::verify(proof, vk, zk)` | `UltraHonk::<_,H>::verify(...)` (ultra_verifier.rs:21) — takes separated public inputs; exact arity at implementation time |
| Share types | `Rep3AcvmType` in input maps | input map is `Rep3SharedInput` (`Rep3Type` values); `Rep3AcvmType` remains at the ACVM layer only |
| Noir artifacts | `noirc-{abi,artifacts}` @ beta.3 | beta.22 (match root co-snarks Cargo.toml pins) |

**The proof/public-inputs separation is the load-bearing change**: the
orchestrator's byte-equality check, the DB `proof` column, the gRPC
response shape, and the contract's capsule layout all assumed one
concatenated blob. On v5-next the contract receives `proof` (458 fields
ZK, *including* the 8 pairing-point fields) and `public_inputs`
separately (ch. 04 §5) — which is what the new API hands us anyway.

## 4. Work items — 5.1a (Rust + circuits, current architecture)

Ordered; each has a gate. Never proceed past a red gate.
**Status 2026-07-13: A0–A4 DONE (all uncommitted on `mc/modernize`);
A5 open.** AS-BUILT notes inline below.

- **A0 ✅ — rails + branch.** DONE: pushurl disabled
  (`DISABLED_no_push_confidentiality_rail`), branch `mc/modernize` @
  base `d333404`. Bonus: upstream `themis/reveal_door_circuit` checked —
  it is an ancestor of main (nothing to salvage for A5).
- **A1 ✅ — recompile `noir_logic` at nargo beta.22.** DONE. Actual
  churn, all in `pss_utils` + one game-lib line: `poseidon2_permutation`
  is 1-arg now; `Poseidon2::hash` moved to the external `poseidon` crate
  (dep added, tag v0.3.0 — same as aztec-nr); `u1`→`bool`
  (`to_le_bits`); `EmbeddedCurvePoint` lost `is_infinite` (struct now
  `{x,y}`, `(0,0)` = infinity — same convention as the co-noir builder);
  array indices must be `u32` (Prng/Commit `position: Field` retyped);
  `Field as bool` cast removed — the game's random-bit draw is now
  explicit LSB (`(rand as u8) % 2`; the compiler's suggested `!= 0`
  would have been a *biased* bit — behavior pinned by the 6 game tests).
  Old `compare*.sh` RETIRED (hardcoded a Taceo dev's machine); new
  `noir_logic/check.sh` + `versions.env` + `scripts/oracle_stub.py`
  (plain nargo can't resolve the custom `TACEO_store` oracle — the stub
  answers it with empty values, faithful since it's side-effect-only;
  MPC runs handle it natively in co-brillig `brillig_vm.rs:392`).
  Gate PASS: 6/6 circuits compile, 23/23 lib tests, bb proves+verifies
  `monty_hall_init` (proof 458 fields ZK / VK 115 / tamper rejected).
  Bonus signal: the old Prover.toml's commitment assertion still passes
  → Poseidon2 semantics unchanged across the jump.
- **A2 ✅ — port the mpc workspace.** DONE. Path-deps into
  `~/co-snarks`; **ark 0.5 → 0.6** (must match co-snarks, else "two
  versions of the same crate" type errors); stale Cargo.lock
  regenerated; `rust-toolchain.toml` (1.90.0) added; protoc installed
  locally (`~/.local/bin/protoc`, v29.3 — protos build.rs needs it).
  Migration went exactly per the §3 delta table; co-noir no longer
  re-exports `NetworkConfig`/`CrsParser`/`VerifyingKey*`/`ZeroKnowledge`
  → import from `mpc_net`/`co_noir_common` directly;
  `get_constraint_system_from_artifact` is 1-arg and `AcirFormat` is not
  Clone (recompute from the artifact where needed). Node now sizes the
  CRS from `compute_circuit_size` (was hardcoded 4096) and computes the
  bb-format VK itself (`generate_vk_barretenberg`) since the ZK prover
  requires it. Gate PASS: build green; clippy warnings are pre-existing
  demo cruft only (unused reveal_door plumbing, unused crypto_device).
- **A3 ✅ — defect fixes** (landed with A2): ZK::Yes everywhere;
  hardcoded `witness_share[i]` extraction replaced by
  `extract_public_returns` (reads the ACIR `return_values` witness
  indices from the artifact — §2.3.2); Postgres TRUNCATE table-name fix
  + `public_inputs` column (new migration); proof/public_inputs
  separation wired through protos (`InitGameResponse.public_inputs`),
  DB, and orchestrator (byte-equality now also on public inputs). Also
  fixed latent: orchestrator deserialized `seed_c` as *compressed* while
  nodes serialize *uncompressed* (same bytes for Fr, but now
  consistent). NOTE for 5.1d: the orchestrator returns HTTP 200 even
  when proof verification fails (log-only error) — e2e.sh greps the log;
  the TS rewrite must return a real error.
- **A4 ✅ — e2e gate (the milestone). PASS 2026-07-13**, repeatable as
  `mpc/e2e.sh` (3 dockerized Postgres + 3 nodes + orchestrator +
  API drive + DB proof extraction + bb cross-verify + tamper negative).
  Evidence: 3 byte-identical proofs + public inputs (orchestrator
  asserts); our verifier accepts against the **bb-written** VK (implicit
  VK byte-parity exercise); **source-built target bb verifies the
  MPC-produced ZK proof** (`Proof verified successfully`, exit 0);
  flipped byte → exit 1. Timings (loopback, 32-core box, 3 nodes
  sharing): witness extension 0.85 s, proving key 0.15 s, ZK prove
  1.74 s per party for `monty_hall_init`.
- **A5 — the `open_door` state-transition round (Q1 scope, §8).** New
  MPC circuit (previous-state commitment opening + transition + new
  commitment + MPC-computed nullifier + nullifying-key relation — the
  contract's `open_door` doc-comment is the spec; `monty_hall_choose`/
  `monty_hall_switch` circuits are starting points), node endpoint
  (replaces the `reveal_door` `todo!()`), orchestrator route, DB state.
  Same gate battery as A4. `choose`/`switch`/`finish` stay out of scope.

## 5. Work items — 5.1b (contract to v5-next aztec-nr)

Dependency source: public aztec-packages tag `v5.0.0-nightly.20260708`
(Q4 ✅ §8: its aztec-nr tree ≡ public v5-next HEAD, and the private
v5-next delta doesn't touch anything this port uses).

### 5.0 Contract-side API delta (surveyed 2026-07-13 on `~/ap-next`
v5-next @ `a455b9a943e` ≡ the tag for aztec-nr; file:line cites are into
`~/ap-next/noir-projects` unless said otherwise)

| Concern | Old (demo, v0.80) | Current (v5-next) |
|---|---|---|
| Function attributes | `#[private]` / `#[public]` / `#[initializer]` | **`#[external("private")]` / `#[external("public")]` / `#[external("utility")]`**; `#[internal(…)]`, `#[only_self]` |
| Public call from private | bare `unsafe { fn_name(args) }` | **`self.enqueue_self._fn(args)`** (own contract) / `self.enqueue(Other::at(addr).fn(args))`; `unsafe{}` no longer used for enqueueing (`contract_self_private.nr:298`) |
| Private state vars | `PrivateImmutable` / `PrivateMutable` (bare) | Now **owned** (per-account, wrapped `Owned<…>`, owner baked in). The demo's bare semantics = **`SinglePrivateImmutable` / `SinglePrivateMutable`** (`state_vars/mod.nr:142-174`) — the natural re-fork base for `PrivateSharedMutable`, since MPC-held state has no per-account owner |
| Note return type | `NoteEmission<Note>` + `.discard()` | **`NoteMessage<Note>`**, `#[must_use]`, expects `.deliver(…)`/`.deliver_to(…)`; **no `.discard()`** — the fork must handle "commitment-only note, nobody to deliver to" internally (check `MessageDelivery` modes at build time) |
| `NoteHash` trait | `compute_note_hash(self, storage_slot)`; `compute_nullifier(self, ctx, nh)`; unconstrained variant returns `Field` | `compute_note_hash(self, owner: AztecAddress, storage_slot: Field, randomness: Field)`; `compute_nullifier(self, ctx, owner, nh)`; unconstrained variant returns **`Option<Field>`** (`note/note_interface.nr:1-48`). TACEONote ignores owner/randomness and keeps returning the MPC commitment |
| `#[custom_note]` | exists | **still exists** (`macros/notes.nr:254-269`); expects `Packable` + your own `NoteHash` impl; in-tree model = `uint-note/src/uint_note.nr:30-83` |
| External-nullifier primitive | fork copied `destroy_note_unsafe` internals | **first-class**: `PrivateContext::push_nullifier_for_note_hash(nullifier, note_hash)` (`context/private_context.nr:423-429`) + `get_note` (`note/note_getter.nr:103`) + `compute_confirmed_note_hash_for_nullification` (`note/utils.nr:84`) + `create_note` (`note/lifecycle.nr:40`) — all `pub`; the fork shrinks to ~a screen |
| `Packable` | generic arg: `impl Packable<4>` | **associated const**: `impl Packable for T { let N: u32 = 4; … }`; bounds elsewhere use `Packable<N = M>` (`protocol_types/traits/packable.nr:76-89`) |
| Capsules | raw `#[oracle(popCapsule)]`, order-coupled stack | oracle **gone** (zero grep hits). Now `aztec::capsules::CapsuleArray<T>` + `oracle/capsules::{store,load,delete,copy}`, keyed by `(contract_address, slot, scope)` (`capsules/mod.nr:7-126`) — kills the ch. 04 §6.9 pop-order fragility; proof and VK go in distinct slots |
| `UintNote` | `UintNote::new(value, owner)` | plain struct literal `UintNote { value }`; owner moved to the state-var layer (`Owned<…>`) |
| Poseidon2 | `std::hash::poseidon2::Poseidon2::hash` | **gone from std**; use `aztec::protocol::hash::poseidon2_hash{,_with_separator}` (backed by the external `poseidon` crate v0.3.0) |
| `verify_proof_with_type` | `std::verify_proof_with_type(vk, proof, public_inputs, key_hash, proof_type)` | **unchanged** (`noir_stdlib/src/lib.nr:82-93`) |
| Constants | hardcoded 463/128/1 | importable: `RECURSIVE_PROOF_LENGTH = 410`, `ULTRA_VK_LENGTH_IN_FIELDS = 115` (`constants.nr:635,654`); `PROOF_TYPE_HONK = 0`; **slot 6 (HONK_ZK) still unexported → literal 6** (enum gap confirmed: …ROOT_ROLLUP_HONK=5, HN_FINAL=7…). No exported ZK-proof-length constant found → 458 as a named local const + a build-time check vs bb output |
| Deps | aztec, value_note, easy_private_state, uint_note @ v0.80 | **`value-note` and `easy-private-state` no longer exist in aztec-nr** — drop (they were unused); keep `aztec` + `uint_note` @ the tag |

### Work items

- **B1 — dependency + mechanical port.** Nargo deps → public tag (drop
  the two dead ones); function attributes; enqueue pattern for the
  public-phase writes; Packable form; poseidon2 import; `UintNote`
  literal + `Owned<PrivateImmutable<UintNote>>` for the player-owned
  door notes. Fix `TACEONote::pack` `.x` bug (§2.3.5) while re-impl'ing
  the new `NoteHash`/`Packable` shapes.
- **B1b — re-fork `PrivateSharedMutable` on `SinglePrivateMutable`.**
  Much smaller than the old fork: only `replace`/`get_note` diverge, and
  they now compose from public primitives (delta table row 7) instead of
  copied internals. Design the NoteMessage handling for
  commitment-only notes (nothing to deliver — the preimage exists
  nowhere; investigate `MessageDelivery` variants / a fork-internal
  sink). Ch. 04 §6.10's "designed nullifier-as-input API" ambition is
  satisfied by exactly this thin layer.
- **B2 — proof-verification surface.** Constants per the delta table
  (import where exported; literal 6 + local 458 with provenance
  comments); `vk_hash` = bb `write_vk` hash asserted in-circuit via
  `poseidon2_hash` (confirm padding/length convention matches bb's VK
  hashing at build time). Public-inputs arrays now carry the separated
  public inputs (NOT baked into the proof). Fix `finish_game` vk_hash
  index bug (§2.3.4) and the duplicate phase consts (§2.3.8).
- **B3 — capsule flow.** `pop_capsule.nr` deleted; proof/VK via
  `CapsuleArray`/`capsules::load` under distinct, named slots. The
  writer side moves to TXE oracles (B4) now and the 5.1c tooling later.
- **B4 — TXE gate.** Current pattern: `TestEnvironment::new()` +
  `env.deploy(…)` + `env.call_private/call_public` (in-tree model:
  `public_immutable_contract/src/main.nr:29-74`; state-var-level tests:
  `state_vars/private_mutable/test.nr`). Tests: (i) contract verifies a
  real MPC-produced (A4) proof; (ii) tampered-proof + wrong-VK +
  wrong-vk-hash negatives; (iii) `PrivateSharedMutable` unit tests
  (initialize/replace with external nullifier, double-replace fails).
  First-ever negative coverage on the contract path (soundness lens,
  ch. 13 §9: the verifier call sites are the soundness surface).

## 6. Work items — 5.1c (on-chain wiring; scope with Mike)

The demo never implemented submission. Options when we get here:
(a) minimal TS glue (aztec.js) just to drive sandbox e2e — accepting a
little TS before 5.1d; (b) defer any on-chain run until the 5.1d TS
orchestrator exists and drive it from there. Leaning (a) — the sandbox
e2e is the real proof the constants/capsule work — but this is a
scope call for Mike at the time (open question Q3, §8).

## 7. Work items — 5.1d (TypeScript orchestration port; after Rust works)

Per Mike's 5.1 note: re-implement the orchestration logic (orchestrator +
user-side flows; NOT the MPC nodes themselves) in TypeScript, since
that's what integrators prefer and it feeds the 5.0 PXE-secret-sharer and
5.2 submission-channel work (both TS-native). Design then; inputs: this
chapter's A-items as the behavioral spec, ch. 09 §1 (WASM-compiled REP3
split — the same wasm-bindgen question arises here), ch. 02 §5.3 (CLI
config surface).

## 8. Open questions — Q1/Q2/Q4 ANSWERED (Mike / verified, 2026-07-13)

- **Q1 ✅ (Mike)**: scope = `init` + ONE state-transition round
  (`open_door`) — exercises nullifier flow +
  `PrivateSharedMutable::replace`, which `init` alone doesn't. The
  remaining game phases (`choose`/`switch`/`finish`/`reveal_door` MPC
  logic) are out of scope; the pattern is what we're proving, not the
  game. NOTE this pulls `open_door`'s MPC circuit + node/orchestrator
  endpoints (currently `todo!()`) INTO scope for A3/A4 — the demo never
  implemented them; the `monty_hall_choose`/`monty_hall_switch` circuits
  exist as a starting point for the state-transition circuit.
- **Q2 ✅ (Mike)**: keep Postgres per node (realistic deployment shape);
  script the local 3-DB bring-up.
- **Q3 (open, decide at 5.1c)**: §6's (a)-vs-(b) on-chain scope call.
- **Q4 ✅ (verified 2026-07-13, tree-hash + diff)**: the private
  v5-next aztec-nr differs from the public tag by ~39 files, ALL in
  messaging/tagging/oracles/partial-notes/test-helpers (+ context/hash
  internals) — **nothing in `state_vars/`, `note/`, note macros, or
  capsules**, i.e. the entire surface this port touches is identical.
  Also: public v5-next HEAD aztec-nr ≡ the public tag (no drift).
  **Decision: pin all contract deps + tooling (aztec-nargo, TXE/sandbox)
  to the public release `v5.0.0-nightly.20260708`** — same tag as the bb
  oracle, one coherent toolchain, and Nargo git-deps resolve against the
  public repo naturally.

## 8a. Pin re-verification (2026-07-13, session-start rule)

`origin/v5-next` (private) has moved since the effective-target tag was
pinned (2026-07-08), but the bb drift is 8 files in `wsdb/` (witness-DB
tooling) + `sol/foundry.toml` — **zero commits in any UH-relevant dir**
(ultra_honk, honk, stdlib_circuit_builders, dsl, plonk_honk_shared,
transcript, commitment_schemes). The Phase-2 parity target and the
source-built oracle remain valid.

## 9. Cross-references

- Ch. 04 §5 — the verified v5-next in-contract recipe (constants, ZK
  reasoning, bb CLI flags). §6 — the design critique this plan answers.
- Ch. 02 §5.3–5.4 — co-noir library/CLI surface; what the repo does not
  provide (submission channel → PLAN 5.2).
- Ch. 12 — sync runbook (oracle provenance gotchas apply to A4's bb
  verify step).
- Ch. 13 §9 — soundness lens; B4's negatives are the contract-side
  analogue.
