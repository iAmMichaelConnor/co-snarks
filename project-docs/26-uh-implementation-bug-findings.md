# Chapter 26 — UH implementation bug-hunt: consolidated findings

*Session 19, 2026-07-26. Durable copy of the session scratchpad
`uh-bug-findings.md`. Method: three parallel full-strength reviewers (soundness
lens over verifier + circuit-builder; MPC share-handling/leakage lens over the
lever pile; general correctness/robustness lens), each read-only and grounded in
file:line reads, with the two highest-severity items coordinator-verified
against the bb C++ reference. Severities and scopes are the reviewers' + the
coordinator's; F1 is the one that motivates PLAN item 4.4.*

## UH implementation bug-hunt — consolidated findings (session 19, 2026-07-26)

## CONFIRMED (coordinator-verified against bb source)

### F1 — Native verifier does not aggregate the public-input pairing-point accumulator
- **Where:** `co-noir/ultrahonk/src/decider/decider_verifier.rs:131-138`
  (`UltraHonk::verify` path).
- **What:** `verify()` computes only the Shplemini/PCS pairing points and checks
  `e(p0,[1])·e(p1,[x])==1`. It never calls the equivalent of bb's
  `inputs.reconstruct_from_public(public_inputs)` +
  `pi_pairing_points.aggregate(pcs_pairing_points)` before the pairing check.
- **bb reference (confirmed):** `~/aztec-packages-private/barretenberg/cpp/src/
  barretenberg/ultra_honk/ultra_verifier.cpp:223-240` — non-recursive path
  reconstructs the accumulator from public inputs, aggregates the PCS points into
  it with a random separator, and does `pi_pairing_points.check()` on the
  AGGREGATED points.
- **Why gates miss it:** all KAT / cross-verify circuits are non-recursive, so
  the public-input accumulator is the infinity default and aggregate ≡ pcs. The
  recursion/recursion_zk circuits DO carry a real accumulator but verify
  honestly, so both verifiers accept — the divergence is only observable on a
  MALICIOUS accumulator.
- **Impact / scope:** soundness gap in co-noir's NATIVE Rust verifier only. The
  prover still emits bb-parity proofs, so bb / aztec-nr / on-chain verification
  is unaffected (those aggregate correctly). Bites only if co-noir's own
  `verify()` is the final arbiter for a circuit that recursively verifies an
  inner proof. Severity medium (high if native verifier is ever the outermost
  check for recursive circuits).
- **Fix sketch:** in `decider_verifier.rs` (or `ultra_verifier.rs`), reconstruct
  the 8 pairing-accumulator field elements from the public inputs (they are the
  last PAIRING_POINTS_SIZE public inputs), aggregate the PCS points into them
  with the transcript separator, then pairing-check the aggregate. Mirror
  bb's IO::reconstruct_from_public + PairingPoints::aggregate.
- **Status:** FIXED 2026-07-27 (session 20, uncommitted). `verify()` now
  reconstructs the accumulator from the last `PAIRING_POINT_ACCUMULATOR_SIZE`
  public inputs and aggregates the PCS points into it (random separator) before
  the pairing check, mirroring bb. Red-validated with a real recursion circuit
  over a tampered inner proof (bb oracle referees: accepts honest / rejects
  malicious; pre-fix co-noir false-accepted, post-fix rejects). Always-on
  regression test `security_regression::f1_pairing_point_accumulator::*`.
  Non-recursive KATs stay byte-identical (default infinity accumulator adopts
  PCS). Design note: native verify() now uses a random separator, so it is
  bb-faithful but non-deterministic — a transcript-derived separator is an
  option if reproducible native verification is ever wanted.

## CONFIRMED — malformed-input DoS/panic cluster (robustness, pre-existing code)

Same class as the Phase-0 finding (co-noir panics rather than clean-rejects on
off-curve points). All triggerable by a bad file handed to `co-noir verify`;
none is a soundness break (they crash, they don't false-accept). Not part of
the lever pile.

### F2 — Keccak proof/public-input parse panics on non-32-aligned length
- `co-noir/noir-types/src/lib.rs:192` — `chunk.try_into().expect("Chunk should
  be 32 bytes")` on `buf.chunks(32)`; short final chunk panics. VERIFIED.
- The Poseidon2 twin (`SerializeF::from_buffer`, lib.rs:210+) validates length
  and returns Err — only the U256/keccak path panics. Severity high (DoS).
- **Status:** FIXED 2026-07-27 (session 20, uncommitted). `U256::from_buffer`
  now validates `buf.len().is_multiple_of(32)` up front and returns
  `eyre::Result`, mirroring `SerializeF::from_buffer`; `HonkProof<U256>::
  from_buffer` delegates to it. Red-validated: reverting reproduces the exact
  original panic (`Chunk should be 32 bytes: TryFromSliceError(())` at
  lib.rs:628). Regression test `security_regression::f2_keccak_short_final_chunk_rejected`.

### F3 — Unchecked `num_public_inputs` from VK drives `Vec::with_capacity`
- `co-noir/ultrahonk/src/oink/oink_verifier.rs:55` — `Vec::with_capacity(
  public_input_size as usize)` where `num_public_inputs` is a raw u64 from VK
  bytes (only `log_circuit_size` is validated in `from_buffer`). Huge value →
  capacity-overflow abort before the clean per-element read loop. VERIFIED.
- `pub_inputs_offset` unchecked too → `1 + pub_inputs_offset` overflow in
  `compute_public_input_delta` (debug panic / release wrap). Severity high/med.
- **Status:** FIXED 2026-07-27 (session 20, uncommitted). Fixed at the root:
  `VerifyingKeyBarretenberg::from_buffer` / `from_buffer_keccak` (co-noir-common)
  now bound `num_public_inputs` and `pub_inputs_offset` against the circuit size
  implied by the (already-validated) `log_circuit_size`, right alongside the
  existing `check_log_circuit_size` — the sole point untrusted VK bytes become a
  `VerifyingKeyBarretenberg` in the real `co-noir verify` flow, so
  `oink_verifier.rs`/`oink_prover.rs` are never reached with an out-of-range
  value; those files are unmodified (F1 preserved). Red-validated two ways: (a)
  the negative tests fail when the new check is disabled; (b) an end-to-end
  repro (bad VK accepted, then run through `UltraHonk::verify`) reproduced the
  exact predicted panic, `capacity overflow` at `oink_verifier.rs:55:30`.
  Regression tests `security_regression::f3_vk_public_input_bounds::*`.

### F4 — JSON proof path unwraps + keccak u128 truncation
- `co-noir/noir-types/src/lib.rs:117,122` — `.parse::<Fr>().unwrap()` panics on
  non-field strings; `:133,138` — `.parse::<u128>().unwrap()` panics on
  non-numeric AND on any legit 256-bit decimal > u128::MAX, then zero-extends
  128→256 (both crash and silent truncation on the keccak JSON path). Severity
  medium. (Agent report; line-cited, not independently re-read.)
- **Status:** FIXED 2026-07-27 (session 20, uncommitted), with one correction
  to the original write-up: the ">u128::MAX" case does NOT silently truncate —
  `str::parse::<u128>()` errors cleanly on overflow (`ParseIntError{PosOverflow}`)
  rather than wrapping, so `.unwrap()` panics there too; confirmed by red-
  validation (`called Result::unwrap() on an Err value: ParseIntError { kind:
  PosOverflow }`). So both halves of the bug are the same class (crash on
  `.unwrap()`), not crash+truncation. Fix: `.parse::<Fr>().unwrap()` →
  `map_err` to a clean `Err`; the u128 detour replaced entirely with
  `Uint<256, 4>`'s own decimal `FromStr` (the full-width path the byte loader
  already uses), so legitimate >u128::MAX field-element strings now parse
  correctly instead of being rejected/truncated at all. Regression tests
  `security_regression::f4_json_string_parsing::*`.

## Cache-robustness hardenings in the NEW sha path (low severity, agent-reported)

### F5 — sha256 trace-cache stale-purge is behind the all-shared early return
- `co-noir/co-acvm/src/mpc/rep3.rs precompute_sha256_block` (~:1820): the
  `!is_shared → return Ok(())` runs BEFORE the leftover-cache clear; a prior
  all-shared compression's leftovers could be popped by a later mixed-input
  compression (only under read-order drift — itself the bug the canary targets).
  One-line fix: move the clear above the gate. Low (defense-in-depth).
  **FIXED 2026-07-27 (session 20, uncommitted): purge now runs before the
  all-shared early return; fast-check --all-fast green.**

### F6 — cache pop is value-blind (tag + public params only, not the keyed share)
- Accepted design blind spot (referee + byte-KAT are the backstop); recorded.

### F7 — plain `recursion` (HONK_IDENTIFIER=0) REP3 proving panics (found by PLAN 4.4)
- Surfaced 2026-07-27 (session 20) by the new bb_verify_standing.sh --full tier.
  `co-noir/co-acvm/src/mpc/rep3.rs` — the shared-case bigfield-limb family
  (`acvm_type_limbs_to_other_acvm_type` + `other_acvm_type_to_acvm_type_limbs` +
  `add/sub/div_mod/madd_div_mod{,_many}_acvm_limbs`) was `unimplemented!` on the
  shared branch, so plain recursion (which drives a shared cross-field
  Fr-limbs→Fq reconstruction during proving) panicked. `recursion_zk`
  (HONK_IDENTIFIER=6, Aztec's used path) is unaffected. Severity: DoS/panic
  class (crash, not false-accept). **RESOLVED 2026-07-27 (uncommitted, Option B
  = clean unsupported error):** 7 shared-case panics → `eyre::bail!` (public
  paths unchanged; Shamir already `panic!`s the family as "not feasible" — MPC
  is genuinely out of scope for it). New 3-party test
  `co-acvm/tests/rep3_bigfield_shared_unsupported.rs` (public reconstructs;
  shared errs cleanly; red-validated). recursion_zk re-confirmed proving +
  bb-verifying vs the v5.0.1 oracle.

## Clean per the correctness reviewer (explicitly checked)
sha256_sparse_trace GC circuit (all sub-gadgets hand-verified, 42,016-bit
layout + 369-read schedule consistent; correctly avoids the buggy
half_adder_const path), y2b_many width-generality, batched big-quad operand
order, two-pass construct_lookup_read_counts determinism, ohv_from_index_many,
mpc-net try_recv instrumentation (observation-only), env-gated bench paths
(default-off, no protocol race), rayon determinism (no new parallel reductions),
both python bench scripts' units.
