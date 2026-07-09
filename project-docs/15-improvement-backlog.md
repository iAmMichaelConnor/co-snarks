# Chapter 15 — Improvement backlog (post-Phase-2 code-complete)

*Created 2026-07-08 during the Phase-2 documentation pass. A concrete,
prioritized backlog derived from re-reading ch. 03 (bb diff), ch. 11 (sync
workplan + AS BUILT), ch. 13 (test plan), ch. 14 (command log) and the
co-noir source in the working tree. **Nothing here is implemented** — each
item is a proposal with rationale, location, and effort/impact tags.
Items marked **VERIFY:** are open questions where the docs/commits do not
prove the matter is handled — check before assuming either way.*

Tags: effort S/M/L (hours / day-ish / multi-day), impact H/M/L.
Soundness-surface labels follow ch. 13 §9: soundness lives in the
**verifiers** and the **co-builder**; the prover carries completeness +
privacy only.

## 1. Missing / under-specified changes (verification tasks)

Ordered roughly by risk. Several are already implied by PLAN item 2.7; they
are listed here so nothing rides on memory.

1. **✅ DONE (was: trailing-proof-bytes check absent).** [S / M —
   verifier robustness + bb parity] — **fixed on `mc/secreg-27`, commit
   `a7621aa4`.** `Transcript::assert_fully_consumed` now asserts
   `num_frs_read == proof_data.len()` after the final (KZG:W) read in the
   plain/MPC decider verify path; new error `HonkProofError::
   ProofNotFullyConsumed`. Regression test `trailing_proof_data_rejected`
   in `tests/tests/noir/proof_tests/security_regression.rs`.
   *(NOTE: the recursion verify path is in-circuit and does not use this
   runtime transcript — its proof-size is instead pinned by the
   `assert_eq!` added in item 2.6's honk_recursion_constraint size check.)*
2. **✅ DONE (was: off-curve points PANIC).** [S–M / M — verifier DoS
   robustness] — **fixed on `mc/secreg-27`, commit `a7621aa4`.** New
   fallible `HonkCurve::g1_affine_from_xy_checked` (`new_unchecked` +
   `is_on_curve()` + `is_in_correct_subgroup_assuming_on_curve()` →
   `HonkProofError::PointNotOnCurve`) used at the three untrusted parse
   sites: `transcript.rs` `receive_point_from_prover` and both
   `verification_key.rs` `from_buffer{,_keccak}`. Regression tests
   `offcurve_proof_point_rejected` + `offcurve_vk_commitment_rejected`.
3. **✅ RESOLVED as DO-NOT-CHANGE (2026-07-08): non-canonical (≥modulus)
   field encodings must be REDUCED, not rejected, in the Ultra path — matches
   bb v5-next.** Investigated: `5f09c55a57` added the ≥modulus *rejection*
   only to **MsgPack** deserialization (and a related trailing-data check
   only to **ChonkProof** MsgPack) — NEITHER touches the UltraHonk
   proof/VK/transcript field path co-noir reimplements. bb v5-next's Ultra
   field deser still reduces (montgomery/`self_reduce_once`); co-noir already
   matches via ark `from_be_bytes_mod_order`. Adding a rejection here would
   DIVERGE from bb → parity break. bb v5-next leaves non-canonical acceptance
   unchanged in the Ultra path → match bb, change nothing. (Honest proofs are
   canonical anyway; out-of-range encodings reduce identically in both → same
   accept/reject.) No code change; this is a parity-match invariant, not a fix.
4. **✅ DONE (2026-07-09): `log_circuit_size` VK check ported
   (`1391c49546`); `5f09c55a57`'s other checks confirmed N/A.** [S / M —
   verifier] Investigation found neither commit had been mirrored, and the
   `log_circuit_size` gap was worse than bb's: the field-encoded
   `from_buffer` path **panicked** on a `log_circuit_size = 0` VK
   (`BigUint::to_u64_digits()` returns an empty vec for zero, so `[0]`
   indexed out of bounds), and `from_buffer_keccak` **silently accepted**
   it → 0 verifier rounds → underflow in the Gemini fold loop.
   **Fix:** new `VerifyingKeyBarretenberg::check_log_circuit_size`
   (reject `0` or `> CONST_PROOF_SIZE_LOG_N`, returns
   `HonkProofError::CorruptedKey`) called in both loaders; the three
   `to_u64_digits()[0]` conversions now use `.first().copied().unwrap_or(0)`;
   defense-in-depth `saturating_sub` at `shplemini_verifier.rs`
   `get_fold_commitments`. Regression test
   `zero_log_circuit_size_vk_rejected` (both loaders). `5f09c55a57`'s
   remaining hunks target IPA / ECCVM / Translator / Chonk (co-noir does not
   implement these) or a KZG `expected_final_msm_size` check whose mismatch
   cannot arise in co-noir's fixed-index Ultra design — no port needed.
   (Non-Ultra MsgPack/Chonk portions were already dispositioned in item 3.)
5. **✅ RESOLVED as BYTE-NEUTRAL (2026-07-09): gemini masking dyadic-size
   commit `1f9d87ba3a` confirmed allocation-only.** [S / L–M — ZK parity]
   Analyzed the commit directly: it only raises the masking poly's
   `virtual_size` to `dyadic_size()`; the random-coefficient count is
   unchanged and the tail is virtual zero → commitment/transcript/MLE
   bit-identical (it fixes a debug-only one-past-end assert). co-noir uses a
   full dyadic all-random masking poly — a different but compatible shape,
   since the poly is per-prover randomness and never byte-compared; the
   bidirectional ZK bb cross-verify covers it. No code change. Closure note
   recorded in ch. 14 §17.
6. **VERIFY: Shamir randomness accounting has zero test coverage at the
   party count that uses it.** [M / H — Shamir completeness]
   Ch. 14 §17.2: 3-party Shamir takes the `num_pairs = 0` on-the-fly path;
   `ultrahonk_num_randomness` (`co-ultrahonk/src/co_ultra_prover.rs`,
   ~line 169+) is only exercised at ≥4 parties. The hand-fixed 24-draw
   undercount would NOT have been caught by any in-tree test. See test idea
   §2.1 below.
7. **VERIFY: examples vector set + the 5 version-pin locations are still at
   beta.20 / old-bb.** [S / M — deliberate 2.7 residue, easy to forget]
   Confirmed in-tree 2026-07-08: `examples/compare.sh`, `compare_mpc.sh`,
   `co-noir/co-noir/Readme.md` still say beta.20; most
   `examples/test_vectors/*` are beta.20-compiled (serde error
   `invalid type: integer 11` when read). Intentional until 2.7 — but 2.7
   must also give `compare*.sh` a third oracle slot for
   `~/.bb-target-src/bb` (ch. 14 §17.2) and ideally `set -o pipefail` +
   artifact-existence checks (the §11/§19.2 silent-failure gotcha, hit
   twice).
8. **✅ RESOLVED (2026-07-09): builder circuit construction is
   deterministic today; the `acir_format.rs:417` comment was stale.**
   [M / H if real — co-builder correctness]
   Full sweep of `co-builder` + `co-acvm` for iterated unordered containers:
   the flagged site was fixed in the SAME commit that introduced the comment
   (upstream `dee0972b3`, 2025-02: `HashMap` → `BTreeMap<block_id, _>`);
   the comment read as an open risk and has now been reworded. Every other
   `HashMap`/`HashSet` in the builder path is either lookup-only (never
   iterated) or iterated in a provably order-independent way (unique-value
   search, commutative fold, debug print). Structural guard already in
   place: crate-level `#![warn(clippy::iter_over_hash_type)]` + CI clippy
   `-D warnings` makes any new hash-map iteration a build error (single
   `#[allow]` in `pss_store.rs:38` audited safe — output never feeds gate
   emission). Residual gap → new test idea §2.9: no in-tree vector has ≥2
   memory blocks, so a `BTreeMap`→`HashMap` revert at that site would pass
   the current single-array KATs.
9. **🔴 CONFIRMED PARITY BREAK (2026-07-09): the `recursion` circuit's VK
   and proof do NOT match bb — co-noir builds a different circuit from the
   same ACIR.** [M / H — recursion soundness surface] The byte-level VK
   oracle this item asked for was built and run (twice, independently, both
   binary format, freshly `nargo compile`d ACIR fed to both sides):
   - `recursion` VK: **DIFFERS** at byte 112 (first SIGMA commitment); 3680
     B both. `recursion_zk`: same, differs at byte 112. Keccak variants
     differ at byte 97. The `poseidon` non-recursion control is
     **byte-identical** → methodology sound.
   - Header (log_circuit_size=20, num_public_inputs=9, pub_inputs_offset=5)
     matches; ~21/28 precomputed commitments differ (SIGMA_1–4, ID_1–4,
     LAGRANGE_LAST, most Q selectors); Q_LOOKUP/TABLE/Q_ELLIPTIC match only
     because unused (all-zero). LAGRANGE_LAST differing ⇒ the *real*
     (pre-pad) gate count differs, i.e. co-builder emits a different number
     and/or order of gates for the in-circuit verifier subcircuit than bb's
     C++ recursion verifier does.
   - **End-to-end impact confirmed**: bb verifies {co-noir proof + co-noir
     VK} = PASS and {bb proof + bb VK} = PASS, but the two CROSS
     combinations ({co-noir proof + bb VK} and {bb proof + co-noir VK}) both
     **FAIL**, and the proofs differ at byte 272. So a co-noir-generated
     recursion proof will NOT verify against a bb-issued VK and vice versa.
   - This was masked because prior "recursion bb-cross-verify" checks used
     the SAME key on both sides (co-noir proof + co-noir VK), which only
     tests co-noir's internal consistency, not parity with bb. PLAN/PROGRESS
     "recursion self-verifies + bb-cross-verifies" is true only in that
     weaker sense.
   - **Scope**: recursion only; all 31 non-recursion circuits are
     byte-identical to bb. Fixing needs a co-builder recursion-verifier
     gate-emission investigation (see the localization note in ch. 14 §21 /
     PROGRESS) — deferred, flagged to Mike. Reproduction artifacts:
     scratchpad `recvk2/`.
10. **✅ RESOLVED (2026-07-08): `(0,0)` sentinel collides with no valid point
    on either curve — verified computationally.** [S / M — co-builder
    soundness] Step ① adopted bb's `(0,0)` encoding for the point at
    infinity with MPC infinity detection (2 eq-tests + 1 mult). The
    argument, checked by direct computation (Euler/cubic-residue criteria):
    - **BN254 G1** (y² = x³ + 3 over F_p): x=0 needs y² = 3, but
      3^((p−1)/2) ≡ −1 (mod p) → 3 is a non-residue → no point has x = 0.
      y=0 needs x³ = −3, but (−3)^((p−1)/3) ≢ 1 (p ≡ 1 mod 3) → −3 is not
      a cubic residue → no point has y = 0 either.
    - **Grumpkin** (y² = x³ − 17 over F_r, the builder's embedded curve):
      (−17)^((r−1)/2) ≡ −1 → no point has x = 0; 17^((r−1)/3) ≢ 1 → no
      point has y = 0.
    So on both curves no valid affine point has **even one** zero
    coordinate; the MPC eq-test detection (is_zero(x) ∧ is_zero(y)) can
    never be triggered — even partially — by a valid shared point.

## 2. Missing test ideas (beyond ch. 13's plan)

Each tied to the surface it guards. The ch. 13 §3a trio (SSIPA
kernel-perturbation case, ROM/RAM field-wrap, non-canonical/trailing)
remains the mandatory floor —
these are additions, not replacements.

1. **≥4-party Shamir proving test.** [M / H — completeness]
   One slow-marked 4-party (or 5-party) Shamir e2e prove+verify for a small
   circuit. This is the only way to exercise `ultrahonk_num_randomness`
   (backlog §1.6); today an under-count ships silently and fails at
   customer runtime. Guards: Shamir randomness accounting.
2. **Transcript-consumption property test.** [S / M — verifier]
   For a valid proof of length L: every truncation rejects, every extension
   rejects, exact length verifies. Generalizes the Phase-0 trailing-bytes
   finding into a cheap loop; subsumes ch. 13 §3.4 once §1.1 lands.
3. **Commit VK KATs + per-KAT provenance.** [S / H — anti-drift + parity]
   There are NO VK byte KATs in-tree (ch. 14 §15); VK parity currently
   exists only as a live-bb check that 2.7 runs manually. Commit
   bb-generated VK bytes for each vector (both hashers) plus a
   `PROVENANCE` file recording the bb version and that it was
   source-built — this also operationalizes the §17.1 oracle lesson.
   Guards: entity order, trace layout, all builder gate changes.
4. **✅ DONE (2026-07-09): entity-order lock test.** [S / M —
   verifier+builder consistency] `entity_order_lock` module in
   `co-noir-common/src/polynomials/entities.rs` (3 tests) asserts every
   precomputed/witness/shifted column index against a hand-transcription of
   bb's `EntityId` enum (global 0–40) from
   `flavor/generated/ultra_flavor_generated.hpp`, plus the three
   `*_ENTITIES_SIZE` totals (28/8/5). Catches an accidental struct/const
   reorder locally, no bb install needed.
5. **Per-relation alpha-assignment negatives.** [M / M — verifier]
   For each relation, a witness violating ONLY that relation's constraint
   (bad range for delta-range, bad EC add for elliptic, …) must be
   rejected. A relation-tuple/alpha mis-assignment (the 2.5 risk class) can
   cancel between relations in ways a single happy-path KAT never probes;
   nine small vectors pin each alpha slice to its subrelation.
6. **Negative recursion test.** [M / H — recursion verifier soundness]
   Feed the in-circuit verifier a tampered inner proof / wrong inner VK and
   assert the outer circuit is unsatisfiable (proving fails or the outer
   proof is rejected). The recursion verifier is a soundness surface with
   currently zero negative coverage — all ch. 13 §3 negatives run the
   native verifier only.
7. **Lookup `table_index ≥ 1` + SHA slice-range regression tests.** [S / M —
   builder soundness, guards the two extra 2.6 findings]
   (a) assert the first assigned lookup table_index is 1 (the logup "at
   least beta cubed" guarantee, bb `0a7d0af035`); (b) a witness with an
   out-of-range (>10-bit) CH-L2 slice must fail to prove/verify (the
   bb `bbbde54094` soundness rationale). These two were *discovered late*
   precisely because nothing tested them; don't let a refactor regress
   them invisibly.
8a. **Multi-block ROM/RAM vector (added 2026-07-09 from §1.8's sweep).**
   [S / M — builder determinism + coverage]
   No in-tree circuit touches ≥2 distinct memory blocks, so the
   `BTreeMap<block_id, _>` grouping in `acir_format.rs` (the determinism
   fix) is unexercised where it matters: a revert to `HashMap` would pass
   every current KAT. One Noir vector with two RAM arrays + a ROM array,
   wired into the compare scripts, closes it (and adds multi-block memory
   parity coverage bb-side too).
8. **MPC-path negatives.** [M / M — MPC mirrors]
   Run the ch. 13 §3/§3a negative set through the REP3 prover→verifier
   loop, not just plain (ch. 13 §5.2 says this but 2.7's current task list
   only mentions the plain path). A soundness gap could live only in a
   `co-` mirror (e.g. the shared-path ROM/RAM pinning in
   `process_ram_array_*` — the MPC variant is separate code from the
   public one).

## 3. Rust refactoring / performance ideas

From the 72 `TACEO TODO`s in `co-noir/` plus doc-recorded hot spots. All are
**post-2.7** work: never refactor mid-sync (ch. 12 §1 rule 2), and each
perf change must re-pass the KAT byte gate. MPC context for
prioritization: an MPC multiplication costs a network round-trip, so
*batching muls* dominates everything CPU-side in the recursion-verifier
path.

1. **Batch MPC multiplications in the recursion verifier.** [M / H]
   Explicit TODOs at
   `co-builder/src/honk_verifier/verifier_relations/{elliptic,delta_range_constraint,memory,poseidon2_external}_relation.rs`
   (~lines 58/51/44/67), `honk_verifier/claim_batcher.rs:72,124`
   (which also recomputes `inverse_vanishing_eval_neg * nu_challenge`
   twice), and `honk_verifier/shplemini.rs:311,372` (incl. "batch invert /
   no zero check"). Each un-batched mul in MPC-recursion is a
   communication round; collecting them into one `mul_many` per relation
   evaluation is the single biggest latency lever for co-snark recursion.
2. **Batch `is_zero` checks on received points.** [M / M]
   `oink_recursive_verifier.rs:89`, `shplemini.rs:74`,
   `types/honk_recursion_constraint.rs:68` — per-point `is_zero` in MPC is
   again a round each; the points arrive together and the checks are
   independent, so one batched round suffices.
3. **Right-size proving-key polynomial allocations.** [M / M–H for large
   circuits]
   `co-builder/src/keys/proving_key.rs:57` "BB allocates less memory for
   the different polynomials": co-noir allocates full-`n` vectors where bb
   sizes per trace block. For MPC the waste is ×(share size) and hits all
   3 parties; for PXE-scale circuits (Phase 5) memory is the binding
   constraint.
4. **Parallelize plain proving-key construction.** [S–M / M]
   `co-builder/src/keys/plain_proving_key.rs:297` "Barretenberg uses
   multithreading here" — the workspace already depends on rayon; a
   `par_iter` over independent polynomial fills is low-risk (no MPC
   ordering concerns in the *plain* key path) and speeds every
   plaindriver-based test loop.
5. **Tighten the Shamir randomness over-allocation.** [M / M]
   The TODO atop `ultrahonk_num_randomness` (`co_ultra_prover.rs`):
   "because a lot is skipped in sumcheck prove, we generate a lot more than
   we really need" — the sumcheck term charges
   `CRAND_PAIRS_FACTOR × MAX_PARTIAL_RELATION_LENGTH × (n−1)` as if every
   relation ran at max width every round. Over-allocation is safe but
   costs Shamir preprocessing time/traffic. ⚠ Do this only AFTER the
   ≥4-party test (§2.1) exists — under-shooting breaks proving at runtime
   with no compile-time signal.
6. **Eliminate the flagged polynomial clones.** [M / M]
   `co-noir-common/src/polynomials/polynomial.rs:259` and
   `co-noir-common/src/mpc/plain.rs:275` ("here we clone…"), plus
   `polynomial.rs:67`'s awkward `zero: F` field (kept only so a method can
   return `&zero`). Borrow/`Cow`/slice-based APIs remove full-vector copies
   on the proving hot path; the `zero` field wants a small API rethink
   (return `F` by value or use `std::sync::LazyLock`-style constant).
7. **Lazy-initialize plookup basic tables.** [M / S–M]
   `co-builder/src/types/plookup.rs:1201` "not all are initialized here! We
   should probably only initialize those we need": every circuit currently
   pays construction of the full table catalogue (incl. the big SHA/uint
   multitables) even when unused. Build on first use keyed by
   `BasicTableId`.
8. **Batch decompositions in the builder.** [M / M for range-heavy
   circuits]
   `ultra_builder.rs:1460,3117,4906,4969` — repeated "could batch"
   decomposition sites; in the MPC-shared path each decomposition is
   communication, so batching compounds with item 1.

## 4. Maintainability / anti-drift ideas

The compile-time 410/458/115 asserts (constants.rs:86-88) are the pattern:
make drift fail loudly and locally. More of the same:

1. **✅ DONE (2026-07-09): compile-time invariant block extended.** [S / M]
   Added `const _` asserts: `NUM_ALL_ENTITIES == 41`, `TRACE_OFFSET == 4`,
   `CONST_PROOF_SIZE_LOG_N == 25`, `NUM_LIBRA_COMMITMENTS == 3`,
   `NUM_SMALL_IPA_EVALUATIONS == 4`, `NUM_SMALL_IPA_OPENING_CLAIMS == 5`
   in `co-noir-common/src/constants.rs`; `NUM_SUBRELATIONS == 29` beside
   each of the three subrelation-count definitions (co-builder verifier
   relations, co-ultrahonk decider relations, ultrahonk decider relations);
   `NUM_ALPHAS == 28` plus cross-crate equality asserts tying `ultrahonk`'s
   duplicated constants to the `co-noir-common` originals. (The `+42 ZK`
   entity count and the separate 4-eval/3-commitment SSIPA breakdown are
   implied by the constants already asserted.)
2. **Entity/relation-order manifest generated from bb's flavor-codegen.**
   [M–L / H]
   bb's source of truth is now TypeScript specs
   (`scripts/flavor-codegen/src/flavors/*.ts`, ch. 03 §2). Check in a small
   derived manifest (JSON/Rust const of the ordered entity + relation
   names) and a test asserting co-noir's iteration order matches it. A
   future sync becomes: regenerate manifest from the new tag → the test
   diff *is* the reorder work list. (Test-idea §2.4 is the manual v0 of
   this.)
3. **Commit VK KATs + provenance files** — see §2.3; listed here too
   because it is the cheapest drift tripwire per byte. [S / H]
4. **✅ DONE (2026-07-09): checked in `rust-toolchain.toml` (pin
   1.90.0).** [S / M] One file at the repo root; rustup now auto-selects the
   right toolchain. Readme "Building this workspace" note updated (no more
   manual `rustup override`).
5. **✅ DONE (2026-07-09): version pins single-sourced in
   `versions.env`.** [S–M / M] New `versions.env` at the repo root holds
   `NARGO_VERSION`, `BARRETENBERG_VERSION`, `BARRETENBERG_BINARY_DEFAULT`;
   sourced by `compare.sh`, `compare_mpc.sh`, and both `compile.sh`; the
   co-noir Readme now points at it. A pin bump is a one-line diff. (The
   scripts already pointed at the source-built oracle by default — item
   §1.7's "third oracle slot" is thus the standing default, env-overridable
   via `BARRETENBERG_BINARY`.)
6. **✅ DONE (2026-07-09): oracle bootstrap scripted.** [S / M]
   `scripts/build-bb-oracle.sh`: `git archive <tag> barretenberg/cpp` →
   cmake preset default `-DAVM=OFF` → install `bb` + write `PROVENANCE.txt`
   → optional `CHECK_AGAINST=<candidate bb>` byte-compares `write_vk`
   output against the fresh source build (the §17.1 rc.2 tripwire). Reads
   the tag from `versions.env`; smoke-tested against the existing
   `~/.bb-target-src/bb` (VK byte-identical). Leaves ~20% of cores free.
7. **✅ DONE (2026-07-09): parity scripts hardened against silent
   failure.** [S / M] `compare.sh` + `compare_mpc.sh` now `set -uo
   pipefail` (not `-e`: the per-case loop deliberately accumulates failures
   in `exit_code`), delete stale `vk`/`proof`/`public_inputs` before each
   bb run, and assert the oracle actually produced non-empty artifacts
   (erroring the case out with a message) before any `diff`/`verify` — the
   exact gotcha behind the two fake "VK DIFF" readings.
8. **Adopt PLAN-item numbering as the only work-item identifier.** [S / S]
   The 2.x numbering drifted three ways across PLAN.md / ch. 11 / the
   session logs (see ch. 11's mapping table). Rule going forward: PLAN.md
   numbers are identifiers; chapter/section numbers are locations; logs
   quote PLAN numbers. Zero code impact, prevents the next
   archaeology session.
9. **Differential-fuzz harness vs bb (ch. 13 §6.1) as the Phase-4
   centerpiece.** [L / H]
   Already planned (PLAN 4.1/4.3); recorded here because several §1 VERIFY
   items (recursion parity, gemini masking byte-neutrality) would be
   subsumed by a random-witness differential loop against nightly bb, and
   the negative-test seed set grows over time as new soundness invariants
   are identified from code review, differential findings, and upstream bb
   changes.
