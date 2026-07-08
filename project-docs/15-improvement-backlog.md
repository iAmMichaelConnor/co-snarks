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
   bb v5-next.** Investigated: `5f09c55a57` (finding 2513) added the ≥modulus
   *rejection* only to **MsgPack** deserialization (and 2501's trailing-data
   check only to **ChonkProof** MsgPack) — NEITHER touches the UltraHonk
   proof/VK/transcript field path co-noir reimplements. bb v5-next's Ultra
   field deser still reduces (montgomery/`self_reduce_once`); co-noir already
   matches via ark `from_be_bytes_mod_order`. Adding a rejection here would
   DIVERGE from bb → parity break. `ignore.md` (governing rule) confirms:
   #1428/#1430/#787 non-canonical acceptance is *unchanged* in v5-next → match
   bb, carry over nothing. (Honest proofs are canonical anyway; adversarial
   ones reduce identically in both → same accept/reject.) No code change; this
   is a parity-checklist invariant, not a fix.
4. **VERIFY: the two verifier-hardening bb commits were never explicitly
   ported.** [S / M — verifier]
   Ch. 03 §2 flagged `1391c49546` (reject VKs with `log_circuit_size = 0` —
   fixed an OOB write in bb's verifier) and `5f09c55a57`
   (BB_ASSERT→throw_or_abort in IPA/KZG/Shplemini error paths) with "mirror
   these as clean `Err` returns" — but no Phase 2 commit record (ch. 14
   §§14–19) mentions them. Check co-noir's VK-load path for a
   log_circuit_size sanity check; fold into the same 2.7 hardening pass as
   items 1–3.
5. **VERIFY: gemini masking dyadic-size commit `1f9d87ba3a` — confirmed
   byte-neutral?** [S / L–M — ZK parity]
   Ch. 03 said "likely allocation-only; confirm ZK bytes unchanged". The
   step-④ scope mentioned a "gemini masking dyadic sizing check" (ch. 14
   §17) but no record confirms the outcome. The ZK bidirectional bb
   cross-verify passing (§17.2) is strong indirect evidence; one line in
   ch. 14 either way would close it.
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
8. **VERIFY: nondeterministic circuit construction — is
   `acir_format.rs:417` an actual MPC-breaking risk today?**
   [M / H if real — co-builder correctness]
   `co-builder/src/acir_format.rs:417`: "TACEO TODO: THIS IS NOT
   DETERMINISTIC IN Barretenberg (use of unordered_map), thus some tests may
   produce different circuits! … the MPC parties may produce different
   circuits and MPC will fail". If any iteration order in co-noir's builder
   is genuinely nondeterministic (HashMap iteration), parties could derive
   different circuits/VKs from identical inputs — an MPC liveness landmine
   and a parity flake source. Audit that site (and any `HashMap` iteration
   feeding gate emission); Rust makes determinism cheap (`BTreeMap` /
   sorted iteration).
9. **VERIFY: recursion verifier parity has no byte-level oracle.** [M / M —
   recursion soundness surface]
   The in-circuit recursion verifier absorbed the biggest churn (entity
   reorder indexing, padding_indicator deletion, honest virtual rounds) but
   `recursion`/`recursion_zk` vectors are only *self*-verified (ch. 13 §1)
   and sit in the slow set that 2.7 hasn't run. A strong check exists:
   build the recursion circuit's **VK with bb and with co-noir and
   byte-compare** — VK equality pins the entire in-circuit verifier's gate
   layout without needing proof determinism.
10. **VERIFY: `(0,0)` infinity-sentinel edge case — confirm no valid BN254
    point collides with the sentinel.** [S / M — co-builder soundness]
    Step ① adopted bb's `(0,0)` encoding for the point at infinity with MPC
    infinity detection (2 eq-tests + 1 mult). BB-ECC-001 (ch. 13 §9.2)
    warns that infinity handling is where EC soundness bugs live. Record
    the one-line argument that x=0 has no on-curve preimage for BN254
    (y² = 3 must be a non-residue) — and, for the MPC path, that the
    eq-test-based detection can't be confused by a shared point with one
    zero coordinate.

## 2. Missing test ideas (beyond ch. 13's plan)

Each tied to the surface it guards. The ch. 13 §3a trio (SSIPA forgery,
ROM/RAM field-wrap, non-canonical/trailing) remains the mandatory floor —
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
4. **Entity-order lock test.** [S / M — verifier+builder consistency]
   Assert co-noir's precomputed/witness/shifted iteration order against a
   hard-coded expected list transcribed from bb's flavor-codegen output
   (`scripts/flavor-codegen/src/flavors/*.ts`). Catches an accidental
   struct-field reorder locally, without bb installed — today only a live
   bb cross-check would notice (ch. 11 §2.3a "don't forget").
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

1. **Extend the compile-time invariant block.** [S / M]
   Add `const _` asserts for `NUM_SUBRELATIONS == 29`, `NUM_ALPHAS == 28`,
   `NUM_ALL_ENTITIES == 41` (+42 ZK), `TRACE_OFFSET == 4`,
   `CONST_PROOF_SIZE_LOG_N == 25`, and the SSIPA claim counts
   (5 opening claims / 4 transcript evals / 3 commitments). Every one of
   these moved (or was audited) this sync; each is one line.
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
4. **Check in `rust-toolchain.toml` (pin 1.90).** [S / M]
   Ch. 14 §2/§9.1: default-toolchain builds die with a misleading error
   wall. A one-file pin removes the whole failure class for every future
   session/machine. (Upstream-facing suggestion too, but the local copy
   can carry it now.)
5. **Single-source the version pins.** [S–M / M]
   The same pin lives in 5 places (Readme, compare.sh, compare_mpc.sh, two
   compile.sh — ch. 02 §6) and they are *intentionally divergent* right
   now (§1.7), which is exactly how a stale pin gets shipped. A
   `versions.env` sourced by all scripts (Readme quoting it) makes a pin
   bump a one-line diff and makes divergence grep-able.
6. **Script the oracle bootstrap.** [S / M]
   Encode ch. 12 §3's first gotcha as a checked-in script:
   `git archive <tag>` → cmake build (`-DAVM=OFF`) → write PROVENANCE.txt →
   byte-compare `write_vk` against any prebuilt candidate. Turns the
   §17.1 lesson from prose into a tool; also gives compare*.sh its
   source-built-oracle slot (§1.7).
7. **Harden the parity scripts against silent failure.** [S / M]
   `set -euo pipefail`, no bare `>/dev/null` on oracle invocations, assert
   artifacts exist before `cmp` — the exact gotcha that produced fake
   "VK DIFF" readings twice (ch. 14 §11.2, §19.2).
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
   the bb-spec-audit claim graphs (PLAN 4.3) supply the negative-test seed
   set as they publish.
