# Chapter 11 — Phase 2 in depth: updating co-noir to the v5-next target

*The concrete, file-by-file work plan to bring co-noir from its current pin
(bb `v5.0.0-nightly.20260324` / nargo beta.20) to the target
(`origin/v5-next` ≡ public `v5.0.0-nightly.20260708`). Grounded in ch. 03
(what changed) + ch. 02/07 (co-noir structure). Change locations spot-verified
in the co-noir tree 2026-07-08. Definition of done and the test harness are in
ch. 13; the repeatable procedure/automation is ch. 12.*

> **Working set for this phase** (authoritative copy in PLAN.md Phase 2
> header; re-verify pins each session): work branch `mc/update-co-noir` in
> `~/co-snarks` (push disabled; local incremental commits); bb diff range
> `v5.0.0-nightly.20260324..v5.0.0-nightly.20260708` in
> `~/aztec-packages-private` (the NEW tag ≡ `origin/v5-next`'s bb tree);
> Noir target `v1.0.0-beta.22`; oracles `~/.bb/bb` (old pin) and
> `~/.bb-target/bb` (= bb 5.0.0-rc.2, UltraHonk-identical to v5-next).
> Corrections from the 2026-07-08 code-verification passes are in ch. 14
> §13.1–13.3 and take precedence over this chapter's file lists where they
> differ (notably: MemOp ACIR overhaul missing below; third relation mirror
> in `co-builder/src/honk_verifier/verifier_relations/`; Shamir accounting
> path is `co-ultrahonk/src/co_ultra_prover.rs:163-202`).

## 0. Orientation: the "mirror chain"

Every proof-affecting change propagates through co-noir in the same order.
When you touch one layer, check the next:

```
bb C++ change
   → ultrahonk/           (plain Rust prover+verifier — get this byte-right FIRST)
   → co-ultrahonk/        (MPC prover — mirror the plain change into co_oink/co_decider)
   → co-builder/          (if it's a gate/VK change: builder + honk_verifier recursion)
   → co-noir-common/      (shared: constants.rs, transcript.rs, keys/)
   → co-acvm / co-brillig (only if witness-gen/opcode semantics changed)
   → test_vectors + tests (regenerate KATs, re-run parity)
```

Rule of thumb: **make `ultrahonk` (plain) match bb exactly first** — its KAT
byte-equality test against a real bb proof is the tightest correctness oracle.
Only once plain is green do you mirror into `co-ultrahonk` (whose MPC output
must equal the plain output for the same witness).

**Independence principle (Mike, 2026-07-08 — PLAN decision 6a):** "mirror"
means mirror the *math and the byte behavior*, never the C++ code structure.
Structure the Rust however best practice dictates, following Taceo's existing
conventions. Independent implementations are a feature: they enable
differential fuzzing of bb-vs-co-noir later (ch. 13 §6). The only mandatory
coupling is at the KAT boundary — proof/VK bytes and mutual verifier
acceptance.

## 1. Pre-flight (before any code change)

1. **Bump the Noir tooling pin** in root `Cargo.toml` (`acir/acvm/brillig/
   noirc-abi/noirc-artifacts`) from `tag = "v1.0.0-beta.20"` to the tag
   v5-next uses. **First check what that tag is**: v5-next's Noir submodule
   is beta.22 (ch. 10 / ch. 06 noted this). Bumping beta.20→beta.22 is itself
   a breaking step — the ACIR opcode format changed (EmbeddedCurveAdd/MSM
   dropped the `is_infinite` field; see §4). Do this pin bump and get the
   workspace compiling *before* touching prover math, because the opcode
   structs the builder/acvm read against will change here.
2. **Install the reference binaries**: `noirup` to the matching nargo,
   `bbup -v 5.0.0-nightly.20260708` for the reference `bb`. These drive the
   parity oracle (ch. 12/13). Our target is a *public* tag, so both install
   cleanly with no private material.
3. **Snapshot current state**: run the existing test suite green at the old
   pin first, so any red after a change is attributable.

## 2. The four proof-format changes (the core of phase 2)

Each maps 1:1 to a ch. 03 §2 item. For each: what to change, where, and the
"don't forget" note. (co-noir's `CONST_PROOF_SIZE_LOG_N` is already 25, so the
proof-length-constant change `1f144a3040` is already absorbed — the effective
list is these four.)

### 2.2 Permutation relation: 2 → 3 subrelations
- **bb**: `UltraPermutationRelation` gained a third subrelation (explicit
  `L₀·z_perm = 0` grand-product initialization identity).
- **co-noir**:
  - `co-noir/ultrahonk/src/decider/relations/permutation_relation.rs` —
    `NUM_RELATIONS: usize = 2` → **3** (verified this constant exists at
    line 61); add the new subrelation's `accumulate` term and its
    `SUBRELATION_PARTIAL_LENGTHS` entry `{6,3}`→`{6,3,3}`.
  - `co-ultrahonk/src/co_decider/relations/permutation_relation.rs` — mirror.
- **Don't forget**: the flavor-wide `NUM_SUBRELATIONS` / total alpha count
  increases by 1 → the **relation-separator alpha vector** lengthens
  (`oink`/`co_oink` alpha generation) and the **sumcheck batching** consumes
  one more alpha. Grep every `NUM_ALL_RELATIONS`/`NUM_SUBRELATIONS`/alpha-count
  site. The Shamir **randomness accounting** (`co_ultra_prover.rs:159-201`)
  counts per-subrelation work → update it or Shamir proving miscounts Beaver
  pairs.

### 2.3a Entity/get_all reorder (ADDED 2026-07-08 — rides the same bb commit as 2.3)
- **bb**: `c075fc182e` also reordered the flavor entity layout
  (`EntityId`/`get_all()`): NEW order = `sigma_1..4, id_1..4,
  lagrange_first, lagrange_last, q_lookup, table_1..4, q_m, q_r, q_o, q_c,
  q_l, q_4, q_arith, q_delta_range, q_elliptic, q_memory, q_nnf,
  q_poseidon2_external, q_poseidon2_internal`, then witnesses, then shifts
  (`flavor/generated/ultra_flavor_generated.hpp:34-77`; source of truth =
  `scripts/flavor-codegen/src/flavors/*.ts`). Proof's 41
  `Sumcheck:evaluations` AND the VK's 28 precomputed commitments serialize
  in this new order. Counts unchanged.
- **co-noir**: the entity iteration order in
  `co-noir-common/src/…/entities.rs` (precomputed/witness/shifted
  get_all-equivalents), everywhere the sumcheck evaluations are
  sent/received in transcript order (plain + co_decider + recursion
  verifier), and VK to_buffer/from_buffer commitment order in
  `keys/verification_key.rs`. Follow Taceo's structure — what must match is
  the *serialized order*, not the code shape (PLAN decision 6a).
- **Don't forget**: VK KATs and the in-circuit recursion verifier's
  evaluation indexing both depend on this order; a mistake here looks like
  "everything verifies except vs bb" — only bb cross-checks catch it.

### 2.3 Relation tuple reorder
- **bb**: Ultra relation order became `Permutation, LogDerivLookup,
  Arithmetic, …` (was `Arithmetic, Permutation, LogDerivLookup, …`).
- **co-noir**: reorder the relation tuple/iteration in
  `ultrahonk/src/decider/relations/mod.rs` and the matching
  `co-ultrahonk/.../relations/mod.rs`, plus anywhere the verifier assigns
  alpha powers to subrelations by index.
- **Don't forget**: this changes **alpha-power → subrelation assignment**, so
  it silently changes challenge usage even though the *set* of relations is
  unchanged. The plain KAT will catch a mistake; make the change in lockstep
  with 2.2's alpha bookkeeping.

### 2.4 Trace-offset rework (moves masking rows to the top; changes every VK)
- **bb**: disabled/masking rows moved from the *end* of the trace to the
  *top* (rows 0–3); `TRACE_OFFSET = NUM_DISABLED_ROWS_IN_SUMCHECK`; content
  starts at row 5; `lagrange_first` at row 4. All precomputed polynomials
  (sigmas, selectors, lagranges) shift → **new VK for every circuit,
  non-ZK included**.
- **co-noir**:
  - `co-noir/co-builder/src/` trace construction / `keys/proving_key.rs` +
    `keys/verification_key.rs` — where rows are laid out and precomputed
    polys populated. This is the largest single change (touches VK bytes for
    *all* circuits).
  - `co-noir-common/src/constants.rs` — add `TRACE_OFFSET` /
    `NUM_DISABLED_ROWS_IN_SUMCHECK` and the row-start offset; update sumcheck
    row-disabling.
  - `ultrahonk/src/decider/sumcheck/` + `co_decider/co_sumcheck/` —
    row-disabling polynomial follows the new layout.
- **Don't forget**: `padding_indicator_array` was **removed** from the
  sumcheck and Shplemini verifiers in the same bb change — delete it in
  `ultrahonk` verifier + shplemini and the co- mirrors. Every stored VK KAT
  must be regenerated (§5). This change and 2.5 (ZK) are entangled — do them
  together.

### 2.5 ZK-flavor rework (masking + SmallSubgroupIPA)
- **bb**: ZK masking randomness now lives in witness rows 1–3 (tail
  `MaskingTailData` deleted); row-disabling factor becomes
  `1 − ∏_{k≥2}(1−u_k)`; SmallSubgroupIPA adds a **5th opening claim `A(1)=0`**
  to the Shplonk batch (`+NUM_SMALL_IPA_OPENING_CLAIMS = 5` instead of 4; the
  constant-term accumulator gains the A(1) term; wire evals stay 4,
  commitments 3 — the claim is untransmitted).
- **co-noir**:
  - `ultrahonk/src/decider/small_subgroup_ipa.rs` +
    `co-ultrahonk/src/co_decider/small_subgroup_ipa.rs` — the 5th claim.
  - `ultrahonk/src/decider/shplemini/` + `co_decider/co_shplemini/` — Shplonk
    nu-power assignment shifts by the extra claim; batch/accumulator update.
  - Libra masking placement in `oink`/`co_oink` (masking into witness rows).
  - `co-noir-common/src/constants.rs` — ZK proof-length constants
    (`ULTRA_PROOF_LENGTH_*_ZK`, `DECIDER_PROOF_LENGTH_ZK`,
    `BATCHED_RELATION_PARTIAL_LENGTH_ZK`) → confirm they yield **458 fields**
    (ch. 04 §5 target).
- **Don't forget**: ZK proofs are randomized, so KAT **byte-equality is
  skipped** for ZK (only verifier round-trip is tested, per the existing
  test harness). That means ZK correctness rests on cross-verification
  against real `bb` (ch. 13) — do not skip the `--oracle_hash poseidon2`
  (ZK-by-default) `bb verify` cross-check. The Shamir randomness accounting
  (`co_ultra_prover.rs`) has a dedicated ZK/Libra branch — update it.

## 3. Verify sizes after 2.2–2.5
Target invariants on v5-next (from ch. 04 §5 / ch. 07):
`NUM_ALL_ENTITIES = 41` (unchanged), non-ZK Ultra proof **410 fields**, ZK
**458**, VK **115**, `CONST_PROOF_SIZE_LOG_N = 25`. Add a compile-time / unit
assertion on these in `constants.rs` so a future drift fails loudly (bb has
`static_assert`s here — mirror them as `const _: () = assert!(...)`).

## 4. Builder / DSL gate-level changes (VK-affecting for the touched programs)
These change gate counts/VKs only for circuits using the feature; still must
match bb for KAT/VK parity.
- **EC add / MSM `is_infinite` removal** (`c0a48189eb`+`0b6bf902ee`): the ACIR
  opcode serde no longer carries `is_infinite`. This surfaces at the beta.22
  pin bump (§1). Update:
  - `co-acvm/src/solver/blackbox_solver.rs` — `MultiScalarMul` /
    `EmbeddedCurveAdd` input/output arity (drop the infinity flag; ch. 06 §1
    documents the old beta.20 shape co-noir currently uses).
  - `co-builder/src/acir_format.rs` (~L785) + the EC-add/MSM builders in
    `ultra_builder.rs` — matching gate construction (EC_ADD 80→76, MSM
    3559→3557 per ch. 03).
  - `co-acvm/src/mpc/{rep3,shamir,plain}.rs` — `embedded_curve_add` signatures.
- **ROM/RAM sorted-index pinning** (`1f7ed2ea79`): first sorted index pinned
  to `zero_idx`, last to constant `N−1`. Update ROM/RAM handling in
  `co-builder/src/types/rom_ram.rs` + `ultra_builder.rs` block constraints.
- **SHA-256 / secp256r1-ECDSA table changes**: only affect gate-count
  constants; since co-noir does **not** implement ECDSA and SHA-256 gate
  counts only matter where used, these are low-touch — but if any test-vector
  circuit uses sha256_compression, its VK KAT changes and must be regenerated.
- **honk recursion constraint exact-size assert** (`669e92b896`): if co-noir's
  `co-builder/src/honk_verifier/` recursion path hard-asserts proof size,
  update the expected size to the new 410/458 (ch. 04 §5).

## 5. Regenerate KATs & test vectors (do this last, once code is right)
- `test_vectors/noir/compile.sh` (+ `co-noir/co-noir/examples/compile.sh`):
  bump `NARGO_VERSION`, re-run to refresh compiled circuits + witnesses for
  all ~34 vectors.
- Regenerate the two committed **bb proof KATs** (`add3u64`, `poseidon`,
  both hashers, non-ZK) with the reference `bb` at the new pin:
  `bb prove --scheme ultra_honk --oracle_hash {poseidon2,keccak} --disable_zk`
  → overwrite `test_vectors/noir/*/kat/*_proof_with_{pos,kec}`.
- Regenerate any committed VK KATs (all VKs change due to 2.4).
- Update version strings: `co-noir/co-noir/Readme.md`, `compare.sh`,
  `compare_mpc.sh`, both `compile.sh` (the 5 pin locations from ch. 02 §6).

## 6. Green-up order (fastest path to a trustworthy pass)
1. Pin bump compiles (§1) → workspace builds.
2. `cargo test -p tests --release` plain-driver KAT for a **non-ZK poseidon2**
   proof turns green (this validates 2.2–2.4 + §4 for the simplest circuit).
3. Keccak non-ZK KAT green (validates the keccak transcript path).
4. REP3 + Shamir MPC KATs green (validates the co- mirrors match plain).
5. ZK variants: verifier round-trip green + `bb verify` cross-check (2.5).
6. Full example suite (`examples/run_*.sh`) + `compare_mpc.sh` 4-way
   cross-verification vs real `bb`.
7. Negative tests (ch. 13) still reject.

## 7. Effort & risk notes
- **Biggest/riskiest**: 2.4 (trace-offset) — touches every VK and entangles
  with 2.5. Budget the most time here; it's where a subtle row-index error
  hides and only a VK-byte diff reveals it.
- **Most mechanical**: 2.2/2.3 (relation count/order) — small diffs, but easy
  to forget an alpha-count site; the plain KAT catches errors immediately.
- **Version-bump collateral**: §1's beta.22 bump + §4's EC opcode change ride
  together; expect the acvm/builder EC paths to need edits just to compile
  before any proof runs.
- **Shamir accounting** (`co_ultra_prover.rs:159-201`) is the easiest thing to
  miss — it doesn't fail to compile, it silently under/over-allocates
  randomness and the Shamir proof breaks at runtime. Re-derive it whenever
  subrelation counts or the ZK path change.
- Total: consistent with the ch. 05 estimate (~2–4 focused engineer-weeks),
  dominated by 2.4/2.5 and KAT regeneration/debugging.
