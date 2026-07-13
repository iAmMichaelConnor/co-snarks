# Chapter 11 — Phase 2 in depth: updating co-noir to the v5-next target

## Relationship to PLAN.md (read this first)

**Is this chapter a duplicate of PLAN.md's Phase 2 section? No — but they
overlap by design, and here is the division of labor:**

- **PLAN.md Phase 2** is the **status tracker**: the authoritative work-item
  list (2.1–2.7) with checkboxes, commit hashes, and the pinned working set
  (branch, diff range, oracle binaries). It answers *"what are the work items
  and where do they stand right now?"* When PLAN.md and this chapter
  disagree on status or pins, **PLAN.md wins** — it is updated first.
- **This chapter (ch. 11)** is the **implementation reference**: the
  file-by-file HOW — which co-noir files each bb change touches, the mirror
  chain, the "don't forget" traps, the green-up order, effort/risk. It
  answers *"how do I (re)do this work, and what did the actual
  implementation look like?"* It was written **before** implementation
  (2026-07-08, session 1) and is now annotated with **✅ AS BUILT** notes
  where reality diverged from the plan.
- **Ch. 14 §§12–19** is the chronological command log of what actually
  happened (including failures); **ch. 12** is the version-agnostic runbook
  for *future* syncs; **ch. 13** is the definition of done (test plan).

The one genuinely harmful duplication — the "working set" pin block below —
has been reduced to a pointer at PLAN.md, because its copy here went stale
(it still named the deprecated rc.2 oracle after PLAN.md was corrected).
Everything else in this chapter is implementation detail PLAN.md
deliberately does not carry.

**⚠ Numbering caution:** this chapter's §2 subsection headings (2.2, 2.3a,
2.3, 2.4, 2.5) predate PLAN.md's final work-item numbering and DO NOT match
it. Mapping (PLAN item → this chapter → landed commit):

| PLAN.md item | topic | this chapter | status / commit |
|---|---|---|---|
| 2.1 | regenerate bb KATs at target pin | §5 | ✅ `e70252e1`, KATs re-generated with the source-built oracle after the §17.1 correction |
| 2.2 | permutation 2→3 subrelations | §2.2 | ✅ `1a13fcdc` |
| 2.3 | trace-offset rework | §2.4 | ✅ `571c1305` |
| 2.4 | ZK rework (masking + SSIPA) | §2.5 | ✅ `571c1305` |
| 2.5 | relation tuple reorder | §2.3 | ✅ `1a13fcdc` |
| 2.5a | entity/get_all reorder | §2.3a | ✅ `1a13fcdc` |
| 2.6 | builder/gate residue | §4 | ✅ `5ac55600` |
| 2.7 | green-up (full sweep + security regressions) | §6 steps 6–7 | ⏳ IN PROGRESS |

(Historical logs use yet another intermediate numbering: ch. 14 §17 and the
PROGRESS.md handoff call the trace-offset + ZK pair "2.4 + 2.6". Trust the
PLAN.md numbering; treat log references as chronology, not identifiers.)

---

*The concrete, file-by-file work plan to bring co-noir from its current pin
(bb `v5.0.0-nightly.20260324` / nargo beta.20) to the target
(`origin/v5-next` ≡ public `v5.0.0-nightly.20260708`). Grounded in ch. 03
(what changed) + ch. 02/07 (co-noir structure). Change locations spot-verified
in the co-noir tree 2026-07-08. Definition of done and the test harness are in
ch. 13; the repeatable procedure/automation is ch. 12. Written pre-
implementation; ✅ AS BUILT annotations added 2026-07-08 after items 2.1–2.6
landed.*

> **Working set for this phase**: see the PLAN.md Phase 2 header — the single
> authoritative copy (branch, diff range, Noir target, oracle binaries);
> re-verify pins each session. ⚠ **Oracle correction (ch. 14 §17.1)**: THE
> target oracle is **`~/.bb-target-src/bb`**, built from source at
> `v5.0.0-nightly.20260708`. The prebuilt `~/.bb-target/bb` (5.0.0-rc.2) is
> **DEPRECATED** — its release binary predates the entity reorder and emits
> OLD-order VKs (an earlier version of this block claimed it was
> "UltraHonk-identical to v5-next"; that compared source trees, not the
> shipped binary). `~/.bb/bb` remains the OLD-pin regression oracle.
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

**Soundness-surface lens (ch. 13 §9 — use it to decide how much care each
edit needs):** soundness of this system lives ONLY in the
**verifiers** (plain + recursion) and the **co-builder** (circuit
construction); the MPC/plain prover carries completeness + privacy, not
soundness. So among the phase-2 items: the verifier-side changes (2.5a
entity/eval order in the verifier; 2.6's SSIPA A(1)=0 which MUST be enforced
through Shplemini on the verify side) and the builder-side changes (2.6
ROM/RAM index pinning; EC add/MSM constraints) are **soundness-critical** and
get negative tests (ch. 13 §3a); an error there can make false proofs verify. An
error confined to the prover only breaks the KAT/self-verify (loud, not
dangerous). Grade review effort accordingly.

## 1. Pre-flight (before any code change)

1. **Bump the Noir tooling pin** in root `Cargo.toml` (`acir/acvm/brillig/
   noirc-abi/noirc-artifacts`) from `tag = "v1.0.0-beta.20"` to the tag
   v5-next uses. **First check what that tag is**: v5-next's Noir submodule
   is beta.22 (ch. 10 / ch. 06 noted this). Bumping beta.20→beta.22 is itself
   a breaking step — the ACIR opcode format changed (EmbeddedCurveAdd/MSM
   dropped the `is_infinite` field; see §4). Do this pin bump and get the
   workspace compiling *before* touching prover math, because the opcode
   structs the builder/acvm read against will change here.

   ✅ **AS BUILT (commit `4e7abb95`; ch. 14 §14):** the plan's predicted pain
   (opcode-struct type errors) was NOT the real breaking change — beta.22
   bumped **arkworks 0.5→0.6**, splitting the dependency graph into two
   incompatible ark universes; the 51 "type errors" were duplicate-crate
   cascade noise. Fix: unify the workspace on ark 0.6 and **vendor two
   registry crates** that hard-pin ark 0.5 (`taceo-circom-types`,
   `taceo-ark-serde-compat`) into `vendor/` via `[patch.crates-io]`. The
   predicted semantic work (MemOp→MemOpKind, EC `(0,0)` infinity sentinel,
   new upstream `predicate` field) was real but secondary. Lesson (now a
   ch. 12 gotcha): on a dep bump yielding dozens of nonsensical type errors,
   run `cargo tree -d` before believing the error text.
2. **Install the reference binaries**: `noirup` to the matching nargo,
   `bbup -v 5.0.0-nightly.20260708` for the reference `bb`. These drive the
   parity oracle (ch. 12/13). Our target is a *public* tag, so both install
   cleanly with no private material.

   ✅ **AS BUILT (ch. 14 §12, §17.1):** this step went differently and
   produced the project's most important operational lesson. The target tag
   has **no public release assets** (the v5 line moved to rc builds), so the
   prebuilt rc.2 binary was adopted as oracle on the strength of a
   source-tree diff — and later found to **predate the entity reorder** in
   its shipped binary (OLD-order VKs). The oracle had to be **built from
   source at the exact target tag** (`~/.bb-target-src/bb`, ~90 s build,
   PROVENANCE.txt alongside). Rule for all future syncs: byte-compare any
   prebuilt oracle's `write_vk` output against a source-built bb before
   trusting it (ch. 12 §3 first checkbox).
3. **Snapshot current state**: run the existing test suite green at the old
   pin first, so any red after a change is attributable.

   ✅ **AS BUILT:** done as Phase 0 (603/603 tests, 29/29 bb cross-verified
   circuits at the old pin; ch. 14 §§4–7).

## 2. The four proof-format changes (the core of phase 2)

Each maps 1:1 to a ch. 03 §2 item. For each: what to change, where, and the
"don't forget" note. (co-noir's `CONST_PROOF_SIZE_LOG_N` is already 25, so the
proof-length-constant change `1f144a3040` is already absorbed — the effective
list is these four.)

### 2.2 Permutation relation: 2 → 3 subrelations  [= PLAN item 2.2 — ✅ DONE, commit `1a13fcdc`]
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
  site. The Shamir **randomness accounting** (`co_ultra_prover.rs:163-202`)
  counts per-subrelation work → update it or Shamir proving miscounts Beaver
  pairs.
- ✅ **AS BUILT (ch. 14 §16.1):** the new subrelation is `L_first·z_perm = 0`
  and required a **third** mirror the plan missed — the recursion verifier's
  relation set in `co-builder/src/honk_verifier/verifier_relations/`
  (found in pre-flight, ch. 14 §13.2). In co-ultrahonk it is
  `mul_with_public_many` (public×shared = linear), so **no new MPC mult**:
  `CRAND_PAIRS_FACTOR` stayed 8 and the Shamir accounting was unchanged by
  this item. Also note `SUBRELATION_PARTIAL_LENGTHS` is not a named const in
  co-noir — it's the `Univariate<F,N>` accumulator widths (the change = add
  `r2: Univariate<F,3>` and wire it through scale/batch/accumulate).

### 2.3a Entity/get_all reorder (ADDED 2026-07-08)  [= PLAN item 2.5a — ✅ DONE, commit `1a13fcdc`]
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
- ✅ **AS BUILT (ch. 14 §16.1):** implemented by renumbering the ONE entity
  struct to the generated hpp order (sigma_1..4, id_1..4, lagrange_first,
  lagrange_last, q_lookup, table_1..4, then selectors in bb's odd sub-order);
  all order-sensitive consumers (VK `to_buffer` both hashers,
  `Sumcheck:evaluations`, recursion `from_elements`, shplemini) iterate that
  struct and followed automatically — exactly the "serialized order, not
  code shape" coupling decision 6a calls for. Side effects: selectors are no
  longer contiguous (`get_selectors_mut` returns disjoint refs in
  trace-block order) and UltraTraceBlock indices became block-local. This
  reorder is also what invalidated the rc.2 prebuilt oracle (§17.1) — its
  binary predates this commit.

### 2.3 Relation tuple reorder  [= PLAN item 2.5 — ✅ DONE, commit `1a13fcdc`]
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
- ✅ **AS BUILT (ch. 14 §16.1):** subrelations 28→29, alphas 27→28; bb's
  convention α_{0,0}=1 means the PERMUTATION grand-product subrelation is
  now the *unscaled* one. In the recursion verifier the accumulate order is
  load-bearing (the constant-1 fast path must run first). Third mirror
  (`verifier_relations/mod.rs`) updated alongside, as in 2.2.

### 2.4 Trace-offset rework (masking rows to the top; changes every VK)  [= PLAN item 2.3 — ✅ DONE, commit `571c1305`]
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
- ✅ **AS BUILT (ch. 14 §17, §17.2):** done together with §2.5 as "step ④",
  as planned (they are entangled). Landed values: `TRACE_OFFSET = 4`,
  masking rows 1–3, lagrange_first row 4, content from row 5.
  `padding_indicator_array` deleted everywhere including the dedicated
  recursion file `co-builder/src/honk_verifier/padding_indicator_array.rs`
  (which the pre-flight pass had located, ch. 14 §13.2). MPC nuance held:
  non-ZK moves structural rows only; ZK relocates masking randomness as
  shares. The prediction "every VK changes" was confirmed — and it is what
  exposed the rc.2 oracle problem (§17.1) when the first VK commitment
  wouldn't match.

### 2.5 ZK-flavor rework (masking + SmallSubgroupIPA)  [= PLAN item 2.4 — ✅ DONE, commit `571c1305`]
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
- ✅ **AS BUILT (ch. 14 §17–17.2):** two divergences from the plan, both
  material:
  1. **A ZK proof-byte change the plan missed**: co-noir padded ZK sumcheck
     to 25 rounds with ZERO univariates, but bb NEW computes **honest
     virtual-round univariates** (single-edge contribution × row-disabling
     factor + that round's Libra univariate; book-keeping folded by
     (1−u_k); gemini masking evaluated over the full 25-challenge vector).
     Discovered mid-implementation; ported faithfully.
  2. **The Shamir randomness accounting re-derivation was the riskiest
     edit**: the implementing agent's draft undercounted by 24 draws (8
     `mask_polynomial` sites × NUM_MASKED_ROWS=3); caught in review against
     the actual consumers. ⚠ Standing caveat: 3-party Shamir takes the
     on-the-fly randomness path, so the accounting is only *exercised* at
     ≥4 parties — the in-tree suite cannot catch a wrong count (ch. 15
     backlog has the test idea).
  Proof-length outcome (settled by step-② KATs, ch. 14 §15): lengths were
  **already correct** — 410/458/115 identical at old and new pins; the whole
  sync changed byte *content/order* only, never lengths.

## 3. Verify sizes after 2.2–2.5  [✅ DONE — commit `5ac55600`]
Target invariants on v5-next (from ch. 04 §5 / ch. 07):
`NUM_ALL_ENTITIES = 41` (unchanged), non-ZK Ultra proof **410 fields**, ZK
**458**, VK **115**, `CONST_PROOF_SIZE_LOG_N = 25`. Add a compile-time / unit
assertion on these in `constants.rs` so a future drift fails loudly (bb has
`static_assert`s here — mirror them as `const _: () = assert!(...)`).

✅ **AS BUILT:** the compile-time asserts exist at
`co-noir/co-noir-common/src/constants.rs:86-88`
(`const _: () = assert!(… == 410 / 458 / 115)`), landed with item 2.6.

## 4. Builder / DSL gate-level changes (VK-affecting for the touched programs)  [= PLAN item 2.6 — ✅ DONE, commit `5ac55600`; EC serde in `4e7abb95`]
These change gate counts/VKs only for circuits using the feature; still must
match bb for KAT/VK parity.

✅ **AS BUILT (ch. 14 §19) — the plan under-predicted this item.** Parity
testing beyond the two KAT circuits surfaced **two extra proof-breaking bb
changes** not in the list below:
1. **Lookup `table_index` now starts at 1** (bb `0a7d0af035` — "so the
   relation batched term always contains at least beta cubed" in logup).
   Changes the bytes of **every lookup-using circuit**.
2. **SHA-256 CH-L2 basic tables are 10-bit** + `w_sparse[0]` gets a 32-bit
   range constraint (bb `bbbde54094`, `5d43e115a2` — soundness fixes:
   the old 2^11-row tables let a prover witness an out-of-range 10-bit
   slice).
Also as built: the uint MultiTable ctor rework was mirrored on the *caller*
side only and verified **byte-neutral**; secp256k1/r1 table changes were NOT
ported (ECDSA unimplemented, ch. 06); recursion size-assert added
(`assert_eq!` on 410/458+pubs) plus the §3 compile-time invariants.
Byte-identical vs the source-built target bb for: ram, rom_shared,
embedded_curve_add, bb_sha256_compression, blackbox_and, blackbox_xor,
get_bytes. Lesson for future syncs: **KAT circuits alone under-cover builder
changes — run per-feature parity circuits (lookup/SHA/ROM/EC) before calling
a builder item done.**
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
  ✅ **AS BUILT:** this is a **SOUNDNESS fix** (a field-wrap gap: Δ²+Δ=0 has
  roots {0,−1}, so an unpinned chain could start at p−1 and perform
  unconstrained memory ops — ch. 03 §6). Correct file is `ultra_builder.rs`'s
  `process_{rom,ram}_array_*` (public + MPC-shared paths);
  `types/rom_ram.rs` is the recursion-verifier LUT, a different thing
  (ch. 14 §13.2). The pinning must copy-constrain to the genuinely
  constrained `zero_idx` — a fresh `add_variable(0)` reopens the gap.
  The ch. 13 §3a field-wrap regression test is MANDATORY in 2.7.
- **SHA-256 / secp256r1-ECDSA table changes**: only affect gate-count
  constants; since co-noir does **not** implement ECDSA and SHA-256 gate
  counts only matter where used, these are low-touch — but if any test-vector
  circuit uses sha256_compression, its VK KAT changes and must be regenerated.
- **honk recursion constraint exact-size assert** (`669e92b896`): if co-noir's
  `co-builder/src/honk_verifier/` recursion path hard-asserts proof size,
  update the expected size to the new 410/458 (ch. 04 §5).

## 5. Regenerate KATs & test vectors  [= PLAN item 2.1 — ✅ DONE, commit `e70252e1` + §17.1 regen; residue → 2.7]
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

✅ **AS BUILT (ch. 14 §15, §17.1, §19.2):** deviations from the plan:
- Done EARLY (step ②, before the prover math) rather than last — so the KATs
  could serve as the byte oracle *during* the port. Noir proof tests then
  ran red-by-design until items 2.2–2.6 landed. This inversion worked well
  and is the recommended order for future syncs.
- The 4 proof KATs were first generated with the **wrong oracle** (prebuilt
  rc.2 — see §17.1) and regenerated with the source-built
  `~/.bb-target-src/bb`; byte-identity independently re-verified.
- **No VK KATs exist in-tree** (nothing to regenerate) — committing them is
  a ch. 15 backlog item; VK parity currently rests on live bb cross-checks.
- ⚠ **Residue moved to 2.7**: only `test_vectors/noir` + the examples
  poseidon vector were recompiled with beta.22 — the rest of
  `examples/test_vectors/*` are still beta.20-compiled (symptom: serde
  error `invalid type: integer 11` = old MemOp format). And the pin strings
  in `compare.sh`/`compare_mpc.sh`/`Readme.md` were **intentionally left at
  beta.20/old-bb** — they gate the old-pin regression path until green-up
  bumps them.

## 6. Green-up order (fastest path to a trustworthy pass)
1. ✅ Pin bump compiles (§1) → workspace builds. (`4e7abb95`)
2. ✅ `cargo test -p tests --release` plain-driver KAT for a **non-ZK poseidon2**
   proof turns green (this validates 2.2–2.4 + §4 for the simplest circuit).
   (THE MILESTONE — landed with `571c1305`, ch. 14 §17.2.)
3. ✅ Keccak non-ZK KAT green (validates the keccak transcript path).
4. ✅ REP3 + Shamir MPC KATs green (noir suite 94/0, 3-party × {ZK, non-ZK}).
5. ✅ ZK variants: verifier round-trip green + **bidirectional** `bb verify`
   cross-check vs `~/.bb-target-src/bb`; VK byte-identical (ch. 14 §17.2 #5).
6. ⏳ Full example suite (`examples/run_*.sh`) + `compare_mpc.sh` 4-way
   cross-verification vs BOTH oracles — **needs a script slot for
   `~/.bb-target-src/bb`** and a full beta.22 recompile of
   `examples/test_vectors/*` (ch. 14 §19.2). ← remaining, = PLAN item 2.7.
7. ⏳ Negative tests (ch. 13) still reject — **including the §3a mandatory
   security regressions** (SSIPA kernel-perturbation case through the
   Shplemini path; ROM/RAM field-wrap; non-canonical encodings + trailing
   bytes) and the
   slow circuit set (aes128, sha256 e2e, recursion, recursion_zk).
   ← remaining, = PLAN item 2.7.

## 7. Effort & risk notes (+ post-hoc retrospective)
- **Biggest/riskiest**: 2.4 (trace-offset) — touches every VK and entangles
  with 2.5. Budget the most time here; it's where a subtle row-index error
  hides and only a VK-byte diff reveals it.
- **Most mechanical**: 2.2/2.3 (relation count/order) — small diffs, but easy
  to forget an alpha-count site; the plain KAT catches errors immediately.
- **Version-bump collateral**: §1's beta.22 bump + §4's EC opcode change ride
  together; expect the acvm/builder EC paths to need edits just to compile
  before any proof runs.
- **Shamir accounting** (`co_ultra_prover.rs:163-202`) is the easiest thing to
  miss — it doesn't fail to compile, it silently under/over-allocates
  randomness and the Shamir proof breaks at runtime. Re-derive it whenever
  subrelation counts or the ZK path change.
- Total: consistent with the ch. 05 estimate (~2–4 focused engineer-weeks),
  dominated by 2.4/2.5 and KAT regeneration/debugging.

✅ **RETROSPECTIVE (what the plan got right and wrong — feed into ch. 12
for the next sync):**
- *Right*: the risk ranking (trace-offset + ZK were indeed the hardest and
  hid the deepest surprise), the mirror-chain order, "Shamir accounting is
  the easiest thing to miss" (it was — the draft edit undercounted by 24
  draws), and the lockstep grouping of 2.2/2.5/2.5a.
- *Under-predicted, in order of impact*: (1) the **oracle-provenance trap**
  (§17.1 — rc.2 prebuilt ≠ target tag; cost a VK-divergence hunt);
  (2) **ark 0.5→0.6** as the real substance of the pin bump; (3) the
  **honest virtual-round univariates** ZK byte change; (4) the **two extra
  builder table changes** (lookup table_index-from-1, SHA 10-bit tables)
  invisible to the KAT circuits; (5) the **third relation mirror**
  (recursion `verifier_relations/`) and the MemOp ACIR overhaul (both caught
  by the pre-flight verification pass, ch. 14 §13 — that pass paid for
  itself and should be standard, see ch. 12).
- *Actual effort*: items 2.1–2.6 landed in ~2 working days of agent-assisted
  sessions (2026-07-08, sessions 2–3) instead of 2–4 weeks — but 2.7
  (the full sweep + security regressions) is deliberately unfinished, and
  the estimate assumed unassisted engineering.

✅ **POSTSCRIPT (2026-07-09, PLAN 2.9 — what the sync AND its green-up both
missed; full record ch. 14 §23):** the in-circuit recursion verifier had
SEVEN gate-emission divergences from bb that survived 2.1–2.7 undetected,
because nothing byte-compared a recursion VK against bb — every recursion
check was self-verify or same-key verify, and the KAT circuits never
exercise the recursion-verifier expansion. Three were security issues in
their own right (missing `mask_points` ∞-asserts guarding the ROM point
tables; bigfield less-than top-limb bound 68 bits vs bb's 50; `compute_naf`
top entry left unconstrained); four were pure order/off-by-one mismatches
(ZK row-disabling once vs per-subrelation, gate-separator multiply operand
order, `self_reduce` quotient-max, SmallSubgroupIPA claim-batching
position). All found by differential gate instrumentation (per-phase counts
→ per-row selector/wire dumps) and fixed to full VK byte-parity +
bidirectional cross-verification. *Lessons for the next sync*: (1) a
cross-key VK byte-diff per circuit — recursion included — is a mandatory
gate, not an optional extra (now standing: `recursion{,_zk}_vk_kat` tests +
compare.sh VK diff); (2) "verifies" is a weak oracle — byte-compare the
artifacts; (3) the differential row-dump method (ch. 14 §23) is cheap to
re-stand-up and localizes any future break to the emitting call in
minutes; (4) test vectors that exist in two places (examples +
test_vectors/noir) WILL drift apart — regen must cover both (ch. 12 §4a).
