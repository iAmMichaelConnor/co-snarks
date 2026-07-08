# Chapter 3 — What changed in bb UltraHonk since co-noir's pin

*Analysis of `~/aztec-packages-private` between `v5.0.0-nightly.20260324`
(co-noir's compatibility pin, tagged commit `4dbf81ec2`, 2026-03-20) and HEAD
`d6a30afe9` (2026-07-07). Verified 2026-07-08; key claims spot-checked against
the working tree. Commit hashes are from the private repo.*

## 0. The public/private split (critical context)

- The **public** aztec-packages repo continues to release on the
  **v5.0.0-nightly** line (newest as of 2026-07-08: `v5.0.0-nightly.20260708`,
  mirrored into the private repo).
- The **private** repo's `next` line became **v6.0.0-nightly** (~2026-06-05,
  when private release machinery landed). There is no single "v6 protocol
  commit" — v6 encapsulates the private-only breaking set below.
- **Taceo can only see the public line.** Everything below is therefore
  labelled **(A)** = public-visible (v5 pin → v5 tip; Taceo can sync
  themselves) or **(B)** = private-only (v5 tip → HEAD; requires private
  access to port).

## 1. The headline answer

**Does the private v6 line break the UltraHonk proof format vs public v5?
Yes — via exactly two commits.** Everything else private-side that touches the
Ultra pipeline is perf/Chonk/Mega/AVM work with no compatibility
impact.

### (B1) `a69ffdf8a1` (2026-06-30) — full-width Fiat–Shamir challenges
`BaseTranscript::get_challenges` now derives one **full ~254-bit field element
per hash** (`Codec::convert_full_challenge`); the old split-into-two-127-bit-
limbs behavior survives only as `get_short_challenges` (used by IPA rounds,
pairing-point `recursion_separator`, AVM). **Every challenge in every Ultra
proof changes value** (eta, beta/gamma, alphas, gate & sumcheck round
challenges, rho, Gemini:r, Shplonk:nu/z), for both Poseidon2 and Keccak
transcripts. Conceptually a small port (transcript core), but it invalidates
all cross-version proofs. Verified: `convert_full_challenge` absent at public
v5 tip, present at HEAD (`transcript/transcript.hpp:272,302,311`).

### (B2) `d3e42f9d3a` (2026-06-19) — ROM via logup
Three coupled breaks reaching plain UltraFlavor:
1. `MemoryRelation` grows **6 → 8 subrelations** → flavor-wide
   `NUM_SUBRELATIONS` +2 → longer alpha vector → verifier math and transcript
   diverge for **every** proof, even circuits without ROM. (Verified:
   `memory_relation.hpp:47` has 8 partial lengths.)
2. New FS challenge **`rom_logup_gamma`** squeezed alongside `eta` in oink
   (`ultra_honk/oink_prover.cpp:137-138`) for every Ultra proof.
3. Builder: single-value ROM reads become logup gates (`rom_ram_logic.cpp`);
   ROM/RAM block reads drop 9→4 gates → **different circuits & VKs** for any
   program with memory blocks. No new witness column (w_4 reused as inverse).

Net (B) surface is otherwise tiny: proof length, entity counts
(`NUM_ALL_ENTITIES = 41`), VK serialization all unchanged across the boundary.

## 2. Public-visible breaking changes (A): pin → v5 tip

Four consensus-level deltas + a set of builder/gate changes:

| Commit | Date | Class | Summary |
|---|---|---|---|
| `1f144a3040` | 2026-03-20 | **Proof format** | `CONST_PROOF_SIZE_LOG_N` 28 → **25** (co-noir already has 25 — see §4). Padded sumcheck univariates and Gemini folds shrink accordingly. |
| `a6c119f89a` | 2026-04-08 | **Relations** | `UltraPermutationRelation` 2→3 subrelations (explicit `L₀·z_perm = 0` init identity) → +1 alpha for every proof. |
| `7dbe0b25c8` | 2026-04-21 | **VK + verifier math** | Masking/disabled rows moved from the *end* to the *top* of the trace (rows 0–3; content starts at row 5; `lagrange_first` at row 4) → **every circuit's VK changes**, non-ZK included. ZK reworked: masking randomness in witness rows 1–3, new row-disabling factor, `padding_indicator_array` removed from verifiers. |
| `58bf73a289` | 2026-05-14 | **Verifier math (ZK)** | SmallSubgroupIPA argument change: adds a 5th (untransmitted) opening claim `A(1)=0` to the Shplonk batch → Shplonk nu-power assignment shifts. |
| `c075fc182e` | 2026-05-28 | **Relation order** | Ultra relation tuple reordered (Permutation, LogDerivLookup, Arithmetic first) → alpha-to-subrelation assignment changes. |
| `c075fc182e` (same commit; + Solidity aligners `03c48e2e44`, `12ee4f962f`) | 2026-05-28 | **Proof + VK byte ORDER** | **(Found in 2026-07-08 re-verification — previously missed.)** Flavor `EntityId`/`get_all()` layout reordered: NEW order puts `sigma_1..4, id_1..4, lagrange_first, lagrange_last, q_lookup, table_1..4` BEFORE the remaining selectors (`q_m, q_r, q_o, q_c, q_l, q_4, q_arith, …`), then witnesses, then shifts (`ultra_flavor_generated.hpp:34-77`). Consequences: the proof's 41 `Sumcheck:evaluations` are transmitted in the new order, and the VK's 28 precomputed commitments serialize in the new order. Entity/commitment COUNTS unchanged. |

Builder/DSL changes affecting gates/VKs of affected programs (all A):
ROM/RAM sorted-list index pinning (`1f7ed2ea79`); EC add/MSM opcode changes
incl. **`is_infinite` removed from the ACIR serde format** (`c0a48189eb`,
`0b6bf902ee`); secp256r1 ECDSA rebuilt on fixed-base plookup (72614→45945
gates, `70d6b831ed`); SHA256 table resize; various bigfield/biggroup, blake,
range-check changes; honk recursion constraint now hard-asserts exact
proof size (`669e92b896`). Authoritative per-opcode gate counts:
`dsl/acir_format/gate_count_constants.hpp`.

Unchanged across the whole range (both A and B): public-input layout,
`PAIRING_POINTS_SIZE = 8` (value corrected 2026-07-08 — was wrongly recorded
as 16; bb `static_assert`s 8 at both tags), Poseidon2 *hash primitive* (the
transcript hasher; the "optimized Poseidon2" commit `3827e14505` is
Mega-only — Ultra keeps the standard gate and identical FS hashing),
KZG/Shplemini wire shape, the 4-wire/14-selector Ultra arithmetization,
entity/commitment COUNTS (41 non-ZK / 42 ZK entities; 28 VK commitments +
3 metadata), BN254 `LIBRA_UNIVARIATES_LENGTH = 9`, and the
`bb prove --scheme ultra_honk` pipeline routing.
**REFUTED 2026-07-08:** "VK serialization structure unchanged" — the
structure (count/shape) held, but the commitment ORDER changed with the
EntityId reorder above.

Secondary findings from the 2026-07-08 re-verification (agent-audited, all
416 bb commits in range triaged):
- **TS flavor-codegen refactor** `c0366aaa5c`: flavors now generated from
  TypeScript specs (`scripts/flavor-codegen/src/flavors/*.ts` →
  `flavor/generated/*_flavor_generated.hpp`) — the .ts files are now the
  source of truth for entity/relation order. Constants relocated/renamed:
  `NUM_SMALL_IPA_EVALUATIONS`→`NUM_SMALL_IPA_TRANSCRIPT_EVALS` (4),
  `NUM_LIBRA_COMMITMENTS`→`NUM_SMALL_IPA_COMMITMENTS` (3), new
  `NUM_SMALL_IPA_OPENING_CLAIMS` (5), all in `small_subgroup_ipa_utils.hpp`.
- **Verifier-acceptance hardening** (accept/reject only, no byte change):
  `1391c49546` rejects VKs with log_circuit_size=0; `5f09c55a57`
  BB_ASSERT→throw_or_abort in IPA/KZG/Shplemini error paths. Mirror these
  as clean `Err` returns in co-noir (nice fit with the Phase 0 finding that
  co-noir panics on malformed input).
- **ZK-only, flag for port**: `1f9d87ba3a` gemini masking poly
  virtual→dyadic size (likely allocation-only; confirm ZK bytes unchanged);
  `15a0b9a393` solidity ZK verifier optimization (verify gas-only).

## 3. Explicitly out of scope (confirmed separate from UltraHonk)

**Chonk** ("Client-side Highly Optimized ploNK", `barretenberg/cpp/src/
barretenberg/chonk/`) is the ClientIVC-successor stack: Mega* flavors,
Hypernova folding, Goblin, ECCVM/Translator, TripleIPA. It already existed at
the pin; its heavy churn (incl. the Mega-only Poseidon2 gate rework) never
touches the Ultra flavor's proof format. `client_ivc/` no longer exists
(renamed to chonk pre-pin). Plain UltraHonk never touches `ipa/`/`triple_ipa/`.

## 4. Porting-gap verdict

- **(A) pin → public v5 tip: MEDIUM.** Same 9 relations, same entity counts,
  same VK serialization — but four consensus deltas that must each be matched
  exactly, plus ~a dozen gate-level builder changes for VK equality. All
  mechanical, all reproducible from the public repo with KAT test vectors.
  (Note: co-noir's `CONST_PROOF_SIZE_LOG_N` is already 25, so the pin
  `20260324` already includes `1f144a3040`; the effective (A) list is the
  other four rows + builder changes.)
- **(B) public v5 tip → private HEAD: SMALL surface, but ACCESS-GATED.**
  Exactly two protocol commits (full-width FS challenges; ROM-via-logup).
  Trivial to port with the code in front of you; impossible for Taceo to do
  blind. Any co-noir compatibility target must therefore either be pinned to a
  public v5 nightly, or someone with private access ports/shares (B).

## 5. Maintenance signal

Over 3.5 months the Ultra proving system took **~6 compatibility-breaking
changes** (4 public + 2 private). That's the ongoing sync burden any co-snark
implementation faces regardless of language — roughly one breaking change per
2–3 weeks, historically absorbed by Taceo in bursts every 1–2 months. A
maintenance plan (CI drift detection, co-snark-aware change review in bb, or a
formalized Taceo relationship) matters more than the one-off catch-up.

## 6. WHY each change was made (rationale mined 2026-07-08, session 2)

*Sources: full commit bodies (bb squash-merges preserve PR descriptions),
in-diff code/README/test comments, surrounding commits. Two fixes came via
the PRIVATE security repo (PR #44, #29 — low numbers amid #22xxx = embargoed,
out-of-tree development); no external CVE IDs exist anywhere. Per-change
security classification and what a re-implementation MUST preserve:*

| Change | Class | Security-critical side |
|---|---|---|
| z_perm init subrelation `a6c119f89a` | Hardening → soundness-critical after trace move | Both (sumcheck relation) |
| Trace offset `7dbe0b25c8` | Engineering (PCS decoupled from dyadic size) + ZK invariants | Both |
| **SSIPA A(1)=0 `58bf73a289`** | **SOUNDNESS FIX** | **Verifier — claim must ride the Shplemini batch** |
| Relation/entity reorder `c075fc182e` | Engineering (+350MiB memory regression) | Consistency only |
| CONST_PROOF_SIZE_LOG_N 28→25 `1f144a3040` | Engineering (25 = SRS max; cuts recursion gates) | Consistency only |
| **ROM/RAM index pinning `1f7ed2ea79`** | **SOUNDNESS FIX (field-wrap case)** | **Prover-side circuit construction** |
| Recursion size assert `669e92b896` | Hardening (DX) | Constraint construction |
| Reject log_circuit_size=0 `1391c49546` | Hardening (OOB write in verifier) | Verifier |
| Graceful verifier failures `5f09c55a57` | Hardening (from bb's internal review process) | Verifier + deserialization |

**The three with the clearest soundness rationale:**

1. **SSIPA `A(1)=0` (PR #44, private security repo).** Without the fifth
   opening, the SSIPA algebraic identity at random r has a one-dimensional
   kernel: at X=1 the boundary condition and the j=0 recurrence collapse
   into a single linear equation, so a homogeneous perturbation
   (δ_A(1)=δ, δ_A(g^j)=−δ/(g−1), δ_s matching) satisfies the identity while
   **producing an invalid claimed Libra inner-product s' = s + δ_s** —
   breaking ZK-sumcheck soundness in every ZK flavor. The fix adds an
   untransmitted claim A(1)=0 (value hardcoded to 0 on BOTH sides, never
   read from the transcript) that supplies the missing rank-1 constraint.
   ⚠ **Port requirement**: the verifier must reconstruct the claim with
   the FIXED value 0 and route it through the Shplemini/Shplonk batched
   opening — bb's own README warns the local `check_consistency` identity
   check alone still accepts this invalid case. bb ships a regression test
   for exactly this case (shplemini.test.cpp) — port it.

2. **ROM/RAM first-sorted-index pinning (PR #29, private security repo).**
   The index-delta subrelation (Δ²+Δ=0) has roots {0,−1} over the field,
   and the first sorted index was an unconstrained free witness
   (`add_variable(FF(0))`) — so the sorted chain could start at p−1
   (≡ −1), wrap to 0 legally, and **read/write unconstrained values at
   phantom index p−1**. Fix: bind the first sorted index to `zero_idx()`
   (backed by a real `fix_witness` gate w·1+0=0) and pin the chain end;
   all indices become symbolically bounded in [0, N−1] without leaning on
   Schwartz–Zippel. ⚠ **Port requirement** (phase-2 item 2.6 builder
   work): copy-constrain to a genuinely-constrained zero witness — a
   fresh `add_variable(0)` reopens the gap. Port bb's rom_ram.test.cpp
   field-wrap regression test.

3. **z_perm init subrelation is a dependency of the trace move.** Before:
   z_perm(0)=0 was enforced *implicitly* by z_perm being opened as a
   shifted polynomial in Gemini. The trace-offset change breaks that
   implicit guarantee (lagrange_first leaves row 0), so the explicit
   `L_first·z_perm=0` subrelation was landed FIRST as a prerequisite
   ("decouple perm arg boundary from shiftability assumptions"). Our port
   order (2.2 before/with 2.4) accidentally-correctly mirrors this;
   any future re-derivation must keep that dependency.

Also relevant to us: bb's `5f09c55a57` rejects **non-canonical
field encodings** (value ≥ modulus now throws instead of silently
reducing) and **trailing proof data** — the exact robustness class our
Phase 0 spot-checks flagged in co-noir (trailing-bytes acceptance;
is_on_curve panics). bb treats these as security-review findings;
co-noir should adopt the same posture during 2.7 (fallible deserialization
+ strict length + canonical-encoding checks).
