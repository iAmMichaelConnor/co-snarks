# Chapter 7 — UltraHonk, explained from a Plonk baseline (and how each stage runs under MPC)

*Audience: knows Plonk (arithmetization, permutation argument, quotient
polynomial, KZG) but hasn't followed SNARKs since. Sources: bb C++ at
`origin/v5-next` and the Rust mirror in `co-noir/ultrahonk` — structure names
below are the Rust ones from ch. 02 §2. Read ch. 01 first for the MPC
vocabulary.*

## 1. From Plonk to UltraHonk in three moves

**Move 1 — richer arithmetization ("Ultra").** Plonk's single gate
`q_L·a + q_R·b + q_O·c + q_M·ab + q_C = 0` becomes a 4-wire trace
(w₁..w₄) with 14 selector columns activating specialized gates: arithmetic,
elliptic-curve point ops (Grumpkin add/double as native gates), range checks
via lookups, ROM/RAM memory records, Poseidon2 rounds (dedicated
internal/external gates), and lookup gates. Copy constraints are still
Plonk's permutation argument over all four wire columns.

**Move 2 — lookups via log-derivatives ("logup"), not sorted plookup.**
Where UltraPlonk's plookup sorted the lookups into an auxiliary polynomial,
UltraHonk proves ∑ᵢ 1/(X − readᵢ) = ∑ⱼ multiplicityⱼ/(X − tableⱼ) at a random
X — set membership via equality of pole structures. The prover must compute
**inverses of shared values** (one per lookup row) — under MPC this is the
mask-and-open batch-inversion pattern (ch. 01 §2.4), and it's why `inv_many`
is in the driver trait.

**Move 3 — sumcheck instead of the quotient polynomial ("Honk").** This is
the big one. Plonk proves "relation holds on every row" by dividing by the
vanishing polynomial Z_H and committing to the quotient — which forces
degree-blowup-sized FFTs and commitments. Honk instead treats each column as
a **multilinear polynomial** over the boolean hypercube {0,1}ⁿ (row index =
binary vector; n = log(circuit size)) and proves

  ∑_{x∈{0,1}ⁿ} pow(x; gate_challenges) · Relation(w(x), σ(x), q(x), …) = 0

with the classic **sumcheck protocol**: n rounds, in round k the prover sends
a small univariate polynomial (the partial sum over the remaining variables),
the verifier checks consistency and sends challenge uₖ, and everything gets
partially evaluated at uₖ. After n rounds the claim reduces to evaluating all
columns at one random point u ∈ 𝔽ⁿ. Costs: no quotient, no big FFTs, prover
work is field ops linear in circuit size; the price is a longer proof (one
univariate per round) and the need for a **multilinear** commitment opening.

**The relation set** (9 relations, each with subrelations, summed with
independent challenge weights α₀..α_{NUM_SUBRELATIONS−1}): ultra_arithmetic,
permutation (Plonk-style grand product z_perm), logderiv_lookup,
delta_range_constraint, elliptic, memory (ROM/RAM consistency),
non_native_field, poseidon2_external, poseidon2_internal
(`ultrahonk/src/decider/relations/`). Sync-sensitive: the count, order, and
per-subrelation degrees all feed the transcript and verifier math — three of
the four v5 breaking changes in ch. 03 §2 are exactly such edits.

## 2. The prover pipeline, stage by stage

Names as in bb/co-noir; transcript = Fiat–Shamir over Poseidon2 (or Keccak).

### Stage O — "Oink" (commitments and challenges)
1. Compute public-input delta; commit to wire polynomials w₁..w₃ (w₄ depends
   on lookups/memory and comes after eta).
2. Challenges η, η₂, η₃ → build sorted-list/memory terms and w₄; commit.
3. Challenges β, γ → build the permutation **grand product z_perm** (running
   product of Plonk terms) and the **logup inverse polynomial**; commit both.
4. Challenges α₀..α_k (relation separators), then gate challenges (powers
   for the `pow` polynomial).

### Stage S — Sumcheck
n (padded: **virtual n = 25**, see §4) rounds; each round the prover computes
a degree-≤MAX_PARTIAL_RELATION_LENGTH univariate by evaluating the full
relation on "edge" pairs of the current hypercube and summing; sends its
coefficients; gets challenge uₖ; partially evaluates every column. Output:
claimed evaluations of all ~41 column polynomials at u (these go in the
proof).

### Stage P — PCS: "Shplemini" = Gemini fold → Shplonk batch → KZG open
The verifier now needs the multilinear evaluations at u proven against the
*univariate* KZG commitments. **Gemini** does the multilinear→univariate
reduction: batch all columns with challenge ρ, then repeatedly "fold"
A_{k+1}(X) = even/odd-combine(A_k, uₖ), committing to each fold (n−1
commitments) and revealing evaluations A_k(±r^{2ᵏ}) at challenge r.
**Shplonk** batches all these opening claims into one quotient with challenge
ν, evaluated at challenge z. A single **KZG** opening proof (one G₁ point,
"KZG:W") finishes. The final pairing check e(P₀, [1]₂) = e(P₁, [τ]₂) is — in
the recursive/in-circuit setting — not performed but **deferred**: (P₀, P₁)
form the 16-field "pairing point object" appended to the public inputs and
accumulated up the recursion stack (ch. 04/ch. 03 "PAIRING_POINTS_SIZE=16").

### What's in a proof
Oink commitments (8 witness-ish G₁ points) → 25 sumcheck univariates →
~41 evaluations → 24 Gemini fold commitments + fold evaluations → Shplonk Q →
KZG W. With Poseidon2 transcript everything is encoded as field elements:
**410 fields non-ZK / 458 fields ZK** on our target (v5-next), plus the
115-field VK (`RECURSIVE_PROOF_LENGTH`, `ULTRA_VK_LENGTH_IN_FIELDS` in
`noir-projects/.../constants.nr:651,670`).

## 3. Fiat–Shamir details that matter for byte-compatibility

- Challenges are derived by hashing a running buffer with **domain-separating
  labels** ("Sumcheck:u_0", "Gemini:r", "Shplonk:nu", …). The label strings,
  the order of absorption, and the encoding of G₁ points into field elements
  are all part of the de-facto proof format. This is why the Rust transcript
  (`co-noir-common/src/transcript.rs`) is a sync hotspot.
- On the v5 line, each 254-bit hash output is **split into two 127-bit
  challenges** (`split_challenge`); the private v6 line moved to full-width
  challenges — the (B1) break of ch. 03. On our v5-next target, the split
  behavior applies.
- The VK is itself hashed into the transcript ("vk_hash") before anything
  else, binding the proof to the exact circuit.

## 4. The ZK flavors (what "+ZK" adds)

Base UltraHonk is only *computationally sound* — it makes no hiding claim:
wire commitments are unblinded and sumcheck reveals genuine evaluations of
witness polynomials at u. The ZK variants add:

1. **Masked witness commitments** — random multiples of vanishing-region
   values blind each committed polynomial (in MPC: the masks are *jointly
   sampled shares*, ch. 01 §4.4).
2. **Libra masking for sumcheck** — a low-degree random polynomial is added
   to the relation so the round univariates are statistically independent of
   the witness; its correctness is proven by an auxiliary argument over a
   **small multiplicative subgroup** (the **SmallSubgroupIPA**, whose 2026
   argument change — the untransmitted A(1)=0 claim — is one of our four sync
   items, ch. 03 §2).
3. **Gemini masking polynomial** for the fold commitments.
4. Disabled rows: the last 4 hypercube rows are reserved so masking terms
   never collide with real trace content — the "trace offset" rework (rows
   moved to the *top*) is another of the four sync items.

Proof grows 410 → 458 fields. **For co-SNARKs, ZK is the safe default**: the
proof is the one public artifact, and without ZK it can leak witness
information to whoever holds it (ch. 01 §5).

**Constant proof size**: with the Poseidon2 transcript, sumcheck/Gemini are
padded to a **virtual log-size of 25** regardless of actual circuit size, so
all proofs have identical shape — essential for recursive verifiers with
fixed circuits. (Keccak-flavor proofs are unpadded; they're for EVM
verification, and have **no in-circuit recursive path** — see ch. 04 §6.)

## 5. The MPC mapping, stage by stage

The columns split into **public** (selectors q, permutation σ, lookup tables,
Lagrange polynomials — all from the circuit, known to everyone) and **shared**
(wires w₁..w₄, z_perm, logup inverses, and all masking polynomials). Public ×
public work is done redundantly by all parties; anything touching shares goes
through the driver trait (ch. 02 §3).

| Stage | Operation | MPC character |
|---|---|---|
| Witness build | ACVM execution | The genuinely interactive phase; see ch. 06 for blackbox costs |
| Oink: commit | MSM(shared coeffs, public CRS) | **Local** → point-share; then **open** (1 round, batched `open_point_many`) and hash publicly |
| Oink: w₄ / sorted terms | products with public η's + a few share×share muls | ~free + batched muls |
| Oink: z_perm | grand product Πᵢ (num/den) | prefix products of shared values: batched muls + **batch inversion** (mask-and-open) |
| Oink: logup inverses | 1/(read − X) per row | **`inv_many`** = mask-and-open batch inversion (2 rounds total) |
| Challenges | hash transcript | **Public** — no MPC at all |
| Sumcheck rounds | evaluate relation on edges, sum | the share×share multiplication workhorse: `local_mul` per edge + one **`reshare`** round per sumcheck round (25 rounds → 25 communication rounds, each heavily batched) |
| Sumcheck: send univariate | open round coefficients | **open** (they're proof content) |
| Gemini fold | linear combos with public uₖ, ρ | **Local**; fold commitments = local MSM + **open** |
| Gemini/Shplonk evals | evaluate shared polys at public r, z | **Local** (linear), then **open** (proof content) |
| KZG W | quotient by (X − z): synthetic division | **Local** (linear), MSM, **open** |
| ZK masking | joint randomness | from correlated RNG shares — no extra rounds |

Total communication: ~25 sumcheck reshare rounds + a handful of
opening/inversion rounds + witness extension. Everything else is local
compute identical in shape to the single prover — which is why the co-prover
tracks bb's code structure so closely, and why a bb sync is "mirror the C++
into ultrahonk/, then mirror that into co_*/" (ch. 02 §6).

The **Shamir wrinkle**: DN07 multiplication consumes preprocessed double
sharings, so the Shamir prover must know the multiplication count in advance
— `co_ultra_prover.rs:159-201` literally accounts for every mul the pipeline
will do (per relation, per round, ZK on/off). Any sync that changes the
proving flow must update this accounting; it's the most fragile file in a
sync (ch. 02 §2).

## 6. Recursion: how an Aztec contract verifies this proof (preview of ch. 04 §6)

`std::verify_proof_with_type(vk, proof, public_inputs, vk_hash, proof_type)`
in a Noir private function becomes an **in-circuit UltraHonk verifier**
(~"the verifier algorithm above, expressed as gates") inside the app's
circuit: proof and VK enter as *private witness fields*, Poseidon2 transcript
is re-run in-circuit, sumcheck is re-checked, and the final pairing is
deferred into the pairing-point accumulator. proof_type 0 = non-ZK Ultra,
6 = ZK Ultra; both recursive verifiers exist and are tested on v5-next. The
co-SNARK proof itself is therefore **never published** — it's witness data
consumed by the user's client-side proof stack.
