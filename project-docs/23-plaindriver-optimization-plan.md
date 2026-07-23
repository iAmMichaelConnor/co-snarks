# Chapter 23 — Optimising the plain (single-prover) co-noir path

*Created 2026-07-23 (session 13), on Mike's ask after the 0.5 bench showed
`plaindriver` ~5.3 s vs bb ~0.3 s on `bb_sha256_compression`. Goal: make the
Rust single-prover significantly faster. This chapter is the plan; execution
is gated on the safety rails in §0 and starts with measurement (§1), never
blind optimisation.*

## 0. The one hard invariant (and the safety rails)

**The proof/VK BYTES must stay identical to bb.** The Rust implementation is
free to differ from the C++ however we like — different data structures,
different parallelisation, different MSM algorithm — **as long as the output
bytes are unchanged and the mathematics is exactly preserved.** Optimisation
here means "same function, computed faster," never "different function."

**Frozen — touching any of these changes the output and is out of scope for
this work:** relation formulas + subrelation order; the Fiat–Shamir
transcript (what is absorbed, in what order, challenge derivation); the
commitment-scheme math (Shplemini/Gemini/KZG, SmallSubgroupIPA); field
encoding + entity/commitment serialization order; RNG-derived masking values
(honest proofs are what the KATs pin). An optimisation may reorder *internal*
computation only where the result is bit-identical (integer field/curve
arithmetic is exact — no floating point — so reassociation that preserves the
algebraic expression is safe; but do not reorder anything that feeds the
transcript).

**Every change is gated, in this order, before it's kept:**
1. `./fast-check.sh --bb` — plain KAT byte-parity (proof AND VK) vs the
   source-built v5.0.1 oracle. This is the tightest oracle; a single flipped
   byte fails it.
2. `cargo test -p tests --release --test noir -- plain vk_kat security_regression`
   — byte-KATs (incl. recursion VK) + the 11 security regressions.
3. `./fast-check.sh --all-fast` — + REP3/Shamir co-mirror parity + bidirectional
   bb cross-verify (the plain path shares machinery with the MPC path; a
   "faster" change that breaks the MPC mirror is caught here).
4. **Measured, not assumed:** re-run the relevant `bench-0_5.sh` cells
   before/after and record the delta with the run manifest (ch. 22 §5a). A
   change with no measured speedup and any parity risk is reverted.
Each optimisation lands as its own small commit so a regression bisects to
one change. Never raise thread caps beyond the mainframe policy.

## 1. Phase A — measure honestly first (no optimisation yet)

Two things must be fixed before any hot-spot claim:

1. **Make the comparison fair.** The bench's bb cell runs `bb prove
   --write_vk`, which also GENERATES the VK — inflating bb's time; and
   `plaindriver` may include circuit construction / witness solving that bb's
   `prove` (fed a precomputed witness `.gz`) skips. Before optimising, split
   both into phased, boundary-matched numbers: (circuit build) / (witness) /
   (VK gen) / (prove-only) / (verify). Compare prove-only to prove-only.
2. **Profile the plain prover** (`samply record` or `cargo flamegraph` /
   `perf record`, release build, on an IDLE box — not while the 0.5 bench
   runs) at all three circuit sizes. Deliverable: a % breakdown across the
   expected buckets — MSM/commitments, sumcheck relation evaluation, grand-
   product + lookup-inverse construction, Gemini/Shplemini folding, transcript
   hashing, allocation/copy overhead. **Optimisation targets follow the
   profile; the §2–§4 levers below are hypotheses ranked by likely impact,
   to be confirmed, not a fixed order.**

## 2. Phase B — build/feature wins (low risk, likely large, cheap to try)

Grounded in the current tree (verified 2026-07-23):

- **Arkworks is built with `default-features = false` → its `parallel` and
  `asm` features are OFF.** Consequences, both directly on the hot path:
  - MSM is `P::msm_unchecked` = arkworks Pippenger running **single-threaded**
    (`co-noir-common/src/mpc/plain.rs:271`). Enabling the arkworks `parallel`
    feature threads Pippenger (and FFT) for free — likely the single biggest
    low-risk win, since MSM/commitments usually dominate a Honk prover and bb
    threads them across all cores while we use one.
  - Field arithmetic uses generic Montgomery, no x86-64 carry-instruction asm.
    ark-ff 0.6 has an `asm` feature (mulx/adcx/adox) — bb's field mul is
    hand-written asm; closing part of that constant factor is a feature flag.
  - Action: enable `parallel` + `asm` on the ark-ec/ark-ff/ark-bn254 deps
    (workspace Cargo.toml). **Byte-parity must be re-verified** (integer
    Montgomery is exact → identical results expected; asm is the same
    reduction, just faster — but verify, don't assume).
- **No `[profile.release]` tuning** (only `ci-dev` exists). Add
  `[profile.release] lto = "fat"`, `codegen-units = 1` (and consider
  `panic = "abort"` only if it doesn't break the test harness — probably
  leave it). Typical 10–30% from LTO+cg1 alone.
- **No `.cargo/config.toml`** → no `target-cpu`. Add `target-cpu=native` for
  local builds (unlocks the CPU's full ISA incl. the ADX/BMI2 the asm field
  wants). Note it makes the binary machine-specific — fine for a local oracle-
  compared build; keep a portable baseline documented. Re-verify parity.

These are independent one-to-few-line changes; land + measure each separately
so the attribution is clean.

## 3. Phase C — parallelise the plain prover (algorithmic)

The plain `ultrahonk` crate's prover path has **no rayon** today (verified;
rayon is present only in the `co-ultrahonk` MPC decider + the mpc modules).
Even with arkworks `parallel` threading MSM internally, the surrounding prover
loops are serial. Confirm against the profile, then parallelise the dominant
ones — each is embarrassingly parallel and math-preserving:

- **Sumcheck relation evaluation** — per-round univariate construction
  evaluates all subrelations across the remaining hypercube rows; parallelise
  over row-chunks with a per-chunk accumulator reduced at the end (the MPC
  side already does something analogous in `co_decider/relations` — mirror the
  structure, keep the plain arithmetic). Associative accumulation → bit-
  identical.
- **Commitment MSMs** across the ~40 witness/aux polynomials — batch and/or
  parallelise across polynomials (in addition to intra-MSM threading).
- **Grand-product (`z_perm`) and lookup `inverses`** — construction is a
  prefix-product / per-row inverse; use **Montgomery batch inversion** (one
  inversion + O(n) muls instead of n inversions) if not already, and
  parallelise the independent segments. Batch inversion is a classic, exactly-
  equivalent speedup.
- **Gemini fold / Shplemini** — parallelise the per-polynomial fold steps.

## 4. Phase D — deeper, profile-directed (higher effort)

Only if §2–§3 leave a gap the profile blames on these:

- **Eliminate hot-path allocations/clones.** `eval_poly` clones into a
  `DensePolynomial` per call (`plain.rs:275`, flagged by a TACEO TODO);
  sumcheck/Gemini may allocate per row/round. Reuse scratch buffers, operate
  on slices, avoid `DensePolynomial` wrappers in inner loops. Pure speed, zero
  math change.
- **Tuned MSM.** If arkworks `parallel` Pippenger is still the bottleneck vs
  bb: precompute per-CRS-point bucket tables (bb keeps a `pippenger_runtime_
  state` with precomputed points), or evaluate a dedicated Pippenger with a
  window size tuned to our sizes. Bigger lift; keep behind the same byte gate.
- **Layout / SIMD.** Flat contiguous `Vec<Fr>` column-major polynomial storage
  for cache-friendly sumcheck sweeps; let autovectorisation/`target-cpu` do
  the SIMD. Only if the profile shows memory-bound stalls.

## 5. Carry-over to the MPC path (why this is worth it beyond plaindriver)

The ultimate product is co-SNARK MPC proving, not single-prover — but the
plain and MPC provers **share** the MSM, field arithmetic, sumcheck relation
machinery, and commitment code (`co-noir-common` + parallel structures in
`co-ultrahonk`). Phase B (features/build) benefits BOTH unconditionally.
Phase C/D local-compute wins carry into the MPC parties' local work (the
`T_compute` term in the ch. 22 cost model); they do NOT reduce the
communication term (`R × latency`), which is the separate, network-bound
lever. So "optimise plaindriver" is both a standalone win and a down payment
on faster co-proving.

## 6. Sequencing, expected impact, risks

| Phase | Change | Effort | Likely impact | Risk |
|---|---|---|---|---|
| A | fair compare + profile | S | (enables the rest) | none (measure only) |
| B1 | arkworks `parallel` feature | S | **high** (threads MSM/FFT) | low — re-verify bytes |
| B2 | ark-ff `asm` feature | S | med (field const-factor) | low — re-verify bytes |
| B3 | release lto+cg1, target-cpu | S | med (10–30%) | low — re-verify bytes |
| C1 | parallelise sumcheck eval | M | high (if profile says so) | med — assoc. reduction, mirror MPC |
| C2 | batch-invert + parallel z_perm/inverses | M | med | med |
| C3 | parallelise commitment MSMs across polys | M | med | low |
| D | tuned Pippenger / de-alloc / layout | L | profile-dependent | med |

Realistic target: closing 18× to low-single-digit× is very achievable from
B+C (single-thread→multi-core MSM + asm field + LTO is most of the gap);
fully matching bb's hand-asm C++ from arkworks-generic is aspirational and
D-territory. **Risks are all caught by the §0 byte gate** — the failure mode
of a "faster" change is a parity break, and the KAT/cross-verify suite makes
that loud and immediate. The only subtle trap is reordering something that
feeds the transcript (changes bytes legitimately-but-wrongly); §0's frozen
list plus the byte gate prevent it.

## 7. First concrete step (when a session picks this up)

On an idle box: Phase A (phased fair compare + one flamegraph per circuit
size), committed as a short findings note appended here (§A results). THEN
B1 alone (arkworks `parallel`), gate + bench, commit. Do not batch B+C into
one commit — the whole point is per-change measured attribution.
