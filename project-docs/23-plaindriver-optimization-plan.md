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

### §A results — MEASURED (2026-07-24 afternoon; permanent env-gated phase
### timers `CO_NOIR_PHASE_TIMINGS=1`, medians of 3, loadavg 23–31/192 cores)

| phase | poseidon 2^11 | sha256 2^16 | recursion_zk 2^20 |
|---|---|---|---|
| read_circuit (JSON) | 0.330s / **61%** | 0.1% | 0.0% |
| build+CRS+PK (pipeline) | 5% | 15% | 11% |
| oink | 8% | 10% | 12.30s / **25.5%** |
| **sumcheck** | 17% | 1.28s / **60.5%** | 26.03s / **54.0%** |
| shplemini batching | 5% | 10% | 6% |
| opening MSM + rest | ~3% | ~3% | ~1% |
| **total** | **0.54s** | **2.11s** | **48.3s** |

Reading (Phase C order, by evidence): **C1 = the sumcheck per-edge
relation-accumulation loop** (54–60% at size; serial today — arkworks'
parallel feature only threads arkworks-internal ops like MSMs, which is
why commitment-heavy phases are already cheap). **C2 = oink** (share grows
7.8%→10.4%→25.5%; its MSMs are already parallel via ark-ec — the serial
suspects are the grand-product prefix scan and lookup-inverse batches).
**C3 = shplemini batching** (6% at 2^20, trivially data-parallel).
NOT worth touching: the final opening MSM (~1%). Bonus finding: small
circuits are bound by the 0.33 s JSON artifact parse, not proving.
**→ FIXED same day (~80×: 0.33 s → 0.004 s).** Root cause: `noir-types`'
`program_artifact_from_reader` called `serde_json::from_reader` on a bare
unbuffered `File` → one read(2) syscall PER BYTE (strace: 317,557
syscalls for the 317 KB poseidon artifact; now 26). Fix: `read_to_end` +
`from_slice`, same signature/error semantics, mends all 6+ CLI call
sites at once (incl. every MPC party's startup read). New fast unit test
`noir-types tests::parses_program_artifact` (in-memory fixture
`co-noir/noir-types/test_fixtures/add3.json`, ~0 s); plain KATs +
fast-check PASS. Timers live in co-ultrahonk (prove path, driver-generic,
transcript untouched; zero output unless env set); parity re-verified.
Residue accounting ≤2.1% everywhere. Detail in PROGRESS s14.

### §A results — earlier same-day preliminary (superseded by the table
### above; kept for the record: samply 500 Hz, box NOT idle)

- **The prover is serial-dominated.** Process-wide, ~68% of samples sit in
  libc `syscall`/`sched_yield`/clone paths = 16 rayon workers parked or
  spinning while one thread works (their arkworks `parallel` pool exists —
  B1 note above — but co-ultrahonk's own passes rarely feed it). Amdahl
  says Phase C (parallelise the prover's passes) is the primary lever,
  matching bb, which hand-threads these loops.
- Main-thread hot leaves (sha256, witness-fed, ZK): glibc memmove/memcpy
  cluster (large-vector copying — Phase D de-alloc/copy territory),
  `partially_evaluate_init` (sumcheck folding), `ark_ff …Fp::mul`, and
  `num_bigint::BigUint::mul` (conversions — includes CRS point
  deserialization; NOT full-file: RSS 21 MB vs 67 MB `bn254_g1.dat`, the
  subset TODO in `co-noir/src/lib.rs` is already partially moot).
- Fair witness-fed baselines (this box, 3 runs): sha256 ~4.67 s vs bb
  0.36 s (~13×); poseidon 0.70 s vs bb 0.17 s (~4×) — v1's plaindriver
  numbers included ~0.6 s witness solving (bench v2 fixed the boundary).
- NEXT for a clean §A: idle box; per-phase wall attribution (tracing spans
  or coarse timers at oink/sumcheck/shplemini/PCS boundaries) for all
  three circuit sizes; THEN pick C-items by share. LTO/codegen-units and
  `target-cpu=native` (below) remain untested, each as its own gated unit.
- Build/profiling change landed meanwhile: `[profile.release] debug=true`
  (symbols for samply/perf; size-only cost).

## 2. Phase B — build/feature wins (low risk, likely large, cheap to try)

Grounded in the current tree (verified 2026-07-23):

**⚠ B1 REFUTED by measurement (2026-07-24, PLAN 6.1):** the
`default-features = false` reading below missed Cargo *feature
unification* — other workspace dependencies already switch `parallel`
(and `asm` on ark-ff) ON for the resolved graph. Verified with
`cargo tree -p co-noir -i ark-{ec,ff,poly}@0.6.0 -f "{p} {f}"`: all three
resolve with `parallel,rayon,std` (+`asm` for ark-ff), and adding the
features explicitly rebuilt nothing (0.5 s no-op build). The features are
now pinned explicitly in the workspace Cargo.toml so they survive
dependency drift, but there is NO win here — the plaindriver-vs-bb gap
(witness-fed sha256: ~4.67 s vs bb 0.36 s, measured 2026-07-24) is
therefore in co-ultrahonk's OWN single-threaded passes (Phase C) and/or
allocation churn (Phase D), which the §1 profile must now arbitrate
before any further lever is pulled. The §1 "measure first" rule wins
again. The original (wrong) analysis is preserved below for the record:

- ~~**Arkworks is built with `default-features = false` → its `parallel` and
  `asm` features are OFF.**~~ Consequences, both directly on the hot path:
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
- ~~**No `[profile.release]` tuning**~~ **B2 MEASURED + DROPPED
  (2026-07-24):** fat and thin LTO (+cg1) both landed inside the ±2–3%
  host-noise floor on a 3-way interleaved A/B (no-LTO / thin / fat run
  back-to-back per pair, sha256 witness-fed, byte-parity gate green via
  compare.sh vs the bb oracle first) — while fat LTO cost ~4.5 min of link
  per rebuild vs ~40 s. Flags removed; rationale note left in Cargo.toml;
  `debug = true` kept (symbols for profiling, size-only). Consistent with
  B1's refutation: the hot loops (ark asm field mul, within-crate poly
  passes) don't cross the crate boundaries LTO optimises.
- **B3 `target-cpu=native` DEPRIORITISED (2026-07-24):** ark-ff's `asm`
  feature (already active) emits its mulx/adcx/adox path via inline asm
  regardless of target-cpu, so the expected win is near zero; after B1+B2
  both measured as no-ops, not worth another 5-min build + noise-floor
  A/B now. Revisit only if Phase A's profile shows leaf time in generic
  (non-asm) field code or autovectorisable loops.

These are independent one-to-few-line changes; land + measure each separately
so the attribution is clean.

### §C results ledger (2026-07-24 evening)

- **C1 LANDED: parallel sumcheck relation accumulation — sumcheck ~6.2×
  (sha 2^16) / ~8.2× (recursion 2^20: 32 s → ~4 s); prove_total ~2.8× /
  ~2.5× (52 s → ~20.5 s).** Design: hybrid — rayon chunks each build
  their edge batch AND accumulate relations into per-chunk accumulators,
  merged by exact field addition (bit-identical regardless of thread
  count; KATs are the referee and stayed green). Plain-driver detection
  via TypeId (only plain's share type is the raw scalar); MPC drivers
  keep the OLD schedule by construction (chunks build partial batches,
  order-preserving concat reproduces the exact sequential batch, one
  accumulation on the caller thread — mul_many batching, network
  scheduling, randomness untouched). ZK needed nothing special: all
  masking randomness is drawn before the rounds; disabled-rows
  contribution stays sequential; PlainState::fork holds no RNG. Files:
  co_sumcheck_round.rs, relations/mod.rs (merge_from), types_batch.rs
  (concat), + new FAST test
  `poseidon_proof_bytes_thread_count_invariance` (0.33 s: 1-thread vs
  16-thread scoped pools ⇒ byte-identical proofs — catches
  scheduling-dependent-reduction bugs structurally).
- **JSON-parse fix** (see §A note): read_circuit ~80× — every CLI call
  site incl. MPC party startup.
- **C2 LANDED: oink 12.33 s → 2.54 s (4.9×) on recursion 2^20;
  prove_total 20.0 s → 12.2 s (1.64×, CONSERVATIVE — the after-reps ran
  at loadavg 71–106 vs before at 12–20).** Root cause was brutal: the
  plain driver's `inv_many*` did one full extended-Euclid inversion PER
  ELEMENT, serially — ~3M inversions ≈ 9.5 s of oink's 12.4 s. Fix:
  `ark_ff::batch_inversion` (Montgomery batch, chunk-parallel; ark skips
  zeros = exact leaking-zeros semantics; strict variants keep
  error-on-zero via parallel pre-scan) — gp/batch_invert ~300×,
  gp/array_prod 14.7×. Also: plain.rs mul_many/local_mul_vec/
  mul_open_many → rayon elementwise (speeds ALL phases); logderiv +
  grand-product row loops → order-preserving indexed par-map (pure local
  ops for all drivers — no TypeId gating needed; operand order, values,
  MPC randomness consumption unchanged; L1's round-batching structure
  preserved). Permanent oink sub-phase timers added (env-gated).
  REP3/Shamir impls verified untouched (0-line diff). Deliberately
  serial: T::rand paths (RNG-stream order = thread-invariance),
  prefix scans (inherent, now ~0.2 s), MSMs (already parallel). New
  FAST test: `batched_inversion_matches_serial_reference` (0.05 s,
  non-chunk-aligned length, zero handling both variants). Oink residual
  ~2.5 s = masking-poly RNG + MSM commits — RNG/MSM work, separate scope.
- **C1b+C3 LANDED: prove_total 10.2 s → 8.0 s (1.27× at 2.5× HIGHER
  load; a matched-load rep showed 7.80 s).** partially_evaluate 2.8×
  (parallel across all 41 columns + within-column for the init variant —
  distinct src/dest buffers make it chunk-safe; in-place variant columns
  only, overlapping writes), shplemini batched_polys 6.5×, shplonk
  batched_quotient 3.0× (per-claim quotients parallel, Q/ν accumulation
  kept serial in the exact original order → bit-identical), plus
  size-gated (≥2^13) parallel slice ops in shared_polynomial/polynomial.
  All parallelised paths are purely local for every driver (no
  net/state/RNG in signature) — no TypeId gating needed. Kept serial:
  factor_roots prefix recurrence (parallel across claims instead),
  in-place halving overlap, Horner within one eval (parallel across
  evals), Q/ν order, transcript. No new tests needed (elementwise/
  independent-task only — KATs + thread-invariance are the coverage;
  all green, fast-check PASS re-verified by coordinator).

**Day punchline (2026-07-24): plain prover recursion_zk 2^20
~52 s → ~8 s (~6.5×), byte-identical proofs throughout.** Remaining
profile is MSM commits (~1.5 s, already parallel — algorithmic work
only), masking-poly RNG (~0.6 s, serial by thread-invariance design),
compute_univariate ~2.3 s (already parallel), pipeline fixed costs.
bb comparison at same circuit: ~4.5 s → the gap is now ~1.8×, down
from ~11×. Phase D (profile-directed deeper work) is now optional
polish, not a mission.

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
