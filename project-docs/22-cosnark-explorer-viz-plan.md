# Chapter 22 — co-SNARK performance explorer (interactive viz) — plan

*Created 2026-07-23 (session 13), on Mike's ask: an interactive HTML site
with sliders (machine size, circuit size, inter-node distance, node count,
…) and side-by-side comparisons, built to convince a **barretenberg-literate
skeptic** that co-SNARK UltraHonk is real and to show where it is/ isn't
practical across circuit sizes and MPC deployments. This chapter is the
plan; the artifact is built by following it.*

## 0. Audience and thesis

Reader = someone who knows bb/UltraHonk cold and is skeptical co-snarks
"really" produce the same proofs at tolerable cost. Two things convince
that reader, in order:

1. **The hard fact first (not a model):** co-noir's REP3 MPC prover emits
   a proof that is **byte-identical** to bb's, accepted by **bb's own
   verifier**, for all 33 test circuits, both hashers, ZK and non-ZK — and
   the single-prover co-noir path (`plaindriver`) is likewise byte-identical
   to bb. This is measured, in-tree, reproducible (compare.sh /
   compare_mpc.sh, VK byte-KATs). The site LEADS with this — a skeptic who
   doubts correctness never gets to the perf question.
2. **Then the honest cost picture:** a model they can interrogate, with
   measured anchor points called out as measured and everything else
   clearly labeled as modeled extrapolation. A skeptic distrusts a smooth
   curve with no data under it; the site must wear its data on its sleeve.

Anti-goal: a glossy chart that overstates. Every modeled number is badged
MODELED; every measured number is badged MEASURED with its provenance.

## 1. The comparison ladder (the spine)

Four prover configurations, increasing "distance from plain bb":

| Config | What it is | Correctness relation to bb | Cost story |
|---|---|---|---|
| **bb** | barretenberg C++, single prover | reference | baseline |
| **plaindriver** | co-noir Rust prover, NO MPC (1 process, `co-noir/co-noir/src/bin/plaindriver.rs`) | **byte-identical proof** to bb | ~Rust-vs-C++ constant factor; answers "is co-noir's prover itself fast?" |
| **REP3 3-party** | co-ultrahonk, 3 nodes, replicated SS | **byte-identical proof** to bb (all 3 parties emit the same bytes) | ~2× CPU + comms rounds × latency |
| **Shamir n-party** | co-ultrahonk, n nodes, threshold t | byte-identical proof (validated 3-party & 5-party t=2) | ~1× CPU + more comms + correlated-randomness stock |

The plaindriver rung is the rhetorical hinge and directly answers Mike's
"can co-ultrahonk run with 1 node / no MPC overhead?" — YES, that is
exactly what plaindriver is, and it already proves the Rust reimplementation
is a faithful, standalone prover before any MPC cost enters.

## 2. Cost model (explicit, so the reader can audit it)

Total wall time per proof:

    T(config, circuit, machine, network) = T_compute + T_comm

- **T_compute** = base_prover_time(circuit_size, machine_cores) × cpu_factor(config)
  - base from measured bb/plaindriver points, scaled by circuit size (≈ n log n
    in gate count for Honk sumcheck+MSM; use measured points to fit the constant)
    and by cores (measured thread-scaling curve — sub-linear, and small
    circuits *prefer* fewer threads, ch. 14 §6.3).
  - cpu_factor: bb=1, plaindriver≈1–1.5, REP3≈2, Shamir≈1 (per Taceo's
    published honest-majority-efficiency numbers + our anchors).
- **T_comm** = R(circuit) × L(network) × config_rounds_factor
  - R = number of SEQUENTIAL communication rounds ≈ dominated by the
    multiplicative depth of witness extension (Poseidon2 S-box chains) +
    the prover's Fiat–Shamir rounds. **R is currently ESTIMATED (1–3k); the
    site must expose it as an adjustable/uncertain parameter and flag that
    bench v2 will measure it exactly via mpc-net ConnectionStats.**
  - L = one-way latency from the "node distance" slider (loopback 0.05 ms →
    same-DC 0.3 ms → region 5–15 ms → continent 40 ms → planet 100–175 ms).
  - config_rounds_factor: bb/plaindriver = 0 (no comms); REP3 ring = 1×;
    Shamir = higher (degree-reduction round-trips).

The model is deliberately simple and its shape is defensible from first
principles; the site's honesty comes from (a) labeling it a model, (b)
pinning it to measured anchors, (c) letting the reader move R and the
factors themselves.

## 3. Sliders / controls

- **Circuit size** — discrete anchors {poseidon ~small, sha256_compression
  ~medium, recursion_zk ~large/704k rows} + a continuous "gate count"
  slider that interpolates/extrapolates (badged MODELED off-anchor).
- **Machine** — cores per node (log slider 4→192), maps to the measured
  thread-scaling curve.
- **Node distance** — presets (same-machine / same-rack / same-region /
  same-continent / opposite sides of Earth) + custom one-way latency ms.
- **Node count** — 1 (=plaindriver), 3 (REP3 or Shamir t=1), 5 (Shamir
  t=2), n; note 3 is the expected deployment (Mike).
- **Protocol** — REP3 / Shamir (Shamir enables node-count > 3).
- **ZK** — on/off (ZK adds SmallSubgroupIPA/masking cost; anchor the delta).
- **Comms rounds R** — expert slider with the "estimated until bench v2"
  badge, so a skeptic can stress-test the latency sensitivity themselves.

## 4. Views / charts (dataviz skill applies)

1. **Correctness banner** (not a chart): "byte-identical to bb — N circuits,
   both hashers, ZK+non-ZK, bb's own verifier accepts" with the reproduce
   command. The trust anchor, top of page.
2. **Ladder bar chart**: wall time for the 4 configs at the current slider
   state, compute vs comms stacked, so the reader SEES when latency
   dominates (the planet-distance case) vs when compute dominates
   (loopback). This single chart carries the main insight.
3. **Circuit-size sweep** (line/log-log): wall time vs gate count per config;
   measured anchors drawn as distinct marker points ON the modeled lines.
4. **Distance sensitivity** (line): wall time vs one-way latency, one line
   per config — visually separates the compute-bound floor from the
   latency-bound regime; the "where does co-snark stop being interactive?"
   read.
5. **Overhead multiplier** (derived): REP3/Shamir time ÷ bb time, vs circuit
   size — the "what does privacy cost?" number a skeptic asks for.
6. **Assumptions panel**: every constant, its value, and whether it's
   MEASURED (with provenance: PROGRESS §/ch. 14 §/bench CSV) or MODELED.

## 5. Data plumbing

- **Now (model-driven):** seed constants from the measured anchors we have
  — Phase 0 (MPC ≈10× plain bb small circuit, loopback), session-6 A4
  per-phase (witext 0.85 / pk 0.15 / ZK prove 1.74 s, loopback), tonight's
  suite-C driver-side per round (0.51/3.76/3.97/3.84 s), thread-scaling
  curve (ch. 14 §6.3: 16→420, 32→465, 62→530, 93→640, 186→950 ms), WAN
  model (ch. 22 §2). All badged, all cited.
- **After the overnight 0.5 bench:** replace the seeds with the CSV's
  per-phase × circuit × protocol × zk medians; recompute the fitted
  constants; the anchor markers become the bench points. The site is
  authored so this is a data-swap, not a rewrite: constants live in one
  `const ANCHORS = {…}` block at the top of the inline script with
  provenance strings, and a `provenance: "measured|modeled"` flag per
  number that drives the badges.

## 5a. Benchmark dataset (re-usable record) — layout & provenance

Runs live in **`~/bench-0_5-results/<date>/`** (dated, so runs accumulate
and are diffable across time — a re-usable dataset, not a one-off). Each
run directory holds:

| file | what | for |
|---|---|---|
| `manifest.json` | **provenance** — started_utc, host, cpu_cores_total, rayon_threads_per_party, co_snarks commit/branch/worktree, bb oracle path + version pin + provenance, nargo version, circuits/protocols/zk/reps, network, and the CSV schema | makes the run **comparable** to any other; without it a CSV is meaningless |
| `results.csv` | raw: `circuit,protocol,zk,rep,phase,seconds,rc` (one row per timed phase per rep; `rc!=0` = failed cell) | re-analysis, custom aggregation |
| `site-anchors.json` | medians per (circuit,config,phase); `null` where unmeasured; embeds the manifest | baking into the explorer (V7) |
| `RESULTS.md` | human-readable per-circuit tables + the provenance header + REP3÷bb ratio | read first; the legible record |
| `launcher.log` | idle-wait + run progress; `BENCH_DONE` line at the end | ops trail |

**v2 (2026-07-24, Mike's asks):** runs now live **in-repo** at
`bench-results/<date>/` (visible in `git status`, committable with the code
that produced them). New per-run content: `netstats/` (per phase × party
JSONs: sent/recv bytes AND message counts from mpc-net — recv-msgs from the
busiest REP3 neighbour at party 0 is the sequential-rounds proxy **R**, the
WAN-latency multiplier; answers "is R constant across circuits?"),
`features/` (per circuit: `co-noir circuit-info` — trace-block composition,
lookup gates/tables/table rows, witness zero-fraction — plus `bb gates`,
`nargo info`), size sweeps (poseidon 2^11→2^20, sha256 2^15→2^20, ascending
with timeout pruning ≥ 600 s/cell, 2 reps ≥ 2^18), FAIR baselines (bb prove
gets `-k` with VK gen timed separately as `vkgen`; plaindriver prove is
witness-fed via `--witness`, the old solve+prove kept as phase
`solveprove` — v1's plaindriver numbers silently included witness solving,
relevant to ch. 23 §A1), and Shamir cells dropped (v1 proved `split-input`
is REP3-only; v2.1 = REP3-split + `translate-witness`).

### §5b. EVERYTHING the v2 suite measures (audit table, 2026-07-24)

Compiled from `scripts/bench-0_5.sh` + `bench-to-site.py` as they exist in
the tree (each row grep-verifiable), after Mike's "tabulate what you're
measuring, I'm not trusting you." Status: ✅ = implemented + smoke-tested
today; ⏳ = designed, not yet implemented.

**Per timed cell** (cell = circuit × config × zk-mode × rep × phase; CSV row):

| measurement | unit | how | status |
|---|---|---|---|
| **wall-clock (ABSOLUTE seconds)** | s, ms-resolution | monotonic ms clock around the command; the primary column, absolute not relative | ✅ |
| exit code | rc (124 = 10-min timeout) | captured per cell; rc≠0 excluded from medians, never hidden | ✅ |
| peak memory | KB (max RSS) | `/usr/bin/time %M`; MPC cells = max over the 3 parties | ✅ |
| CPU utilisation | % of one core (1600% = 16 cores) | `/usr/bin/time %P` (single-process cells; parallelism-story data) | ✅ |
| **host load at cell start** | 1-min loadavg (HOST-wide, incl. other mainframe tenants) | `/proc/loadavg` stamped per row — the noise context for the absolute seconds | ✅ |

**Phases timed** (each its own cell): bb `vkgen`; bb `prove` (zk + non-zk,
VK pre-supplied via `-k` so prove is pure prove); bb `verify` (zk + non-zk
— verifier-time baseline, added 2026-07-25); plaindriver `prove`
(witness-fed, zk + non-zk<2^18) + `solveprove` (base circuits — quantifies
the witness-solving boundary) + `verify_bb` (bb cross-verifies the
plaindriver zk proof: rc=0 is the verifier-side parity invariant, in-run);
REP3 `split`, `witext` (3 parties parallel), `prove` (zk + non-zk,
3 parties parallel), `verify`. **v2 RAN 2026-07-25** →
`bench-results/2026-07-25/` (65 min, 314 rows, clean; findings in
ch. 24 §3a + PROGRESS session 15).

**Per MPC phase × party** (files, not CSV rows):

| measurement | unit | how | status |
|---|---|---|---|
| bytes sent/received per peer | B | mpc-net counters → `netstats/*.json` | ✅ |
| messages sent/received per peer | count | same | ✅ |
| **R — sequential comms rounds** | count | recv-msgs from ring predecessor (protocol is synchronous → bounds the sequential chain); exact, immune to CPU noise | ✅ |
| per-party wall / peak RSS / CPU% | s / KB / % | `/usr/bin/time` per party → `mem/*.time` (party-skew: how long the fast parties wait) | ✅ |

**Per circuit, once** (`features/` — the composition data for correlating
against proving time):

| measurement | how | status |
|---|---|---|
| finalized rows + dyadic size | `co-noir circuit-info` | ✅ |
| per-trace-block gate composition (arithmetic, delta-range, elliptic, aux/memory, poseidon2 ext/int, lookup, …) | same | ✅ |
| lookup gates, #lookup tables, total table rows | same | ✅ |
| ACIR opcode histogram incl. blackbox calls by name | same | ✅ |
| public-input count | same | ✅ |
| witness length + zero-fraction | same (with `--witness`) | ✅ |
| bb's own acir_opcodes + circuit_size (cross-check) | `bb gates` | ✅ |
| nargo opcode counts (cross-check) | `nargo info --json` | ✅ |
| proof / VK / public-input byte sizes per prover | `stat` before cleanup → `artifact-sizes.json` | ✅ |

**Per run, once** (`manifest.json`): UTC start, host, kernel, CPU model,
core count, thread cap, co-snarks commit/branch/dirty, bb oracle
path+pin+provenance, nargo version, matrix definition, reps, timeout,
fairness notes, CSV schema. Plus `launcher.log`: per-circuit progress
lines with estimates vs actuals, suite ETA. Both ✅.

**Matrix**: {poseidon 2^11, poseidon_2e17…2e20, bb_sha256_compression 2^15,
sha256_2e16…2e20, recursion_zk 2^19.4} × {bb, plaindriver, REP3} ×
{zk, nonzk} × 3 reps (2 for ≥2^18), 16 threads/party, loopback, TCP.

**NOT measured (honest gaps, all planned):** Shamir (⏳ v2.1:
REP3-split + translate-witness); real network latency/distance (⏳ v3:
netem sweeps — currently the explorer MODELS distance from measured R ×
assumed latency); malicious-security variants (out of scope, semi-honest
REP3 per PLAN decision 5); per-cell energy (no RAPL access in sysbox);
bb peak-RSS for the MPC cells' bb-equivalent phases IS captured, but bb's
internal phase split (oink/sumcheck/…) is not — that's ch. 23 Phase A
territory, not the bench's.

**Re-run:** `BENCH_OUT=$ROOT/bench-results/$(date +%F) bash scripts/bench-0_5.sh`
(or `scripts/bench-0_5-launcher.sh` to idle-wait first). **Compare two
runs:** diff their `manifest.json` first (same machine/threads/commit?),
then their `results.csv`/`RESULTS.md`. **Never** compare timings across
runs whose manifests differ on cores, thread cap, or bb/nargo vintage
without saying so. The CSV schema is stable; new phases/configs append
columns-worth of rows, never renumber.

### §5c. External-practice survey (2026-07-25) → measurement/presentation backlog

Agent survey of public SNARK/co-SNARK benchmarking (zkalc, Celer
Pantheon/zk-Harness, zk-Bench eprint 2023/1503, ZKProof benchmarking
proposal, ZPrize, TACEO's posts, Ozdemir–Boneh USENIX'22, zkSaaS,
Scalable-coZK eprint 2024/143 + USENIX'25, MP-SPDZ, Thaler F·B,
ethproofs.org, zkbenchmarks.com, EF zkEVM team; full cited report in
PROGRESS session 15). Ranked backlog for US, deduped against §5b:

1. **WAN prediction model from R + bytes, validated by netem later**
   (zk-Bench's estimator-vs-ground-truth pattern): predict per-phase
   `compute + R×RTT + bytes/bw` NOW, report prediction error when netem
   lands — stronger result than "we measured WAN", nearly free.
2. **Adopt the literature's netem tiers verbatim** (Scalable-coZK:
   Local 10 Gbps/0.1 ms, LAN 1 Gbps/2 ms, WAN third rung) so our
   REP3÷bb ratios are directly comparable to published numbers.
3. **Busy-vs-blocked-on-recv split per party per phase** (critical-path
   decomposition; instrument + validate on loopback while it's cheap).
4. **$-cost/proof** (Σ-party instance-price × wall vs 1×bb host) and
   **energy proxy** (Σ TDP×wall — ethproofs' formula; RAPL unavailable
   in the sysbox). Board-level columns every public dashboard leads with.
5. **Gates/sec throughput normalization** per gate-class (derivable
   today from features × wall — puts both sweeps on one axis).
6. **bb + plaindriver `verify` as timed phases** (only REP3 verify is
   timed today) + a "verifier-side overhead = 0, byte-identical VK/proof"
   line item stated as a measured invariant, not an assumption.
7. **Cost-accounting disclosure** next to every headline number (ZKProof
   proposal): which phases are "in" (witext? split? vkgen?). Audit the
   explorer + RESULTS.md once.
8. **Security-model caveat next to the overhead ratio** (semi-honest
   honest-majority REP3 vs single-prover — Ozdemir–Boneh's honest-vs-
   malicious ~1×/~2× split is the most-cited number in the field; we
   can't replicate it without a malicious mode, so say so).
9. **1–2 application-shaped circuits** alongside the synthetic sweeps
   (EF zkEVM critique of Fibonacci-style benches; Aztec kernel-shaped
   candidate) — v2.2+.
10. **Raw-dataset export** from the explorer (CSV/JSON download — every
    mature effort ships it; we already have the files, link them).
Deprioritised: cross-hardware sweep (zk-Bench found 40–50% tool-dependent
instance effects — matters at production party-placement time, not now);
n>3 parties (different-in-kind axis, zkSaaS/Scalable-coZK territory);
recursion-throughput north-star (post-pipeline-integration).

## 6. Build constraints (Artifacts runtime)

Self-contained single HTML (strict CSP: no external CDN/scripts/fonts):
all CSS/JS inline, charts hand-rolled as inline SVG (no Chart.js from a
CDN). Theme-aware (light/dark). Responsive; wide charts scroll in their own
container. Load the `artifact-design` skill (calibration) and the `dataviz`
skill (color formula, mark specs, log-axis handling) BEFORE writing chart
code. Favicon: a fixed emoji (e.g. 📊). Title stable across redeploys.

**Honesty features (non-negotiable, this is the whole point for the
audience):** MEASURED vs MODELED badges on every number; an assumptions
panel; the reproduce-it command for the correctness claim; R flagged as
estimated; no axis that hides the latency-dominated regime.

## 7. Work items

- [x] V0 — load artifact-design + dataviz skills; lock the palette + layout.
- [x] V1 — `ANCHORS` constant block with provenance strings (from §5 now-set).
- [x] V2 — cost-model functions (§2), unit-checked against the anchors
      (model at an anchor's inputs must reproduce that anchor within a
      stated tolerance, or the badge is a lie).
- [x] V3 — controls (§3) + state wiring.
- [x] V4 — the six views (§4), SVG, theme-aware, dataviz-compliant.
- [x] V5 — honesty layer: badges, assumptions panel, reproduce command.
- [x] V6 — published (private): https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa  (redeploy same file path to keep the URL).
- [x] V8 — **DONE 2026-07-25** v2 bake: family-split sweep, censored ▲ floor, measured-R default 385, RSS tile, verify_bb banner, provenance → 89666ce5 (same URL).
- [x] V9 — **DONE 2026-07-26** v2.1 bake (optimised-tree run): anchors re-baked (~110 values), dated Update-2026-07-26 banner (lever results −20…−30% prove-proper; sha root cause resolved → L0e; R-caveat resolved via per-phase netstats), R default 385→384, dirty-tree provenance → 049d3435 + session-17 levers, assumptions refresh (whole-step ~10.4× / prove-proper ~8.8× at 2^20 zk). 07-25 banner + historical CSV blocks kept verbatim. Same URL; source explorer-v4.html in session-17 scratchpad.
- [x] V7 — **DONE 2026-07-24** (bench ran clean overnight 2026-07-23
      22:11–22:46 UTC): measured medians baked into CIRCUITS (all 3 circuits
      × bb/plaindriver/REP3 × zk/non-zk + REP3 split/witext/verify);
      constant-factor model replaced by log-log interpolation through the
      anchors (model reproduces every anchor exactly — the §7 V2 rule);
      comms adds only above-loopback latency; badges flipped; same URL
      redeployed. Shamir stays modeled (split-input is REP3-only —
      bench v2: REP3-split + translate-witness). Headline finding recorded
      in PROGRESS session 14: REP3÷bb = 6.0×/439.6×/29.8× (poseidon/sha256/
      recursion_zk) — composition-dependent, non-monotonic in gate count.
      NOTE: `bench-to-site.py` split/witext zk="-" lookup bug found+fixed
      during the bake. Original pipeline notes: swap ANCHORS to measured
      medians, flip badges, redeploy same URL. **Pipeline wired (2026-07-23):** the
      launcher runs `scripts/bench-to-site.py results.csv → site-anchors.json`
      (medians of rc==0 rows per circuit/config/phase; loopback only;
      unmeasured cells emitted as `null` so they STAY modeled — never
      fabricated; a CONTENDED-box run is flagged so those numbers are
      badged not-clean). Remaining manual step (one Artifact call): read
      `site-anchors.json` into the explorer's `ANCHOR`/`CIRCUITS` block,
      flip those cells' badge to measured, redeploy the same file path to
      keep the URL. Distance axis + off-anchor gate sizes remain modeled
      by construction (we can't place nodes across the planet; bench v2
      would add netem latency sweeps + mpc-net ConnectionStats to measure
      R and retire the biggest modeled unknown).

## 8. Scope / honesty boundary

This is a decision-support + explanatory tool, NOT a benchmark of record.
It never presents a modeled number as measured. If, once the bench lands,
reality diverges sharply from the model (e.g. R is far from the 1–3k
estimate), the DIVERGENCE is itself a finding to surface, not to smooth
over. The site is only as convincing as it is honest — for this audience
that is literally the design constraint.
