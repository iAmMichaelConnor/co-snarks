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
- [ ] V7 — after the 0.5 bench: swap ANCHORS to measured medians, flip
      badges, redeploy same URL.

## 8. Scope / honesty boundary

This is a decision-support + explanatory tool, NOT a benchmark of record.
It never presents a modeled number as measured. If, once the bench lands,
reality diverges sharply from the model (e.g. R is far from the 1–3k
estimate), the DIVERGENCE is itself a finding to surface, not to smooth
over. The site is only as convincing as it is honest — for this audience
that is literally the design constraint.
