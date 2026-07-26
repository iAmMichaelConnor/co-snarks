# Bench v3 — netem latency tiers: predicted vs. measured

**Date:** 2026-07-26 (session 19). **Tree:** `c5204a03` (post session-18
commit-split: L8 + L0e U1–U3 + L2-1a + all prior committed levers).
**Oracle:** source-built bb v5.0.1 (`versions.env`). **Threads:**
`RAYON_NUM_THREADS = nproc*8/30` (~80% split across 3 parties). Host is a shared
sysbox mainframe — `host_load1m` stamped per row; read absolute numbers with
that context, lean on ratios within a tier.

## Why this run

Every prior benchmark (v1, v2, v2.1, v2.2) was **loopback** — sub-millisecond
RTT, effectively infinite bandwidth. That hides the entire cost structure of a
real deployment, where the three MPC parties sit on different machines. The
lever work (L1, L2b/c, L0c/d, L8, L0e, L2-1a) was steered by loopback wall time,
which is **compute-bound**; several levers (L8, L0c, L2-1a) were explicitly
"WAN-structural" — they collapse *communication rounds* whose cost is ~zero at
loopback but dominant under latency. Bench v3 shapes the loopback interface with
`tc netem` to emulate the tier model's three network tiers and measures what
those levers — and the remaining bottlenecks — actually cost under latency.

This is the zk-Bench "estimator vs. ground-truth" pattern: `bench-tier-model.py`
**predicts** per-phase cost from the loopback round/byte histograms; this run
**measures** it under emulated latency. Agreement validates the model (and lets
us keep predicting WAN cost from cheap loopback runs); disagreement localizes
where the model is wrong.

## Method

netem shapes `lo`. A loopback round-trip crosses `lo` once per direction, so
RTT ≈ 2×`delay`; we set `delay = RTT/2` and `rate` = the tier bandwidth, matching
`scripts/bench-tier-model.py`'s `TIERS` exactly:

| tier | bandwidth | RTT | `tc qdisc ... dev lo root netem` |
|------|-----------|-----|--------------------------------|
| loopback (control) | ~unshaped | ~0.05 ms | *(no qdisc)* |
| lan  | 1 Gbps   | 2 ms  | `delay 1ms rate 1000mbit` |
| wan  | 100 Mbps | 40 ms | `delay 20ms rate 100mbit` |

Each tier: shape → verify (`tc qdisc show` + `ping -c4 127.0.0.1` recorded in
each tier's `NETEM-PROVENANCE.txt`) → run the bench matrix → unshape → verify
unshaped. A cleanup trap removed the qdisc on any exit (the interface was
confirmed `noqueue` at completion). Cells: `poseidon_2e17`, `poseidon_2e20`,
`bb_sha256_compression`, REP3 (netem is irrelevant to the single-party bb /
plaindriver baselines, which are present but not analyzed here). Per-cell
timeout 600 s (the harness default); timed-out cells are **censored** (`≥600 s`),
not failures.

## Headline: the tier model brackets the truth — and it exposed the real
## bottleneck the loopback benches hid

**witness-extension (`witext`) is the dominant cost under latency, by a wide
margin, and it was completely invisible at loopback.** `witext` is
round-catastrophic — poseidon_2e17's witext runs **11,276 logical rounds**
(33,399 messages/party); poseidon_2e20's runs **92,224 rounds**. At loopback
those pipeline down to ~1.7 s / ~12 s and nobody noticed. Under latency they
explode. This is the single most valuable thing this run surfaced, and it is a
**new** optimization target: all the committed levers touched pk-gen and
prove-proper, because those are what loopback wall time showed.

## Predicted vs. measured (REP3, median of reps; seconds)

"Predicted (LAN)" = the loopback tier-model estimate for the LAN tier as
`pipelined … dep_hi` (optimistic pipelined floor → pessimistic no-overlap
ceiling; true cost expected between). Measured is this run's wall time at that
tier.

| circuit / phase | loopback | LAN measured | LAN predicted [pipe…dep_hi] | WAN measured | WAN predicted [pipe…dep_hi] |
|---|---|---|---|---|---|
| **poseidon_2e17 witext** | 1.69 | **35.9** | 22.6 … 66.8 ✓ inside | **≥600** (timeout) | 451 … 1336 ✓ (censored, consistent) |
| poseidon_2e17 prove (nonzk) | 9.33 | 16.8 | +net 3.4 … 3.6 ✗ under (see bw caveat) | — (not reached) | — |
| **poseidon_2e20 witext** | 11.95 | **289.5** | 184 … 539 ✓ inside | *skipped (family timeout)* | 3689 … 10788 (correctly pruned) |
| poseidon_2e20 prove (nonzk) | 66.3 | 132.5 | +net 25.6 … 25.9 ✗ under (bw caveat) | — | — |
| **sha256_compression pk-gen** | 8.1 | ~54 (of 57.7 prove) | 28.5 … 70.5 ✓ inside | **≥600** (timeout) | 546 … 1370 ✓ (censored, consistent) |
| sha256_compression prove (nonzk) | 12.1 | 57.7 | — | ≥600 | — |

**Reading it:** for the **latency-bound** phases (witext, sha pk-gen — the
round-heavy ones) the measured LAN cost lands **inside** the model's
`[pipelined, dep_hi]` bracket every time, and the WAN cells hit the 600 s
timeout exactly where the model predicted pipelined values of 451–3689 s. The
model's bracket is validated as a predictor: `pipelined` is an optimistic floor,
`dep_hi` a pessimistic ceiling, truth in between. We can keep predicting WAN
cost from cheap loopback histograms.

## Findings

1. **witext is the #1 bottleneck under any real network.** Round count scales
   ~linearly with circuit size (11k @ 2^17 → 92k @ 2^20). LAN penalty ≈ 21×
   (2^17) / 24× (2^20); WAN blows past 600 s (predicted 451 s / 3689 s
   pipelined). This phase — MPC witness extension / input resharing — was never
   a lever target because loopback made it look free. **It should be the next
   optimization: collapse its per-element round-trips (the same round-batching
   pattern L8/L2-1a applied to pk-gen).**

2. **L8's pk-gen round collapse is validated under latency.** poseidon pk-gen is
   now **2–3 rounds** (was 11,127 pre-L8): predicted WAN network cost ~0.34 s,
   i.e. latency-immune. That is exactly what L8 was for, now confirmed against
   real 40 ms RTT — not just the loopback msg-count fence.

3. **sha pk-gen is the one pk-gen still round-bound — L2-1a helped but did not
   finish the job.** 13,135 rounds → 8 s loopback → ~54 s LAN → ≥600 s WAN.
   This directly motivates the queued next sha lever (collapse the
   construct-lookup-read-counts / remaining big-quad rounds the way L8 collapsed
   the poseidon ones). The "~5,800 rounds" figure in the L2-1a notes counted one
   sub-term; the full pk-gen round depth here is ~13k.

4. **poseidon prove-proper is bandwidth-bound, and the model under-predicts it
   ~2–2.6× — an honest single-`lo` artifact.** prove-proper moves a lot of data
   (398 MB @ 2^17, 3.2 GB @ 2^20 per the histograms). netem on one `lo` rate-
   limits **aggregate** loopback throughput — all three parties' six directional
   flows share the single 1 Gbps/100 Mbps pipe — whereas the tier model assumes
   a per-link budget. So bandwidth-bound phases run ~2× the per-peer prediction
   here. A real 3-machine testbed with independent NICs would separate this out;
   until then, treat the model's bandwidth arm as a *lower* bound and its latency
   arm (validated in finding-set above) as trustworthy.

5. **WAN penalty summary (measured):** sha whole-prove 12 s → ≥600 s (≥50×);
   poseidon_2e17 witext 1.7 s → ≥600 s (≥350×). LAN: sha prove 4.8×, poseidon
   witext 21–24×, poseidon prove ~2×.

## Caveats (honest limits)

- **Loopback netem is an idealized symmetric link**: no TCP slow-start /
  congestion / reordering modeled, and (finding 4) the single-`lo` rate cap is
  shared across all parties, so the **bandwidth** arm is pessimistic vs. a real
  per-machine LAN/WAN. The **latency** arm (round count × RTT) is faithful and
  is what the bracket validation rests on.
- **Censored cells**: poseidon_2e17/sha WAN and poseidon_2e20 WAN hit the 600 s
  timeout (or were family-pruned after their sibling did). They are consistent
  with the model's predictions but are lower bounds, not point measurements. A
  follow-up with a raised timeout (or the witext lever landed) would de-censor
  them.
- **Shared-host load** varied 15–60 during the run (stamped per row); the sha zk
  `prove_proper` tier-model row was skipped for one peer (pkgen histogram not a
  prefix of prove's — a benign aggregation guard, noted in the launcher log).
- Reps: 3 for 2^17 / sha, 2 for 2^20.

## Artifacts

Per tier (`loopback/`, `lan/`, `wan/`): `results.csv` (per-cell wall/rss/cpu/
load), `phase-split.csv` (pk-gen vs prove-proper), `netstats/` (per-phase
round/byte histograms), `tiers.csv` (the model's per-tier predictions — the
loopback one is the predictor used above), `phase-timings/`, `NETEM-PROVENANCE.txt`
(exact `tc`/`ping` outputs + verified RTT), `launcher.log`. Runner script:
session-19 scratchpad `run-bench-v3.sh`.
