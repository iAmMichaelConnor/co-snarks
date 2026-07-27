# Bench v3.1 — netem latency tiers: measuring the U2 + L2-1b WAN wins

**Date:** 2026-07-27 (session 20 follow-up). **Tree:** `ae9f2ff2` (`witext U2 —
REP3 per-level `mul_many` batching`, on top of L2-1b sha pk-gen batching + witext
U1). **Oracle:** n/a for this run — no bb/plaindriver baselines (see Scope).
**Threads:** `RAYON_NUM_THREADS = nproc*8/30` = 51/party on this 192-core box
(3×51 = 153, ~20% cores free). Shared sysbox mainframe — `host_load1m` stamped
per CSV row; it drifted 14–79 during the run (indep8 loopback ran at load ~79).
Read absolute numbers with that context; lean on ratios and on the head-to-head
against v3.

## Why this run

Bench v3 (`2026-07-26-v3-netem`) shaped loopback with `tc netem` into three
network tiers and found the thing every loopback bench had hidden: **witness
extension (`witext`) is the dominant cost under latency**, because it was
round-catastrophic (poseidon_2e17 = 11,276 logical rounds; sha pk-gen still
round-bound at ~13k). v3 could only *predict* what fixing that would buy,
because the fixes had not landed. Since v3, two levers landed:

- **witext U2** (`ae9f2ff2`): REP3 per-level `mul_many` batching — collapses
  the per-element multiplication round-trips in witext into one batched
  `mul_many` per DAG level (the same round-batching pattern L8/L2-1a applied to
  pk-gen, now applied to witext).
- **L2-1b** (`6941f132`): `ohv_many` + OR-tree read tags in
  `construct_lookup_read_counts` — collapses the sha pk-gen rounds L2-1a did not
  finish.

v3.1 **measures** those two wins with real netem numbers, head-to-head against
v3's censored/predicted cells.

## Method (identical netem model to v3)

netem shapes `lo`; a loopback round-trip crosses `lo` once per direction, so
`RTT ≈ 2×delay`. Tiers match `scripts/bench-tier-model.py`'s `TIERS` exactly:

| tier | bandwidth | RTT | `tc qdisc … dev lo root netem` | verified ping RTT |
|------|-----------|-----|--------------------------------|-------------------|
| loopback (control) | ~unshaped | ~0.05 ms | *(no qdisc)* | 0.049 ms |
| lan  | 1 Gbps   | 2 ms  | `delay 1ms rate 1000mbit` | 2.048 ms |
| wan  | 100 Mbps | 40 ms | `delay 20ms rate 100mbit` | 40.068 ms |

Per tier: shape → **verify** (`tc qdisc show` + `ping -c4 127.0.0.1`, recorded in
each tier's `NETEM-PROVENANCE.txt`) → run → unshape → **verify** `noqueue`. A
bulletproof `trap … EXIT INT TERM` unshaped `lo` and killed strays on any exit;
`lo` was confirmed `noqueue` between every tier and at completion. Per-cell
timeout 600 s (`rc=124` = **censored**, not failed). Private config dir, ports
18000–18002, run on **copies** of the test vectors (committed vectors untouched).

**Scope (focused on the levers, not a full matrix):** REP3, **nonzk**, only the
lever phases — `witext` and `prove` (with the pk-gen snapshot so
`bench-retro-phase-split.py` splits pk-gen vs prove-proper). No bb / plaindriver
/ zk / Shamir / verify baselines (netem-irrelevant; dropping them is what made a
full 3-tier WAN sweep tractable). Circuits: `poseidon_2e17` and `poseidon_2e20`
(the U2 headline), `bb_sha256_compression` (L2-1b sha pk-gen), and
`poseidon_indep8` (8 independent poseidon hashes — the U2 batch-collapse demo).
Reps: 3 (2 for 2^20). Driver: scratchpad `run-bench-v3.1.sh`.

## Headline 1 — witext U2: the WAN cell v3 could only predict is now measured

poseidon_2e17 witext at WAN went from **≥600 s (v3 timeout, censored)** to a real
**363.5 s** — below even v3's *optimistic* pipelined prediction of 451 s.

| circuit / phase | tier | **v3.1 measured (U2)** | v3 (pre-U2) | rounds v3.1 / v3 | msgs v3.1 / v3 |
|---|---|---|---|---|---|
| **poseidon_2e17 witext** | loopback | 1.66 | 1.69 | 8,079 / 11,276 | 17,943 / 33,399 |
| | LAN | **20.2** | 35.9 | " | " |
| | WAN | **363.5** | **≥600 (timeout)** | " | " |
| **poseidon_2e20 witext** | loopback | 13.35 | 11.95 | 62,896 / 92,224 | 144,888 / — |
| | LAN | **162.8** | 289.5 | " | " |
| | WAN | **≥600 (timeout)** | *skipped* | " | " |

**Reading it.** U2 cuts witext logical rounds ~1.4× and received-messages ~1.9×,
and — visible in the LAN column — it also *improves pipelining*: v3's LAN 2e17
witext (35.9 s) sat at the model's no-overlap `dep_hi` ceiling; v3.1's 20.2 s
sits near the pipelined *floor* (model pipelined 16.2 s from this run's
histogram, bracket `[16.2, 35.9]`). So the win is bigger than the raw round
ratio: batching same-level muls lets the remaining rounds overlap. At WAN the
measured 363.5 s vs the model's pipelined 323 s (8,079 × 40 ms) is a 1.12×
overlap gap — the model's latency arm is validated again.

poseidon_2e20 witext still exceeds the 600 s cap at WAN (LAN 162.8 s × ~18×
RTT-scaling ≈ 2,900 s; model pipelined 2,516 s) — U2 nearly halved it (v3 LAN
289.5 → 162.8) but 2^20 needs the byte/round count brought down further before it
fits a WAN budget. Censored, consistent with the model.

## Headline 2 — poseidon_indep8: the K× independent-hash witext collapse

8 *independent* poseidon hashes. Before U2, each hash drove its own per-level mul
round-trips serially; U2 batches all 8 hashes' same-level muls into one
`mul_many` per level, so witext cost becomes ~the depth of **one** batched
schedule instead of 8 stacked ones. Measured before/after (pre-U2 = tree
`d687252a`, rebuilt and run under the identical netem harness):

| tier | **pre-U2 witext** | **post-U2 witext** | speedup |
|------|-------------------|--------------------|---------|
| loopback | 0.15 s | 0.17 s | ~1× (no latency to hide) |
| LAN  | 3.13 s | **0.29 s** | **~11×** |
| WAN  | 58.79 s | **4.27 s** | **~14×** |

Rounds **985 → 128** (7.7×); received-messages **2,907 → 198** (14.7×). The WAN
speedup tracks the message collapse. This is the clean demonstration of U2's
mechanism: **witext round-cost of K independent hashes is now ~flat in K**, not
K×. (At loopback there is no latency for the collapsed rounds to hide, so the two
are within noise — exactly the round-collapse signature: neutral at loopback, big
under latency.)

## Headline 3 — L2-1b: sha pk-gen, from round-bound timeout to bandwidth-bound

sha256_compression pk-gen at WAN went from **≥600 s (v3 timeout, censored)** to
**~175 s** — and the *character* of the cost changed. L2-1b collapsed pk-gen
logical rounds **~13,000 → 1,290**; what's left is not latency but the 502 MB
pk-gen transfer.

| phase | tier | **v3.1 measured** | v3 (pre-L2-1b) |
|---|---|---|---|
| **sha pk-gen** | loopback | 10.8 | 8.1 |
| | LAN | **21.2** | ~54 |
| | WAN | **175.4** | **≥600 (timeout)** |
| sha prove-proper | loopback / LAN / WAN | 3.44 / 6.97 / 48.5 | — |
| sha prove (pk-gen+proper) | loopback / LAN / WAN | 14.8 / 28.6 / 224.4 | 12.1 / 57.7 / ≥600 |

**Reading it.** LAN pk-gen 54 → 21.2 s (2.5×); WAN de-censored to 175 s. But the
model (from the new 1,290-round histogram) predicts WAN pk-gen `[pipelined 70 s …
dep_hi 123 s]`, and measured 175 s sits *above* `dep_hi`. That is the expected
single-`lo` bandwidth artifact (v3 finding-4): 502 MB over the shared 100 Mbps
pipe (all parties' flows share one `lo` rate cap) is ~pessimistic vs a per-link
budget. The signal for the next sha lever: **L2-1b finished the round job — sha
pk-gen is now bandwidth-bound, so the next win is bytes, not rounds.** (loopback
pk-gen 8.1 → 10.8 s is a small compute cost of the batching with no latency to
repay it, within this run's load noise — loopback ran at host_load ~35.)

## Full measured table (REP3, nonzk, median of reps; seconds)

| circuit | phase | loopback | LAN | WAN |
|---|---|---|---|---|
| poseidon_2e17 | witext | 1.66 | 20.2 | 363.5 |
| | pk-gen | 0.28 | 0.33 | 1.04 |
| | prove-proper | 8.20 | 15.55 | 109.8 |
| poseidon_2e20 | witext | 13.35 | 162.8 | ≥600 (censored) |
| | pk-gen | 3.16 | 3.25 | — |
| | prove-proper | 60.75 | 125.3 | — |
| bb_sha256_compression | witext | 0.22 | 0.15 | 0.66 |
| | pk-gen | 10.8 | 21.2 | 175.4 |
| | prove-proper | 3.44 | 6.97 | 48.5 |
| poseidon_indep8 | witext | 0.17 | 0.29 | 4.27 |
| | pk-gen | 0.04 | 0.04 | 0.19 |
| | prove-proper | 1.34 | 2.24 | 15.8 |

(pk-gen / prove-proper from `phase-split.csv`, the per-party log markers;
witext / prove-total wall from `results.csv`. poseidon pk-gen stays 2–3 rounds
and ~latency-immune — L8, re-confirmed.)

## Findings

1. **U2 de-censors witext at WAN and improves LAN pipelining.** 2e17 witext WAN
   ≥600 s → 363.5 s (measured, below v3's 451 s pipelined prediction); LAN
   35.9 → 20.2 s. Rounds ×1.4 / msgs ×1.9 down, plus better overlap.
2. **The independent-hash collapse is real and ~14× at WAN** (indep8 58.8 → 4.3 s;
   rounds 985 → 128). Witext round-cost of K independent hashes is now ~flat in K.
3. **L2-1b converted sha pk-gen from round-bound to bandwidth-bound.** WAN
   ≥600 s → 175 s; rounds ~13k → 1,290. The residual is the 502 MB transfer, so
   the next sha lever should target bytes.
4. **2^20 witext still overflows a WAN budget** (≥600 s; ~half of v3 at LAN).
   Needs further round/byte reduction before it fits 40 ms RTT.
5. **prove-proper is unchanged by these levers, as designed** (2e17 WAN 109.8 s,
   2e20 LAN 125.3 s ≈ v3's 132.5 s) — U2/L2-1b touch witext and pk-gen only.

## Head-to-head summary (WAN, before → after)

| metric | v3 (before) | v3.1 (after) |
|---|---|---|
| poseidon_2e17 witext WAN | ≥600 s (timeout) | **363.5 s** |
| poseidon_2e20 witext LAN | 289.5 s | **162.8 s** |
| poseidon_indep8 witext WAN | 58.8 s (pre-U2) | **4.27 s** (~14×) |
| sha pk-gen WAN | ≥600 s (timeout) | **175.4 s** |
| sha whole-prove WAN | ≥600 s (timeout) | **224.4 s** |

## Caveats (same honest limits as v3)

- **Single-`lo` bandwidth is shared** across all parties' directional flows, so
  the *bandwidth* arm is pessimistic vs a real per-NIC LAN/WAN (finding 3 / sha
  pk-gen 175 vs model 123). The *latency* arm (rounds × RTT) is faithful and is
  what the witext validation rests on. A real 3-machine testbed would separate
  these.
- **Censored cells** (poseidon_2e20 witext WAN) are lower bounds consistent with
  the model, not point measurements. A raised timeout or the next round/byte
  lever would de-censor them.
- **Shared-host load** varied 14–79 (stamped per row). Reps: 3 (2 for 2^20).

## Artifacts

Per tier (`loopback/`, `lan/`, `wan/`): `results.csv`, `phase-split.csv`,
`tiers.csv` (model predictions from this run's histograms), `netstats/`,
`mem/`, `phase-timings/`, `NETEM-PROVENANCE.txt`, `launcher.log`. Pre-U2 indep8
before/after: `preU2-indep8/`. Driver + pre-U2 driver + this analysis are copied
to the session scratchpad `rebench-v3.1/`.
