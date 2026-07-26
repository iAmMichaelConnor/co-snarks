# bench-results/ — the co-SNARK benchmark dataset

Every benchmark run of this repo lands here as one dated directory, plus a
single SQLite database (`bench.sqlite`) aggregating all runs for querying
and visualisation. This README is the pick-up-here doc for humans and
future Claude sessions. The suite itself: `scripts/bench-0_5.sh` (matrix),
`scripts/bench-0_5-launcher.sh` (detached/overnight wrapper),
`scripts/bench-to-site.py` (per-run aggregation), `scripts/bench-ingest.py`
(all-runs → SQLite). Design + full measurement audit table:
`project-docs/22-cosnark-explorer-viz-plan.md` §5a/§5b. Optimisation plans
consuming this data: ch. 23 (single-prover), ch. 24 (MPC path).

## Quick start

```bash
# run the full matrix (~2.5–3.5 h; absolute seconds are load-stamped per row)
BENCH_OUT=bench-results/$(date +%F) bash scripts/bench-0_5.sh

# smoke-test the pipeline on one circuit (~30 s)
BENCH_OUT=/tmp/smoke BENCH_CIRCUITS=poseidon bash scripts/bench-0_5.sh

# aggregate one run for the explorer + humans (also run automatically by the launcher)
python3 scripts/bench-to-site.py bench-results/<date>/results.csv bench-results/<date>/site-anchors.json

# rebuild the database from ALL runs
python3 scripts/bench-ingest.py            # writes bench-results/bench.sqlite
```

⚠ Shared-mainframe rule: this box's load average and fork counters are
HOST-wide (other tenants included). Never gate a run on "quiet load" — run
when convenient; every CSV row records `host_load1m` so each absolute
number carries its own noise context. Use medians across reps; prefer
same-window ratios for fine comparisons. Leave ~20% of cores free
(RAYON_NUM_THREADS=16/party is the measured optimum anyway).

## Per-run directory layout

| path | what |
|---|---|
| `manifest.json` | provenance: UTC start, host, kernel, CPU model, cores, thread cap, co-snarks commit/branch/dirty, bb oracle pin+provenance, nargo version, matrix, reps, timeout, CSV schema. A run without a manifest is not comparable to anything. |
| `results.csv` | one row per timed cell: `circuit,protocol,zk,rep,phase,seconds,rc,max_rss_kb,cpu_pct,host_load1m`. `rc!=0` = failed (124 = 10-min timeout); failed cells are kept, never hidden, excluded from medians. |
| `netstats/*.json` | per MPC phase × party: bytes AND message counts per peer. `recv_msgs` from the ring predecessor ≈ **R**, the sequential round count (exact, CPU-noise-immune) — but only an UPPER BOUND at scale (see the v2.2 `rounds` field below, added 2026-07-26). |
| `mem/*.time` | per MPC phase × party: wall / peak-RSS / CPU% (`%e %M %P`) — party-skew data. |
| `features/*.circuit-info.json` | per circuit: trace-block gate composition, lookup gates / tables / table rows, ACIR opcode histogram, public inputs, witness zero-fraction, dyadic size. |
| `features/*.bbgates.json`, `*.nargo-info.json` | independent cross-checks of size/opcode counts. |
| `features/*.artifact-sizes.json` | proof / VK / public-input byte sizes per prover. |
| `phase-timings/*.json` | added 2026-07-26 (v2.2). Per REP3/SHAMIR prove cell: every co-ultrahonk `[phase-timing]` line (oink/sumcheck/pcs sub-phases, `CO_NOIR_PHASE_TIMINGS=1`) captured from the cell's combined 3-party log into structured `{phase, seconds}` entries — NOT attributed to a single party (coarse; ~3 entries per phase name is expected). |
| `tiers.csv` | added 2026-07-26 (v2.2), written by `scripts/bench-tier-model.py`. Per circuit×protocol×phase×zk×tier (Local 10 Gbps/0.1 ms, LAN 1 Gbps/2 ms, WAN 100 Mbps/40 ms): a MODELED transfer-time estimate (`Σ_rounds max(RTT, bytes_r/bandwidth)`) from the per-round byte histogram, plus a synthesized `prove_proper` phase (prove minus the pkgen prefix). This is a model, not a real-network measurement — see the netem v3 follow-up in ch. 24 §3a. |
| `RESULTS.md` | human-readable per-circuit tables (read this first). |
| `site-anchors.json` | machine shape the explorer bakes in (nulls = unmeasured, never fabricated). |
| `launcher.log` | progress lines with per-circuit estimate-vs-actual and suite ETA. |

Standalone captures (no timing run needed) live in dated dirs too, e.g.
`circuit-features-2026-07-24/` — features for all 12 matrix circuits,
captured independently of any bench run.

## The database (`bench.sqlite`)

Rebuilt idempotently by `scripts/bench-ingest.py` from all run dirs (plus
the legacy pre-repo run at `~/bench-0_5-results/2026-07-23`). Tables:

- `runs(run_id, dir, started_utc, host, cpu_model, cores, threads_per_party, commit, bb_pin, nargo, …)` — one row per run, from the manifest.
- `cells(run_id, circuit, protocol, zk, rep, phase, seconds, rc, max_rss_kb, cpu_pct, host_load1m)` — every timed cell, including failures.
- `netstats(run_id, circuit, protocol, phase, zk, rep, party, peer, sent_bytes, recv_bytes, sent_msgs, recv_msgs)`.
- `features(run_id, circuit, dyadic_size, finalized_rows, block_arithmetic, block_delta_range, block_lookup, block_elliptic, block_aux, block_poseidon2_external, block_poseidon2_internal, lookup_gates, num_lookup_tables, total_table_rows, public_inputs, witness_len, witness_zero_fraction, acir_opcodes)`.
- `artifact_sizes(run_id, circuit, artifact, bytes)`.

Convenience views: `medians` (per run/circuit/config/zk/phase median of
successful reps) and `overhead` (REP3÷bb prove ratio per circuit, joined
with features — the composition-vs-cost analysis in one query).

Example (the headline question):

```sql
SELECT circuit, lookup_gates, total_table_rows, rep3_over_bb
FROM overhead WHERE zk='zk' ORDER BY lookup_gates;
```

## Rules (why this dataset stays trustworthy)

1. **Absolute seconds are the primary data** — with their per-row load
   stamps. Ratios are the noise-robust derived layer, not a replacement.
2. Nothing is fabricated: failed/timeout cells stay in the CSV with their
   rc; unmeasured cells are null everywhere downstream.
3. Compare runs only after diffing manifests (machine, threads, versions,
   commit). The ingest DB makes cross-run queries easy — comparability
   stays the analyst's responsibility.
4. Timing-affecting changes to the suite bump the manifest `benchmark`
   name (currently "… v2"); pure capture additions don't.

## Current state / history

- **v1 run 2026-07-23** (legacy location `~/bench-0_5-results/2026-07-23`,
  ingested into the DB): 3 circuits, wall-clock only. Headline: REP3÷bb =
  6.0× (poseidon) / 439.6× (sha256) / 29.8× (recursion_zk) — MPC cost
  tracks gate composition, not size.
- **circuit-features-2026-07-24/**: features for all 12 matrix circuits.
  Explains the headline: sha256 is ~70% lookup gates + 33,944 table rows;
  poseidon is pure arithmetic; the sha 2e16→2e20 sweep scales lookup gates
  17× at constant table rows — a natural experiment for the cost model.
- **v2 full run 2026-07-25** (`2026-07-25/`, commit 89666ce5, clean tree,
  post-optimisation C1–C3+L1, host load ~15–25 throughout, 65 min): all
  12 circuits, 314 rows; only failures = expected 600 s timeout pruning
  (sha256_2e16 REP3 prove → family pruned ≥2e17). Headlines: REP3÷bb
  (zk) = 3.1× poseidon 2^11 → plateaus ~13× across the poseidon sweep;
  bb_sha256_compression 473× (140.5 s); sha256_2e16 >1,140× (timeout).
  **Lookup GATES, not table rows, drive MPC cost** (same dyadic 2^16,
  same 12 tables/33,944 rows, 15× lookup gates → >4.3× REP3 prove).
  verify_bb rc=0 on all 12 (verifier-side parity is now a measured
  invariant). L1's −8 rounds confirmed exactly (poseidon prove R
  319→311 nonzk, 393→385 zk). REP3 prove CPU ~260%/1600% (vs bb
  ~1450%) — the MPC path is serial/comms-bound locally, ch. 24 L4.
- **⚠ R-column caveat (learned from this run):** `recv_msgs` from the
  ring predecessor equals sequential rounds only for SMALL circuits
  (poseidon 2^11 matches the relation×round theory exactly). At scale,
  message counts grow ~linearly with data volume (application-level
  batching splits work into many frames per logical round; mpc-net does
  NOT chunk sends — verified): poseidon prove "R" ≈ 11.3k (2e17) →
  90k (2e20) at a suspiciously constant ~37 KB/msg. Treat large-circuit
  msg counts as an UPPER bound on round depth; a logical-round counter
  is the ch. 24 backlog fix. Genuinely round-deep by contrast: poseidon
  witext (sequential hash chain — 39 B/msg, 270k real dependency rounds
  at 2e20; a WAN latency killer that no bandwidth fixes).
- **v2.1 full run 2026-07-26** (`2026-07-26/`, commit 049d3435 + the
  session-17 UNCOMMITTED optimisation tree — manifest records the dirty
  worktree; levers in tree: L2b, L2c, L1-followup, L0c, L0d,
  perm-lagrange rayon; L0a/L0b implemented-then-reverted, ch. 24 §4.
  Host load1m 45.8 at launch decaying to ~13–30 during the run — read
  absolutes with the per-row load stamps; 60 min, rc=0, 314 rows, only
  failures = the designed sha timeout pruning; verify_bb 12/12 rc=0).
  Suite additions this run (capture-only): native `phase-split.csv`
  (launcher post-step) and per-phase netstats — `netstats/*_pkgen_*`
  is a mid-run snapshot after pk-gen (CO_NOIR_NET_STATS_JSON_PKGEN);
  subtract from `*_prove_*` totals for true prove-proper comms.
  Headlines vs v2 (phase-split medians):
  - **REP3 prove-proper −20…−30% across every measured size**:
    poseidon 2^17 10.6→7.7 s (nonzk), 2^20 zk 90.2→66.2 s,
    recursion_zk zk 85.2→67.1 s. REP3÷bb (zk, 2^20) ~11.4×→**8.8×**;
    REP3÷plaindriver (zk, 2^20) ~4.7×→3.9×. The cumulative
    L2b+L2c+L1f+L0d effect, now measured on the full matrix.
  - **sha pk-gen unchanged** (136.7→136.2 s, −0.4%) — as predicted
    post-L0a/b-refutation: the per-call Yao tax is garbling COMPUTE,
    not per-call setup or RTTs (at loopback). ch. 24 L0e is the
    remaining sha lever.
  - **v2's R-column caveat RESOLVED by the phase split**: the
    size-linear frame growth belonged to PK-GEN (tiny ~253 B frames:
    89.9k at poseidon 2^20 zk, 11.1k at 2^17); PROVE-PROPER recv_msgs
    is a true round-depth proxy after all — a few hundred,
    ~10·log n + const (204 at 2^17 nonzk — byte-for-byte equal to the
    in-process T2 fence pin incl. L0d's +6; 336 at 2^20 zk;
    recursion_zk 627). v2's "constant ~37 KB/msg" was the bimodal
    average of pk-gen's tiny frames and prove's ~2 MB frames. WAN
    implication: prove-proper is latency-bound by only ~300–600
    rounds; pk-gen/witext carry the frame-count problem.
  - The in-process-vs-TCP frame-count anomaly (floor-table
    known_anomalies) is hereby LOCALIZED to pk-gen (in-process pkgen
    = 116 msgs at any poseidon size vs 11k–90k over TCP). Root cause
    still open — now a much smaller haystack.
- **Bench-granularity extension, 2026-07-26 (v2.2, ch. 24 §3a + PROGRESS
  session-17 close-out queue item 8; uncommitted at time of writing).**
  Mike's directive: keep extending what the suite measures. New capture,
  purely additive to existing readers (see the layout table above for the
  new artifacts):
  - **Logical-round counter + per-round byte histogram** in mpc-net
    (`mpc_net::RoundCounters`, wired through the blocking TCP/TLS and
    in-process `local` backends — the two paths this repo actually uses).
    A round boundary = a `recv` that found nothing queued and had to
    actually wait for the peer (peeked via a non-blocking `try_recv`
    before the real receive — observation-only, never adds/merges/
    resizes/reorders a frame). `CO_NOIR_NET_STATS_JSON` now carries, per
    peer, `rounds`, `blocked_recv_ms` (cumulative wall time blocked — the
    busy-vs-blocked split, item 3 of the same ask), and
    `recv_bytes_histogram` (bytes received per round). **Validated**: the
    T2-proper comms fences (exact msg/byte pins) stayed BYTE-IDENTICAL
    with this instrumentation in the tree (`fast-check --mpc` PASS,
    14/14) — confirms the round counter adds no protocol traffic. Cross-
    checked against the existing message-count metric on a live 3-party
    poseidon prove (isolated ports, not the fixed bench-script ports):
    prove-proper (final snapshot minus the pk-gen snapshot) recv_msgs =
    204 at BOTH 2^11 and 2^17, exactly matching the in-process T2 fence
    pin and the prior v2.1 finding that message count is size-flat for
    poseidon's prove-proper phase. The NEW round-depth number is
    genuinely finer: 121 rounds at 2^11 vs 74 at 2^17 — LOWER at the
    bigger size, not higher, the opposite of a naive "more log n, more
    rounds" guess. Read honestly: this says the local compute between
    synchronisation points grows with n (more field ops per round to
    produce the next batch), giving the peer's frames more time to
    arrive before this party asks for them — i.e. `rounds` measures
    actual stalling, which shrinks at loopback as compute-per-round
    grows, not a purely protocol-structural constant like message count.
    Only 2 sizes measured; the 2^18–2^20 continuation is queued (see
    "remains" below), and this loopback behaviour may not hold under
    real WAN latency where the network, not local compute, gates the
    round.
  - **Distance-tier transfer-time model**: `scripts/bench-tier-model.py`
    (wired into `bench-0_5-launcher.sh`) turns the per-round histogram
    into a Local(10 Gbps/0.1 ms) / LAN(1 Gbps/2 ms) / WAN(100 Mbps/40 ms)
    estimate per phase (`Σ_rounds max(RTT, bytes_r/bandwidth)`), written
    to `tiers.csv`, plus a synthesized `prove_proper` phase (pkgen is
    provably a byte-identical PREFIX of prove's histogram — the
    subtraction is exact, not approximate; verified on the smoke data).
    This is a MODEL: no real network was touched. Validate against netem
    before treating it as more than an order-of-magnitude guide (still
    queued, ch. 24 §3a "v3").
  - **Busy-vs-blocked wait split**: `blocked_recv_ms` per peer (summed to
    `total_blocked_recv_ms` per phase) in the same JSON — the same
    instrumentation as the round counter (both come from timing the
    same `try_recv`-detected wait), so no extra cost to add.
  - **Shamir cells, poseidon family**: `bench-0_5.sh` now runs a SHAMIR
    prove cell per poseidon size/zk-mode via REP3-split + translate-
    witness (reusing that rep's REP3 witext output), closing one piece
    of the v2.1 deferral (other families still deferred). **Smoke-tested
    only** (translate-witness + SHAMIR build-and-generate-proof + verify
    on the base `poseidon` circuit, isolated ports): all 3 parties
    rc=0, verify rc=0, and the SHAMIR proof came back **byte-identical
    to the plain-driver KAT** — the real protocol ran. No full Shamir
    sweep was launched.
  - **Per-cell sub-phase timers**: REP3/SHAMIR prove cells now run with
    `CO_NOIR_PHASE_TIMINGS=1`; the existing oink/sumcheck/pcs
    `[phase-timing]` stderr lines are captured per cell into
    `phase-timings/*.json` instead of living only in the `.log` files.
  - **Remains** (not done this pass): the round-counter size sweep
    beyond 2^11/2^17; wiring `tiers.csv`/`phase-timings/` into
    `bench-ingest.py`/`bench.sqlite` and the explorer; a real netem v3
    run to validate the tier model; widening the Shamir cells beyond
    the poseidon family; per-peer (rather than per-connection) sent-side
    byte histograms (this pass only tracks bytes RECEIVED per round).
