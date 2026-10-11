#!/usr/bin/env python3
"""Distance-tier transfer-time model (ch. 24 §3a measurement backlog item).

Takes the per-round received-byte histogram the CO_NOIR_NET_STATS_JSON /
CO_NOIR_NET_STATS_JSON_PKGEN files started carrying alongside `rounds` and
`blocked_recv_ms` (2026-07-26 bench-granularity extension: see
mpc_net::RoundCounters's doc for exactly what a "round" is and why
`len(recv_bytes_histogram)` can be >= `rounds`) and estimates, PER PHASE,
how long the observed communication would take under three synchronous
network tiers:

    Local : 10 Gbps,  0.1 ms RTT   (same machine / same rack)
    LAN   : 1 Gbps,   2 ms RTT     (same datacentre)
    WAN   : 100 Mbps, 40 ms RTT    (cross-region)

Model (as specified, ch. 24 §3a): for each tier, estimated_seconds =
Σ_rounds max(RTT, bytes_r / bandwidth) -- every round pays at least one
RTT (the synchronisation cost), or the serialization/transfer time if that
dominates (a big round on a slow/high-bandwidth link). This is a coarse,
first-cut estimate: real networks pipeline sends ahead of blocking waits,
TCP slow-start/congestion control isn't modelled, and the three tiers here
are a simplified cut of ch. 24 §3a's fuller same-rack/same-DC/
same-continent/cross-continent taxonomy -- a future extension, not
implemented here. VALIDATE against real netem runs before treating these
numbers as more than an order-of-magnitude guide (ch. 24 §3a's own caveat).

Phases modelled directly from the netstats files: witext, pkgen, prove
(REP3/SHAMIR's `prove` snapshot is CUMULATIVE pk-gen+prove -- see
bench-results/README.md), translate (Shamir's translate-witness step).
PLUS a synthetic `prove_proper` phase, computed here (not by the CLI):
subtract the pkgen snapshot's per-peer histogram from the matching prove
snapshot's histogram. This subtraction is exact, not an approximation --
the pkgen snapshot is taken from the SAME live counters that keep
accumulating into the final snapshot, so pkgen's histogram is guaranteed
to be a PREFIX of prove's histogram (verified: `finalize()` only ever
appends, a snapshot never truncates or resets what's already there); the
tail after that prefix is exactly prove-proper's own rounds. A prefix
mismatch (would indicate a broken pairing, e.g. mismatched reps) is
detected and that peer's prove_proper is skipped with a warning rather
than silently producing a wrong number.

Combining rule (documented, not obvious from the spec alone): a netstats
JSON can report more than one peer per party (e.g. REP3's two ring
neighbours don't produce interleaved round sequences we can merge
precisely) -- we take the MAX across peers within a party (the party is
gated by whichever connection is slower) and then the MAX across the three
parties in a rep (wall-clock phase time is gated by the slowest party,
matching how bench-0_5.sh times MPC cells). Across reps: MEDIAN, matching
the "medians across reps" rule in bench-results/README.md.

Usage: bench-tier-model.py <run-dir>   # e.g. bench-results/2026-07-26
Writes <run-dir>/tiers.csv. Silently skips any netstats file that lacks
`recv_bytes_histogram` (i.e. was captured before this extension landed) --
old run dirs are safe to point this at, they just produce no rows.
"""

import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

NETSTATS_NAME = re.compile(
    r"^(?P<circuit>.+)_(?P<protocol>REP3|SHAMIR)_"
    r"(?P<phase>witext|prove|pkgen|translate)"
    r"(?:_(?P<zk>nonzk|zk))?_r(?P<rep>\d+)_p(?P<party>\d+)\.json$"
)

TIERS = {
    # name: (bandwidth_bytes_per_sec, rtt_seconds)
    "local": (10e9 / 8, 0.0001),
    "lan": (1e9 / 8, 0.002),
    "wan": (100e6 / 8, 0.040),
}


def tier_seconds(histogram: list, bandwidth_bps: float, rtt_s: float) -> float:
    return sum(max(rtt_s, nbytes / bandwidth_bps) for nbytes in histogram)


def party_estimate(peers: dict, tier_name: str) -> tuple:
    """Element-wise worst over this party's peer connections:
    (pipelined_seconds, rounds, recv_bytes, recv_msgs, dep_lo, dep_hi).

    Two different round notions feed two different estimates (both kept —
    they bracket reality):
    - `rounds` (blocking-boundary count) feeds `pipelined_seconds`
      (Σ_r max(RTT, bytes_r/bw) over the histogram). At loopback,
      independent messages pipeline, so this UNDERCOUNTS dependency depth
      (measured: poseidon_2e17 prove has 204 recv_msgs but only ~74
      blocking rounds) — treat it as the OPTIMISTIC/pipelined estimate.
    - `recv_msgs` is the true per-peer dependency-round proxy for the
      CURRENT serial protocol (validated in bench-results/README.md v2.1:
      prove-proper recv_msgs matches the in-process fence pins exactly,
      and pk-gen is one blocking mul_many round per big-quad constraint —
      ch. 24 §4 L8). It feeds the conservative bracket:
        dep_lo = max(msgs·RTT, bytes/bw)   (latency- or bandwidth-bound)
        dep_hi = msgs·RTT + bytes/bw       (no overlap at all)
      True WAN cost for today's code lies in [dep_lo, dep_hi]; the
      pipelined estimate is a lower anchor that assumes loopback-grade
      overlap survives the added latency (it mostly won't).
    """
    bandwidth_bps, rtt_s = TIERS[tier_name]
    best = (0.0, 0, 0, 0, 0.0, 0.0)
    for peer in peers.values():
        hist = peer.get("recv_bytes_histogram")
        if not hist:
            continue
        seconds = tier_seconds(hist, bandwidth_bps, rtt_s)
        nbytes = sum(hist)
        msgs = peer.get("recv_msgs", 0)
        dep_lo = max(msgs * rtt_s, nbytes / bandwidth_bps)
        dep_hi = msgs * rtt_s + nbytes / bandwidth_bps
        cand = (seconds, peer.get("rounds", 0), nbytes, msgs, dep_lo, dep_hi)
        best = tuple(max(a, b) for a, b in zip(best, cand))
    return best


def subtract_prefix(prove_peers: dict, pkgen_peers: dict, cell_desc: str) -> dict:
    """Per-peer histogram tail (prove minus the pkgen prefix); see module doc."""
    out = {}
    for peer_id, prove_peer in prove_peers.items():
        prove_hist = prove_peer.get("recv_bytes_histogram") or []
        pkgen_hist = (pkgen_peers.get(peer_id) or {}).get("recv_bytes_histogram") or []
        if prove_hist[: len(pkgen_hist)] != pkgen_hist:
            print(
                f"warning: {cell_desc} peer {peer_id}: pkgen histogram is not a "
                "prefix of prove's -- skipping prove_proper for this peer "
                "(mismatched pairing?)",
                file=sys.stderr,
            )
            continue
        tail = prove_hist[len(pkgen_hist):]
        pkgen_peer = pkgen_peers.get(peer_id) or {}
        out[peer_id] = {
            "recv_bytes_histogram": tail,
            "rounds": max(prove_peer.get("rounds", 0) - pkgen_peer.get("rounds", 0), 0),
            "recv_msgs": max(prove_peer.get("recv_msgs", 0) - pkgen_peer.get("recv_msgs", 0), 0),
        }
    return out


def main(run_dir: Path) -> None:
    netstats_dir = run_dir / "netstats"
    if not netstats_dir.is_dir():
        print(f"no netstats/ dir in {run_dir} -- nothing to model", file=sys.stderr)
        return

    # raw[(circuit, protocol, phase, zk, rep, party)] = peers dict (from the JSON)
    raw: dict = {}
    n_seen = 0
    n_with_histogram = 0
    for f in sorted(netstats_dir.glob("*.json")):
        m = NETSTATS_NAME.match(f.name)
        if not m:
            continue
        n_seen += 1
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        peers = data.get("peers", {})
        if not any(p.get("recv_bytes_histogram") for p in peers.values()):
            continue  # pre-extension netstats file: no histogram to model
        n_with_histogram += 1
        key = (m["circuit"], m["protocol"], m["phase"], m["zk"] or "-", int(m["rep"]), int(m["party"]))
        raw[key] = peers

    if n_seen == 0:
        print(f"no netstats files matched the expected naming in {netstats_dir}", file=sys.stderr)
    elif n_with_histogram == 0:
        print(
            f"{n_seen} netstats files found in {netstats_dir}, none carry "
            "recv_bytes_histogram (captured before the ch. 24 §3a extension "
            "landed) -- tiers.csv will be empty",
            file=sys.stderr,
        )

    # Synthesize prove_proper = prove minus the pkgen prefix, per (circuit,
    # protocol, zk, rep, party) that has both a prove and a pkgen snapshot.
    synthetic: dict = {}
    for (circuit, protocol, phase, zk, rep, party), peers in raw.items():
        if phase != "prove":
            continue
        pkgen_key = (circuit, protocol, "pkgen", zk, rep, party)
        if pkgen_key not in raw:
            continue
        cell_desc = f"{circuit}/{protocol}/{zk}/rep{rep}/party{party}"
        synthetic[(circuit, protocol, "prove_proper", zk, rep, party)] = subtract_prefix(
            peers, raw[pkgen_key], cell_desc
        )
    raw.update(synthetic)

    # Reduce: for each (circuit, protocol, phase, zk, rep), max over parties;
    # then median over reps. cells[(...)][party] = peers dict.
    cells: dict = defaultdict(dict)
    for (circuit, protocol, phase, zk, rep, party), peers in raw.items():
        cells[(circuit, protocol, phase, zk, rep)][party] = peers

    # reduced[(circuit, protocol, phase, zk)][tier] = list of per-rep (seconds, rounds, bytes)
    reduced: dict = defaultdict(lambda: defaultdict(list))
    for (circuit, protocol, phase, zk, _rep), by_party in cells.items():
        for tier_name in TIERS:
            party_estimates = {p: party_estimate(peers, tier_name) for p, peers in by_party.items()}
            if not party_estimates:
                continue
            worst = max(party_estimates.values(), key=lambda v: v[0])
            reduced[(circuit, protocol, phase, zk)][tier_name].append(worst)

    rows = []
    for (circuit, protocol, phase, zk), by_tier in sorted(reduced.items()):
        for tier_name in TIERS:
            vals = by_tier.get(tier_name)
            if not vals:
                continue
            seconds_med = statistics.median(v[0] for v in vals)
            rounds_med = statistics.median(v[1] for v in vals)
            bytes_med = statistics.median(v[2] for v in vals)
            msgs_med = statistics.median(v[3] for v in vals)
            dep_lo_med = statistics.median(v[4] for v in vals)
            dep_hi_med = statistics.median(v[5] for v in vals)
            bandwidth_bps, rtt_s = TIERS[tier_name]
            rows.append(
                {
                    "circuit": circuit,
                    "protocol": protocol,
                    "phase": phase,
                    "zk": zk,
                    "tier": tier_name,
                    "bandwidth_mbps": round(bandwidth_bps * 8 / 1e6, 3),
                    "rtt_ms": round(rtt_s * 1000, 3),
                    "rounds": round(rounds_med),
                    "recv_msgs": round(msgs_med),
                    "recv_bytes": round(bytes_med),
                    "n_reps": len(vals),
                    "est_pipelined_seconds": round(seconds_med, 6),
                    "est_dependency_lo_seconds": round(dep_lo_med, 6),
                    "est_dependency_hi_seconds": round(dep_hi_med, 6),
                }
            )

    out = run_dir / "tiers.csv"
    fields = [
        "circuit", "protocol", "phase", "zk", "tier", "bandwidth_mbps",
        "rtt_ms", "rounds", "recv_msgs", "recv_bytes", "n_reps",
        "est_pipelined_seconds", "est_dependency_lo_seconds",
        "est_dependency_hi_seconds",
    ]
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out} ({len(rows)} rows from {n_with_histogram}/{n_seen} netstats files with histograms, "
          f"incl. {len(synthetic)} synthesized prove_proper party-cells)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <run-dir>", file=sys.stderr)
        sys.exit(2)
    main(Path(sys.argv[1]))
