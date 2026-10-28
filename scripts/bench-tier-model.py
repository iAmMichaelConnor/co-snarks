#!/usr/bin/env python3
"""Estimate transfer time from per-peer received-byte histograms.

The local, LAN, and WAN tiers use (10 Gbps, 0.1 ms), (1 Gbps, 2 ms), and
(100 Mbps, 40 ms), respectively. The histogram estimate sums
max(RTT, bytes / bandwidth) across blocking receive groups. A message-count
estimate also reports max(messages * RTT, bytes / bandwidth) and their sum.
These are model scenarios, not measured network times or guaranteed bounds:
queued messages, pipelining, protocol dependencies, and congestion affect them.

The prove snapshot includes proving-key generation. To derive prove_proper,
subtract the matching pkgen histogram prefix; mismatches produce a warning and
skip that peer. Estimates take the maximum across peers and parties, then the
median across repetitions. Files without histograms are skipped.

Usage: bench-tier-model.py <run-dir>
Writes <run-dir>/tiers.csv.
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
    """Maximum per-peer estimates: histogram time, rounds, bytes, messages,
    and the two message-count transfer scenarios described in the module doc.
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
            "recv_bytes_histogram (histogram capture "
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
