#!/usr/bin/env python3
"""Build the co-SNARK explorer's full embedded dataset (site-data.json).

Unlike bench-to-site.py (which emitted only loopback medians for the model
anchors), this ingests EVERYTHING the revised explorer tabulates:

  * per-circuit features (gate-block composition, lookups, opcode histogram,
    witness sparsity, dyadic size) — from features/*.circuit-info.json
  * per (circuit,protocol,zk,phase) loopback median wall-seconds — results.csv
  * pk-gen vs prove-proper split — phase-split.csv
  * peak memory (MB) per config — results.csv max_rss_kb
  * comms STRUCTURE per phase (sequential rounds + total bytes, busiest peer)
    — netstats/*.json (network-independent: same rounds/bytes at any latency),
    with the pk-gen snapshot subtracted so prove-proper comms is isolated
  * proof / VK / public-input byte sizes — features/*.artifact-sizes.json
  * MEASURED distance-tier wall-seconds from one or more netem runs, recorded
    as (rtt_ms, bw_mbps, seconds, censored) points so several runs coexist on
    the distance chart.

It never invents numbers: a missing/all-failed cell is emitted as null so the
site keeps MODELLING it (badged modeled). The distance MODEL itself is computed
client-side from the measured rounds+bytes+loopback-compute; this file just
supplies the measured inputs and the measured anchors.

Usage:
  bench-explorer-data.py --full <full_run_dir> [--netem v31=<dir>] [--netem v32=<dir>] [-o site-data.json]
"""
import argparse, csv, json, os, re, statistics
from collections import defaultdict

# ---- distance-tier definitions (RTT ms, bandwidth Mbps) per known netem run.
# netem shapes `lo`; a loopback RTT crosses it twice, so RTT = 2*delay.
NETEM_TIERMAPS = {
    # v3.1 (2026-07-27): the original 3 tiers.
    "v31": {
        "loopback": {"rtt_ms": 0.05, "bw_mbps": None},
        "lan":      {"rtt_ms": 2.0,  "bw_mbps": 1000},
        "wan":      {"rtt_ms": 40.0, "bw_mbps": 100},
    },
    # v3.2 (2026-07-27): Mike's four deployment scenarios (headline tiers).
    "v32": {
        "same-machine":   {"rtt_ms": 0.05,  "bw_mbps": None},
        "same-rack":      {"rtt_ms": 0.2,   "bw_mbps": 10000},
        "same-continent": {"rtt_ms": 60.0,  "bw_mbps": 1000},
        "antipodal":      {"rtt_ms": 250.0, "bw_mbps": 100},
    },
}

FAMILY = lambda c: ("poseidon" if c.startswith("poseidon")
                    else "sha256" if "sha256" in c
                    else "recursion" if "recursion" in c else c)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_results(run_dir):
    """(circuit,proto,zk,phase) -> {'secs':[...], 'rss_kb':[...]} for rc==0."""
    buckets = defaultdict(lambda: {"secs": [], "rss_kb": []})
    path = os.path.join(run_dir, "results.csv")
    if not os.path.exists(path):
        return buckets
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if (row.get("rc") or "").strip() != "0":
                continue
            try:
                secs = float(row["seconds"])
            except (ValueError, KeyError, TypeError):
                continue
            k = (row["circuit"], row["protocol"], row["zk"], row["phase"])
            buckets[k]["secs"].append(secs)
            try:
                rss = int(row.get("max_rss_kb") or 0)
                if rss:
                    buckets[k]["rss_kb"].append(rss)
            except (ValueError, TypeError):
                pass
    return buckets


def read_phase_split(run_dir):
    """(circuit,proto,zk) -> (median pkgen_s, median proveproper_s)."""
    path = os.path.join(run_dir, "phase-split.csv")
    pk = defaultdict(list); pp = defaultdict(list)
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            k = (row["circuit"], row["protocol"], row["zk"])
            try:
                pk[k].append(float(row["pkgen_seconds"]))
                pp[k].append(float(row["prove_seconds"]))
            except (ValueError, KeyError, TypeError):
                pass
    out = {}
    for k in pk:
        out[k] = (round(statistics.median(pk[k]), 4) if pk[k] else None,
                  round(statistics.median(pp[k]), 4) if pp[k] else None)
    return out


def busiest_peer(ns):
    """Return the peer dict with the most recv_msgs (the sequential-round
    bottleneck), or None."""
    peers = (ns or {}).get("peers", {})
    best = None
    for v in peers.values():
        if best is None or v.get("recv_msgs", 0) > best.get("recv_msgs", 0):
            best = v
    return best


def comms_for(run_dir, circuit, proto, phase_glob, zk=None):
    """Median comms structure across reps/parties for a phase, from netstats.
    phase_glob picks the filename middle: 'witext', 'prove_nonzk', 'pkgen_nonzk'.
    Returns {rounds_msgs, rounds_logical, recv_bytes, sent_bytes_total} or None.
    rounds/bytes are network-independent, so loopback netstats give the truth."""
    ns_dir = os.path.join(run_dir, "netstats")
    if not os.path.isdir(ns_dir):
        return None
    pat = re.compile(rf"^{re.escape(circuit)}_{proto}_{phase_glob}_r\d+_p(\d)\.json$")
    per_rep_p0 = []          # busiest-peer recv_msgs/rounds/recv_bytes at party 0
    sent_totals = []         # sum of sent_bytes over peers at party 0
    for fn in sorted(os.listdir(ns_dir)):
        m = pat.match(fn)
        if not m or m.group(1) != "0":
            continue
        ns = load_json(os.path.join(ns_dir, fn))
        bp = busiest_peer(ns)
        if not bp:
            continue
        per_rep_p0.append((bp.get("recv_msgs", 0), bp.get("rounds", 0), bp.get("recv_bytes", 0)))
        peers = ns.get("peers", {})
        sent_totals.append(sum(int(p.get("sent_bytes", 0)) for p in peers.values()))
    if not per_rep_p0:
        return None
    med = lambda i: int(statistics.median([x[i] for x in per_rep_p0]))
    return {
        "rounds_msgs": med(0),
        "rounds_logical": med(1),
        "recv_bytes": med(2),
        "sent_bytes_total": int(statistics.median(sent_totals)) if sent_totals else None,
    }


def sub_comms(total, pk):
    """prove-proper comms = prove_total - pkgen snapshot (element-wise, floored)."""
    if not total:
        return None
    if not pk:
        return total
    return {k: max(0, (total.get(k) or 0) - (pk.get(k) or 0)) for k in total}


def med_or_none(vals):
    return round(statistics.median(vals), 4) if vals else None


def build_circuit(c, full_dir, results, psplit):
    ci = load_json(os.path.join(full_dir, "features", f"{c}.circuit-info.json")) or {}
    bg = load_json(os.path.join(full_dir, "features", f"{c}.bbgates.json")) or {}
    art = load_json(os.path.join(full_dir, "features", f"{c}.artifact-sizes.json"))

    def m(proto, zk, phase):
        return med_or_none(results.get((c, proto, zk, phase), {}).get("secs", []))

    def rss_mb(proto, zk, phase):
        v = results.get((c, proto, zk, phase), {}).get("rss_kb", [])
        return round(statistics.median(v) / 1024, 1) if v else None

    bb_gate_fns = (bg.get("functions") or [{}])
    bb0 = bb_gate_fns[0] if bb_gate_fns else {}

    timings = {
        "bb": {"vkgen": m("bb", "-", "vkgen"),
               "prove_nonzk": m("bb", "nonzk", "prove"), "prove_zk": m("bb", "zk", "prove"),
               "verify_nonzk": m("bb", "nonzk", "verify"), "verify_zk": m("bb", "zk", "verify")},
        "plaindriver": {"prove_nonzk": m("plaindriver", "nonzk", "prove"),
                        "prove_zk": m("plaindriver", "zk", "prove"),
                        "solveprove_zk": m("plaindriver", "zk", "solveprove"),
                        "verify_bb_zk": m("plaindriver", "zk", "verify_bb")},
        "REP3": {"split": m("REP3", "-", "split"), "witext": m("REP3", "-", "witext"),
                 "prove_nonzk": m("REP3", "nonzk", "prove"), "prove_zk": m("REP3", "zk", "prove"),
                 "verify_nonzk": m("REP3", "nonzk", "verify"), "verify_zk": m("REP3", "zk", "verify")},
        "SHAMIR": {"translate": m("SHAMIR", "-", "translate"),
                   "prove_nonzk": m("SHAMIR", "nonzk", "prove"), "prove_zk": m("SHAMIR", "zk", "prove"),
                   "verify_nonzk": m("SHAMIR", "nonzk", "verify"), "verify_zk": m("SHAMIR", "zk", "verify")},
    }
    for proto in ("REP3", "SHAMIR"):
        for zk in ("nonzk", "zk"):
            sp = psplit.get((c, proto, zk))
            timings[proto][f"pkgen_{zk}"] = sp[0] if sp else None
            timings[proto][f"proveproper_{zk}"] = sp[1] if sp else None

    memory = {"bb_prove_zk": rss_mb("bb", "zk", "prove"),
              "plaindriver_prove_zk": rss_mb("plaindriver", "zk", "prove"),
              "REP3_witext": rss_mb("REP3", "-", "witext"),
              "REP3_prove_zk": rss_mb("REP3", "zk", "prove"),
              "SHAMIR_prove_zk": rss_mb("SHAMIR", "zk", "prove")}

    # comms structure (network-independent) from the loopback full run
    witext = comms_for(full_dir, c, "REP3", "witext")
    prove_tot = comms_for(full_dir, c, "REP3", "prove_nonzk")
    pkgen = comms_for(full_dir, c, "REP3", "pkgen_nonzk")
    comms = {"witext": witext, "prove_total": prove_tot,
             "pkgen": pkgen, "proveproper": sub_comms(prove_tot, pkgen)}

    return {
        "family": FAMILY(c),
        "features": {
            "finalized_rows": ci.get("finalized_rows"),
            "dyadic_size": ci.get("dyadic_size"),
            "public_inputs": ci.get("public_inputs"),
            "witness_len": ci.get("witness_len"),
            "witness_zero_fraction": ci.get("witness_zero_fraction"),
            "acir_opcodes": ci.get("acir_opcodes"),
            "lookup_gates": ci.get("lookup_gates"),
            "num_lookup_tables": ci.get("num_lookup_tables"),
            "total_table_rows": ci.get("total_table_rows"),
            "blocks": ci.get("blocks") or {},
            "opcode_histogram": ci.get("opcode_histogram") or {},
            "bb_circuit_size": bb0.get("circuit_size"),
            "bb_acir_opcodes": bb0.get("acir_opcodes"),
        },
        "artifact_sizes": art,
        "timings_loopback": timings,
        "memory_mb": memory,
        "comms": comms,
        "netem": {},   # filled by ingest_netem
    }


def ingest_netem(data, label, run_dir):
    tmap = NETEM_TIERMAPS.get(label)
    if not tmap:
        return
    run_meta = {"label": label, "dir": run_dir, "tiers": []}
    # per tier: read results.csv (witext, prove) + phase-split (pkgen/proveproper)
    for tier, spec in tmap.items():
        tdir = os.path.join(run_dir, tier)
        res = read_results(tdir)
        psp = read_phase_split(tdir)
        # censored (rc=124) detection: scan raw csv for 124 rows per circuit/phase
        censored = defaultdict(bool)
        rpath = os.path.join(tdir, "results.csv")
        if os.path.exists(rpath):
            with open(rpath, newline="") as f:
                for row in csv.DictReader(f):
                    if (row.get("rc") or "").strip() == "124":
                        censored[(row["circuit"], row["phase"])] = True
        prov = None
        pf = os.path.join(tdir, "NETEM-PROVENANCE.txt")
        if os.path.exists(pf):
            try:
                with open(pf) as f:
                    txt = f.read()
                mm = re.search(r"rtt [^\n]*?=\s*([\d.]+)/([\d.]+)/", txt) or \
                     re.search(r"min/avg/max[^\n]*=\s*([\d.]+)/([\d.]+)/", txt)
                if mm:
                    prov = float(mm.group(2))
            except OSError:
                pass
        run_meta["tiers"].append({"name": tier, "rtt_ms": spec["rtt_ms"],
                                  "bw_mbps": spec["bw_mbps"], "measured_ping_rtt_ms": prov})
        for c in data["circuits"]:
            def pt(phase, secs, cens):
                data["circuits"][c]["netem"].setdefault(phase, []).append(
                    {"run": label, "tier": tier, "rtt_ms": spec["rtt_ms"],
                     "bw_mbps": spec["bw_mbps"], "seconds": secs, "censored": cens})
            w = med_or_none(res.get((c, "REP3", "-", "witext"), {}).get("secs", []))
            pr = med_or_none(res.get((c, "REP3", "nonzk", "prove"), {}).get("secs", []))
            sp = psp.get((c, "REP3", "nonzk"))
            if w is not None or censored.get((c, "witext")):
                pt("witext", w, censored.get((c, "witext"), False))
            if pr is not None or censored.get((c, "prove")):
                pt("prove_total", pr, censored.get((c, "prove"), False))
            if sp:
                pt("pkgen", sp[0], False)
                pt("proveproper", sp[1], False)
    data["meta"].setdefault("netem_runs", []).append(run_meta)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", required=True, help="loopback full-matrix run dir")
    ap.add_argument("--netem", action="append", default=[],
                    help="label=dir  (label in {v31,v32})", metavar="L=DIR")
    ap.add_argument("--ksweep", default=None,
                    help="k-sweep.csv (batch size K vs wall/rounds/bytes/RSS)")
    ap.add_argument("-o", "--out", default="site-data.json")
    args = ap.parse_args()

    full = args.full
    results = read_results(full)
    psplit = read_phase_split(full)
    manifest = load_json(os.path.join(full, "manifest.json")) or {}
    circuits = sorted({k[0] for k in results if k[0] != "SKIPPED"} |
                      {fn[:-len(".circuit-info.json")]
                       for fn in os.listdir(os.path.join(full, "features"))
                       if fn.endswith(".circuit-info.json")})

    data = {
        "meta": {
            "full_run_dir": full,
            "full_manifest": manifest,
            "tier_model": NETEM_TIERMAPS["v32"],
            "note": "loopback medians of rc==0 rows; comms rounds/bytes are "
                    "network-independent; distance tiers modelled client-side "
                    "from these + measured netem anchors.",
        },
        "circuits": {},
    }
    for c in circuits:
        data["circuits"][c] = build_circuit(c, full, results, psplit)

    for spec in args.netem:
        if "=" not in spec:
            continue
        label, d = spec.split("=", 1)
        if os.path.isdir(d):
            ingest_netem(data, label, d)

    # ---- k-sweep: batch size K vs wall / pk-gen rounds / bytes / peak RSS ----
    if args.ksweep and os.path.exists(args.ksweep):
        pts, circ = [], None
        with open(args.ksweep, newline="") as f:
            for row in csv.DictReader(f):
                if (row.get("rc") or "0").strip() not in ("0", ""):
                    continue  # skip failed/censored K points
                circ = row.get("circuit") or circ
                try:
                    pts.append({
                        "K": int(row["K"]),  # 0 = unbounded (all gates one batch)
                        "seconds": float(row["seconds"]),
                        "pkgen_rounds": int(row.get("pkgen_rounds") or 0),
                        "pkgen_bytes": int(row.get("pkgen_recv_bytes") or 0),
                        "peak_rss_kb": int(row.get("peak_rss_kb_party") or 0),
                    })
                except (ValueError, KeyError):
                    continue
        if pts:
            data["meta"]["k_sweep"] = {"circuit": circ, "points": pts}

    with open(args.out, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    print(f"wrote {args.out}: {len(circuits)} circuits, "
          f"{len(data['meta'].get('netem_runs', []))} netem run(s)")


if __name__ == "__main__":
    main()
