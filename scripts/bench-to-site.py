#!/usr/bin/env python3
"""Aggregate a bench-0_5 results.csv into the explorer's data block.

Reads results.csv (columns: circuit,protocol,zk,rep,phase,seconds,rc),
takes the MEDIAN across reps of the successful (rc==0) rows per
(circuit, protocol, zk, phase), and writes site-anchors.json — the shape
the co-SNARK explorer uses for its measured anchors.

It never invents numbers: a (circuit,config) cell absent or all-failed in
the CSV is emitted as null, so the site keeps MODELING that point (badged
modeled) rather than showing a fabricated measurement. Distances other
than loopback and off-anchor gate sizes are NOT measured here and stay
modeled in the site by construction.

Usage: bench-to-site.py <results.csv> [out.json]
"""
import csv, json, sys, statistics
from collections import defaultdict

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: bench-to-site.py <results.csv> [out.json]")
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "site-anchors.json"

    # (circuit, protocol, zk, phase) -> [seconds...] for rc==0 rows only
    buckets = defaultdict(list)
    rss = defaultdict(list)   # same key -> [max_rss_kb...] (optional column)
    contended = "CONTENDED" in src  # launcher renames the CSV if the box was busy
    with open(src, newline="") as f:
        for row in csv.DictReader(f):
            if row["rc"].strip() != "0":
                continue
            try:
                secs = float(row["seconds"])
            except ValueError:
                continue
            key = (row["circuit"], row["protocol"], row["zk"], row["phase"])
            buckets[key].append(secs)
            try:
                rss[key].append(int(row.get("max_rss_kb") or 0) or None)
            except (ValueError, TypeError):
                pass

    def med(circuit, proto, zk, phase):
        v = buckets.get((circuit, proto, zk, phase))
        return round(statistics.median(v), 4) if v else None

    def med_rss_mb(circuit, proto, zk, phase):
        v = [x for x in rss.get((circuit, proto, zk, phase), []) if x]
        return round(statistics.median(v) / 1024, 1) if v else None

    # Fold in the run manifest (provenance) if present beside the CSV — this
    # is what makes a run comparable to another; a dataset without it is a
    # one-off.
    import os
    manifest = {}
    mpath = os.path.join(os.path.dirname(src) or ".", "manifest.json")
    if os.path.exists(mpath):
        try:
            with open(mpath) as mf:
                manifest = json.load(mf)
        except (ValueError, OSError):
            manifest = {}

    # ---- comms stats (netstats/<circuit>_REP3_<phase>_r<rep>_p<party>.json)
    # R proxy = recv_msgs from the busiest single peer at party 0 (the REP3
    # protocol is synchronous; the per-peer recv chain bounds the sequential
    # round count that WAN latency multiplies). Bytes = party 0 total sent.
    run_dir = os.path.dirname(src) or "."
    net = defaultdict(lambda: defaultdict(list))  # (circuit, phase) -> {"R":[], "sent_bytes":[]}
    ns_dir = os.path.join(run_dir, "netstats")
    if os.path.isdir(ns_dir):
        import re
        pat = re.compile(r"^(?P<c>.+)_REP3_(?P<ph>witext|prove_zk|prove_nonzk)_r\d+_p(?P<p>\d)\.json$")
        for fn in sorted(os.listdir(ns_dir)):
            m = pat.match(fn)
            if not m or m.group("p") != "0":
                continue
            try:
                with open(os.path.join(ns_dir, fn)) as nf:
                    peers = json.load(nf).get("peers", {})
                recvs = [int(v.get("recv_msgs", 0)) for v in peers.values()]
                sents = [int(v.get("sent_bytes", 0)) for v in peers.values()]
            except (ValueError, OSError, TypeError):
                continue
            if recvs:
                key = (m.group("c"), m.group("ph"))
                net[key]["R"].append(max(recvs))
                net[key]["sent_bytes"].append(sum(sents))
    def net_med(circuit, phase, field):
        v = net.get((circuit, phase), {}).get(field)
        return int(statistics.median(v)) if v else None

    def load_json_or_none(path):
        if not os.path.exists(path):
            return None
        try:
            with open(path) as jf:
                return json.load(jf)
        except (ValueError, OSError):
            return None

    # ---- circuit features (features/<circuit>.circuit-info.json etc.)
    def load_features(circuit):
        out = {}
        p = os.path.join(run_dir, "features", f"{circuit}.circuit-info.json")
        if os.path.exists(p):
            try:
                with open(p) as ff:
                    out["circuit_info"] = json.load(ff)
            except (ValueError, OSError):
                pass
        p = os.path.join(run_dir, "features", f"{circuit}.bbgates.json")
        if os.path.exists(p):
            try:
                with open(p) as ff:
                    fns = json.load(ff).get("functions", [])
                if fns:
                    out["bb_gates"] = {"acir_opcodes": fns[0].get("acir_opcodes"),
                                       "circuit_size": fns[0].get("circuit_size")}
            except (ValueError, OSError):
                pass
        return out or None

    circuits = sorted({k[0] for k in buckets})
    data = {
        "provenance": "measured",
        "contended": contended,   # site must badge these NOT-clean if true
        "source": src,
        "manifest": manifest,     # machine / versions / commit / thread cap
        "note": "medians across reps of rc==0 rows; loopback only; "
                "null => keep modeling that cell",
        "circuits": {},
    }
    for c in circuits:
        data["circuits"][c] = {
            "bb":          {"prove_nonzk": med(c, "bb", "nonzk", "prove"),
                            "prove_zk":    med(c, "bb", "zk", "prove"),
                            "vkgen":       med(c, "bb", "-", "vkgen"),
                            "prove_zk_rss_mb": med_rss_mb(c, "bb", "zk", "prove")},
            "plaindriver": {"prove_zk":    med(c, "plaindriver", "zk", "prove"),
                            "prove_nonzk": med(c, "plaindriver", "nonzk", "prove"),
                            "solveprove_zk": med(c, "plaindriver", "zk", "solveprove"),
                            "prove_zk_rss_mb": med_rss_mb(c, "plaindriver", "zk", "prove")},
            "rep3_rss_mb": {"witext": med_rss_mb(c, "REP3", "-", "witext"),
                            "prove_zk": med_rss_mb(c, "REP3", "zk", "prove")},
            "artifact_sizes": load_json_or_none(
                os.path.join(run_dir, "features", f"{c}.artifact-sizes.json")),
            "net": {ph: {"R": net_med(c, ph, "R"),
                         "sent_bytes_party0": net_med(c, ph, "sent_bytes")}
                    for ph in ("witext", "prove_zk", "prove_nonzk")},
            "features": load_features(c),
            # split/witext happen once per protocol, before proving — the CSV
            # stamps them zk="-", not per ZK mode.
            "rep3": {z: {ph: med(c, "REP3", "-" if ph in ("split", "witext") else z, ph)
                         for ph in ("split", "witext", "prove", "verify")}
                     for z in ("nonzk", "zk")},
            "shamir": {z: {ph: med(c, "SHAMIR", "-" if ph in ("split", "witext") else z, ph)
                           for ph in ("split", "witext", "prove", "verify")}
                       for z in ("nonzk", "zk")},
        }

    with open(out, "w") as f:
        json.dump(data, f, indent=2)

    # Also emit a human-readable RESULTS.md next to the JSON, so the record
    # is legible without tooling (the overnight run must leave something a
    # person can read on waking, independent of any downstream bake step).
    import os
    md_path = os.path.join(os.path.dirname(out) or ".", "RESULTS.md")
    lines = ["# co-SNARK benchmark results", ""]
    if contended:
        lines += ["> ⚠ **CONTENDED run** — the box was busy (10 h idle-wait "
                  "cap hit); treat these as upper bounds, not clean numbers.", ""]
    if manifest:
        lines += ["**Run provenance** (what produced these numbers — required "
                  "to compare against another run):", ""]
        for k in ("started_utc", "host", "cpu_cores_total",
                  "rayon_threads_per_party", "co_snarks_commit",
                  "co_snarks_branch", "co_snarks_worktree", "bb_oracle_path",
                  "bb_version_pin", "nargo_version", "network"):
            if k in manifest:
                lines.append(f"- **{k}**: {manifest[k]}")
        lines.append("")
    lines += [f"Source: `{src}`  ·  medians across reps of successful rows  ·  "
              "loopback only  ·  `—` = not measured (stays modeled in the site).", ""]
    def cell(v): return f"{v:.3f}s" if isinstance(v, (int, float)) else "—"
    for c in circuits:
        d = data["circuits"][c]
        lines += [f"## {c}", "",
                  "| config | split | witext | prove | verify | prove (non-ZK) |",
                  "|---|---|---|---|---|---|",
                  f"| bb (1 prover) | — | — | {cell(d['bb']['prove_zk'])} | — | {cell(d['bb']['prove_nonzk'])} |",
                  f"| plaindriver (co-noir, no MPC) | — | — | {cell(d['plaindriver']['prove_zk'])} | — | {cell(d['plaindriver']['prove_nonzk'])} |",
                  f"| REP3 3-party (ZK) | {cell(d['rep3']['zk']['split'])} | {cell(d['rep3']['zk']['witext'])} | {cell(d['rep3']['zk']['prove'])} | {cell(d['rep3']['zk']['verify'])} | {cell(d['rep3']['nonzk']['prove'])} |",
                  f"| Shamir 3-party (ZK) | {cell(d['shamir']['zk']['split'])} | {cell(d['shamir']['zk']['witext'])} | {cell(d['shamir']['zk']['prove'])} | {cell(d['shamir']['zk']['verify'])} | {cell(d['shamir']['nonzk']['prove'])} |"]
        bb = d['bb']['prove_zk']; rep3 = d['rep3']['zk']['prove']
        if isinstance(bb, (int, float)) and isinstance(rep3, (int, float)) and bb > 0:
            lines += ["", f"REP3-prove ÷ bb-prove (ZK): **{rep3/bb:.1f}×** (loopback compute only)."]
        extras = []
        if isinstance(d['bb'].get('vkgen'), (int, float)):
            extras.append(f"bb vkgen {cell(d['bb']['vkgen'])}")
        if isinstance(d['plaindriver'].get('solveprove_zk'), (int, float)):
            extras.append(f"plaindriver solve+prove (ZK) {cell(d['plaindriver']['solveprove_zk'])}")
        if extras:
            lines += ["", "Other phases: " + " · ".join(extras) + "."]
        mems = []
        for lbl, v in (("bb prove", d['bb'].get('prove_zk_rss_mb')),
                       ("plaindriver prove", d['plaindriver'].get('prove_zk_rss_mb')),
                       ("REP3 witext", d['rep3_rss_mb']['witext']),
                       ("REP3 prove (per party)", d['rep3_rss_mb']['prove_zk'])):
            if v is not None:
                mems.append(f"{lbl} {v:,.0f} MB")
        if mems:
            lines += ["", "**Peak memory (ZK)** — " + " · ".join(mems) + "."]
        nets = []
        for ph in ("witext", "prove_zk", "prove_nonzk"):
            n = d["net"][ph]
            if n["R"] is not None:
                mb = (n['sent_bytes_party0'] or 0) / 1e6
                nets.append(f"{ph}: R≈{n['R']:,} rounds, {mb:.1f} MB sent (party 0)")
        if nets:
            lines += ["", "**Comms (measured)** — " + " · ".join(nets) + "."]
        f_ = d.get("features") or {}
        ci = f_.get("circuit_info") or {}
        bg = f_.get("bb_gates") or {}
        feat = []
        if bg.get("circuit_size"):
            feat.append(f"{bg['circuit_size']:,} rows (bb)")
        for k, lbl in (("dyadic_size", "dyadic"), ("lookup_gates", "lookup gates"),
                       ("num_lookup_tables", "tables"), ("total_table_rows", "table rows"),
                       ("witness_zero_fraction", "witness zeros")):
            if ci.get(k) is not None:
                v = ci[k]
                feat.append(f"{lbl} {v:.1%}" if k == "witness_zero_fraction" else f"{lbl} {v:,}")
        if feat:
            lines += ["", "**Shape**: " + " · ".join(feat) + "."]
        lines += [""]
    lines += ["---", "",
              "This report measures the honest proving path. Consult verification "
              "cells and the comparison test suite for correctness evidence."]
    with open(md_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"wrote {out} + {md_path}: {len(circuits)} circuits"
          + (" [CONTENDED — flag these in the site]" if contended else ""))

if __name__ == "__main__":
    main()
