#!/usr/bin/env python3
"""Aggregate a bench-0_5 results.csv into the explorer's data block.

Reads results.csv (columns: circuit,protocol,zk,rep,phase,seconds,rc),
takes the MEDIAN across reps of the successful (rc==0) rows per
(circuit, protocol, zk, phase), and writes site-anchors.json — the shape
the co-SNARK explorer bakes in for its MEASURED anchors (ch. 22 §5/V7).

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

    def med(circuit, proto, zk, phase):
        v = buckets.get((circuit, proto, zk, phase))
        return round(statistics.median(v), 4) if v else None

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
                            "prove_zk":    med(c, "bb", "zk", "prove")},
            "plaindriver": {"prove_zk":    med(c, "plaindriver", "zk", "prove")},
            "rep3": {z: {ph: med(c, "REP3", z, ph)
                         for ph in ("split", "witext", "prove", "verify")}
                     for z in ("nonzk", "zk")},
            "shamir": {z: {ph: med(c, "SHAMIR", z, ph)
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
    lines = ["# PLAN 0.5 benchmark — results", ""]
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
                  f"| plaindriver (co-noir, no MPC) | — | — | {cell(d['plaindriver']['prove_zk'])} | — | — |",
                  f"| REP3 3-party (ZK) | {cell(d['rep3']['zk']['split'])} | {cell(d['rep3']['zk']['witext'])} | {cell(d['rep3']['zk']['prove'])} | {cell(d['rep3']['zk']['verify'])} | {cell(d['rep3']['nonzk']['prove'])} |",
                  f"| Shamir 3-party (ZK) | {cell(d['shamir']['zk']['split'])} | {cell(d['shamir']['zk']['witext'])} | {cell(d['shamir']['zk']['prove'])} | {cell(d['shamir']['zk']['verify'])} | {cell(d['shamir']['nonzk']['prove'])} |"]
        bb = d['bb']['prove_zk']; rep3 = d['rep3']['zk']['prove']
        if isinstance(bb, (int, float)) and isinstance(rep3, (int, float)) and bb > 0:
            lines += ["", f"REP3-prove ÷ bb-prove (ZK): **{rep3/bb:.1f}×** (loopback compute only).", ""]
        else:
            lines += [""]
    lines += ["---", "",
              "Correctness (measured, not here): proofs byte-identical to bb — "
              "`compare_mpc.sh`, VK byte-KATs. This file times the honest path only.",
              "", "Next: bake `site-anchors.json` into the co-SNARK explorer "
              "(project-docs ch.22 V7) and redeploy the same artifact URL."]
    with open(md_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"wrote {out} + {md_path}: {len(circuits)} circuits"
          + (" [CONTENDED — flag these in the site]" if contended else ""))

if __name__ == "__main__":
    main()
