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

    circuits = sorted({k[0] for k in buckets})
    data = {
        "provenance": "measured",
        "contended": contended,   # site must badge these NOT-clean if true
        "source": src,
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
    print(f"wrote {out}: {len(circuits)} circuits"
          + (" [CONTENDED — flag these in the site]" if contended else ""))

if __name__ == "__main__":
    main()
