#!/usr/bin/env python3
"""SUPERSEDED by scripts/bench-phase-split.py (v4, 2026-07-29). Kept because the
v2.1-v3 run dirs' phase-split.csv files were produced by this script and are
reused as-is; nothing re-derives them.

Do not use it for new runs. It splits the MPC cell at the binary's
'Build proving key took' log line, which is a CODE boundary, not the
precomputability boundary a reader assumes: measurement showed 0.02%-10% of that
phase is circuit-only work and the rest is per-proof MPC over the shared witness.
The successor resolves setup / witness / prove for all four provers.

Retro-split REP3 'prove' cells into pk-gen vs prove wall times.

The v2 bench timed `co-noir generate-proof` as ONE cell, but the binary
logs 'Build proving key took X ms' and 'Generate proof took Y ms' per
party. This recovers the split for every completed REP3 cell from the
per-cell logs — no rerun needed. (bb cells already had vkgen split at
run time; plaindriver logs carry no phase lines — v2.1 splits those
cells properly at the launcher level.)

Usage: bench-retro-phase-split.py <run-dir>   # e.g. bench-results/2026-07-25
Writes <run-dir>/phase-split.csv and prints per-cell medians.
"""

import csv
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LOGNAME = re.compile(r"^(?P<circuit>.+)_(?P<protocol>REP3|SHAMIR)_(?P<zk>nonzk|zk)_prove_r(?P<rep>\d+)\.log$")
PK = re.compile(r"Build proving key took ([0-9.]+) ms")
PR = re.compile(r"Generate proof took ([0-9.]+) ms")

def main(run_dir: Path) -> None:
    rows = []
    for log in sorted(run_dir.glob("*_prove_r*.log")):
        m = LOGNAME.match(log.name)
        if not m:
            continue
        text = ANSI.sub("", log.read_text())
        pks = [float(v) / 1000 for v in PK.findall(text)]
        prs = [float(v) / 1000 for v in PR.findall(text)]
        if not pks and not prs:
            continue  # timed-out cell: no completed phases to split
        for party, (pk, pr) in enumerate(zip(pks, prs)):
            rows.append({
                "circuit": m["circuit"], "protocol": m["protocol"], "zk": m["zk"],
                "rep": int(m["rep"]), "party": party,
                "pkgen_seconds": round(pk, 3), "prove_seconds": round(pr, 3),
            })
        # parties that logged pk-gen but died before proving (partial cells)
        for party in range(len(prs), len(pks)):
            rows.append({
                "circuit": m["circuit"], "protocol": m["protocol"], "zk": m["zk"],
                "rep": int(m["rep"]), "party": party,
                "pkgen_seconds": round(pks[party], 3), "prove_seconds": "",
            })

    out = run_dir / "phase-split.csv"
    fields = ["circuit", "protocol", "zk", "rep", "party",
              "pkgen_seconds", "prove_seconds"]
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    med = defaultdict(lambda: {"pk": [], "pr": []})
    for r in rows:
        key = (r["circuit"], r["protocol"], r["zk"])
        med[key]["pk"].append(r["pkgen_seconds"])
        if r["prove_seconds"] != "":
            med[key]["pr"].append(r["prove_seconds"])
    print(f"wrote {out} ({len(rows)} party-rows)\n")
    print(f"{'circuit':<28} {'proto':<7} {'zk':<6} {'pkgen_med_s':>12} {'prove_med_s':>12}")
    for (circuit, proto, zk), v in sorted(med.items()):
        pk = statistics.median(v["pk"]) if v["pk"] else float("nan")
        pr = statistics.median(v["pr"]) if v["pr"] else float("nan")
        print(f"{circuit:<28} {proto:<7} {zk:<6} {pk:>12.3f} {pr:>12.3f}")

if __name__ == "__main__":
    main(Path(sys.argv[1]))
