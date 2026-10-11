#!/usr/bin/env python3
"""Resolve every prover's measured pipeline into SETUP / WITNESS / PROVE buckets.

Replaces bench-retro-phase-split.py (v2.1-v3), which split only the MPC cell,
and split it at the binary's own "Build proving key took" log line. That is a
CODE boundary, not a precomputability boundary, and the difference is large:

  * "pk-gen" is dominated by per-proof MPC over the shared witness. On
    sha256 2^16, 128.2 s of the 139.8 s pk-gen is construct_lookup_read_counts
    (secret table indices -> one-hot vectors over MPC rounds) and 11.6 s is the
    builder's sha gadget over shared values. The circuit-only slice is 31 ms.
  * On poseidon the circuit-only slice is a larger fraction (9.9% at 2^20) but
    tiny in absolute terms (307 ms of a 74.9 s pipeline).

So a chart that offers to "exclude proving-key generation" removes almost
entirely per-proof cost, while a chart that wants to answer "what does a node
pay per proof, given it already holds everything derivable from the circuit?"
must remove something much smaller. This script measures the latter.

Buckets (identical definition for all four provers):

  SETUP    circuit-only, precomputable once per circuit, identical for every
           user and every proof: ACIR parse, structural circuit build, selector
           / permutation (sigma,id) / lookup-table polynomials, the commitments
           to them (= the VK), CRS load.
  WITNESS  per-proof work before the prover proper: MPC work over shared witness
           values, lookup read counts and tags, memory records, wire polynomial
           population, witness-file/ACVM input handling.
  PROVE    per-proof prover proper: witness-polynomial commitments, grand
           products, sumcheck, PCS.

Two further columns are kept out of those buckets on purpose, because folding
them in would overstate what precomputation can buy:

  ALLOC        allocating and zeroing the polynomial arena and copy-cycle table.
               Not circuit setup and not mathematically per-proof: a long-lived
               node can pool the buffers. Amortisable, so shown separately.
  SELFVERIFY   bb and plaindriver both verify the proof they just produced
               (bb: bbapi_ultra_honk.cpp "Sanity-check the generated proof";
               plaindriver: its own verify phase). co-noir's prove does not.
               Reported so the baselines can be compared without it.

Sources, per prover (all measurements, no modelling):

  bb           setup   = pk-build line in the write_vk log, i.e.
                         "CircuitProve: Proving key computed in N ms" with an
                         EMPTY witness -> the structural build alone
               witness = same line in the prove log, minus the above
               prove   = prove cell wall minus the prove-log pk-build
               (bb needed no new instrumentation: it has always logged this.)
  plaindriver  from its [phase-timing] lines (v4 runs it with
               CO_NOIR_PHASE_TIMINGS=1): read_circuit, read_crs,
               vkgen/commit_precomputed and the pkgen/* setup slice are SETUP;
               build_circuit + the rest of pkgen/prover_instance are WITNESS;
               prove_total is PROVE.
  REP3/SHAMIR  pk-gen and prove-proper still come from the two tracing lines
               (authoritative, and comparable with every earlier run); the
               pkgen/* sub-phases then resolve pk-gen into its setup slice, its
               allocation cost and its per-proof remainder.

The once-per-circuit setup cells live in results.csv, not here:
  protocol=bb      phase=vkgen   -> bb write_vk
  protocol=co-noir phase=vkgen   -> co-noir create-vk (new in v4; v2/v3 ran it
                                    untimed, so the MPC path's setup cost was
                                    missing from the dataset entirely)

Usage: bench-phase-split.py <run-dir>
Writes <run-dir>/phase-split.csv and prints per-config medians.
"""

import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
MPC_LOG = re.compile(
    r"^(?P<circuit>.+)_(?P<protocol>REP3|SHAMIR)_(?P<zk>nonzk|zk)_prove_r(?P<rep>\d+)\.log$"
)
BB_LOG = re.compile(r"^(?P<circuit>.+)_bb_(?P<zk>nonzk|zk)_r(?P<rep>\d+)\.log$")
BB_VK_LOG = re.compile(r"^(?P<circuit>.+)_bb_-_r1\.log$")
PK = re.compile(r"Build proving key took ([0-9.]+) ms")
PR = re.compile(r"Generate proof took ([0-9.]+) ms")
BB_PK = re.compile(r"Proving key computed in (\d+) ms")

# pkgen/* sub-phases, by bucket. Anything emitted but not listed here lands in
# the per-proof remainder, which is the safe direction: an unclassified phase
# never inflates the precomputable slice.
SETUP_SUBPHASES = ("pkgen/selectors", "pkgen/permutation_polys", "pkgen/lookup_table_polys")
ALLOC_SUBPHASES = ("pkgen/alloc_polynomials", "pkgen/alloc_copy_cycles")
# plaindriver-only setup phases (its prove run always writes a VK)
PD_SETUP_PHASES = ("read_circuit", "read_crs", "vkgen/commit_precomputed")
# Setup work in the MPC prove cell that sits OUTSIDE the pk-gen and prove timers:
# ACIR parse, a second full structural circuit build (compute_circuit_size builds
# and finalizes the circuit with an empty witness just to size the CRS), the CRS
# load and the VK read. Before v4 these were invisible — a residual of the cell
# wall — which charged per-circuit setup to per-proof cost.
MPC_SETUP_PHASES = ("setup/acir_parse", "setup/compute_circuit_size",
                    "setup/crs_load", "setup/vk_read")
MPC_WITNESS_PHASES = ("witness/deserialize_shares",)
# Session infrastructure: a deployed node holds its connections open across
# proofs, so this is neither per-circuit nor per-proof. Kept out of both buckets.
INFRA_PHASES = ("infra/net_connect",)

FIELDS = [
    "circuit", "protocol", "zk", "cell", "rep", "parties",
    "setup_inline_seconds", "witness_seconds", "prove_seconds",
    "alloc_seconds", "selfverify_seconds", "infra_seconds", "unaccounted_seconds",
    "pkgen_seconds", "proveproper_seconds",
]


def read_text(path):
    try:
        return ANSI.sub("", path.read_text(errors="replace"))
    except OSError:
        return ""


def cell_medians(run_dir):
    """(circuit,protocol,zk,phase) -> {rep: seconds} for rc==0 rows."""
    out = defaultdict(dict)
    path = run_dir / "results.csv"
    if not path.exists():
        return out
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if (row.get("rc") or "").strip() != "0":
                continue
            try:
                out[(row["circuit"], row["protocol"], row["zk"], row["phase"])][
                    int(row["rep"])
                ] = float(row["seconds"])
            except (ValueError, KeyError, TypeError):
                continue
    return out


def phase_entries(run_dir, name):
    """phase-name -> [seconds...] from one phase-timings JSON (empty if absent).

    MPC JSONs hold one entry per phase PER PARTY, unattributed; single-prover
    JSONs hold one. Callers take medians, so party identity is never needed.
    """
    path = run_dir / "phase-timings" / f"{name}.json"
    try:
        with path.open() as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    agg = defaultdict(list)
    for e in doc.get("entries", []):
        try:
            agg[e["phase"]].append(float(e["seconds"]))
        except (KeyError, TypeError, ValueError):
            continue
    return agg


def med(vals):
    return statistics.median(vals) if vals else None


def sum_med(agg, names):
    """Sum of per-phase medians over `names`; missing names contribute 0."""
    total = 0.0
    for n in names:
        v = med(agg.get(n, []))
        if v:
            total += v
    return total


def mpc_rows(run_dir, cells):
    rows = []
    for log in sorted(run_dir.glob("*_prove_r*.log")):
        m = MPC_LOG.match(log.name)
        if not m:
            continue
        c, proto, zk, rep = m["circuit"], m["protocol"], m["zk"], int(m["rep"])
        text = read_text(log)
        pks = [float(v) / 1000 for v in PK.findall(text)]
        prs = [float(v) / 1000 for v in PR.findall(text)]
        if not pks:
            continue  # timed-out cell: nothing completed to resolve
        agg = phase_entries(run_dir, f"{c}_{proto}_{zk}_prove_r{rep}")
        pkgen, proveproper = med(pks), med(prs)
        alloc = sum_med(agg, ALLOC_SUBPHASES)
        infra = sum_med(agg, INFRA_PHASES)
        # Setup = the slice inside pk-gen + the pre-pk-gen setup phases.
        setup = sum_med(agg, SETUP_SUBPHASES) + sum_med(agg, MPC_SETUP_PHASES)
        # Per-proof: pk-gen's remainder (MPC over shared values, read counts,
        # memory records, wire population) plus the share deserialize. Clamped at
        # 0 because on circuits where pk-gen is a few milliseconds the sub-phase
        # medians can sum past it through timer granularity, and a negative bucket
        # would be nonsense.
        witness = (max(0.0, (pkgen or 0.0) - sum_med(agg, SETUP_SUBPHASES) - alloc)
                   + sum_med(agg, MPC_WITNESS_PHASES))
        cell = cells.get((c, proto, zk, "prove"), {}).get(rep)
        unacc = None
        if cell is not None:
            unacc = max(0.0, cell - setup - witness - alloc - infra - (proveproper or 0.0))
        rows.append({
            "circuit": c, "protocol": proto, "zk": zk, "cell": "prove",
            "rep": rep, "parties": len(pks),
            "setup_inline_seconds": round(setup, 6),
            "witness_seconds": round(witness, 6),
            "prove_seconds": round(proveproper, 6) if proveproper is not None else "",
            "alloc_seconds": round(alloc, 6),
            "selfverify_seconds": 0.0,   # co-noir's prove does not self-verify
            "infra_seconds": round(infra, 6),
            "unaccounted_seconds": round(unacc, 6) if unacc is not None else "",
            "pkgen_seconds": round(pkgen, 6),
            "proveproper_seconds": round(proveproper, 6) if proveproper is not None else "",
        })
    return rows


def witext_rows(run_dir, cells):
    """The MPC witness-extension cell, split the same way.

    witext is per-proof in its entirety as a phase, but the cell also parses the
    program artifact (setup) and opens the connections (infra), so leaving it
    unsplit charged those to per-proof cost too.
    """
    rows = []
    for path in sorted((run_dir / "phase-timings").glob("*_witext_r*.json")):
        m = re.match(r"^(?P<circuit>.+)_(?P<protocol>REP3|SHAMIR)_witext_r(?P<rep>\d+)$", path.stem)
        if not m:
            continue
        c, proto, rep = m["circuit"], m["protocol"], int(m["rep"])
        agg = phase_entries(run_dir, path.stem)
        if not agg:
            continue
        setup = sum_med(agg, MPC_SETUP_PHASES)
        infra = sum_med(agg, INFRA_PHASES)
        witness = sum_med(agg, ("witness/deserialize_input_shares", "witness/extension"))
        cell = cells.get((c, proto, "-", "witext"), {}).get(rep)
        unacc = ""
        if cell is not None:
            unacc = round(max(0.0, cell - setup - witness - infra), 6)
        rows.append({
            "circuit": c, "protocol": proto, "zk": "-", "cell": "witext",
            "rep": rep, "parties": len(agg.get("witness/extension", [])) or 3,
            "setup_inline_seconds": round(setup, 6),
            "witness_seconds": round(witness, 6),
            "prove_seconds": 0.0,
            "alloc_seconds": 0.0,
            "selfverify_seconds": 0.0,
            "infra_seconds": round(infra, 6),
            "unaccounted_seconds": unacc,
            "pkgen_seconds": "",
            "proveproper_seconds": "",
        })
    return rows


def bb_rows(run_dir, cells):
    """bb's own log already carries its internal pk-build boundary."""
    structural = {}   # circuit -> empty-witness pk build (the structural build)
    for log in sorted(run_dir.glob("*_bb_-_r1.log")):
        m = BB_VK_LOG.match(log.name)
        if not m:
            continue
        hits = BB_PK.findall(read_text(log))
        if hits:
            structural[m["circuit"]] = float(hits[0]) / 1000
    rows = []
    for log in sorted(run_dir.glob("*_bb_*_r*.log")):
        m = BB_LOG.match(log.name)
        if not m:
            continue
        c, zk, rep = m["circuit"], m["zk"], int(m["rep"])
        hits = BB_PK.findall(read_text(log))
        if not hits:
            continue
        pkbuild = float(hits[0]) / 1000
        cell = cells.get((c, "bb", zk, "prove"), {}).get(rep)
        if cell is None:
            continue
        # The structural build happens INSIDE the with-witness build, so it can
        # never exceed it; where the two are within noise (they usually are for a
        # plain prover, whose witness handling is a memcpy) witness lands at ~0.
        setup = min(structural.get(c, 0.0), pkbuild)
        rows.append({
            "circuit": c, "protocol": "bb", "zk": zk, "cell": "prove",
            "rep": rep, "parties": 1,
            "setup_inline_seconds": round(setup, 6),
            "witness_seconds": round(max(0.0, pkbuild - setup), 6),
            "prove_seconds": round(max(0.0, cell - pkbuild), 6),
            "alloc_seconds": "",         # bb does not report it
            # bb verifies the proof it just made; the CLI verify cell is the
            # closest measurement of that internal pass (it additionally pays
            # process start + file reads, so treat it as an upper bound).
            "selfverify_seconds": round(cells.get((c, "bb", zk, "verify"), {}).get(rep, 0.0), 6),
            "infra_seconds": 0.0,        # single process, no network
            "unaccounted_seconds": 0.0,  # cell == pkbuild + prove by construction
            "pkgen_seconds": round(pkbuild, 6),
            "proveproper_seconds": round(max(0.0, cell - pkbuild), 6),
        })
    return rows


def plaindriver_rows(run_dir, cells):
    rows = []
    for path in sorted((run_dir / "phase-timings").glob("*_plaindriver_*_prove_r*.json")):
        m = re.match(r"^(?P<circuit>.+)_plaindriver_(?P<zk>nonzk|zk)_prove_r(?P<rep>\d+)$",
                     path.stem)
        if not m:
            continue
        c, zk, rep = m["circuit"], m["zk"], int(m["rep"])
        agg = phase_entries(run_dir, path.stem)
        if not agg:
            continue
        setup = sum_med(agg, PD_SETUP_PHASES) + sum_med(agg, SETUP_SUBPHASES)
        alloc = sum_med(agg, ALLOC_SUBPHASES)
        instance = sum_med(agg, ("pkgen/prover_instance",))
        # WITNESS = the builder pass + whatever in prover-instance is neither the
        # setup slice nor allocation (wire population, read counts, memory
        # records) + the witness-file read ("witness" phase; the ACVM solve
        # itself when the driver is run in solve+prove mode).
        witness = (sum_med(agg, ("build_circuit", "witness"))
                   + max(0.0, instance - sum_med(agg, SETUP_SUBPHASES) - alloc))
        prove = sum_med(agg, ("prove_total",))
        selfverify = sum_med(agg, ("verify",))
        cell = cells.get((c, "plaindriver", zk, "prove"), {}).get(rep)
        unacc = ""
        if cell is not None:
            unacc = round(max(0.0, cell - setup - witness - alloc - prove - selfverify), 6)
        rows.append({
            "circuit": c, "protocol": "plaindriver", "zk": zk, "cell": "prove",
            "rep": rep, "parties": 1,
            "setup_inline_seconds": round(setup, 6),
            "witness_seconds": round(witness, 6),
            "prove_seconds": round(prove, 6),
            "alloc_seconds": round(alloc, 6),
            "selfverify_seconds": round(selfverify, 6),
            "infra_seconds": 0.0,        # single process, no network
            "unaccounted_seconds": unacc,
            # Legacy-comparable boundary: everything before the prover proper.
            "pkgen_seconds": round(sum_med(agg, ("build_circuit",)) + instance
                                   + sum_med(agg, ("vkgen/commit_precomputed",)), 6),
            "proveproper_seconds": round(prove, 6),
        })
    return rows


def main(run_dir: Path) -> None:
    cells = cell_medians(run_dir)
    rows = (mpc_rows(run_dir, cells) + witext_rows(run_dir, cells)
            + bb_rows(run_dir, cells) + plaindriver_rows(run_dir, cells))

    out = run_dir / "phase-split.csv"
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["circuit"], r["protocol"], r["zk"],
                                               r["cell"], r["rep"])))

    agg = defaultdict(lambda: defaultdict(list))
    for r in rows:
        for k in ("setup_inline_seconds", "witness_seconds", "prove_seconds",
                  "alloc_seconds", "pkgen_seconds"):
            if r[k] != "":
                agg[(r["circuit"], r["protocol"], r["zk"] + "/" + r["cell"])][k].append(float(r[k]))

    # Reconciliation gate on our OWN attribution: every bucket plus the leftovers
    # must add back up to the cell's measured wall-clock. A bucket double-counted
    # or dropped shows up here and nowhere else, and would otherwise silently skew
    # whatever the site publishes. Reported per row, tolerance 5% or 50 ms.
    bad = []
    for r in rows:
        cell = cells.get((r["circuit"], r["protocol"], r["zk"],
                          "witext" if r["cell"] == "witext" else "prove"), {}).get(r["rep"])
        if cell is None:
            continue
        parts = sum(float(r[k] or 0) for k in
                    ("setup_inline_seconds", "witness_seconds", "prove_seconds",
                     "alloc_seconds", "infra_seconds", "unaccounted_seconds"))
        # bb's self-verify happens inside its prove cell; plaindriver's inside its
        # process. Both are part of the wall-clock, so count them here even though
        # they are excluded from the two cost bases.
        parts += float(r["selfverify_seconds"] or 0) if r["protocol"] != "bb" else 0.0
        resid = cell - parts
        if abs(resid) > max(0.05, 0.05 * cell):
            bad.append((r["circuit"], r["protocol"], r["zk"], r["cell"], r["rep"],
                        cell, parts, resid))
    if bad:
        print(f"!! {len(bad)} row(s) do not reconcile with their cell wall-clock "
              f"(bucket sum vs measured cell):")
        for b in bad[:12]:
            print(f"   {b[0]:<22} {b[1]:<12} {b[2]:<6} {b[3]:<7} r{b[4]}  "
                  f"cell={b[5]:.3f} parts={b[6]:.3f} residual={b[7]:+.3f}")
        print()

    print(f"wrote {out} ({len(rows)} rows)\n")
    hdr = f"{'circuit':<24} {'proto':<12} {'zk':<6} {'setup':>9} {'witness':>10} {'prove':>10} {'alloc':>9} {'setup %':>8}"
    print(hdr)
    print("-" * len(hdr))
    for key in sorted(agg):
        v = agg[key]
        s, wi, pr = (med(v["setup_inline_seconds"]) or 0, med(v["witness_seconds"]) or 0,
                     med(v["prove_seconds"]) or 0)
        al = med(v["alloc_seconds"]) or 0
        tot = s + wi + pr + al
        pct = 100 * s / tot if tot else 0
        print(f"{key[0]:<24} {key[1]:<12} {key[2]:<6} {s:>9.3f} {wi:>10.3f} {pr:>10.3f} {al:>9.3f} {pct:>7.2f}%")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
