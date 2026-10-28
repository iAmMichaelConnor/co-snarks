#!/usr/bin/env python3
"""Ingest all benchmark runs into bench-results/bench.sqlite.

Idempotent: drops and rebuilds the whole database from the on-disk run
directories every time (the run dirs are the source of truth; the DB is a
derived, queryable convenience for analysis/visualisation). See
bench-results/README.md for the dataset layout and schema description.

Usage: bench-ingest.py [--db PATH] [RUN_DIR ...]
  With no RUN_DIRs: ingests every dated dir under bench-results/ plus the
  legacy v1 run at ~/bench-0_5-results/2026-07-23 if present, plus any
  circuit-features-* standalone capture dirs (features only, run_id =
  dir name).
"""
import argparse
import csv
import glob
import json
import os
import re
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(ROOT, "bench-results", "bench.sqlite")

SCHEMA = """
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS cells;
DROP TABLE IF EXISTS netstats;
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS artifact_sizes;
DROP TABLE IF EXISTS medians;
DROP VIEW IF EXISTS overhead;

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY, dir TEXT, started_utc TEXT, host TEXT,
  kernel TEXT, cpu_model TEXT, cores INTEGER, threads_per_party INTEGER,
  commit_hash TEXT, branch TEXT, worktree TEXT, bb_pin TEXT, nargo TEXT,
  benchmark TEXT, network TEXT
);
CREATE TABLE cells (
  run_id TEXT, circuit TEXT, protocol TEXT, zk TEXT, rep INTEGER,
  phase TEXT, seconds REAL, rc INTEGER, max_rss_kb INTEGER,
  cpu_pct INTEGER, host_load1m REAL
);
CREATE TABLE netstats (
  run_id TEXT, circuit TEXT, protocol TEXT, phase TEXT, zk TEXT,
  rep INTEGER, party INTEGER, peer INTEGER,
  sent_bytes INTEGER, recv_bytes INTEGER, sent_msgs INTEGER, recv_msgs INTEGER
);
CREATE TABLE features (
  run_id TEXT, circuit TEXT, dyadic_size INTEGER, finalized_rows INTEGER,
  block_arithmetic INTEGER, block_delta_range INTEGER, block_lookup INTEGER,
  block_elliptic INTEGER, block_aux INTEGER,
  block_poseidon2_external INTEGER, block_poseidon2_internal INTEGER,
  lookup_gates INTEGER, num_lookup_tables INTEGER, total_table_rows INTEGER,
  public_inputs INTEGER, witness_len INTEGER, witness_zero_fraction REAL,
  acir_opcodes INTEGER
);
CREATE TABLE artifact_sizes (
  run_id TEXT, circuit TEXT, artifact TEXT, bytes INTEGER
);

-- medians is a real table, filled by the ingest script in Python after the
-- cells load (SQLite can't express MEDIAN cleanly; matches bench-to-site.py)
CREATE TABLE medians (
  run_id TEXT, circuit TEXT, protocol TEXT, zk TEXT, phase TEXT,
  median_seconds REAL, ok_reps INTEGER, failed_reps INTEGER,
  mean_host_load REAL
);

-- the headline analysis: REP3-vs-bb prove overhead joined with composition
CREATE VIEW overhead AS
SELECT m1.run_id, m1.circuit, m1.zk,
       m1.median_seconds AS rep3_prove_s,
       m2.median_seconds AS bb_prove_s,
       m1.median_seconds / NULLIF(m2.median_seconds, 0) AS rep3_over_bb,
       f.dyadic_size, f.lookup_gates, f.total_table_rows,
       f.block_arithmetic, f.block_delta_range, f.witness_zero_fraction
FROM medians m1
JOIN medians m2 ON m2.run_id=m1.run_id AND m2.circuit=m1.circuit
               AND m2.zk=m1.zk AND m2.protocol='bb' AND m2.phase='prove'
LEFT JOIN features f ON f.run_id=m1.run_id AND f.circuit=m1.circuit
WHERE m1.protocol='REP3' AND m1.phase='prove';
"""

NETSTAT_PAT = re.compile(
    r"^(?P<c>.+?)_(?P<proto>REP3|SHAMIR)_(?P<phase>witext|prove)"
    r"(?:_(?P<zk>zk|nonzk))?_r(?P<rep>\d+)_p(?P<party>\d)\.json$")


def ingest_manifest(cur, run_id, d):
    m = {}
    p = os.path.join(d, "manifest.json")
    if os.path.exists(p):
        try:
            m = json.load(open(p))
        except (ValueError, OSError) as e:
            print(f"  warning: unreadable manifest in {d}: {e}", file=sys.stderr)
    cur.execute(
        "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, d, m.get("started_utc"), m.get("host"), m.get("kernel"),
         m.get("cpu_model"), m.get("cpu_cores_total"),
         m.get("rayon_threads_per_party"), m.get("co_snarks_commit"),
         m.get("co_snarks_branch"), m.get("co_snarks_worktree"),
         m.get("bb_version_pin"), m.get("nargo_version"),
         m.get("benchmark"), m.get("network")))


def ingest_cells(cur, run_id, d):
    for name in ("results.csv", "CONTENDED-results.csv"):
        p = os.path.join(d, name)
        if not os.path.exists(p):
            continue
        with open(p, newline="") as f:
            for row in csv.DictReader(f):
                cur.execute(
                    "INSERT INTO cells VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, row["circuit"], row["protocol"], row["zk"],
                     _int(row.get("rep")), row["phase"],
                     _float(row.get("seconds")), _int(row.get("rc")),
                     _int(row.get("max_rss_kb")), _int(row.get("cpu_pct")),
                     _float(row.get("host_load1m"))))
        return True
    return False


def ingest_netstats(cur, run_id, d):
    for p in glob.glob(os.path.join(d, "netstats", "*.json")):
        m = NETSTAT_PAT.match(os.path.basename(p))
        if not m:
            continue
        try:
            peers = json.load(open(p)).get("peers", {})
        except (ValueError, OSError):
            continue
        for peer, s in peers.items():
            cur.execute(
                "INSERT INTO netstats VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, m.group("c"), m.group("proto"), m.group("phase"),
                 m.group("zk") or "-", int(m.group("rep")),
                 int(m.group("party")), _int(peer),
                 _int(s.get("sent_bytes")), _int(s.get("recv_bytes")),
                 _int(s.get("sent_msgs")), _int(s.get("recv_msgs"))))


def ingest_features(cur, run_id, d):
    for p in glob.glob(os.path.join(d, "*.circuit-info.json")) + \
             glob.glob(os.path.join(d, "features", "*.circuit-info.json")):
        try:
            j = json.load(open(p))
        except (ValueError, OSError):
            continue
        c = os.path.basename(p).replace(".circuit-info.json", "")
        b = j.get("blocks", {})
        cur.execute(
            "INSERT INTO features VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, c, j.get("dyadic_size"), j.get("finalized_rows"),
             b.get("arithmetic"), b.get("delta_range"), b.get("lookup"),
             b.get("elliptic"), b.get("aux") or b.get("memory"),
             b.get("poseidon2_external"), b.get("poseidon2_internal"),
             j.get("lookup_gates"), j.get("num_lookup_tables"),
             j.get("total_table_rows"), j.get("public_inputs"),
             j.get("witness_len"), j.get("witness_zero_fraction"),
             j.get("acir_opcodes")))
    for p in glob.glob(os.path.join(d, "features", "*.artifact-sizes.json")):
        try:
            j = json.load(open(p))
        except (ValueError, OSError):
            continue
        c = os.path.basename(p).replace(".artifact-sizes.json", "")
        for art, n in j.items():
            cur.execute("INSERT INTO artifact_sizes VALUES (?,?,?,?)",
                        (run_id, c, art, n))


def _int(v):
    try:
        return int(v) if v not in (None, "", "-") else None
    except (ValueError, TypeError):
        return None


def _float(v):
    try:
        return float(v) if v not in (None, "", "-") else None
    except (ValueError, TypeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("run_dirs", nargs="*")
    args = ap.parse_args()

    dirs = args.run_dirs
    if not dirs:
        base = os.path.join(ROOT, "bench-results")
        dirs = sorted(
            d for d in glob.glob(os.path.join(base, "*"))
            if os.path.isdir(d))
        legacy = os.path.expanduser("~/bench-0_5-results/2026-07-23")
        if os.path.isdir(legacy):
            dirs.append(legacy)

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    if os.path.exists(args.db):
        os.remove(args.db)  # fully derived — rebuilt from run dirs every time
    con = sqlite3.connect(args.db)
    con.executescript(SCHEMA)
    cur = con.cursor()
    for d in dirs:
        run_id = os.path.basename(d.rstrip("/"))
        if d.startswith(os.path.expanduser("~/bench-0_5-results")):
            run_id = f"v1-legacy-{run_id}"
        had_csv = ingest_cells(cur, run_id, d)
        ingest_manifest(cur, run_id, d)
        ingest_netstats(cur, run_id, d)
        ingest_features(cur, run_id, d)
        kind = "run" if had_csv else "capture-only"
        print(f"ingested {run_id} ({kind})")
    # fill the medians table (median over rc==0 reps per cell group)
    import statistics
    groups = {}
    loads = {}
    fails = {}
    for run_id, c, proto, zk, phase, secs, rc, load in cur.execute(
            "SELECT run_id, circuit, protocol, zk, phase, seconds, rc, "
            "host_load1m FROM cells").fetchall():
        k = (run_id, c, proto, zk, phase)
        if rc == 0 and secs is not None:
            groups.setdefault(k, []).append(secs)
            if load is not None:
                loads.setdefault(k, []).append(load)
        else:
            fails[k] = fails.get(k, 0) + 1
    for k in set(groups) | set(fails):
        v = groups.get(k, [])
        ld = loads.get(k, [])
        cur.execute(
            "INSERT INTO medians VALUES (?,?,?,?,?,?,?,?,?)",
            (*k, round(statistics.median(v), 4) if v else None, len(v),
             fails.get(k, 0),
             round(sum(ld) / len(ld), 1) if ld else None))
    con.commit()
    for t in ("runs", "cells", "medians", "netstats", "features",
              "artifact_sizes"):
        n = cur.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {n} rows")
    con.close()
    print(f"wrote {args.db}")


if __name__ == "__main__":
    main()
