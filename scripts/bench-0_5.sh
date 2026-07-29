#!/usr/bin/env bash
# PLAN 0.5 benchmark matrix — v2 (2026-07-24).
# v1 (2026-07-23 overnight) measured wall-clock only, at 3 circuit sizes.
# v2 adds, per Mike's asks:
#   * results INSIDE the repo (bench-results/<date>/ — untracked until committed)
#   * comms measurement: bytes + message counts per phase per party via
#     CO_NOIR_NET_STATS_JSON (recv-msgs from a REP3 neighbour ~ sequential
#     rounds R — the WAN-latency multiplier; answers "is R constant?")
#   * circuit FEATURE capture (gate composition, lookup/table sizes, witness
#     sparsity) via `co-noir circuit-info` + `bb gates` + `nargo info` —
#     because v1 showed MPC cost tracks composition, not size (REP3/bb:
#     6x poseidon, 440x sha256, 30x recursion_zk)
#   * size sweeps: poseidon 2^11..2^20, sha256 2^15..2^20 (ascending; a
#     config that times out at one size skips the larger ones)
#   * FAIR baselines (fixes v1): bb prove no longer pays --write_vk (VK gen
#     timed separately, prove gets -k); plaindriver prove is witness-fed
#     (--witness) like bb, with the old solve+prove kept as its own phase
#   * runtime caps: per-cell timeout (default 600 s, rc=124 rows), 2 reps
#     instead of 3 for >=2^18 cells
#   * Shamir cells DROPPED (v1 proved split-input is REP3-only; v2.1 =
#     REP3-split + translate-witness)
# v2.2 (2026-07-26, ch. 24 §3a bench-granularity extension):
#   * CO_NOIR_NET_STATS_JSON now additionally carries, per peer: `rounds`
#     (logical communication-round count — a stricter, generally SMALLER
#     depth proxy than recv_msgs, since a `recv` that finds data already
#     queued isn't a synchronisation wait; see mpc_net::RoundCounters's doc),
#     `blocked_recv_ms` (cumulative wall time actually blocked on that peer —
#     the busy-vs-blocked split), and `recv_bytes_histogram` (bytes received
#     per round). Purely additive to the JSON; old readers are unaffected.
#   * `scripts/bench-tier-model.py` (wired into the launcher) turns that
#     histogram into a distance-tier (Local/LAN/WAN) transfer-time estimate
#     per phase, written to tiers.csv next to phase-split.csv.
#   * REP3 prove cells now also run with CO_NOIR_PHASE_TIMINGS=1; the
#     [phase-timing] lines already emitted by co-ultrahonk (oink/sumcheck/
#     pcs sub-phases) are captured per cell into phase-timings/*.json
#     alongside the existing per-cell .log files (which still get everything).
#   * Shamir cells: one small step out of the v2.1 deferral — the poseidon
#     family additionally gets a SHAMIR prove cell per size/zk-mode via
#     REP3-split + translate-witness (reusing that rep's REP3 witext
#     output), timed as protocol=SHAMIR rows. Other families still deferred.
# v4 (2026-07-29): SETUP vs PER-PROOF taxonomy.
#   The v2/v3 datasets split the MPC prove cell into "pk-gen" and
#   "prove-proper" at the binary's own `Build proving key took` log line. That
#   is a CODE boundary, not a precomputability boundary: measurement showed
#   0.02%-10% of "pk-gen" is circuit-only work (selector / permutation / lookup
#   table polynomials) and the rest is per-proof MPC over the shared witness
#   (lookup read counts dominate lookup-heavy circuits: 128.2 s of sha256 2^16's
#   139.8 s pk-gen). Naming it "proving key" implied a reusable per-circuit
#   artifact that does not exist in UltraHonk — the reusable artifact is the VK.
#   v4 therefore measures three buckets, symmetrically for all four provers:
#     SETUP      circuit-only, precomputable once, user-independent: ACIR parse,
#                trace structure, selector/permutation/lookup-table polys,
#                their commitments (= the VK), CRS load.
#     WITNESS    per-proof work before the prover proper: MPC builder work over
#                shared values, lookup read counts/tags, memory records, wire
#                polynomial population.
#     PROVE      per-proof prover proper: witness commitments, grand products,
#                sumcheck, PCS.
#   New/changed measurements to support it:
#     * co-noir create-vk is now a TIMED cell (protocol=co-noir phase=vkgen).
#       It was run untimed in v2/v3, so the MPC path's setup cost was invisible.
#     * plaindriver cells run with CO_NOIR_PHASE_TIMINGS=1, so its own
#       read_circuit / read_crs / build_circuit / vkgen-commit / prove_total
#       phases are captured. Its prove cell always writes a VK, so ~30% of the
#       v3 plaindriver number was setup — now attributable instead of hidden.
#     * REP3/SHAMIR prove cells additionally emit pkgen/* sub-phase lines
#       (co-builder, same CO_NOIR_PHASE_TIMINGS gate) splitting pk-gen into its
#       setup slice, its per-proof slice and its allocation cost.
#     * bb needs no change: `bb prove` already logs
#       "CircuitProve: Proving key computed in N ms", so its internal
#       pk-build/prove-proper boundary is recoverable from the existing logs.
#     * manifest heredoc is now quoted-safe (v2/v3 ran the backticked field
#       names in the prose as commands, blanking parts of manifest.json).
#     * circuit list adds poseidon 2^12..2^16 (K=2/5/11/23/46, rows=1410K+2) so
#       the poseidon sweep is contiguous 2^11..2^20, and drops sha256 2^20,
#       which only ever produced censored rows (4 cells x the cell cap).
# MUST run on a QUIET box — use scripts/bench-0_5-launcher.sh. Serial by design.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/co-noir/co-noir/examples"
source "$ROOT/versions.env"
BB="${BARRETENBERG_BINARY:-${BARRETENBERG_BINARY_DEFAULT/#\$HOME/$HOME}}"
BENCH_OUT="${BENCH_OUT:?set BENCH_OUT to a results dir}"
mkdir -p "$BENCH_OUT" "$BENCH_OUT/netstats" "$BENCH_OUT/features" "$BENCH_OUT/mem" "$BENCH_OUT/phase-timings"
CSV="$BENCH_OUT/results.csv"
echo "circuit,protocol,zk,rep,phase,seconds,rc,max_rss_kb,cpu_pct,host_load1m" >"$CSV"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-16}"   # measured small-circuit optimum
# 30-min cap per timed cell. v4 default matches what the v3.x runs were actually
# launched with (the old 600 default would censor sha256 2^19's ~1,290 s pk-gen).
CELL_TIMEOUT="${CELL_TIMEOUT:-1800}"

# Ascending size per family so a timeout can prune the larger sizes.
# BENCH_CIRCUITS overrides the list (space-separated) — smoke tests only.
if [[ -n ${BENCH_CIRCUITS:-} ]]; then
  read -r -a CIRCUITS <<<"$BENCH_CIRCUITS"
else
  # v4: contiguous poseidon sweep 2^11..2^20; sha256 2^20 dropped (censored in
  # every prior run — 4 cells x the 30-min cap for no data).
  CIRCUITS=(poseidon poseidon_2e12 poseidon_2e13 poseidon_2e14 poseidon_2e15
            poseidon_2e16 poseidon_2e17 poseidon_2e18 poseidon_2e19 poseidon_2e20
            bb_sha256_compression sha256_2e16 sha256_2e17 sha256_2e18 sha256_2e19
            recursion_zk)
fi
family() { case "$1" in poseidon*) echo poseidon;; *sha256*) echo sha256;; *) echo "$1";; esac; }
is_big() { case "$1" in *2e18|*2e19|*2e20) return 0;; *) return 1;; esac; }  # 2 reps, not 3
declare -A DEAD   # DEAD[family:config]=size that timed out -> skip larger sizes

BIN="$ROOT/target/release/co-noir"
PLAINDRIVER="$ROOT/target/release/plaindriver"
cargo build --release --bin co-noir --bin plaindriver >/dev/null 2>&1

git_desc=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
git_branch=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
git_dirty=$(git -C "$ROOT" diff --quiet 2>/dev/null && echo clean || echo dirty)
nargo_v=$(nargo --version 2>/dev/null | head -1 || echo unknown)
bb_prov=$([[ -f "$(dirname "$BB")/PROVENANCE.txt" ]] && head -1 "$(dirname "$BB")/PROVENANCE.txt" || echo "no PROVENANCE.txt")
# NOTE: this heredoc is deliberately UNQUOTED (the fields below interpolate
# $(...) probes of the host). Never put a backtick in the prose: v2/v3 did, and
# the shell executed the backticked field names, blanking parts of the manifest.
cat >"$BENCH_OUT/manifest.json" <<MANIFEST
{
  "benchmark": "PLAN 0.5 co-SNARK proving matrix v4",
  "started_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "kernel": "$(uname -sr)",
  "cpu_model": "$(lscpu 2>/dev/null | awk -F': +' '/Model name/{print $2; exit}' | sed 's/"//g')",
  "cpu_cores_total": $(nproc --all),
  "rayon_threads_per_party": ${RAYON_NUM_THREADS},
  "co_snarks_commit": "$git_desc",
  "co_snarks_branch": "$git_branch",
  "co_snarks_worktree": "$git_dirty",
  "bb_oracle_path": "$BB",
  "bb_version_pin": "${BARRETENBERG_VERSION:-unknown}",
  "bb_provenance": "$(printf '%s' "$bb_prov" | sed 's/"/\\"/g')",
  "nargo_version": "$(printf '%s' "$nargo_v" | sed 's/"/\\"/g')",
  "circuits": "${CIRCUITS[*]}",
  "protocols": "bb plaindriver REP3 (Shamir: v2.2 adds poseidon-family-only SHAMIR prove cells via REP3-split + translate-witness, reusing REP3 witext; other families still deferred)",
  "zk_modes": "nonzk zk",
  "reps": "3 (2 for >=2^18 circuits)",
  "cell_timeout_s": ${CELL_TIMEOUT},
  "fairness": "bb prove uses -k (VK pregen, timed as vkgen); plaindriver prove is witness-fed; plaindriver solve+prove kept as separate phase; verify cells: bb verify per zk-mode (verifier-time baseline), plaindriver verify_bb = bb cross-verifies the plaindriver zk proof (rc=0 is the verifier-side parity invariant), REP3/SHAMIR verify via co-noir. v4 caveats that remain: bb prove and plaindriver both self-verify the proof they just made (bb ~20 ms, plaindriver ~7 ms) while co-noir prove does not; bb runs its own thread pool (32 threads observed) whereas RAYON_NUM_THREADS caps only the Rust provers",
  "taxonomy_v4": "three buckets, cut identically for all four provers. SETUP = circuit-only, precomputable once per circuit, identical for every user and every proof: ACIR parse, trace structure, selector + permutation (sigma/id) + lookup-table polynomials, their commitments (the VK), CRS load. WITNESS = per-proof work before the prover proper: MPC builder work over shared witness values, lookup read counts and tags, memory records, wire polynomial population. PROVE = per-proof prover proper: witness-polynomial commitments, grand products, sumcheck, PCS. The v2/v3 'pk-gen' phase is NOT the setup bucket -- it is WITNESS plus a small SETUP slice (measured 0.02% of pk-gen on sha256 2^16, 9.9% on poseidon 2^20); see phase-split.csv for the resolved split",
  "netstats": "per phase x party JSONs in netstats/ when the co-noir binary supports CO_NOIR_NET_STATS_JSON; recv_msgs from one REP3 neighbour ~ sequential rounds R (upper bound at scale -- see the v2.2 rounds field below); the *_pkgen_* JSONs are mid-run snapshots after proving-key generation (CO_NOIR_NET_STATS_JSON_PKGEN) — subtract from the matching *_prove_* totals for true per-phase comms; v2.2 (2026-07-26): each peer entry additionally carries rounds (logical-round count: a recv that found nothing queued and had to wait -- a tighter round-depth proxy than recv_msgs), blocked_recv_ms (cumulative time blocked in those waits), and recv_bytes_histogram (bytes received per round) -- all purely additive, old readers unaffected. Setup does no communication at all (single party, no network), so it has no netstats entry",
  "phase_timings": "REP3/SHAMIR prove cells and (new in v4) plaindriver cells run with CO_NOIR_PHASE_TIMINGS=1; the [phase-timing] stderr lines are captured per cell into phase-timings/*.json. co-ultrahonk emits the prover sub-phases (oink/sumcheck/pcs); co-builder emits the pkgen/* sub-phases that resolve pk-gen into its setup slice (pkgen/selectors, pkgen/permutation_polys, pkgen/lookup_table_polys), its per-proof slice (pkgen/build_circuit, pkgen/wires_and_copy_cycles, pkgen/lookup_read_counts, pkgen/memory_records) and its allocation cost (pkgen/alloc_polynomials, pkgen/alloc_copy_cycles); plaindriver adds read_circuit, witness, build_circuit, read_crs, create_proving_key, vkgen/commit_precomputed, prove_total, verify, main_total. MPC entries are NOT attributed to a party -- each name normally appears once per party per prove, so ~3x entries per name is expected",
  "tiers_csv": "v2.2: scripts/bench-tier-model.py (run by the launcher) turns the per-round byte histogram into a Local/LAN/WAN transfer-time estimate per phase, written to tiers.csv",
  "features": "per circuit JSONs in features/ (co-noir circuit-info, bb gates, nargo info)",
  "network": "loopback (single host; distance/latency NOT measured here — tiers.csv is a MODEL, not a real-network measurement; see project-docs ch. 24 §3a for the netem v3 follow-up)",
  "csv_schema": "circuit,protocol,zk,rep,phase,seconds,rc,max_rss_kb,cpu_pct,host_load1m (rc!=0 failed, rc=124 timeout, excluded from medians; max_rss_kb = peak RSS, max over the 3 parties for MPC cells; cpu_pct empty for MPC cells — per-party detail in mem/; host_load1m = HOST-wide 1-min loadavg at cell start — shared-mainframe noise context for the absolute seconds; SHAMIR rows add a 'translate' phase for the translate-witness step). v4 adds protocol=co-noir phase=vkgen: the MPC path's per-circuit setup (co-noir create-vk), which v2/v3 ran untimed and therefore never reported",
  "extra_data": "mem/ per-party wall/RSS/CPU files (party skew); features/<c>.artifact-sizes.json proof/VK bytes"
}
MANIFEST

declare -a pids
now_ms() { date +%s%3N; }
# host_load1m: HOST-wide 1-min loadavg at cell start (this is a sysbox on a
# shared mainframe — the load includes other tenants). It is the per-row
# noise context for the absolute seconds; medians + this column let a reader
# judge each number instead of trusting the run was quiet.
row() { echo "$1,$2,$3,$4,$5,$6,$7,${8:-},${9:-},${LOAD1M:-}" >>"$CSV"; }
load_stamp() { LOAD1M=$(awk '{print $1}' /proc/loadavg); }
TIMETMP="$BENCH_OUT/.time_out"
timed() { # circuit proto zk rep phase cmd...   (timeout + peak-RSS/CPU via /usr/bin/time)
  local c=$1 p=$2 z=$3 r=$4 ph=$5; shift 5
  local t0 t1 rc rss cpu
  load_stamp
  t0=$(now_ms)
  /usr/bin/time -f "%M %P" -o "$TIMETMP" \
    timeout -k 15 "$CELL_TIMEOUT" "$@" >>"$BENCH_OUT/${c}_${p}_${z}_r${r}.log" 2>&1; rc=$?
  t1=$(now_ms)
  rss=$(awk 'NF==2{print $1}' "$TIMETMP" 2>/dev/null | tail -1)
  cpu=$(awk 'NF==2{print $2}' "$TIMETMP" 2>/dev/null | tail -1 | tr -d '%')
  row "$c" "$p" "$z" "$r" "$ph" "$(awk "BEGIN{printf \"%.3f\", ($t1-$t0)/1000}")" "$rc" "$rss" "$cpu"
  [[ $rc -eq 124 ]] && DEAD["$(family "$c"):$p"]=1
  return $rc
}
# max RSS (KB) over the 3 parties' /usr/bin/time files (format "%e %M %P")
max_rss3() { awk 'NF==3{print $2}' "$@" 2>/dev/null | sort -n | tail -1; }
reps_for() { if is_big "$1"; then echo 2; else echo 3; fi; }

# Per-cell sub-phase timers (v2.2, ch. 24 §3a item 5): CO_NOIR_PHASE_TIMINGS=1
# makes co-ultrahonk print "[phase-timing] name: X.XXXXXXs" lines to stderr
# (oink/sumcheck/pcs sub-phases; see co-noir/co-ultrahonk/src/lib.rs) for
# EVERY party. The prove cell's combined log already captures all 3 parties'
# stdout+stderr (unattributed to a specific party -- coarse, matching the
# "cumulative blocking-recv wall time per phase" coarseness elsewhere in this
# extension); this pulls just the phase-timing lines into a structured JSON
# per bench cell so per-sub-phase scaling is queryable data, not log-grepping.
# v4 additionally captures co-builder's pkgen/* lines (which resolve pk-gen into
# setup vs per-proof vs allocation) and runs the same extraction on plaindriver
# cells, whose phase names are single-party and therefore appear exactly once.
extract_phase_timings() { # circuit proto zk rep logfile
  local c=$1 p=$2 z=$3 r=$4 log=$5
  local out="$BENCH_OUT/phase-timings/${c}_${p}_${z}_prove_r${r}.json"
  _extract_phase_timings_to "$out" "$c" "$p" "$z" "$r" "$log"
}
_extract_phase_timings_to() { # out circuit proto zk rep logfile [skip_lines]
  # skip_lines: ignore the first N lines of the log. Needed where several timed
  # cells append to one log file (plaindriver prove and solveprove share
  # <c>_plaindriver_zk_r1.log) so each cell's JSON holds only its own phases.
  local out=$1 c=$2 p=$3 z=$4 r=$5 log=$6 skip=${7:-0}
  awk -v c="$c" -v p="$p" -v z="$z" -v r="$r" -v skip="$skip" '
    BEGIN {
      printf "{\n  \"circuit\": \"%s\", \"protocol\": \"%s\", \"zk\": \"%s\", \"rep\": %s,\n", c, p, z, r
      print "  \"_note\": \"one entry per [phase-timing] line seen in the combined 3-party log (v2.2, ch. 24 \xc2\xa73a item 5); NOT attributed to a party -- each phase name normally appears once per party per prove, so ~3x entries per phase name is expected, not a bug. malformed_lines counts lines that matched the marker but failed validation (see v4 note in bench-0_5.sh); it should be 0.\","
      print "  \"entries\": ["
      first = 1; bad = 0
    }
    NR <= skip { next }
    /\[phase-timing\]/ {
      line = $0
      gsub(/\033\[[0-9;]*m/, "", line)
      if (match(line, /\[phase-timing\] ([^:]+): ([0-9.]+)s/, m)) {
        # v4: VALIDATE before emitting. Three MPC parties append to one log, so a
        # spliced line used to yield a broken name/number and hence invalid JSON
        # (the whole file then silently failed to parse downstream). Names are
        # [A-Za-z0-9_/] by construction and the number is always d+.d+; anything
        # else is counted, not emitted.
        if (m[1] ~ /^[A-Za-z0-9_\/]+$/ && m[2] ~ /^[0-9]+\.[0-9]+$/) {
          if (!first) print ","
          first = 0
          printf "    {\"phase\": \"%s\", \"seconds\": %s}", m[1], m[2]
        } else { bad++ }
      } else { bad++ }
    }
    END { print ""; print "  ],"; printf "  \"malformed_lines\": %d\n", bad; print "}" }
  ' "$log" >"$out" 2>/dev/null
}

HAVE_CIRCUIT_INFO=0
"$BIN" circuit-info --help >/dev/null 2>&1 && HAVE_CIRCUIT_INFO=1

# ---- progress + ETA (stdout lands in launcher.log) -------------------------
# Nominal dyadic size from the circuit name; crude v1-measured s/row rates per
# family × config. Estimates are for pacing a human reading the log, not data.
# ETA input only, never data. bb_sha256_compression is dyadic 2^16 (6,778 gate
# rows, but sha's 12 lookup tables add 33,944 table rows) — v2/v3 had 32768 here,
# which is why its estimate read ~20 min for a ~1.5 min cell.
nominal_rows() { case "$1" in
  poseidon) echo 2048;; bb_sha256_compression) echo 65536;; recursion_zk) echo 704000;;
  *2e12) echo 4096;; *2e13) echo 8192;; *2e14) echo 16384;; *2e15) echo 32768;;
  *2e16) echo 65536;; *2e17) echo 131072;; *2e18) echo 262144;;
  *2e19) echo 524288;; *2e20) echo 1048576;; *) echo 100000;; esac; }
est_circuit_secs() { # rough total for all cells of one circuit
  local c=$1 rows rate_rep3 nprove
  rows=$(nominal_rows "$c")
  case "$(family "$c")" in
    poseidon) rate_rep3=0.00050;; sha256) rate_rep3=0.00480;; *) rate_rep3=0.00019;;
  esac
  if is_big "$c"; then nprove=4; else nprove=6; fi   # (zk+nonzk) × reps
  # REP3 proves dominate; add ~30% for witext/split/baselines/verify/overhead.
  awk "BEGIN{printf \"%d\", $rows*$rate_rep3*$nprove*1.3}"
}
SUITE_EST=0; declare -A CIRC_EST
for c in "${CIRCUITS[@]}"; do
  [[ -f "test_vectors/$c/target/$c.json" ]] || continue
  CIRC_EST[$c]=$(est_circuit_secs "$c"); SUITE_EST=$((SUITE_EST + CIRC_EST[$c]))
done
echo "bench v4: ${#CIRCUITS[@]} circuits queued; crude suite estimate ~$((SUITE_EST/60)) min (timeout prunes cells >${CELL_TIMEOUT}s; sha rates are the least certain)"
DONE_EST=0; CIRC_IDX=0; SUITE_T0=$SECONDS
progress() { # called at each circuit start
  local c=$1 rem=$((SUITE_EST - DONE_EST))
  CIRC_IDX=$((CIRC_IDX + 1))
  echo "[$(date -u +%H:%M:%S)] circuit $CIRC_IDX/${#CIRCUITS[@]}: $c (rows~$(nominal_rows "$c"), est ~$(( ${CIRC_EST[$c]:-0} / 60 )) min) — elapsed $(( (SECONDS - SUITE_T0) / 60 )) min, est remaining ~$((rem/60)) min"
}
circuit_done() { # actual vs estimate, per circuit
  local c=$1 t=$2
  DONE_EST=$((DONE_EST + ${CIRC_EST[$c]:-0}))
  echo "[$(date -u +%H:%M:%S)]   $c done in $((t/60))m$((t%60))s (est was ~$(( ${CIRC_EST[$c]:-0} / 60 )) min)"
}

for c in "${CIRCUITS[@]}"; do
  [[ -f "test_vectors/$c/target/$c.json" ]] || { echo "bench: $c missing target artifacts, skipping" | tee -a "$BENCH_OUT/skipped.log"; continue; }
  fam=$(family "$c")
  REPS=$(reps_for "$c")
  progress "$c"; CIRC_T0=$SECONDS
  # witness gen is untimed setup — skip when the artifact already exists
  # (variant witnesses are pre-generated; 2^20 ACVM execution costs minutes)
  [[ -f "test_vectors/$c/target/$c.gz" ]] || (cd "test_vectors/$c" && nargo execute >/dev/null 2>&1)

  # ---- circuit features (once; untimed for the matrix, cheap) ----
  [[ $HAVE_CIRCUIT_INFO -eq 1 ]] && "$BIN" circuit-info \
      --circuit "test_vectors/$c/target/$c.json" --witness "test_vectors/$c/target/$c.gz" \
      >"$BENCH_OUT/features/${c}.circuit-info.json" 2>>"$BENCH_OUT/features/errors.log"
  "$BB" gates --scheme ultra_honk -b "test_vectors/$c/target/$c.json" \
      >"$BENCH_OUT/features/${c}.bbgates.json" 2>/dev/null
  (cd "test_vectors/$c" && nargo info --json 2>/dev/null) >"$BENCH_OUT/features/${c}.nargo-info.json"

  # ---- single-prover baselines ----
  # bb: VK gen timed once, then prove-only with -k (fair vs a prover that has its VK)
  if [[ -z ${DEAD["$fam:bb"]:-} ]]; then
    timed "$c" bb - 1 vkgen \
      "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 \
        -b "test_vectors/$c/target/$c.json" -o "test_vectors/$c/"
    for r in $(seq 1 "$REPS"); do
      timed "$c" bb nonzk "$r" prove \
        "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
          -b "test_vectors/$c/target/$c.json" -w "test_vectors/$c/target/$c.gz" \
          -k "test_vectors/$c/vk" -o "test_vectors/$c/"
      # verifier-time baseline (verify the proof just written, same zk mode)
      timed "$c" bb nonzk "$r" verify \
        "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
          -k "test_vectors/$c/vk" -p "test_vectors/$c/proof" \
          -i "test_vectors/$c/public_inputs"
      timed "$c" bb zk "$r" prove \
        "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 \
          -b "test_vectors/$c/target/$c.json" -w "test_vectors/$c/target/$c.gz" \
          -k "test_vectors/$c/vk" -o "test_vectors/$c/"
      timed "$c" bb zk "$r" verify \
        "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 \
          -k "test_vectors/$c/vk" -p "test_vectors/$c/proof" \
          -i "test_vectors/$c/public_inputs"
    done
  fi
  if [[ -z ${DEAD["$fam:plaindriver"]:-} ]]; then
    # witness-fed prove (boundary-matched to bb prove). Runtime cuts:
    # non-ZK plaindriver only below 2^18 (its ZK-overhead is answered by the
    # small/medium sizes); solve+prove reference only on the base circuits
    # (it exists to quantify the witness-solving boundary once per family).
    for r in $(seq 1 "$REPS"); do
      zmodes=(zk); is_big "$c" || zmodes=(nonzk zk)
      for z in "${zmodes[@]}"; do
        zflag=""; [[ $z == zk ]] && zflag="--zk"
        # v4: CO_NOIR_PHASE_TIMINGS=1 so this cell reports its own setup vs
        # per-proof split. plaindriver ALWAYS writes a VK, so a third of the
        # v2/v3 plaindriver number was per-circuit setup with no way to see it.
        # env(1), not a bash assignment prefix: `VAR=x some_function` leaks the
        # assignment past the call in bash, and `timed` is a function.
        # shellcheck disable=SC2086
        timed "$c" plaindriver "$z" "$r" prove \
          env CO_NOIR_PHASE_TIMINGS=1 \
          "$PLAINDRIVER" --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat \
            --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat \
            --input "test_vectors/$c/Prover.toml" --witness "test_vectors/$c/target/$c.gz" \
            --circuit "test_vectors/$c/target/$c.json" \
            --hasher poseidon2 --out-dir "test_vectors/$c" $zflag
        _extract_phase_timings_to \
          "$BENCH_OUT/phase-timings/${c}_plaindriver_${z}_prove_r${r}.json" \
          "$c" plaindriver "$z" "$r" "$BENCH_OUT/${c}_plaindriver_${z}_r${r}.log"
      done
    done
    # bb cross-verify of the plaindriver ZK proof: the timed cell doubles as a
    # verifier-side parity invariant in the dataset (rc=0 <=> bb accepts our
    # proof with our VK — 0% verifier-side overhead stated as a measurement,
    # not an assumption). Last plaindriver prove above was always zk.
    timed "$c" plaindriver zk 1 verify_bb \
      "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 \
        -k "test_vectors/$c/vk_plaindriver" -p "test_vectors/$c/proof_plaindriver" \
        -i "test_vectors/$c/public_inputs_plaindriver"
    # solveprove also gets phase timings in v4: its 'witness' phase is the plain
    # ACVM solve, i.e. the single-prover denominator for REP3's witext cell.
    case "$c" in poseidon|bb_sha256_compression|recursion_zk)
    pd_log_pre=$(wc -l <"$BENCH_OUT/${c}_plaindriver_zk_r1.log" 2>/dev/null || echo 0)
    timed "$c" plaindriver zk 1 solveprove \
      env CO_NOIR_PHASE_TIMINGS=1 \
      "$PLAINDRIVER" --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat \
        --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat \
        --input "test_vectors/$c/Prover.toml" --circuit "test_vectors/$c/target/$c.json" \
        --hasher poseidon2 --out-dir "test_vectors/$c" --zk
    _extract_phase_timings_to \
      "$BENCH_OUT/phase-timings/${c}_plaindriver_zk_solveprove_r1.json" \
      "$c" plaindriver zk 1 "$BENCH_OUT/${c}_plaindriver_zk_r1.log" "$pd_log_pre" ;;
    esac
  fi

  # ---- REP3 (Shamir deferred, see manifest) ----
  proto=REP3
  if [[ -z ${DEAD["$fam:$proto"]:-} ]]; then
    # VK once per circuit (was per-rep in v1: pure wall-clock waste).
    # v4: TIMED as protocol=co-noir phase=vkgen. This is the whole of the MPC
    # path's per-circuit setup — ACIR parse, structural circuit build with an
    # empty witness, precomputed polynomials, their commitments, CRS load — and
    # it is the number a deployment amortises away by holding the VK. It is
    # protocol-independent (CreateVKConfig has no protocol field), so the one
    # cell covers REP3 and SHAMIR alike. v2/v3 ran it untimed, which is why the
    # MPC setup cost was missing from the dataset entirely.
    timed "$c" co-noir - 1 vkgen \
      env CO_NOIR_PHASE_TIMINGS=1 \
      "$BIN" create-vk --circuit "test_vectors/$c/target/$c.json" \
        --crs ../../co-noir-common/src/crs/bn254_g1.dat --hasher poseidon2 \
        --vk "test_vectors/$c/cosnark_vk"
    _extract_phase_timings_to "$BENCH_OUT/phase-timings/${c}_co-noir_vkgen_r1.json" \
      "$c" co-noir - 1 "$BENCH_OUT/${c}_co-noir_-_r1.log"
    for r in $(seq 1 "$REPS"); do
      [[ -n ${DEAD["$fam:$proto"]:-} ]] && break
      ok=1
      timed "$c" "$proto" - "$r" split \
        "$BIN" split-input --circuit "test_vectors/$c/target/$c.json" \
          --input "test_vectors/$c/Prover.toml" --protocol "$proto" \
          --out-dir "test_vectors/$c" || ok=0
      if [[ $ok -eq 1 ]]; then
        load_stamp
        t0=$(now_ms)
        for i in 0 1 2; do
          CO_NOIR_NET_STATS_JSON="$BENCH_OUT/netstats/${c}_${proto}_witext_r${r}_p${i}.json" \
          CO_NOIR_PHASE_TIMINGS=1 \
          /usr/bin/time -f "%e %M %P" -o "$BENCH_OUT/mem/${c}_${proto}_witext_r${r}_p${i}.time" \
          timeout -k 15 "$CELL_TIMEOUT" \
          "$BIN" generate-witness --input "test_vectors/$c/Prover.toml.$i.shared" \
            --circuit "test_vectors/$c/target/$c.json" --protocol "$proto" \
            --config "configs/party$((i + 1)).toml" \
            --out "test_vectors/$c/$c.gz.$i.shared" \
            >>"$BENCH_OUT/${c}_${proto}_wit_r${r}.log" 2>&1 &
          pids[$i]=$!
        done
        rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=$?; done
        row "$c" "$proto" - "$r" witext "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc" \
          "$(max_rss3 "$BENCH_OUT/mem/${c}_${proto}_witext_r${r}_p"*.time)" ""
        _extract_phase_timings_to "$BENCH_OUT/phase-timings/${c}_${proto}_witext_r${r}.json" \
          "$c" "$proto" - "$r" "$BENCH_OUT/${c}_${proto}_wit_r${r}.log"
        [[ $rc -eq 124 ]] && DEAD["$fam:$proto"]=1
        [[ $rc -ne 0 ]] && ok=0
      fi
      if [[ $ok -eq 1 ]]; then
        for z in nonzk zk; do
          zflag=""; vflag=""
          [[ $z == zk ]] && { zflag="--zk"; vflag="--has-zk"; }
          load_stamp
          t0=$(now_ms)
          for i in 0 1 2; do
            out="test_vectors/$c/cosnark_proof"; pubflag="--public-input test_vectors/$c/cosnark_public_input"
            [[ $i -ne 0 ]] && { out="test_vectors/$c/cosnark_proof.$i.proof"; pubflag=""; }
            # shellcheck disable=SC2086
            CO_NOIR_NET_STATS_JSON="$BENCH_OUT/netstats/${c}_${proto}_prove_${z}_r${r}_p${i}.json" \
            CO_NOIR_NET_STATS_JSON_PKGEN="$BENCH_OUT/netstats/${c}_${proto}_pkgen_${z}_r${r}_p${i}.json" \
            CO_NOIR_PHASE_TIMINGS=1 \
            /usr/bin/time -f "%e %M %P" -o "$BENCH_OUT/mem/${c}_${proto}_prove_${z}_r${r}_p${i}.time" \
            timeout -k 15 "$CELL_TIMEOUT" \
            "$BIN" build-and-generate-proof --witness "test_vectors/$c/$c.gz.$i.shared" \
              --circuit "test_vectors/$c/target/$c.json" \
              --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol "$proto" \
              --hasher poseidon2 --config "configs/party$((i + 1)).toml" \
              --out "$out" $pubflag $zflag --vk "test_vectors/$c/cosnark_vk" \
              >>"$BENCH_OUT/${c}_${proto}_${z}_prove_r${r}.log" 2>&1 &
            pids[$i]=$!
          done
          rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=$?; done
          row "$c" "$proto" "$z" "$r" prove "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc" \
            "$(max_rss3 "$BENCH_OUT/mem/${c}_${proto}_prove_${z}_r${r}_p"*.time)" ""
          [[ $rc -eq 124 ]] && DEAD["$fam:$proto"]=1
          extract_phase_timings "$c" "$proto" "$z" "$r" "$BENCH_OUT/${c}_${proto}_${z}_prove_r${r}.log"
          timed "$c" "$proto" "$z" "$r" verify \
            "$BIN" verify --proof "test_vectors/$c/cosnark_proof" \
              --vk "test_vectors/$c/cosnark_vk" \
              --public-input "test_vectors/$c/cosnark_public_input" \
              --hasher poseidon2 --crs ../../co-noir-common/src/crs/bn254_g2.dat $vflag
        done
      fi

      # ---- Shamir, poseidon family only (v2.2, ch. 24 §3a item 4 / v2.1
      # deferral): REP3-split + translate-witness, reusing this rep's
      # already-generated REP3 witext shares. VK is protocol-independent
      # (CreateVKConfig has no protocol field) so REP3's cosnark_vk is
      # reused as-is. Other families stay deferred (scope: "the poseidon
      # size sweep", per the ask) -- extend the `$fam == poseidon` guard
      # below to widen coverage later. ----
      if [[ $ok -eq 1 && "$fam" == poseidon && -z ${DEAD["$fam:SHAMIR"]:-} ]]; then
        proto2=SHAMIR
        load_stamp
        t0=$(now_ms)
        for i in 0 1 2; do
          CO_NOIR_NET_STATS_JSON="$BENCH_OUT/netstats/${c}_${proto2}_translate_r${r}_p${i}.json" \
          timeout -k 15 "$CELL_TIMEOUT" \
          "$BIN" translate-witness --witness "test_vectors/$c/$c.gz.$i.shared" \
            --src-protocol REP3 --target-protocol SHAMIR \
            --config "configs/party$((i + 1)).toml" \
            --out "test_vectors/$c/shamir_$c.gz.$i.shared" \
            >>"$BENCH_OUT/${c}_${proto2}_translate_r${r}.log" 2>&1 &
          pids[$i]=$!
        done
        rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=$?; done
        row "$c" "$proto2" - "$r" translate "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc" "" ""
        [[ $rc -eq 124 ]] && DEAD["$fam:SHAMIR"]=1
        ok2=1; [[ $rc -ne 0 ]] && ok2=0

        if [[ $ok2 -eq 1 ]]; then
          for z in nonzk zk; do
            zflag=""; vflag=""
            [[ $z == zk ]] && { zflag="--zk"; vflag="--has-zk"; }
            load_stamp
            t0=$(now_ms)
            for i in 0 1 2; do
              out="test_vectors/$c/cosnark_proof_shamir"; pubflag="--public-input test_vectors/$c/cosnark_public_input_shamir"
              [[ $i -ne 0 ]] && { out="test_vectors/$c/cosnark_proof_shamir.$i.proof"; pubflag=""; }
              # shellcheck disable=SC2086
              CO_NOIR_NET_STATS_JSON="$BENCH_OUT/netstats/${c}_${proto2}_prove_${z}_r${r}_p${i}.json" \
              CO_NOIR_NET_STATS_JSON_PKGEN="$BENCH_OUT/netstats/${c}_${proto2}_pkgen_${z}_r${r}_p${i}.json" \
              CO_NOIR_PHASE_TIMINGS=1 \
              /usr/bin/time -f "%e %M %P" -o "$BENCH_OUT/mem/${c}_${proto2}_prove_${z}_r${r}_p${i}.time" \
              timeout -k 15 "$CELL_TIMEOUT" \
              "$BIN" build-and-generate-proof --witness "test_vectors/$c/shamir_$c.gz.$i.shared" \
                --circuit "test_vectors/$c/target/$c.json" \
                --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol "$proto2" \
                --hasher poseidon2 --config "configs/party$((i + 1)).toml" \
                --out "$out" $pubflag $zflag --vk "test_vectors/$c/cosnark_vk" \
                >>"$BENCH_OUT/${c}_${proto2}_${z}_prove_r${r}.log" 2>&1 &
              pids[$i]=$!
            done
            rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=$?; done
            row "$c" "$proto2" "$z" "$r" prove "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc" \
              "$(max_rss3 "$BENCH_OUT/mem/${c}_${proto2}_prove_${z}_r${r}_p"*.time)" ""
            [[ $rc -eq 124 ]] && DEAD["$fam:SHAMIR"]=1
            extract_phase_timings "$c" "$proto2" "$z" "$r" "$BENCH_OUT/${c}_${proto2}_${z}_prove_r${r}.log"
            timed "$c" "$proto2" "$z" "$r" verify \
              "$BIN" verify --proof "test_vectors/$c/cosnark_proof_shamir" \
                --vk "test_vectors/$c/cosnark_vk" \
                --public-input "test_vectors/$c/cosnark_public_input_shamir" \
                --hasher poseidon2 --crs ../../co-noir-common/src/crs/bn254_g2.dat $vflag
          done
        fi
      fi
    done
  else
    row "$c" REP3 - 0 SKIPPED_family_timeout 0 1
  fi
  # artifact sizes (bytes) — site data; must run BEFORE cleanup
  {
    echo "{"
    first=1
    for f in proof public_inputs vk proof_plaindriver public_inputs_plaindriver \
             vk_plaindriver cosnark_proof cosnark_public_input cosnark_vk \
             cosnark_proof_shamir cosnark_public_input_shamir; do
      p="test_vectors/$c/$f"
      [[ -f $p ]] || continue
      [[ $first -eq 0 ]] && echo ","
      first=0
      printf '  "%s": %s' "$f" "$(stat -c %s "$p")"
    done
    echo; echo "}"
  } >"$BENCH_OUT/features/${c}.artifact-sizes.json"
  # scoped cleanup between circuits (same patterns as compare*.sh)
  find "test_vectors/$c" -maxdepth 1 \( -name "*.shared" -o -name "cosnark_*" \
    -o -name "vk" -o -name "proof" -o -name "public_inputs" \) -type f -delete
  circuit_done "$c" $((SECONDS - CIRC_T0))
done

echo "bench-0_5 v4: done — results in $CSV"
