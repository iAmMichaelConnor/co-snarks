#!/usr/bin/env bash
# Serial benchmark matrix for bb, plaindriver, REP3, and Poseidon-only SHAMIR.
# Set BENCH_OUT to a new result directory; BENCH_CIRCUITS overrides the circuit
# list. CELL_TIMEOUT caps each cell. Run on an otherwise quiet host.
# results.csv records wall time, status, peak RSS, and host load. netstats/ and
# phase-timings/ capture communication and setup/witness/prove breakdowns.
# Witness-fed proving and circuit setup are timed separately. The baselines
# self-verify; co-noir proving requires a separate verification cell. Rayon
# limits apply to Rust provers; bb manages its own thread pool.
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
# Per-cell wall-clock cap, in seconds.
CELL_TIMEOUT="${CELL_TIMEOUT:-1800}"

# Ascending size per family so a timeout can prune the larger sizes.
# BENCH_CIRCUITS overrides the list (space-separated) — smoke tests only.
if [[ -n ${BENCH_CIRCUITS:-} ]]; then
  read -r -a CIRCUITS <<<"$BENCH_CIRCUITS"
else
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
cargo build --locked --release --bin co-noir --bin plaindriver || exit 1

git_desc=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
git_branch=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
git_dirty=$(git -C "$ROOT" diff --quiet 2>/dev/null && echo clean || echo dirty)
nargo_v=$(nargo --version 2>/dev/null | head -1 || echo unknown)
bb_prov=$([[ -f "$(dirname "$BB")/PROVENANCE.txt" ]] && head -1 "$(dirname "$BB")/PROVENANCE.txt" || echo "no PROVENANCE.txt")
# Unquoted heredoc: keep literal shell syntax out of interpolated prose.
cat >"$BENCH_OUT/manifest.json" <<MANIFEST
{
  "benchmark": "co-SNARK proving matrix",
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
  "protocols": "bb plaindriver REP3 SHAMIR (SHAMIR uses translated REP3 witnesses for Poseidon only)",
  "zk_modes": "nonzk zk",
  "reps": "3 (2 for >=2^18 circuits)",
  "cell_timeout_s": ${CELL_TIMEOUT},
  "fairness": "bb prove receives a precomputed VK; plaindriver prove receives a witness. solveprove is separate. bb and plaindriver self-verify; co-noir verification is separate. Rayon limits only the Rust provers.",
  "taxonomy_v4": "SETUP: circuit-only work and VK commitments. WITNESS: per-proof builder work over witness values. PROVE: witness commitments, grand products, sumcheck and PCS. Allocation and self-verification are separate in phase-split.csv.",
  "netstats": "Per-phase, per-party JSON files. Prove counters include pkgen; subtract matching pkgen snapshots for prove-proper. rounds counts blocking receive boundaries; recv_msgs counts frames. Setup uses no network.",
  "phase_timings": "CO_NOIR_PHASE_TIMINGS=1 emits prover and pkgen subphases. phase-timings JSON holds one entry per valid log line, normally three per phase for MPC. Entries are not attributed to individual parties.",
  "tiers_csv": "Local/LAN/WAN transfer model from received-byte histograms; these are estimates, not network measurements.",
  "features": "per circuit JSONs in features/ (co-noir circuit-info, bb gates, nargo info)",
  "network": "loopback (single host)",
  "csv_schema": "circuit,protocol,zk,rep,phase,seconds,rc,max_rss_kb,cpu_pct,host_load1m. Nonzero rc means failure; 124 means timeout. MPC peak RSS is the maximum over parties. CPU percent is blank for MPC. host_load1m is host-wide.",
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

# Extract validated phase-timing lines from combined party logs.
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
      print "  \"_note\": \"One entry per valid phase-timing line; combined MPC logs normally contain three entries per phase. malformed_lines counts invalid marker lines.\","
      print "  \"entries\": ["
      first = 1; bad = 0
    }
    NR <= skip { next }
    /\[phase-timing\]/ {
      line = $0
      gsub(/\033\[[0-9;]*m/, "", line)
      if (match(line, /\[phase-timing\] ([^:]+): ([0-9.]+)s/, m)) {
        # Validate before emitting. Three MPC parties append to one log, so a
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
# Rough pacing estimates only; these are not benchmark measurements.
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
declare -A CIRCUIT_PATH WITNESS_PATH
# Tracked examples keep artifacts beside Nargo.toml; nargo writes to target/.
# Compile source-only examples and generate absent witnesses before timing.
for c in "${CIRCUITS[@]}"; do
  dir="test_vectors/$c"
  [[ -f "$dir/Nargo.toml" ]] || { echo "bench: unknown circuit $c" >&2; exit 1; }
  if [[ -f "$dir/target/$c.json" && -f "$dir/target/$c.gz" ]]; then
    CIRCUIT_PATH[$c]="$dir/target/$c.json"; WITNESS_PATH[$c]="$dir/target/$c.gz"
  elif [[ -f "$dir/$c.json" && -f "$dir/$c.gz" ]]; then
    CIRCUIT_PATH[$c]="$dir/$c.json"; WITNESS_PATH[$c]="$dir/$c.gz"
  else
    (cd "$dir" && nargo execute) || exit 1
    CIRCUIT_PATH[$c]="$dir/target/$c.json"; WITNESS_PATH[$c]="$dir/target/$c.gz"
  fi
  [[ -f "${CIRCUIT_PATH[$c]}" && -f "${WITNESS_PATH[$c]}" ]] || {
    echo "bench: circuit or witness artifact missing for $c" >&2; exit 1;
  }
  CIRC_EST[$c]=$(est_circuit_secs "$c"); SUITE_EST=$((SUITE_EST + CIRC_EST[$c]))
done
echo "bench: ${#CIRCUITS[@]} circuits queued; crude suite estimate ~$((SUITE_EST/60)) min (timeout prunes cells >${CELL_TIMEOUT}s; sha rates are the least certain)"
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
  circuit="${CIRCUIT_PATH[$c]}"; witness="${WITNESS_PATH[$c]}"
  fam=$(family "$c")
  REPS=$(reps_for "$c")
  # These fixtures contain public inner proofs and use BB's public profile.
  recursion_flags=()
  case "$c" in recursion|recursion_zk) recursion_flags=(--reveal-recursion-inputs);; esac
  progress "$c"; CIRC_T0=$SECONDS

  # ---- circuit features (once; untimed for the matrix, cheap) ----
  [[ $HAVE_CIRCUIT_INFO -eq 1 ]] && "$BIN" circuit-info \
      --circuit "$circuit" --witness "$witness" \
      >"$BENCH_OUT/features/${c}.circuit-info.json" 2>>"$BENCH_OUT/features/errors.log"
  "$BB" gates --scheme ultra_honk -b "$circuit" \
      >"$BENCH_OUT/features/${c}.bbgates.json" 2>/dev/null
  (cd "test_vectors/$c" && nargo info --json 2>/dev/null) >"$BENCH_OUT/features/${c}.nargo-info.json"

  # ---- single-prover baselines ----
  # bb: VK gen timed once, then prove-only with -k (fair vs a prover that has its VK)
  if [[ -z ${DEAD["$fam:bb"]:-} ]]; then
    timed "$c" bb - 1 vkgen \
      "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 \
        -b "$circuit" -o "test_vectors/$c/"
    for r in $(seq 1 "$REPS"); do
      timed "$c" bb nonzk "$r" prove \
        "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
          -b "$circuit" -w "$witness" \
          -k "test_vectors/$c/vk" -o "test_vectors/$c/"
      # verifier-time baseline (verify the proof just written, same zk mode)
      timed "$c" bb nonzk "$r" verify \
        "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
          -k "test_vectors/$c/vk" -p "test_vectors/$c/proof" \
          -i "test_vectors/$c/public_inputs"
      timed "$c" bb zk "$r" prove \
        "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 \
          -b "$circuit" -w "$witness" \
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
        # Phase timers separate setup from per-proof work.
        # shellcheck disable=SC2086
        timed "$c" plaindriver "$z" "$r" prove \
          env CO_NOIR_PHASE_TIMINGS=1 \
          "$PLAINDRIVER" --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat \
            --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat \
            --input "test_vectors/$c/Prover.toml" --witness "$witness" \
            --circuit "$circuit" \
            --hasher poseidon2 --out-dir "test_vectors/$c" "${recursion_flags[@]}" $zflag
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
    # solveprove phase timings: its 'witness' phase is the plain
    # ACVM solve, i.e. the single-prover denominator for REP3's witext cell.
    case "$c" in poseidon|bb_sha256_compression|recursion_zk)
    pd_log_pre=$(wc -l <"$BENCH_OUT/${c}_plaindriver_zk_r1.log" 2>/dev/null || echo 0)
    timed "$c" plaindriver zk 1 solveprove \
      env CO_NOIR_PHASE_TIMINGS=1 \
      "$PLAINDRIVER" --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat \
        --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat \
        --input "test_vectors/$c/Prover.toml" --circuit "$circuit" \
        --hasher poseidon2 --out-dir "test_vectors/$c" "${recursion_flags[@]}" --zk
    _extract_phase_timings_to \
      "$BENCH_OUT/phase-timings/${c}_plaindriver_zk_solveprove_r1.json" \
      "$c" plaindriver zk 1 "$BENCH_OUT/${c}_plaindriver_zk_r1.log" "$pd_log_pre" ;;
    esac
  fi

  # ---- REP3 (Shamir deferred, see manifest) ----
  proto=REP3
  if [[ -z ${DEAD["$fam:$proto"]:-} ]]; then
    # Circuit-only VK setup is timed once and reused by REP3 and SHAMIR.
    timed "$c" co-noir - 1 vkgen \
      env CO_NOIR_PHASE_TIMINGS=1 \
      "$BIN" create-vk --circuit "$circuit" \
        --crs ../../co-noir-common/src/crs/bn254_g1.dat --hasher poseidon2 \
        --vk "test_vectors/$c/cosnark_vk" "${recursion_flags[@]}"
    _extract_phase_timings_to "$BENCH_OUT/phase-timings/${c}_co-noir_vkgen_r1.json" \
      "$c" co-noir - 1 "$BENCH_OUT/${c}_co-noir_-_r1.log"
    for r in $(seq 1 "$REPS"); do
      [[ -n ${DEAD["$fam:$proto"]:-} ]] && break
      ok=1
      timed "$c" "$proto" - "$r" split \
        "$BIN" split-input --circuit "$circuit" \
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
            --circuit "$circuit" --protocol "$proto" \
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
              --circuit "$circuit" \
              --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol "$proto" \
              --hasher poseidon2 --config "configs/party$((i + 1)).toml" \
              --out "$out" $pubflag $zflag --vk "test_vectors/$c/cosnark_vk" "${recursion_flags[@]}" \
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

      # Poseidon SHAMIR cells reuse this repetition's translated REP3 witness.
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
                --circuit "$circuit" \
                --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol "$proto2" \
                --hasher poseidon2 --config "configs/party$((i + 1)).toml" \
                --out "$out" $pubflag $zflag --vk "test_vectors/$c/cosnark_vk" "${recursion_flags[@]}" \
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

[[ $(wc -l <"$CSV") -gt 1 ]] || { echo "bench: no measurements recorded" >&2; exit 1; }

echo "bench-0_5: done — results in $CSV"
