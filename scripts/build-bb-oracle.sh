#!/usr/bin/env bash
# Build a trustworthy bb parity oracle from source at an exact tag, and write a
# PROVENANCE.txt beside it. Prebuilt release binaries are NOT trustworthy
# oracles: a release binary can predate the tag's source tree (the 5.0.0-rc.2
# lesson — its binary predated the entity reorder and emitted old-order VKs).
#
# Usage:
#   scripts/build-bb-oracle.sh [TAG] [OUT_DIR] [BB_REPO]
#     TAG      defaults to BARRETENBERG_VERSION from versions.env (v-prefixed)
#     OUT_DIR  defaults to the binary directory in versions.env
#     BB_REPO  defaults to ~/aztec-packages
#
# Optionally set CHECK_AGAINST=/path/to/other/bb to byte-compare write_vk
# output of the fresh build against a candidate prebuilt binary.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/versions.env"

TAG=${1:-v$BARRETENBERG_VERSION}
OUT_DIR=${2:-"$(dirname "$BARRETENBERG_BINARY_DEFAULT")"}
BB_REPO=${3:-"$HOME/aztec-packages"}
# Leave ~20% of the box free (shared-mainframe policy)
JOBS=${CARGO_BUILD_JOBS:-8}

command -v cmake >/dev/null || { echo "ERROR: cmake not found"; exit 1; }
CC=${CC:-$(command -v clang-20 || command -v clang)} || { echo "ERROR: clang not found"; exit 1; }
CXX=${CXX:-$(command -v clang++-20 || command -v clang++)}

git -C "$BB_REPO" rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  || { echo "ERROR: tag $TAG not found in $BB_REPO"; exit 1; }
COMMIT=$(git -C "$BB_REPO" rev-list -n 1 "$TAG")

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bb-oracle-XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== Exporting barretenberg/cpp at $TAG ($COMMIT) from $BB_REPO"
git -C "$BB_REPO" archive "$TAG" barretenberg/cpp | tar -x -C "$WORK_DIR"

echo "== Building bb (preset default, -DAVM=OFF -DBB_LITE=OFF, -j$JOBS)"
cd "$WORK_DIR/barretenberg/cpp"
CC="$CC" CXX="$CXX" cmake --preset default -DAVM=OFF -DBB_LITE=OFF
cmake --build build --target bb -j "$JOBS"

BB_BIN=$(find build -name bb -type f | head -1)
[[ -n "$BB_BIN" && -x "$BB_BIN" ]] || { echo "ERROR: bb binary not produced"; exit 1; }

mkdir -p "$OUT_DIR"
install -m 755 "$BB_BIN" "$OUT_DIR/bb"
cat > "$OUT_DIR/PROVENANCE.txt" <<EOF
built from $(basename "$BB_REPO") tag $TAG (${COMMIT:0:12}), $("$CC" --version | head -1 | awk '{print $1"-"$3}'), preset default, -DAVM=OFF -DBB_LITE=OFF, $(date +%F)
built by $REPO_ROOT/scripts/build-bb-oracle.sh
note: source-built bb prints a placeholder --version (zeros) — expected.
EOF

echo "== Installed $OUT_DIR/bb"
cat "$OUT_DIR/PROVENANCE.txt"

# Optional: compare a candidate prebuilt binary's write_vk bytes against the
# fresh source build (catches a release binary that predates the tag's tree).
if [[ -n "${CHECK_AGAINST:-}" ]]; then
  CIRCUIT_JSON=$(find "$REPO_ROOT/co-noir/co-noir/examples/test_vectors" -name '*.json' -path '*/target/*' | sort | head -1)
  [[ -n "$CIRCUIT_JSON" ]] || { echo "ERROR: no compiled circuit found for the write_vk check (run examples/compile.sh first)"; exit 1; }
  echo "== Byte-comparing write_vk output vs $CHECK_AGAINST (circuit: $CIRCUIT_JSON)"
  mkdir -p "$WORK_DIR/vk_a" "$WORK_DIR/vk_b"
  "$OUT_DIR/bb" write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$CIRCUIT_JSON" -o "$WORK_DIR/vk_a/"
  "$CHECK_AGAINST" write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$CIRCUIT_JSON" -o "$WORK_DIR/vk_b/"
  if cmp "$WORK_DIR/vk_a/vk" "$WORK_DIR/vk_b/vk"; then
    echo "OK: candidate binary's VK is byte-identical to the source build"
  else
    echo "MISMATCH: $CHECK_AGAINST does not match the source-built oracle — do NOT use it as an oracle"
    exit 1
  fi
fi
