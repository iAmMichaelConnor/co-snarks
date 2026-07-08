# Chapter 14 — Phase 0 + Phase 2 command log (exact commands, in order, with outcomes)

*A faithful, chronological record of every command run during Phase 0
(validate the co-noir pipeline at the current pin), including the ones that
FAILED and why — plus the doc-improvement notes they motivate (§9). Machine:
186-core / 752 GB Linux box; repo = `~/co-snarks` @ `36da0ea8` (upstream main,
2026-07-06). Started 2026-07-08.*

Conventions: `[OK]` = succeeded, `[FAIL]` = failed (kept deliberately — the
failure modes are the most useful content here). Commands run from the repo
root unless a `cd` is shown.

## 1. Pin re-verification (before touching anything)

```bash
# [OK] co-snarks repo state: main @ 36da0ea8 (2026-07-06), clean vs origin/main
git log -1 --format='%h %ad %s' --date=short
git status -sb

# [OK] co-noir's claimed bb compatibility pin (v5.0.0-nightly.20260324)
grep -rn "nightly" co-noir/co-noir/Readme.md

# [OK] target branch re-check: v5-next had moved same-day (289aaec1e0 → d5cfa2a32f)…
cd ~/aztec-packages-private
git fetch origin v5-next
git log -1 --format='%h %ad %s' --date=short origin/v5-next

# [OK] …but its bb + noir trees are UNCHANGED — still ≡ public v5.0.0-nightly.20260708
# (both diffs empty ⇒ the ch. 03 gap analysis remains valid)
git diff --stat v5.0.0-nightly.20260708 origin/v5-next -- barretenberg   # empty
git diff --stat 289aaec1e0 origin/v5-next -- barretenberg noir           # empty
```

Lesson: the *branch* moving does not mean the *bb tree* moved — always diff
the subtree against the last-known-equivalent public tag, not just compare
commit hashes.

## 2. Toolchain (first failure of the day)

```bash
# [FAIL] first build attempt — default rustc was 1.85.0
cargo build --release
#   error: rustc 1.85.0 is not supported by the following packages:
#   acir@…, ruint@1.18.0, taceo-ark-serde-compat@0.5.0, ultrahonk@0.6.0 … require rustc 1.90
# Root cause: workspace Cargo.toml declares rust-version = "1.90", but there is
# no rust-toolchain.toml in the repo, so rustup silently uses the default.

# [OK] fix: install 1.90 and pin it as a directory override (repo-local, not global)
rustup install 1.90
rustup override set 1.90          # from within ~/co-snarks

# [OK] rebuild — 1m17s on 186 cores
cargo build --release             # Finished `release` profile … in 1m 17s
# produces target/release/{co-noir,plaindriver,…}
```

Gotcha (self-inflicted, worth recording): piping build output through
`| tail` masks cargo's exit code — the harness reported "exit 0" for the
FAILED build above because `tail` succeeded. Use `${pipestatus[1]}` (zsh) /
`${PIPESTATUS[0]}` (bash) or `set -o pipefail` when scripting builds.

## 3. Reference binaries for the parity oracle (nargo + bb at the pin)

The pins come from `co-noir/co-noir/examples/compare.sh` header:
`NARGO_VERSION=1.0.0-beta.20`, `BARRETENBERG_VERSION=5.0.0-nightly.20260324`,
`BARRETENBERG_BINARY=~/.bb/bb`.

```bash
# [OK] state check: wrong versions were installed (nargo beta.18, bb 0.72.1)
nargo --version        # 1.0.0-beta.18  → needs beta.20
~/.bb/bb --version     # 0.72.1         → needs 5.0.0-nightly.20260324

# [OK] nargo via noirup — clean
noirup -v 1.0.0-beta.20
nargo --version        # nargo version = 1.0.0-beta.20

# [FAIL] bb via the installed bbup — corrupt download
~/.bb/bbup -v 5.0.0-nightly.20260324
#   gzip: stdin: not in gzip format / tar: Child returned status 1
# Root cause: the OLD bbup constructs
#   …/releases/download/aztec-packages-v${version}/barretenberg-…tar.gz
# but v5-era nightlies are published under the tag `v${version}` (no
# `aztec-packages-` prefix), so it downloaded a 404 HTML page and untarred it.

# [OK] diagnosis: probe both tag shapes; only the unprefixed one exists
curl -sIL -o /dev/null -w '%{http_code}' \
  https://github.com/AztecProtocol/aztec-packages/releases/download/v5.0.0-nightly.20260324/barretenberg-amd64-linux.tar.gz   # 200
# (aztec-packages-v… variant → 404)

# [OK] fix: fetch the official release tarball directly, bypass bbup
cd ~/.bb
curl -sL https://github.com/AztecProtocol/aztec-packages/releases/download/v5.0.0-nightly.20260324/barretenberg-amd64-linux.tar.gz -o bb-nightly.tar.gz
tar xzf bb-nightly.tar.gz
./bb --version        # 5.0.0-nightly.20260324  ✓
```

Note: downloading *public* release binaries is inbound-only and does not
touch the project confidentiality rule (nothing was uploaded anywhere).

## 4. Task 0.1 — workspace test suite

```bash
# full tests package, includes the bb-KAT byte-equality proof tests
# (tests/tests/noir/proof_tests/{plain,plaindriver,rep3,shamir}.rs)
cargo test -p tests --release
# detached run; log: <scratchpad>/test-suite.log
# check status:  pgrep -f 'cargo test' ; grep -E '^test result|TEST_EXIT' <log>
```

**FINAL RESULT (2026-07-08): 603 passed, 0 failed** — circom binary 346
(769.8 s), mpc binary 163 (19.9 s), noir binary 94 (6.5 s), plus doc-tests.
118 tests "ignored" are the suite's default-skipped slow cases (run with
`-- --ignored` if ever needed). The noir binary includes the bb-KAT proof
byte-equality tests (plain/plaindriver/REP3/Shamir) — all green.

Why the suite is slow even on 186 cores: it is an *integration* suite —
every test does real 3-party MPC proving; the circom binary alone contains
several hundred such tests and binaries run one-at-a-time.

## 5. Task 0.2 — 3-party local REP3 demo  ✅

Prerequisites verified present in-tree (no setup needed):
- party configs `co-noir/co-noir/examples/configs/party{1,2,3}.toml`
  (localhost ports 10000–10002, mutual TLS);
- TLS material `examples/data/{key,cert}{0,1,2}.der`;
- CRS `co-noir/co-noir-common/src/crs/bn254_{g1,g2}.dat`.

```bash
# [FAIL] first attempt — ran from co-noir/co-noir/. The script's relative paths
# (test_vectors/, configs/, ../../co-noir-common/…) resolve from examples/.
cd ~/co-snarks/co-noir/co-noir && bash examples/run_full_poseidon.sh   # wrong cwd

# [OK] must be run FROM the examples directory:
cd ~/co-snarks/co-noir/co-noir/examples
bash run_full_poseidon.sh
# pipeline: split-input → 3× generate-witness (MPC) → create-vk →
#           3× build-and-generate-proof (MPC, mutual TLS on localhost) → verify
# → "Proof verified successfully", exit 0
```

Results (poseidon circuit, REP3, keccak transcript, non-ZK, 186-core box):
- witness extension: ~11 ms/party MPC time; proving-key build ~10.5 ms;
  **proof generation ~752 ms per party** (all three within 0.5 ms of each
  other — they run the same synchronized protocol); verify 3.3 ms.
- **All three parties' proofs are byte-identical** (`md5sum proof.{0,1,2}.proof`
  agree). Empirically confirms ch. 01/02: there is no "proof-shard
  recombination" — every party emits the complete, standard proof.

## 6. Task 0.3 — live cross-verification vs real bb

```bash
# [RUNNING at time of writing] full MPC matrix: 29 circuits ×
# {poseidon2, keccak} × {ZK, non-ZK}, REP3 3-party proving, then 4-way
# cross-verification with the real bb binary (our/their proof × our/their VK)
cd ~/co-snarks/co-noir/co-noir/examples
bash compare_mpc.sh          # detached via setsid nohup; log in scratchpad
```

Operational gotchas hit while orchestrating (worth knowing):
- `compare_mpc.sh` runs `bash cleanup.sh` after EVERY circuit — it deletes
  proof/witness artifacts in `examples/` and `test_vectors/`. Don't keep
  by-hand artifacts there while it runs (it deleted our demo outputs
  mid-experiment; soundness rig moved to an isolated copy, §7).
- The script auto-invokes `bbup`/`noirup` on version mismatch — with a stale
  bbup that path silently installs garbage (§3). Pre-install the right
  versions so the check no-ops.

*(Result recorded in §6.1 when complete.)*

### 6.1 FINAL RESULT (2026-07-08): all 29 circuits, ZERO errors ✅

Completed 14:31. Every circuit passed all checks: co-noir REP3 proof bytes
== bb proof bytes (non-ZK, both hashers), public inputs match, and all four
proof×VK cross-verifications accepted by real bb — poseidon2 and keccak,
ZK and non-ZK. (`grep -c '::error' compare_mpc.log` → 0.)
Not yet run: the slow set (`aes128`, `bb_sha256_compression`,
`recursion_zk`) — set `TEST_SLOWER_CIRCUITS=1` in the script.

Monitoring gotcha (cost ~50 min of imagined "still running"): checking the
detached job with `pgrep -f compare_mpc.sh` from an orchestrating shell
whose own command line contains that string **matches itself** — the job
had long finished. Use `pgrep -x` on the process name, or check the log's
mtime, or have the job write a sentinel line on exit.

### 6.2 First benchmark data points (poseidon circuit, poseidon2 hasher, non-ZK)

Indicative only — plan item 0.5 (proper matrix: sizes × REP3/Shamir × ZK) is
still to come. 186-core box, all local.

| prover | what's measured | time |
|---|---|---|
| bb (single prover, native C++) | whole `bb prove` process incl. startup | ~0.07–0.08 s |
| co-noir REP3 3-party MPC | internal "Generate proof took" per party | ~0.75 s |
| plaindriver (plain Rust, single prover) | whole process: CRS load + witness ext + prove + **verify** | ~1.5 s |

Honest caveats: the three rows measure different spans (bb row includes
process startup but not witness generation; the plaindriver row includes CRS
parsing and a verification pass; the REP3 row is the proving stage only).
Even so, the headline is plausible and matches Taceo's public claim: MPC
proving is roughly ~10× a plain bb prove for a small circuit on loopback
networking — losing ~an order of magnitude, not several.

### 6.3 Thread-count scaling for 3 co-located parties (measured 2026-07-08)

Question (Mike): would raising `compare_mpc.sh`'s `RAYON_NUM_THREADS` cap
from `nproc/3` to 50% of the box speed things up? **Measured answer: no —
it's strictly slower.** 3-party REP3 proving of poseidon on the 186-core
box, `Generate proof took` per party (2–3 reps each):

| threads/party | total threads vs cores | proving time |
|---|---|---|
| 16 | 26% | **~410–428 ms (fastest)** |
| 32 | 52% | ~460–475 ms |
| 62 = nproc/3 (script default) | 100% | ~520–560 ms |
| 93 = 50% each (proposed) | 150% (oversubscribed) | ~640 ms (+23%) |
| 186 = all cores each | 300% (oversubscribed) | ~950 ms (+80%) |

Two effects: (a) oversubscription always loses — the three parties advance
in lockstep, so contention just adds scheduling latency at every sync point;
(b) for *small* circuits, per-party parallelism overhead (fork/join over
tiny polynomials) exceeds its benefit, so fewer threads win. Larger circuits
will shift the optimum up — re-measure in the 0.5 benchmark matrix.
✏️ Script updated (local): default unchanged (`nproc/3`) but now
env-overridable (`RAYON_NUM_THREADS=16 bash compare_mpc.sh`), with these
numbers in a comment. NB the run_full_* demo scripts set no cap at all —
each party defaults to all 186 cores (3× oversubscription): that's why the
demo measured ~752 ms vs the ~520 ms the same proof takes at nproc/3.

## 7. Task 0.4 — soundness spot-checks  ✅ (with 2 findings)

Isolated rig (so the compare run can't clean it up): copy the poseidon test
vector to a scratch dir, prove with the **plaindriver** (plain single-prover
binary, same Rust codebase), then tamper.

```bash
# [OK] setup — proof artifacts in isolation
cp -r ~/co-snarks/co-noir/co-noir/examples/test_vectors/poseidon <scratch>/soundness/
cd <scratch>/soundness/poseidon && nargo execute
~/co-snarks/target/release/plaindriver \
  --prover-crs …/crs/bn254_g1.dat --verifier-crs …/crs/bn254_g2.dat \
  --input Prover.toml --circuit target/poseidon.json --hasher poseidon2 --out-dir .
# artifact sizes confirm ch. 04 §5 constants: proof 13120 B = 410 fields (non-ZK),
# VK 3680 B = 115 fields ✓
```

Tamper matrix — each case verified with BOTH verifiers
(`co-noir verify` and `bb verify --scheme ultra_honk --oracle_hash poseidon2
--disable_zk` at the pin). Exit code: 0 = accept, 1 = reject, 101 = Rust panic.

| case | co-noir | bb | verdict |
|---|---|---|---|
| baseline (untampered) | 0 accept | 0 accept | ✓ completeness |
| flip byte @100 (commitment region) | 1 reject | 1 reject | ✓ |
| flip byte @6000 (sumcheck region) | 1 reject | 1 reject | ✓ |
| flip byte @13000 (KZG tail) | **101 panic** | 1 reject | ⚠ finding 2 |
| wrong public input (last byte) | 1 reject | 1 reject | ✓ |
| tampered VK (byte @600) | **101 panic** | 1 reject | ⚠ finding 2 |
| truncated proof (−32 B) | 1 reject | 1 reject | ✓ |
| **extended proof (+32 zero B)** | **0 ACCEPT** | 1 reject | **⚠ finding 1** |

**Finding 1 — proof-not-fully-consumed (parity divergence, predicted by
ch. 13 §3.4):** co-noir's verifier accepts a valid proof with trailing junk
appended; bb rejects it. Not a forgery vector by itself (the embedded proof is
genuine), but it breaks byte-strictness parity with bb and could mask
length-related bugs. → add a "transcript fully consumed" check during the
Phase 2 work (we'll be in that code anyway).

**Finding 2 — panic instead of clean reject on malformed curve points:**
tampering a G1 point (in proof KZG tail or VK) hits ark-ec's
`assertion failed: point.is_on_curve()` (ark-ec 0.5.0 short_weierstrass
affine.rs:72) — the verifier *process crashes* (exit 101) where bb returns a
clean "verification failed". Soundness is intact (off-curve points can't
verify), but it's a DoS/robustness divergence: a verifier service fed
malicious proofs would crash rather than reject. → co-noir should use
fallible deserialization (`from_random_bytes`/checked decompress that returns
`Err`) at the proof/VK parsing boundary. Record for Phase 2.

Soundness conclusion: **no false accepts in any tamper case** — the pipeline
at the pin is sound under these spot-checks; the two findings are
strictness/robustness divergences, not soundness holes.

## 8. Environment summary (what a fresh machine needs)

| Requirement | Version | How obtained |
|---|---|---|
| rustc/cargo | **1.90** (workspace `rust-version`) | `rustup install 1.90 && rustup override set 1.90` |
| nargo | 1.0.0-beta.20 | `noirup -v 1.0.0-beta.20` |
| bb | 5.0.0-nightly.20260324 | direct tarball download (bbup broken for v5 nightlies, §3) |
| CRS, TLS certs, party configs | — | already in-tree |

## 9. Doc-improvement notes (for co-noir / barretenberg READMEs)

Accumulated as failures/friction are hit; ✏️ = applied locally (never pushed).

1. **co-noir `Readme.md` / root README: no Rust version stated.** The
   workspace requires rustc 1.90 (`rust-version` in Cargo.toml) but no README
   mentions it and there is no `rust-toolchain.toml`, so a default-toolchain
   build dies with a wall of per-crate errors. Fix: one line in the README
   ("requires Rust ≥ 1.90") — or better, commit a `rust-toolchain.toml`.
2. **`examples/compare.sh` & `compare_mpc.sh`: bbup instructions are stale.**
   The scripts auto-run `bbup -v $BARRETENBERG_VERSION` when the version
   mismatches, but old bbup binaries use the `aztec-packages-v*` release-tag
   URL shape and silently install garbage ("not in gzip format"). The comment
   block in the scripts already hints at this ("If bb is causing problems…").
   Fix: state the direct-download fallback URL shape
   (`releases/download/v<VER>/barretenberg-amd64-linux.tar.gz`) or pin a
   known-good bbup.
3. **barretenberg (aztec-packages): release-tag rename broke downstream
   installers.** The move from `aztec-packages-v*` to `v*` tags is exactly
   what broke bbup here; worth a note in bb's release docs that old bbup
   versions predate the rename. (Can't fix upstream — confidentiality rule —
   but recorded for when Aztec-side docs are touched through normal work.)
4. ✏️ **`examples/*.sh` must be run from the `examples/` directory** — every
   relative path (`test_vectors/`, `configs/`, `../../co-noir-common/…`)
   assumes that cwd, but no README says so and the scripts don't `cd` to
   their own location. Running `bash examples/run_full_poseidon.sh` from the
   crate root fails. One-line fix in the scripts
   (`cd "$(dirname "$0")"`) or a README note.
5. **`compare_mpc.sh` / `compare.sh` destroy bystander artifacts** —
   `cleanup.sh` runs after every circuit and wipes proof/witness files in
   `examples/` and `test_vectors/`. Worth a warning line in the script
   header. (Bit us: deleted demo artifacts mid-session, §6.)
6. **co-noir verifier: no "proof fully consumed" check** (§7 finding 1) —
   trailing bytes accepted; bb rejects. Code fix for Phase 2, and until then
   a known-divergences note belongs in co-noir's Readme compatibility section.
7. **co-noir proof/VK parsing panics on off-curve points** (§7 finding 2) —
   ark-ec `is_on_curve` assert instead of a fallible decode → verifier
   process crash on malformed input where bb cleanly rejects. Code fix for
   Phase 2 (fallible point deserialization at the parse boundary).

*(More entries appended as found.)*

## 10. Local doc edits applied (✏️, never pushed — confidentiality rule)

1. `co-noir/co-noir/Readme.md` — added a "Building" note: requires
   Rust ≥ 1.90 (`rustup override set 1.90`), examples scripts must run from
   `examples/`, and the bbup-for-v5-nightlies direct-download fallback.
2. `co-noir/co-noir/examples/compare_mpc.sh` — `RAYON_NUM_THREADS` default
   unchanged (`nproc/3`, measured optimal for co-located parties, §6.3) but
   now env-overridable; measurement table in the comment.

## 11. Session-ops gotchas (orchestration mistakes made THIS session — read
## before babysitting long jobs in future sessions)

All of these cost real time today; none are co-noir's fault.

1. **`pgrep -f <pattern>` matches the shell that runs it** if the
   orchestrating command line contains the pattern (it always does when you
   write `pgrep -f compare_mpc.sh` inside a `zsh -c … compare_mpc …`
   wrapper). Symptom: a finished job reports "still running" forever — cost
   us ~50 min of imagined waiting on compare_mpc.sh (it had exited at 14:31).
   Fix: `pgrep -x <procname>`, or check the log file's mtime
   (`ls --time-style=+%T <log>`), or append a sentinel line on exit
   (`…; echo DONE >> log`) and grep for that.
2. **`cmd | tail` masks the exit code** — the pipeline exits with tail's
   status. The failed rustc-1.85 build reported "exit 0" this way (§2).
   Fix: zsh `${pipestatus[1]}` / bash `${PIPESTATUS[0]}` / `set -o pipefail`.
3. **The harness Bash tool resets cwd between calls** — a bare
   `bash run_full_poseidon.sh` after an earlier `cd` ran from the wrong dir
   (§5). Fix: absolute `cd` inside the same command string, every time.
4. **Harness background tasks are killed at their timeout cap (10 min)** —
   long test suites / compare runs must be `setsid nohup … &`-detached with
   a log file, then watched via the log.
5. **`cleanup.sh` inside compare scripts deletes bystander artifacts**
   (§6) — keep hand-made artifacts in an isolated scratch dir, never in
   `examples/` or `test_vectors/` while a compare run is live.

---

# Phase 2 command log (sync co-noir → v5-next; started 2026-07-08)

## 12. Setup: git branch + push rail + target oracle

```bash
# [OK] branch for all Phase 2 work; local commits authorized by Mike this
# session (branch mc/update-co-noir). First commit 74ab4cc3 = Phase 0 state.
git checkout -b mc/update-co-noir

# [OK] hard safety rail: origin's push URL now points at a non-repo, so
# `git push` physically fails (fetch still works — fetch URL untouched).
# Undo (if ever needed): git config --unset remote.origin.pushurl
git config remote.origin.pushurl "DISABLED-never-push-confidentiality-rule"
git push --dry-run origin mc/update-co-noir   # → fatal: not a git repository ✓

# [FAIL] target reference bb: the tag v5.0.0-nightly.20260708 has NO public
# release assets (404) — the v5 line moved from nightlies to release
# candidates (v5.0.0-rc.1/rc.2) around July.
curl …/releases/download/v5.0.0-nightly.20260708/barretenberg-amd64-linux.tar.gz  # 404

# [OK] resolution: in ~/ap-next (public repo), `git diff v5.0.0-rc.2
# origin/v5-next -- barretenberg` touches ONLY vm2/ (the AVM) — UltraHonk
# trees are identical. And v5.0.0-nightly.20260708's bb tree ≡ v5-next
# (empty diff, re-verified). So bb v5.0.0-rc.2 is a valid UH parity oracle
# for the v5-next target.
mkdir -p ~/.bb-target && cd ~/.bb-target
curl -sL …/releases/download/v5.0.0-rc.2/barretenberg-amd64-linux.tar.gz | tar xz
~/.bb-target/bb --version   # 5.0.0-rc.2
# NB: ~/.bb/bb stays at the OLD pin (5.0.0-nightly.20260324) — both oracles
# are needed during the sync (old = regression reference, new = target).
```

## 13. Pre-flight plan validation (before any code change)

Three parallel read-only verification passes launched over the actual code
(results recorded when complete): (a) re-derive the bb UltraHonk diff
OLD-pin→v5-next from the C++ and check ch. 03 §2's breaking-change list for
completeness; (b) verify every ch. 11 file/line claim against co-noir's Rust;
(c) pin down the exact Noir tooling target version + ACIR serde changes for
the dependency bump.

### 13.1 Result (c) — Noir pin bump [COMPLETE]

- **Target confirmed: `v1.0.0-beta.22`** (v5-next noir submodule =
  `c57152f912…` = exactly the upstream release-tag commit; ap-next agrees).
  Cargo change: 5 dep lines in root `Cargo.toml` (acir/acvm/brillig/
  noirc-abi/noirc-artifacts), `1.0.0-beta.20`→`22` in both `version` and
  `tag`. Fallback vendoring possible from
  `aztec-packages-private/noir/noir-repo/{acvm-repo,tooling}/…`.
- **PLAN GAP FOUND — ch. 11 §4 missed a breaking ACIR change:** the
  **`MemOp` overhaul** — `MemOp<F>`→ non-generic `MemOp`,
  `operation: Expression<F>` → `MemOpKind` enum (serde: bool renamed
  `"read"`; false=Read), `index`/`value`: `Expression<F>` → `Witness`.
  Affected co-noir sites (won't compile post-bump):
  `co-builder/src/acir_format.rs` (~L336, L928–1011 —
  `is_read_operation(&mem_op.operation)`, q_c/linear-term checks),
  `co-acvm/src/solver/memory_solver.rs` (L49 generic, L56/L103
  `op.operation.q_c`).
- `is_infinite` removal confirmed, **and it's semantic**: EC add/MSM
  infinity now uses the `(0,0)` sentinel — co-acvm's explicit
  `is_infinity`/`res_infinite` computation must be reworked, not re-typed
  (`blackbox_solver.rs` L287/300/303/315; `acir_format.rs` L271/289/795/798).
- New opt-in serialization `Format::MsgpackTagged=4` (beta.22); default
  MsgpackCompact=3 unchanged → stock nargo artifacts fine, but if any
  toolchain sets `NOIR_SERIALIZATION_FORMAT=msgpack-tagged`, co-noir needs
  the beta.22 acir crate to read byte 4. `BlackBoxFunc` enum unchanged.
- beta.21 compiler changes (InsideOut loop unrolling default, poseidon2
  stdlib strip-down, division-truncation fix, SSA passes) ⇒ **all test
  vectors must be recompiled with beta.22 nargo** (and old committed
  artifacts may not even deserialize under new types).

### 13.2 Result (b) — co-noir claims (ch. 11) [COMPLETE]

All 10 ch. 11 claims CONFIRMED in substance; corrections that change the
work plan's file list:

- **THIRD relation mirror missed by ch. 11**: the recursion verifier has a
  complete relation set at
  `co-builder/src/honk_verifier/verifier_relations/` (own `mod.rs` L53-61
  NUM_SUBRELATIONS sum, L152-161 relation order macro, L184-193 alpha-slice
  macro; `permutation_relation.rs:27` NUM_RELATIONS=2). Items 2.2 and 2.3
  must touch it alongside the plain + MPC mirrors.
- **Path fixes**: Shamir randomness accounting is
  `co-ultrahonk/src/co_ultra_prover.rs:163-202` (not co_decider/…); it
  counts via per-relation `CRAND_PAIRS_FACTOR` (perm currently 8,
  `co_decider/relations/permutation_relation.rs:62`) — a subrelation bump
  does NOT auto-adjust it; re-derive by hand iff the new L₀·z_perm
  subrelation adds MPC mults. ROM/RAM sorted-list pinning target is
  `ultra_builder.rs` `process_{rom,ram}_array_*` (L1933/1989/2100/2220) —
  `types/rom_ram.rs` is the recursion-verifier LUT, different thing.
- **SUBRELATION_PARTIAL_LENGTHS isn't a named const** — it's the
  `Univariate<F,N>` accumulator field widths (perm: r0:6, r1:3) → the 2.2
  change = add `r2: Univariate<F,3>` + wire through scale/batch/accumulate.
- **Current counts**: NUM_SUBRELATIONS=28, NUM_ALPHAS=27 (perm bump →
  29/28; every alpha slice `[3..]` onward shifts in all three mod.rs files).
- **Already satisfied** (down-scope ch. 11): CONST_PROOF_SIZE_LOG_N=25;
  proof-length constants already yield 410/458/115; NUM_ALL_ENTITIES=41;
  recursion size assert already targets 402/450+pubs. **Not present yet**
  (to add): TRACE_OFFSET, 5th SSIPA opening claim (currently exactly 4,
  `shplemini_prover.rs:675-709`), static proof-length asserts.
- Masking rows currently randomized at the trace END
  (`polynomial.rs:237-246`, NUM_MASKED_ROWS=3) — pre-change layout
  confirmed; `padding_indicator_array` present in plain verifier + a
  dedicated recursion file `honk_verifier/padding_indicator_array.rs` (to
  delete in 2.4), NOT in the MPC prover (comment only).
- KATs: only `add3u64` + `poseidon` have committed bb *proof* KATs (× 2
  hashers); 5 pin locations confirmed (compare.sh, compare_mpc.sh, 2×
  compile.sh, Readme.md).

### 13.3 Result (a) — bb diff completeness [COMPLETE; 1 critical miss found]

Audited all 416 bb commits in `v5.0.0-nightly.20260324..v5.0.0-nightly.
20260708`. All 5 documented consensus changes CONFIRMED (hashes, substance,
key hunks). **One material miss (now ch. 03 §2 row 6): the EntityId/
`get_all()` reorder** riding on `c075fc182e` — proof sumcheck-evaluation
order AND VK precomputed-commitment order both change (counts don't).
"VK serialization structure unchanged" is REFUTED; ch. 03 corrected.
Corrections: PAIRING_POINTS_SIZE = 8 not 16 (unchanged). Ruled out as
NOT Ultra-breaking after code reading: optimized-Poseidon2 `3827e14505`
(Mega-only; FS hashing identical), Grumpkin Libra length (ECCVM-only),
n1-apps transcript commit (Translator-only). Secondary: TS flavor-codegen
is now the source of truth for entity/relation order
(`scripts/flavor-codegen/src/flavors/*.ts`); SSIPA constants renamed;
2 verifier-hardening commits (accept/reject only); 2 ZK-only low-risk
commits flagged. Verified NEW constants: TRACE_OFFSET=4, lagrange_first
row 4, content row 5, subrelations 29 / alphas 28, perm partial lengths
{6,3,3}, SSIPA claims 5 (transmitted 4, commitments 3), non-ZK proof
without pubs = 402 fields (matches co-noir's existing constant).
Open item: agent's computed ZK length (421+masking commitment) vs
co-noir's `..._ZK = 450` — settle empirically from target-bb KAT bytes
during 2.1 (the KATs adjudicate, not the arithmetic).
