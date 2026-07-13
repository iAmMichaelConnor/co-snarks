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
appended; bb rejects it. Not itself a way to make an invalid proof verify
(the embedded proof is genuine), but it breaks byte-strictness parity with bb and could mask
length-related mistakes. → add a "transcript fully consumed" check during the
Phase 2 work (we'll be in that code anyway).

**Finding 2 — panic instead of clean reject on malformed curve points:**
tampering a G1 point (in proof KZG tail or VK) hits ark-ec's
`assertion failed: point.is_on_curve()` (ark-ec 0.5.0 short_weierstrass
affine.rs:72) — the verifier *process crashes* (exit 101) where bb returns a
clean "verification failed". Soundness is intact (off-curve points can't
verify), but it's a DoS/robustness divergence: a verifier service fed
malformed proofs would crash rather than reject. → co-noir should use
fallible deserialization (`from_random_bytes`/checked decompress that returns
`Err`) at the proof/VK parsing boundary. Record for Phase 2.

Soundness conclusion: **no false accepts in any tamper case** — the pipeline
at the pin is sound under these spot-checks; the two findings are
strictness/robustness divergences, not soundness gaps.

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

> ⚠ **SUPERSEDED (see §17.1):** the "rc.2 is a valid UH parity oracle"
> conclusion above later proved FALSE — the rc.2 *release binary* predates
> the entity reorder even though its *source tree* matches. THE target
> oracle is `~/.bb-target-src/bb` (source-built at the target tag). The
> record above is kept as-is because the flawed reasoning (source-tree diff
> ⇒ binary equivalence) is exactly the lesson.

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

Reviewed all 416 bb commits in `v5.0.0-nightly.20260324..v5.0.0-nightly.
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

## 14. Phase 2 step ① — Noir pin bump beta.20→beta.22

```bash
# [OK] the 5 dep lines (root Cargo.toml:35-39) + fetch
sed -i 's/1\.0\.0-beta\.20/1.0.0-beta.22/g; s/v1\.0\.0-beta\.20/v1.0.0-beta.22/g' Cargo.toml
cargo fetch

# [OK, informative] error surface: 51 compile errors
cargo check --workspace 2>&1 | grep -cE "^error"   # 51
```

**Per-commit gate for all Phase 2 code commits** (= Taceo's CI bar from
`.github/workflows/rust_lint.yml`, per the follow-their-conventions
decision): `cargo fmt --all -- --check` && `cargo clippy --workspace
--all-targets -- -D warnings` && compiles && targeted fast tests green
(full suite at milestones only). NB rust-analyzer needs a restart after a
dependency-tag bump (stale crate graph) and is expectedly red while a
refactor is mid-flight.

**REVISED after step ① retrospective (Mike + Claude, 2026-07-08) — the
test loop for the remaining work items 2.2–2.6 shrinks to match the
surgical nature of the changes** (step ①'s heavy gates were one-time
costs of the ark-0.6 dependency overhaul; ark 0.6 is validated forever):
1. per edit: `cargo check -p <touched crate>` (seconds);
2. per commit: fmt + `clippy -p` touched crates + ONE plaindriver
   self-verify smoke (~2 s; prover+verifier updated in lockstep must stay
   self-consistent even mid-sync);
3. per milestone (post 2.2+2.5+2.5a; post 2.4+2.6): the plain
   poseidon/add3u64 KAT byte-equality tests — the only meaningful oracle
   mid-sync, and the one check never to skip (self-verification cannot
   catch bb-incompatible byte order);
4. once at green-up (2.7): full suite + compare_mpc.sh both oracles +
   negative tests (= definition of done, not a loop).
Never again in phase 2: circom/mpc suites (ark-validated), workspace-wide
clippy per commit.

Error surface (2026-07-08): `noir-types` (2), `co-brillig` (47), downstream
crates (co-acvm/co-builder) not yet reached.

**Root cause turned out different from ALL predictions** (mine and the
pre-analysis): Noir beta.22 bumped **arkworks 0.5→0.6**, splitting the
dependency graph into two incompatible ark universes — the E0614 "cannot be
dereferenced" errors were duplicate-crate cascade noise, not field-shape
changes. Once the workspace unified on ark 0.6, noir-types and co-brillig
compiled with ZERO source changes. Lesson (add to ch. 12 gotchas): when a
dep bump yields dozens of nonsensical type errors, suspect a duplicated
transitive dependency (`cargo tree -d`) before believing the error text.

Fix (agent-executed, reviewed): workspace ark 0.5→0.6; two registry crates
that hard-pin ark 0.5 (`taceo-circom-types` 0.2.5,
`taceo-ark-serde-compat` 0.5.0 — no ark-0.6 releases exist) **vendored
into `vendor/` with ark bumped**, wired via `[patch.crates-io]` (drop when
upstream ships ark-0.6 builds); `ark-relations` 0.6 removed
`r1cs::{Matrix, ConstraintMatrices}` → defined verbatim in vendored
circom-types, co-groth16 re-exports from there. Plus the predicted
semantic work: MemOp (MemOpKind match replaces q_c inspection;
index/value read as Witness), EC add/MSM (0,0)-sentinel — MPC driver
trait kept its explicit infinity flags (rep3/plain already emit (0,0) at
infinity, so the encodings coincide); shared-point infinity detection =
2 eq-tests + 1 mult per input point; NEW upstream `predicate` field
handled (shared predicate → mask outputs with 2 MPC mults; public →
skip/passthrough). Builder EC gates re-mirrored to current bb
(`ec_operations.cpp`/`multi_scalar_mul.cpp`) — `TODO(phase2-2.6)` marks
the gate-count parity re-check. Details: agent report, session 2.

**Step ① gate results:**
- `cargo check/build --workspace --all-targets`: clean, zero warnings.
- `cargo fmt --all -- --check`: clean (baseline main@36da0ea8 also clean —
  the repo was well-formatted before we started; RA redness during the
  refactor was mid-flight state + stale post-bump crate graph).
- beta.22 end-to-end smokes (nargo execute → plaindriver prove+verify):
  poseidon ✓, **ram ✓ (MemOp path), embedded_curve_add ✓ ((0,0) path),
  rom_shared ✓** — all "Proof verified successfully".
- circom + mpc test binaries (ark-0.6 regression gate): **PASSED** —
  346 + 163 tests, 0 failed, exit 0. The ark-0.6 unification + vendored
  crates are behaviorally clean on the entire circom/MPC stack.
- clippy ours-vs-baseline (`-D warnings`, rustc 1.90): **identical
  findings in both** — 2 pre-existing `collapsible_else_if` lints in
  mpc-net (`tcp.rs:99`, `tls.rs:203`); zero new findings from our
  changes. Answer to "was the repo dirty before?": fmt no (clean),
  clippy yes-under-1.90 (Taceo CI pins an older toolchain that predates
  the lint). ✏️ Fixed both lints locally (trivial collapses) so the
  full-tree clippy gate can run to completion; final run recorded below.
- Watcher post-mortem (add to §11 list): the 3-gate watcher silently hit
  its 10-min background timeout before the slowest gate finished — give
  watchers a timeout comfortably above the slowest job's runtime, and
  prefer exit-sentinel lines in logs (`echo DONE >> log`) over process
  polling.

Step ① committed: `4e7abb95` (40 files, +8070/−382, incl. vendor/).

## 15. Phase 2 step ② — vector + KAT regeneration at target pin  ✅

```bash
# [OK] pins: both compile.sh NARGO_VERSION 1.0.0-beta.20 → 1.0.0-beta.22
# (compare.sh / compare_mpc.sh / Readme pins intentionally NOT bumped —
# they gate the old-pin regression path until green-up 2.7)
sed -i 's/NARGO_VERSION=1.0.0-beta.20/NARGO_VERSION=1.0.0-beta.22/' \
  test_vectors/noir/compile.sh co-noir/co-noir/examples/compile.sh

# [OK] all 32 vectors recompiled+executed with nargo beta.22
bash test_vectors/noir/compile.sh

# [OK at the time — but see §17.1: ~/.bb-target/bb was later found to be a
# WRONG oracle (rc.2 binary predates the entity reorder); these 4 KATs were
# regenerated with the source-built ~/.bb-target-src/bb during step ④]
# 4 bb proof KATs regenerated with TARGET bb (~/.bb-target/bb):
# add3u64+poseidon × {poseidon2,keccak}, non-ZK, via write_vk+prove
# [FAIL→OK] ZK length probe: first attempt reused the non-ZK VK — ZK prove
# needs a VK written WITHOUT --disable_zk. Retried correctly:
~/.bb-target/bb write_vk --scheme ultra_honk --oracle_hash poseidon2 -b … -o …
~/.bb-target/bb prove    --scheme ultra_honk --oracle_hash poseidon2 -b … -w … -k …
```

**Empirical result (settles §13.3's open question):** at the target pin,
non-ZK proof = 13120 B = **410 fields**, ZK = 14656 B = **458 fields**,
VK = 3680 B = **115 fields** — all IDENTICAL to the old pin; co-noir's
existing length constants are already correct. The whole sync therefore
changes byte *content/order* only, never lengths. (The §13.3 agent's
hand-computed ZK length of ~421 was wrong; the KAT adjudicated, as the
plan intended.) No VK KATs exist in-tree (nothing further to regen).

State after step ②: noir proof tests **red by design** (target-format KATs
vs old-format prover) until 2.2–2.6 land. Committed: `e70252e1`.
Next: work item 2.2 (perm subrelation, 3 mirrors) in lockstep with
2.5+2.5a (relation-tuple + entity reorders), then 2.4+2.6 (trace offset +
ZK/SSIPA), per the amended green-up order.

## 16. Phase 2 step ③ — relations + entity reorders (2.2 + 2.5 + 2.5a)

*(In progress — launched 2026-07-08 ~17:3x as a delegated coding task;
this section records the setup now and the commands/results on landing.)*

Scope (one lockstep unit — all three ride bb commit `c075fc182e` or
entangle through alpha bookkeeping):
- 2.2 third permutation subrelation (z_perm init identity) in all THREE
  relation mirrors (`ultrahonk`, `co-ultrahonk`,
  `co-builder/honk_verifier/verifier_relations`) — subrelations 28→29,
  alphas 27→28, partial lengths {6,3}→{6,3,3};
- 2.5 relation-tuple reorder (Permutation, LogDerivLookup, Arithmetic
  first) + alpha-slice renumbering in the three `mod.rs` files;
- 2.5a entity/get_all reorder (sigmas/ids/lagranges/q_lookup/tables before
  the other selectors) — sumcheck-evaluation transmit order + VK
  commitment serialization + recursion-verifier indexing.
References given to the implementer: NEW-tag generated flavor headers via
`git show v5.0.0-nightly.20260708:barretenberg/cpp/src/barretenberg/
flavor/generated/ultra_flavor_generated.hpp` (+ ZK variant, + the TS
sources under `scripts/flavor-codegen/src/flavors/`), with instruction to
trust bb code over any paraphrase. Open question the implementer must
settle from the algebra: whether the new subrelation adds a shared×shared
MPC mult (→ CRAND_PAIRS_FACTOR + Shamir randomness re-derive) — expected
NO (lagrange polys are public; public×shared is linear).

Gate for this step (reduced loop, §"REVISED" above): check/fmt/clippy on
touched crates + plaindriver self-verify non-ZK AND ZK + 3-party REP3
demo self-verify. KAT-vs-bb NOT expected green until 2.4+2.6.

### 16.1 Result ✅ (landed 2026-07-08; all gates green; independently re-verified)

- **2.2**: 3rd subrelation = `L_first·z_perm = 0` (accumulator 2, partial
  length 3; bb comment: forces z_perm[0]=0 so `(z_perm+L_first)`=1 at row
  0, otherwise z_perm could be seeded arbitrarily at that row). Implemented in
  all THREE mirrors; in co-ultrahonk it's `mul_with_public_many`
  (public×shared, linear) → **CRAND_PAIRS_FACTOR stays 8, Shamir
  randomness accounting unchanged** (comment left at the constant).
- **2.5**: new tuple order Perm, LogDeriv, Arith, Delta, Elliptic, Memory,
  NNF, Pos2Ext, Pos2Int; subrelations 29, alphas 28; new slices perm
  [1,e0,e1], lookup e[2..5], arith e[5..7], delta e[7..11], elliptic
  e[11..13], memory e[13..19], nnf e[19..20], pos_ext e[20..24], pos_int
  e[24..28]. bb convention confirmed in relations/utils.hpp: α_{0,0}=1 →
  the PERMUTATION grand-product subrelation is now the unscaled one. In
  the recursion verifier the accumulate order is load-bearing (constant-1
  fast path must run first) — handled.
- **2.5a**: precomputed order renumbered exactly to the generated hpp —
  sigma_1..4(0-3), id_1..4(4-7), lagrange_first(8), lagrange_last(9),
  q_lookup(10), table_1..4(11-14), then selectors in bb's odd sub-order
  q_m,q_r,q_o,q_c,q_l,q_4(15-20), q_arith..q_pos2int(21-27). Witness +
  shifted partitions were already correct; ZK masking entity already at
  position 0. All order-sensitive consumers (VK to_buffer both hashers,
  Sumcheck:evaluations, recursion from_elements, shplemini) iterate the
  one struct → followed automatically. Side effect: selectors no longer
  contiguous → `get_selectors_mut` returns disjoint refs in trace-block
  order; UltraTraceBlock indices decoupled (block-local 0..13).
- Gates: workspace check clean; fmt/clippy(-D) touched crates clean;
  plaindriver poseidon self-verify non-ZK + ZK ✓ (ZK re-run independently
  ✓); REP3 3-party demo (keccak path) ✓. Independent spot-checks: bb C++
  algebra read directly ✓; entity indices ✓.
- Note: examples/test_vectors/poseidon artifact was still beta.20 →
  regenerated with nargo beta.22 (pre-existing issue, unrelated).

Committed: `1a13fcdc`.

## 17. Phase 2 step ④ — trace-offset + ZK/SSIPA rework (2.4 + 2.6)

*(In progress — launched 2026-07-08 evening, delegated; results appended
on landing.)* The biggest/riskiest pair, entangled through the ZK path:
- 2.4: masking/disabled rows END→TOP (TRACE_OFFSET=4; masking rows 1–3;
  lagrange_first row 0→4; content from row 5); every VK changes;
  padding_indicator_array deleted everywhere incl. the dedicated
  recursion-verifier file; new sumcheck row-disabling factor; MPC nuance —
  non-ZK: structural rows only; ZK: masking randomness as shares
  (relocated from tail).
- 2.6: SSIPA 5th UNTRANSMITTED Shplonk claim A(1)=0 (claims 4→5,
  transmitted evals stay 4, commitments 3); Shplonk nu-power shift;
  MaskingTailData deletion; gemini masking dyadic sizing check; Shamir ZK
  randomness re-derive if mechanics changed.
**Gate adds THE MILESTONE**: plain KAT byte-equality vs regenerated
target-bb KATs (add3u64+poseidon × pos/kec, non-ZK) SHOULD go green —
first end-to-end byte-parity point with the target. Plus: ZK
bidirectional cross-verify with ~/.bb-target/bb, VK byte-identity check,
REP3 proof verified by target bb. Divergence protocol: if KAT red, agent
reports first divergent field index + proof section, ONE fix attempt,
then stop with analysis (no thrashing).

Mid-step discovery (implementer, 2026-07-08 ~18:35): co-noir pads ZK
sumcheck to 25 rounds with ZERO univariates, but bb NEW computes **honest
virtual-round univariates** (single-edge contribution × row-disabling
factor + that round's Libra univariate; book-keeping folded by (1−u_k);
gemini masking eval over the full 25-challenge vector) — a ZK proof-byte
change neither ch. 11 nor the pre-analysis had called out explicitly.
Being implemented faithfully.

### 17.1 ⚠ ORACLE CORRECTION (implementer, 2026-07-08 ~18:43–18:57): rc.2 is NOT the target

While chasing a VK divergence at the *first commitment*, the implementer
found the prebuilt `~/.bb-target/bb` (5.0.0-rc.2) serializes the VK in the
**OLD q_m-first entity order** — rc.2 was cut *before* the entity reorder
(`c075fc182e`) and is therefore NOT UltraHonk-identical to v5-next,
contradicting the step-② assumption (the earlier "rc.2 ≡ v5-next" check
compared bb *source trees*, but the rc.2 *release binary* predates the tag).
Consequences:
- The step-② KATs (commit `e70252e1`) were generated from a wrong oracle.
- Fix: bb was **built from source** at the true target tag —
  `git archive v5.0.0-nightly.20260708 barretenberg/cpp` out of
  `~/aztec-packages-private`, `CC=clang-20 CXX=clang++-20 cmake --preset
  default -DAVM=OFF`, `cmake --build build --target bb -j 90` (~90 s).
  Preserved at **`~/.bb-target-src/bb`** (+PROVENANCE.txt) — this is now
  THE target oracle; do not use `~/.bb-target/bb` for anything.
- All 4 proof KATs regenerated with it (`bb prove … -o`, then `cp` over
  `test_vectors/noir/*/kat/*_proof_with_*`).
**Lesson (also in ch. 12 gotchas): never trust a prebuilt bb release binary
as oracle without first byte-comparing its VK output against the target
tag's source; rc/nightly binaries can lag the tag by proof-breaking days.**

### 17.2 Result ✅ (landed 2026-07-08 evening→night, across a token pause)

The step-④ agent died at its session limit at 19:15 with ONE edit unfired
(the Shamir randomness accounting in `co_ultra_prover.rs`; its last two
attempts also hit "claude-opus-4-8 temporarily unavailable" API errors).
Everything else was in the tree and the workspace compiled. Recovery
session (this one) then:
1. **Re-verified the KAT provenance independently**: regenerated all 4
   proofs fresh with `~/.bb-target-src/bb` → `cmp` byte-identical to the
   working-tree KATs (MATCH ×4). (First attempt at the compare loop failed
   silently-wrong: zsh does NOT word-split `set -- $pair` — printed empty
   paths. Re-ran with explicit per-file `cmp`.)
2. **Completed the randomness accounting** — applied the agent's intended
   edit (recovered verbatim from its transcript) after verifying every term
   against the consumers, and fixed one real omission in it: the 8
   `mask_polynomial` call sites (w_l/w_r/w_o, read_counts/read_tags/w_4,
   lookup_inverses/z_perm) each draw NUM_MASKED_ROWS=3 Shamir pairs in ZK —
   24 pairs the agent's version undercounted. Full derivation now in the
   function comments. Note: in-tree Shamir tests run 3-party which takes
   the `num_pairs=0` on-the-fly path — the accounting is only exercised at
   ≥4 parties, so a wrong count would NOT show in the suite.
3. Removed 2 now-unfulfilled `#[expect(clippy::too_many_arguments)]`;
   `cargo fmt`; clippy → **0 warnings workspace-wide**.
4. **Gates**: full noir suite `cargo test -p tests --release --test noir`
   → **94 passed / 0 failed** in 39 s (incl. THE MILESTONE: plain KAT
   byte-equality vs true-target-bb KATs, both circuits × both hashers;
   REP3 + Shamir 3-party × {ZK, non-ZK}).
5. **ZK bidirectional cross-verify vs `~/.bb-target-src/bb`** (poseidon,
   poseidon2 hasher): our ZK proof verified by bb with our VK ✓ and with
   bb's VK ✓; bb's ZK proof verified by `co-noir verify --has-zk` ✓
   (flag is `--has-zk`, not `--zk` — prover and verifier CLIs differ);
   **VK byte-identical**; ZK proof exactly 458 fields (14656 B), non-ZK
   410 (13120 B) — the ch. 04 §5 invariants hold at the target.
6. Committed as `571c1305` (36 files, +628/−1095).

**§17 closure (2026-07-09, backlog ch. 15 §1.5) — gemini masking dyadic
sizing (`1f9d87ba3a`) confirmed byte-neutral.** The bb fix only enlarges the
masking poly's `virtual_size` from `max_end_index()` to `dyadic_size()`; the
random-coefficient *count* is unchanged and the new tail is virtual **zero**,
so the commitment (MSM over the backed range), transcript entry, and MLE
evaluation are bit-identical — it removes a debug-only one-past-end assert,
not a value. co-noir sizes its masking poly to the full dyadic `w_l().len()`
with all-random coefficients (plain `oink_prover.rs:95`, MPC
`co_oink_prover.rs:566`); it doesn't mirror bb's zero-tail split, but the
masking poly is per-prover ZK randomness (never byte-compared), co-noir is
internally commit↔eval consistent, and the bidirectional ZK cross-verify
(item 5 above) covers compatibility. No co-noir change required.

Remaining for Phase 2 after step ④: PLAN 2.6 builder/DSL residue (ROM/RAM
sorted-index pinning `1f7ed2ea79` — soundness fix; EC gate-count parity
check EC_ADD 80→76 / MSM 3559→3557; recursion size-assert), then 2.7
green-up (full example suite, compare_mpc.sh — note: needs a THIRD oracle
slot pointing at `~/.bb-target-src/bb` — and the ch. 13 §3a mandatory
security regressions).

## 18. Rationale-mining pass (launched 2026-07-08, per Mike's challenge)

Gap acknowledged: our analysis nailed WHAT changed, but the WHY (PR
descriptions, commit bodies, soundness motivations) was only
fragmentarily captured. A read-only agent is mining full commit bodies /
added code comments / linked issues for all 6 consensus changes + ROM/RAM
pinning + recursion size-assert + verifier hardenings, classifying each
as SOUNDNESS FIX / ZK-PRIVACY FIX / HARDENING / ENGINEERING, and
identifying which side (prover/verifier) carries the security burden.
Highest stakes: `58bf73a289` (if A(1)=0 fixed an SSIPA soundness gap, the
VERIFIER-side enforcement is the critical half — a bytes-only port could
reintroduce the hole) and `1f7ed2ea79` (ROM/RAM boundary pinning smells
like a sorted-list soundness fix). Results → ch. 03 per-change "why"
sections + extra negative tests in the 2.7 green-up if warranted.

## 19. Phase 2 item 2.6 — builder/DSL residue ✅ (2026-07-08 night, commit 5ac55600)

Scope: ROM/RAM sorted-index pinning, EC gate parity, recursion size assert —
plus TWO extra proof-breaking table changes found by parity-testing circuits
the KAT suite doesn't cover.

### 19.1 What bb changed (read from source; commits + why)
- `1f7ed2ea79` **ROM/RAM pinning (SOUNDNESS)**: index-delta subrelation
  `Δ²+Δ=0` has roots {0,−1} → sorted chain could start at p−1 and allow
  reads/writes at that index without a genuine constraint. Fix: first
  sorted index_witness = zero_idx
  (ROM+RAM), last ROM index = put_constant_variable(N−1). bb ships negative
  tests (Rom/RamMaliciousFieldWrap) — mirror in our 2.7 security regressions.
- `0a7d0af035` **lookup table_index starts at 1**: "so the relation batched
  term always contains at least beta cubed" (logup). All lookup circuits'
  bytes change.
- `bbbde54094` **SHA 10-bit basic tables (SOUNDNESS)**: SHA256_BASE28_ROTATE3
  and SHA256_BASE16 generated 2^11 rows for a 10-bit declared slice — a
  prover could witness an out-of-range slice. Now `<28,10,3>` / `<16,10,0>`.
- `5d43e115a2` (a bb defense-in-depth pass): `w_sparse[0].create_range_constraint(32)`
  in sha extend_witness — "the only vk change" of that commit.
- uint.hpp/types.hpp MultiTable ctor rework: ctor coefficient loop 0..n →
  1..n paired with uint callers passing n+1. NET byte-neutral for
  repeated-coefficient tables (all step sizes = the constant base; extra
  trailing coefficient unused). Mirrored the callers, left co-noir's ctor
  (old n+1 style) alone — verified byte-neutral empirically.
- `54a8d2d1df`/`70d6b831ed` secp256k1 clamp + r1 fixed-base tables: NOT
  ported — ECDSA blackbox unimplemented in co-noir (ch. 06).
- `669e92b896` recursion-constraint proof-size assert: mirrored as
  `assert_eq!(input.proof.len(), PUBLIC_INPUTS_SIZE + ULTRA_PROOF_LENGTH_
  WITHOUT_PUB_INPUTS(_ZK))`; recursion vectors declare 410/458+115 ✓.
  Also added ch. 11 §3's compile-time invariants in constants.rs:
  `const _: () = assert!(… == 410 / 458 / 115)`.

### 19.2 Command record (failures included)
1. ram/rom_shared parity, first attempt: **all bb+plaindriver invocations
   silently failed behind `>/dev/null`** and `cmp` on missing files printed
   "VK DIFF; PROOF DIFF" — the EXACT §11 pipe-masking gotcha, repeated.
   Lesson reinforced: log to files, check artifacts exist before cmp.
2. Root cause of the failures: examples/test_vectors/{ram,rom_shared,…}
   are still **beta.20-compiled** (step ② only regenerated
   test_vectors/noir + examples poseidon) → beta.22 serde error
   `invalid type: integer 11, expected a sequence` (MemOp overhaul).
   Fixed per circuit: `nargo compile && nargo execute` (beta.22).
   ⚠ 2.7 must recompile the WHOLE examples vector set.
3. Parity harness per circuit (plaindriver + ~/.bb-target-src/bb
   write_vk/prove, poseidon2, --disable_zk, cmp vk+proof):
   ram ✓, rom_shared ✓ (after pinning), embedded_curve_add ✓ (EC gate
   counts settled — no extra work needed beyond step ①'s serde),
   blackbox_and ✓, blackbox_xor ✓, get_bytes ✓ (after table_index+uint),
   bb_sha256_compression ✓ (after 10-bit tables + table_index + w[0] range).
   sha VK "lagrange_first diff" red herring during triage: with table
   content differing, EVERY row shifts → nearly all precomputed
   commitments differ; don't over-read per-commitment diff lists.
4. Gates: fmt ✓, clippy 0 warnings ✓, noir suite 94/0 ✓ (37.7 s).

### 19.3 Phase 2 remaining = 2.7 green-up only
Full examples-vector recompile (beta.22) → compare.sh/compare_mpc.sh with a
~/.bb-target-src/bb slot → ch. 13 §3a security regressions (SSIPA
kernel-perturbation case, ROM/RAM field-wrap — mirror bb's
Rom/RamMaliciousFieldWrap —,
trailing-bytes/non-canonical encodings + the Phase-0 panic-on-off-curve fix)
→ slow set (aes128, sha256_compression e2e, recursion, recursion_zk).

## 20. Recursion resolved (2026-07-08, session 3) — stale vectors + wrong K, NOT a verifier-code issue

The 2.7 sweep found `recursion`/`recursion_zk` panicking at circuit-build
(`assert_equal`, `ultra_builder.rs:223`). Root cause (two independent test-
vector issues; **no `.rs` verifier code was wrong** — the step-④ recursion
port is correct):
1. **Stale inner proof.** `recursion*/Prover.toml` embedded a beta.20-era bb
   inner proof whose bytes no longer round-trip through the synced relation
   logic. Regenerated with target bb (commands in ch. 12 §4a).
2. **Wrong public-input count.** `recursion*/src/main.nr` declared
   `public_inputs: pub [Field; 3]`; the inner circuit has 1 public input, and
   the pairing-point object (PUBLIC_INPUTS_SIZE=8) lives inside `proof`, not
   `public_inputs`. K=3 shifted the transcript read cursor by 2 → all
   downstream reads corrupted → first sumcheck `check_sum` mismatch. Fixed to
   `[Field; 1]`. (K=3 worked at the OLD pin only because pairing-points were
   16 and accounted differently pre-sync.)

**Confirmations:**
- Pre-project pin `36da0ea8` (old code + old vectors): recursion self-verifies
  ✅ — so recursion worked before Phase 2; the break was ours (via vectors).
- After both fixes: `recursion` + `recursion_zk` build/prove/self-verify on
  main ✅ and cross-verify vs `~/.bb-target-src/bb` ✅ (410/458/115 counts).
- Merge gotcha hit + recorded: gitignored `target/*.json`+`*.gz` don't travel
  with git; after the merge, main still had the K=3 build → same panic until
  `nargo compile && execute` (≈0.6 s). See ch. 12 §3 + §4a.

Prevention pointers added: ch. 12 §3 (two new gotchas: stale recursion
vectors + gitignored artifacts) and ch. 12 §4a (regen procedure, WHEN-only).
Committed: recgen fix `61100009`, merged to mc/update-co-noir `4b4a8f51`.

**⚠ Addendum (2026-07-09): two of this section's conclusions were later
qualified.** (1) The "cross-verify vs bb ✅" above was a SAME-KEY check —
the true cross-key parity break it masked was found and fixed as PLAN 2.9
(§23 below). (2) This regen fixed only the `examples/test_vectors` copies;
the cargo suite's `test_vectors/noir/recursion{,_zk}` copies stayed stale
until 2026-07-09 (§23; regen procedure updated in ch. 12 §4a to cover both
locations). The core finding here — the self-verify failure was vectors,
not verifier code — stands.

## 21. Overnight backlog run (2026-07-08 23:48 → 2026-07-09 ~00:32, ended at
## usage limit) — ch. 15 items closed + recursion VK parity break found

Autonomous session working through `15-improvement-backlog.md`. Ended
mid-item at the usage limit; all work left UNCOMMITTED on
`mc/update-co-noir` (verified green next morning: `./fast-check.sh` PASS,
`./fast-check.sh --sec` 8/8 PASS incl. the new tests).

**Closed (code landed, uncommitted):** §1.4 `log_circuit_size` VK
range-check (both deserializers + panic-proof `to_u64_digits` header reads +
`saturating_sub` guard in the Gemini fold loop, mirrors bb `1391c49546`;
tests `zero_log_circuit_size_vk_rejected` etc. in
`security_regression.rs`); §2.4 entity-order lock tests (bb `EntityId`
0–40 transcribed independently into `entities.rs` unit tests, 3 pass);
§3.1 compile-time invariant block extended (NUM_ALL_ENTITIES=41,
TRACE_OFFSET=4, CONST_PROOF_SIZE_LOG_N=25, libra/SSIPA counts); §4.4
`rust-toolchain.toml` (1.90.0); §4.5 `versions.env` single-sourcing the
nargo/bb pins for all four scripts + Readme; §4.6 `scripts/
build-bb-oracle.sh` (git archive → cmake -DAVM=OFF → PROVENANCE.txt →
optional `CHECK_AGAINST` write_vk byte-compare; smoke-tested: fresh source
build's VK byte-identical to `~/.bb-target-src/bb`); §4.7 parity-script
hardening (`set -euo pipefail`, no bare `>/dev/null` on oracle calls).

**Closed (analysis, no code needed):** §1.5 bb gemini-masking dyadic-size
commit `1f9d87ba3a` confirmed byte-neutral (§17 closure above); §1.8
builder-determinism sweep (the flagged HashMap site was already BTreeMap
since upstream `dee0972b3`; clippy `iter_over_hash_type` guard in place);
§1.10 `(0,0)` infinity sentinel proven collision-free on BN254 G1 and
Grumpkin by residue computation.

**🔴 §1.9 — CONFIRMED recursion VK/proof parity break** (the headline; full
record in ch. 15 §1.9). Running the byte-level VK oracle that §1.9 called
for revealed: for `recursion`/`recursion_zk` (same freshly-compiled ACIR fed
to both sides), co-noir and bb emit **different circuits** — VK differs from
byte 112 (first SIGMA commitment; header matches; ~21/28 precomputed
commitments differ incl. LAGRANGE_LAST ⇒ real gate count differs), proofs
differ from byte 272, and cross-verification **fails both ways** while each
side self-verifies. All 31 non-recursion circuits remain byte-identical
(control: `poseidon` VK byte-identical → methodology sound). The earlier
"recursion bb-cross-verify PASS" (§20) was a same-key check (co-noir proof +
co-noir VK under bb's verifier) — internal consistency, not parity.
Repro: `nargo compile` recursion; `bb write_vk --scheme ultra_honk
--oracle_hash poseidon2 -b recursion.json` (oracle `~/.bb-target-src/bb`) vs
`co-noir create-vk`; `cmp` the two VKs. Artifacts preserved (session
scratchpad `recvk2/`). A read-only localization agent was spawned but died
with the session ~2 min later — **no diagnosis exists yet**; localization is
the next step (prompt preserved in the 2026-07-08 session transcript;
suspects: recursion-verifier gate emission in `co-builder/src/
honk_verifier/*` vs bb `stdlib/honk_verifier/*`).

**In flight at cutoff:** §2.3/§4.3 VK byte-KATs — bb VKs generated but not
committed. Completed next morning as PLAN 2.10; see §22.

## 22. PLAN 2.10 — VK byte-KATs ✅ (2026-07-09 morning)

Regenerated the four bb VKs fresh (`~/.bb-target-src/bb write_vk --scheme
ultra_honk --oracle_hash {poseidon2|keccak} [--disable_zk] -b <kat json>`)
for add3u64 + poseidon; byte-identical to the overnight generation, and
zk == nozk for all four (so one VK KAT per circuit×hasher covers both
modes). Committed as `test_vectors/noir/<c>/kat/<c>_vk_with_{pos,kec}`
(poseidon2 field format 3680 B; keccak U256 format 1888 B) plus a
`PROVENANCE.txt` per kat/ dir (bb tag, source-built provenance, commands,
do-not-regenerate-with-co-noir rule). `plain_test`
(tests/tests/noir/proof_tests/plain.rs) now takes the VK KAT path + the
matching serializer (`to_buffer` / `to_buffer_keccak`) and asserts
byte-equality right after `create_keys`, in BOTH zk modes. Gates: 4/4
plain tests pass; tripwire validated (flipping KAT byte 112 → clean
assertion failure, restored, green). Recursion VK KAT deliberately NOT
added — blocked on the 2.9 parity break (it would be red today) and is
the natural anti-regression to add with the 2.9 fix.

## 23. PLAN 2.9 — recursion parity: localization + fix round 1 (2026-07-09, IN PROGRESS)

**Localization (read-only agent, per-phase gate instrumentation on scratch
copies of both codebases):** both sides byte-equal through Oink,
gate-challenges, non-ZK sumcheck, and Shplemini; three divergences account
for the gate-count deltas exactly (non-ZK: arith −66, delta_range +32;
ZK: arith −98, delta_range +34):
1. `mask_points` (big_group_edgecase_handling.rs) missing bb's
   point-at-infinity assertions — offset generator + every masked point
   (biggroup_edgecase_handling.hpp). ALSO A SECURITY GAP: those asserts are
   what stop a malicious prover exploiting ∞ entries in ROM point tables.
2. `unsafe_assert_less_than` (big_field.rs) range-constrained the top limb
   r3 at 68 bits instead of NUM_LAST_LIMB_BITS=50 (weaker bound + different
   range-list shape; bb bigfield_impl.hpp).
3. ZK-only: row-disabling factor applied once to the batched sumcheck total
   instead of per subrelation (bb utils.hpp `scale_and_batch_elements`:
   element × α × rd; algebraically identical, 28 fewer mul gates).

**Fix round 1 (applied, uncommitted):** all three ported mirroring bb's
emission order (∞-asserts via `BoolCT::assert_equal` against constant
false = bb's `assert_equal_constant`, 1 gate each; r3 →
`Self::NUM_LAST_LIMB_BITS`; rd factor computed between relation
accumulation and batching, folded per subrelation in
`scale_by_challenge_and_accumulate`, single post-multiply removed from
`sumcheck.rs`). Gates: workspace check clean; 4/4 plain VK+proof KATs
pass (non-recursion parity intact); fast-check --sec PASS.
**Result: NOT yet parity** — recursion/recursion_zk VK still differs at
byte 112; 21/28 commitment blocks differ (19 blocks DID move vs pre-fix,
so the fixes bite but something residual remains: order/content or a
mis-accounted delta). Residual re-instrumentation running (same agent,
fixed files copied into its scratch workspace). Artifacts: scratchpad
`recfix/`.

**Fix round 2 (2026-07-09, applied, uncommitted).** Re-instrumentation
verdicts: fixes #2 (r3 width) and #3 (ZK row-disabling) verified complete —
all nine range lists and the post-sumcheck/post-shplemini counts now match
bb exactly. Fix #1's ∞-asserts emit ZERO gates (bb's `assert_equal` vs a
constant is a pure copy constraint) — the original 64/68/2 attribution was
coincidental; asserts kept (bb security check + copy-constraint parity).
The REAL arith source: co-noir `compute_naf` (big_group.rs) never pinned
`naf_entries[0]` — bb emits `fix_witness()` (1 arith gate per MSM scalar,
biggroup_nafs.hpp; also a soundness gap: the Strauss rounds don't consume
entry 0, so outside the scalar-reconstruction sum it was unconstrained).
**Fix 4**: `builder.fix_witness(naf_entries[0].witness_index, 0)` right
after the witness creation (bb's order). Result: differing commitment
blocks 21 → **11** (recursion) / **12** (recursion_zk); remaining diffs are
content-level (same gate counts, different selector/wire values) in blocks
[0–7,16,19,22(,15 zk)]. Row-level selector/wire dump in progress. Plain
KATs 4/4 + fast-check --sec still PASS after every fix round.

**Fix round 3 (2026-07-09) — recursion AT PARITY.** Row-level dump (all
~682k/704k trace rows, both sides) found only 29 (non-ZK) / 41 (ZK)
differing rows in three clusters:
- **A** (both circuits): `GateSeparatorPolynomial::partially_evaluate`
  multiply operand order — bb puts the challenge in the mul gate's left
  wire (`challenge × (β−1)`); co-noir had `(β−1) × challenge`. Fixed
  (gate_separator.rs).
- **B** (both): `self_reduce` quotient limb maximum off by one —
  `2^max_quotient_bits` vs bb's `2^max_quotient_bits − 1`
  (bigfield_impl.hpp); the extra bit rippled into the carry MSB and
  re-bucketed 4 range-list entries. Fixed (big_field.rs).
- **C** (ZK only): SmallSubgroupIPA `check_consistency` emits the same 9
  subexpression gates in a different order than bb
  (small_subgroup_ipa.hpp) — fix pending (shplemini.rs reorder,
  row-dump-guided).

**After A+B: `recursion` VK BYTE-IDENTICAL to bb** ✅ and fully
cross-verified: co-noir plaindriver proof → bb verifier w/ bb VK PASS;
bb proof → co-noir verifier PASS; public inputs byte-identical; VK from
plaindriver also byte-identical. Proof BYTES legitimately differ (byte
272 onward): `mask_points` uses a prover-chosen random offset generator
(free witness), so proof bytes are prover-specific for recursion even
non-ZK — VK identity + mutual verification is the right parity criterion
(this is also why compare.sh excludes recursion from proof byte-diffs).
`recursion_zk` down to 6 differing VK blocks [0,1,2,15,16,19] =
SIGMA_1–3, Q_M, Q_R, Q_L — exactly cluster C's footprint. Plain KATs 4/4
+ fast-check --sec PASS after every round.

**Fix round 4 (2026-07-09) — recursion_zk AT PARITY; 2.9 CLOSED.**
Cluster C course-correction: the divergence was NOT in
`check_consistency` (already in perfect parity) but in the tail of
**`add_zk_data`** — the SmallSubgroupIPA claim batching. bb groups the
batching scalars by backing commitment INSIDE the claim loop
(`grouped_scalars[commitment_index] -= scaling_factor`, between the
ν-power multiply and the evaluation multiply — shplonk/shplemini.hpp
`batch_small_ipa_opening_claims`); co-noir negated per-claim scalars in
the loop and emitted the two grouping additions after it — same values,
two gates in the wrong positions + witness-numbering ripple. Fix
(row-dump-verified in the instrumented build before porting): grouping
subtraction moved inside the loop with
`COMMITMENT_INDEX = [0,1,1,1,2]`. Row diff after fix: **0 of 703,658
rows**. Ported to `shplemini.rs`; verified in the main repo:
- `recursion` AND `recursion_zk` VK byte-identical to bb (create-vk).
- ZK bidirectional cross-verify: co-noir plaindriver --zk proof → bb
  verifier w/ bb VK PASS; bb ZK proof → co-noir verifier (`--has-zk`)
  PASS.
- Gotcha: plaindriver hit a stack overflow proving recursion_zk with the
  default stack; `ulimit -s unlimited` (or a large RUST_MIN_STACK)
  fixes it → ch. 15 backlog item.

**Bonus finding — the cargo suite's OWN recursion vectors were still
stale.** §20's regen fixed only `examples/test_vectors`; the suite's
`test_vectors/noir/recursion{,_zk}` copies still had K=3 main.nr + the
beta.20 inner proof in Prover.toml (same `ultra_builder.rs:223` panic
signature). Never caught because the only suite recursion tests
(rep3/plaindriver) are `#[ignore]`d as too slow. Fixed: main.nr +
Prover.toml copied from the examples set, `nargo execute`, target→kat
per the compile.sh convention.

**Anti-regression landed (closes the 2.10 deferral):**
- `test_vectors/noir/recursion{,_zk}/kat/` now hold bb VK byte-KATs
  (source-built oracle) + PROVENANCE.txt (incl. why there is no proof
  byte-KAT for recursion circuits).
- New ALWAYS-ON suite tests `recursion_vk_kat` / `recursion_zk_vk_kat`
  (plain.rs `vk_kat_test`: build + create_keys + VK byte-assert, no
  proving — ~5 s for both): the fast tripwire that would have caught
  this whole class of break on day one.
- `compare.sh` now byte-diffs `vk` vs `vk_plaindriver` for EVERY
  circuit, recursion included (the previously-missing tripwire), with
  comments explaining the proof-diff exclusion.
Final gates: plain suite 6/6 (incl. both new vk_kat tests),
fast-check --sec PASS, clippy 0 warnings.

## 24. PLAN 5.1a — monty-hall-aztec modernization command log (2026-07-13)

*Repo: `~/monty-hall-aztec`, branch `mc/modernize` (base `d333404`,
origin pushurl DISABLED). Full narrative: ch. 16 §4 AS-BUILT; session
log: PROGRESS session 6. Commands + failures only here.*

### 24.1 A1 — circuits at beta.22
- `nargo compile` (in `noir_logic/monty_hall_init/`) — first run listed
  the breakage set: `is_infinite` field gone, `u1` removed,
  `poseidon2_permutation` arity, Field array-indexing. After fixes
  (ch. 16 §4 A1): all 6 circuits compile; `nargo test` in pss_utils
  (17) + monty_hall (6) green.
- ⚠ `nargo execute` FAILED: `No handler could be found for foreign call
  'TACEO_store'` → wrote `noir_logic/scripts/oracle_stub.py` (JSON-RPC,
  returns empty values) + `nargo execute --oracle-resolver
  http://127.0.0.1:5599 witness` — witness solved; old Prover.toml's
  commitment assertion still passes (Poseidon2 unchanged).
- ⚠ bb GOTCHA (target tag): `bb prove` now REQUIRES `-k <vk>` (defaults
  to `./target/vk`, errors if absent) → run `write_vk` FIRST. My first
  "PASS" was fake: `&&`-chain + `tail` masked the missing-proof failure
  — re-hit the §11/§19.2 silent-failure lesson; check.sh asserts
  artifact existence.
- ⚠ bb verify exit code is only meaningful UN-piped (`bb verify | tail`
  → `$?` is tail's). Un-piped: honest exit 0, tampered exit 1.
- Gate script: `noir_logic/check.sh` (sources `versions.env`) — PASS.

### 24.2 A2/A3 — mpc workspace port
- Path-deps to `~/co-snarks`; deleted stale `Cargo.lock`.
- ⚠ FIRST BUILD: 75 errors, "two types coming from two different
  versions of the same crate" — mpc workspace pinned ark 0.5, co-snarks
  uses **ark 0.6** → bumped ark-bn254/-serialize/-ff to 0.6. Rebuild: 3
  real errors (`get_constraint_system_from_artifact` is now 1-arg;
  `AcirFormat` not Clone → recompute from artifact inside the blocking
  task). Then green.
- ⚠ `protoc` not installed (protos build.rs needs it) → installed
  protoc v29.3 to `~/.local/bin` from the protobuf GitHub release zip;
  build with `PATH=$HOME/.local/bin:$PATH`.
- `cargo build --release -j 26` (leave ~20% cores free) + clippy:
  remaining warnings are pre-existing demo cruft only.

### 24.3 A4 — e2e
- 3× dockerized Postgres: `docker run -d --rm --name mh-pg$i -e
  POSTGRES_PASSWORD=postgres -p $((8080+i)):5432 postgres:16-alpine`
  (docker usable without sudo on this box).
- Staged into `mpc/mpc-node/data/`: fresh beta.22 circuit JSONs,
  `bn254_g2.dat` (copied from co-snarks `co-noir-common/src/crs/`),
  `monty_hall_init_bb.vk` (bb `write_vk` output — byte-identical to
  co-noir's own VK per Phase 2, and the ZK prover requires a VK).
- 3 nodes + orchestrator launched (see `mpc/e2e.sh` for exact args);
  `curl /api/sample_rand` then `/api/init_game` → HTTP 200 + orchestrator
  log "retrieved proofs!". Proof pulled from node0 DB via `docker exec
  mh-pg0 psql ... encode(proof,'hex')` → **target bb verify: PASS**;
  tampered byte at offset 2000 → exit 1.
- ⚠ teardown: hit the pgrep SELF-MATCH trap again (`pgrep -f
  "release/mpc-node"` matches its own cmdline) → `pgrep -f
  "[r]elease/mpc-node"`. (Memory: watcher-discipline.)
- Repeatable gate: `mpc/e2e.sh` — full clean-room rerun PASS (~40 s).
- Commits: monty-hall `455893f` (all of A0–A4); co-snarks docs
  `d8970588`, `4a7d5550`.
