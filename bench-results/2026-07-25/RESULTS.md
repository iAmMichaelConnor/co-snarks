# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-25T11:15:40Z
- **host**: mike-box
- **cpu_cores_total**: 192
- **rayon_threads_per_party**: 16
- **co_snarks_commit**: 89666ce5
- **co_snarks_branch**: mc/update-co-noir
- **co_snarks_worktree**: clean
- **bb_oracle_path**: /mnt/user-data/mike/.bb-target-src-v5.0.1/bb
- **bb_version_pin**: 5.0.1
- **nargo_version**: nargo version = 1.0.0-beta.22
- **network**: loopback (single host; distance/latency NOT measured here)

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-25/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.297s | — | 0.195s |
| plaindriver (co-noir, no MPC) | — | — | 0.899s | — | 0.740s |
| REP3 3-party (ZK) | 0.010s | 0.119s | 140.557s | 0.021s | 140.531s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **473.3×** (loopback compute only).

Other phases: bb vkgen 0.098s · plaindriver solve+prove (ZK) 0.909s.

**Peak memory (ZK)** — bb prove 69 MB · plaindriver prove 233 MB · REP3 witext 27 MB · REP3 prove (per party) 1,214 MB.

**Comms (measured)** — witext: R≈6 rounds, 0.0 MB sent (party 0) · prove_zk: R≈43,564 rounds, 870.6 MB sent (party 0) · prove_nonzk: R≈43,452 rounds, 870.5 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.148s | — | 0.077s |
| plaindriver (co-noir, no MPC) | — | — | 0.185s | — | 0.140s |
| REP3 3-party (ZK) | 0.013s | 0.132s | 0.463s | 0.022s | 0.404s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **3.1×** (loopback compute only).

Other phases: bb vkgen 0.043s · plaindriver solve+prove (ZK) 0.176s.

**Peak memory (ZK)** — bb prove 14 MB · plaindriver prove 12 MB · REP3 witext 11 MB · REP3 prove (per party) 44 MB.

**Comms (measured)** — witext: R≈366 rounds, 0.0 MB sent (party 0) · prove_zk: R≈385 rounds, 6.3 MB sent (party 0) · prove_nonzk: R≈311 rounds, 6.3 MB sent (party 0).

**Shape**: 1,412 rows (bb) · dyadic 2,048 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.2%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.094s | — | 0.955s |
| plaindriver (co-noir, no MPC) | — | — | 2.326s | — | 2.116s |
| REP3 3-party (ZK) | 0.170s | 1.494s | 12.067s | 0.021s | 12.101s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **11.0×** (loopback compute only).

Other phases: bb vkgen 0.659s.

**Peak memory (ZK)** — bb prove 215 MB · plaindriver prove 691 MB · REP3 witext 57 MB · REP3 prove (per party) 3,115 MB.

**Comms (measured)** — witext: R≈33,399 rounds, 1.3 MB sent (party 0) · prove_zk: R≈11,432 rounds, 425.6 MB sent (party 0) · prove_nonzk: R≈11,322 rounds, 425.6 MB sent (party 0).

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.974s | — | 1.818s |
| plaindriver (co-noir, no MPC) | — | — | 4.397s | — | — |
| REP3 3-party (ZK) | 0.330s | 3.133s | 24.325s | 0.025s | 24.159s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **12.3×** (loopback compute only).

Other phases: bb vkgen 1.273s.

**Peak memory (ZK)** — bb prove 417 MB · plaindriver prove 1,329 MB · REP3 witext 103 MB · REP3 prove (per party) 5,553 MB.

**Comms (measured)** — witext: R≈67,158 rounds, 2.7 MB sent (party 0) · prove_zk: R≈22,691 rounds, 852.1 MB sent (party 0) · prove_nonzk: R≈22,575 rounds, 852.1 MB sent (party 0).

**Shape**: 260,852 rows (bb) · dyadic 262,144 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.663s | — | 3.500s |
| plaindriver (co-noir, no MPC) | — | — | 8.165s | — | — |
| REP3 3-party (ZK) | 0.653s | 6.212s | 48.789s | 0.020s | 48.468s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **13.3×** (loopback compute only).

Other phases: bb vkgen 2.446s.

**Peak memory (ZK)** — bb prove 814 MB · plaindriver prove 2,529 MB · REP3 witext 199 MB · REP3 prove (per party) 10,780 MB.

**Comms (measured)** — witext: R≈134,676 rounds, 5.4 MB sent (party 0) · prove_zk: R≈45,203 rounds, 1705.1 MB sent (party 0) · prove_nonzk: R≈45,081 rounds, 1705.1 MB sent (party 0).

**Shape**: 523,112 rows (bb) · dyadic 524,288 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 7.880s | — | 7.443s |
| plaindriver (co-noir, no MPC) | — | — | 19.334s | — | — |
| REP3 3-party (ZK) | 1.339s | 14.963s | 101.063s | 0.022s | 98.445s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **12.8×** (loopback compute only).

Other phases: bb vkgen 5.335s.

**Peak memory (ZK)** — bb prove 1,520 MB · plaindriver prove 4,368 MB · REP3 witext 389 MB · REP3 prove (per party) 20,249 MB.

**Comms (measured)** — witext: R≈269,712 rounds, 10.8 MB sent (party 0) · prove_zk: R≈90,221 rounds, 3411.2 MB sent (party 0) · prove_nonzk: R≈90,093 rounds, 3411.1 MB sent (party 0).

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## recursion_zk

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.553s | — | 3.433s |
| plaindriver (co-noir, no MPC) | — | — | 12.893s | — | 11.845s |
| REP3 3-party (ZK) | 0.011s | 0.116s | 94.818s | 0.020s | 92.117s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **26.7×** (loopback compute only).

Other phases: bb vkgen 2.129s · plaindriver solve+prove (ZK) 13.001s.

**Peak memory (ZK)** — bb prove 971 MB · plaindriver prove 3,702 MB · REP3 witext 9 MB · REP3 prove (per party) 20,160 MB.

**Comms (measured)** — witext: R≈3 rounds, 0.0 MB sent (party 0) · prove_zk: R≈38,577 rounds, 3983.0 MB sent (party 0) · prove_nonzk: R≈38,433 rounds, 3983.0 MB sent (party 0).

**Shape**: 703,658 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 13.6%.

## sha256_2e16

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.526s | — | 0.427s |
| plaindriver (co-noir, no MPC) | — | — | 1.304s | — | 1.238s |
| REP3 3-party (ZK) | 0.012s | 1.360s | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.283s.

**Peak memory (ZK)** — bb prove 114 MB · plaindriver prove 283 MB · REP3 witext 26 MB.

**Comms (measured)** — witext: R≈48 rounds, 0.5 MB sent (party 0).

**Shape**: 62,022 rows (bb) · dyadic 65,536 · lookup gates 43,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.905s | — | 0.763s |
| plaindriver (co-noir, no MPC) | — | — | 2.248s | — | 2.085s |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.502s.

**Peak memory (ZK)** — bb prove 210 MB · plaindriver prove 565 MB.

**Shape**: 129,104 rows (bb) · dyadic 131,072 · lookup gates 92,672 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.577s | — | 1.392s |
| plaindriver (co-noir, no MPC) | — | — | 3.955s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.942s.

**Peak memory (ZK)** — bb prove 408 MB · plaindriver prove 1,204 MB.

**Shape**: 259,322 rows (bb) · dyadic 262,144 · lookup gates 188,240 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 2.892s | — | 2.683s |
| plaindriver (co-noir, no MPC) | — | — | 7.431s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 1.818s.

**Peak memory (ZK)** — bb prove 745 MB · plaindriver prove 2,251 MB.

**Shape**: 523,704 rows (bb) · dyadic 524,288 · lookup gates 382,272 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 5.491s | — | 4.990s |
| plaindriver (co-noir, no MPC) | — | — | 14.566s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 3.441s.

**Peak memory (ZK)** — bb prove 1,447 MB · plaindriver prove 3,594 MB.

**Shape**: 1,048,522 rows (bb) · dyadic 1,048,576 · lookup gates 767,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
