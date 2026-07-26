# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-26T01:13:16Z
- **host**: mike-box
- **cpu_cores_total**: 192
- **rayon_threads_per_party**: 16
- **co_snarks_commit**: 049d3435
- **co_snarks_branch**: mc/update-co-noir
- **co_snarks_worktree**: dirty
- **bb_oracle_path**: /mnt/user-data/mike/.bb-target-src-v5.0.1/bb
- **bb_version_pin**: 5.0.1
- **nargo_version**: nargo version = 1.0.0-beta.22
- **network**: loopback (single host; distance/latency NOT measured here)

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-26/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.295s | — | 0.197s |
| plaindriver (co-noir, no MPC) | — | — | 0.912s | — | 0.748s |
| REP3 3-party (ZK) | 0.010s | 0.210s | 139.480s | 0.021s | 139.561s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **472.8×** (loopback compute only).

Other phases: bb vkgen 0.096s · plaindriver solve+prove (ZK) 0.913s.

**Peak memory (ZK)** — bb prove 63 MB · plaindriver prove 247 MB · REP3 witext 29 MB · REP3 prove (per party) 1,212 MB.

**Comms (measured)** — witext: R≈5 rounds, 0.0 MB sent (party 0) · prove_zk: R≈42,993 rounds, 870.6 MB sent (party 0) · prove_nonzk: R≈42,881 rounds, 870.5 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.168s | — | 0.069s |
| plaindriver (co-noir, no MPC) | — | — | 0.190s | — | 0.145s |
| REP3 3-party (ZK) | 0.012s | 0.131s | 0.342s | 0.020s | 0.372s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **2.0×** (loopback compute only).

Other phases: bb vkgen 0.046s · plaindriver solve+prove (ZK) 0.177s.

**Peak memory (ZK)** — bb prove 12 MB · plaindriver prove 12 MB · REP3 witext 11 MB · REP3 prove (per party) 40 MB.

**Comms (measured)** — witext: R≈366 rounds, 0.0 MB sent (party 0) · prove_zk: R≈384 rounds, 6.3 MB sent (party 0) · prove_nonzk: R≈310 rounds, 6.3 MB sent (party 0).

**Shape**: 1,412 rows (bb) · dyadic 2,048 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.2%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.094s | — | 0.960s |
| plaindriver (co-noir, no MPC) | — | — | 2.277s | — | 2.048s |
| REP3 3-party (ZK) | 0.169s | 1.562s | 9.329s | 0.020s | 9.111s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **8.5×** (loopback compute only).

Other phases: bb vkgen 0.615s.

**Peak memory (ZK)** — bb prove 212 MB · plaindriver prove 668 MB · REP3 witext 57 MB · REP3 prove (per party) 2,951 MB.

**Comms (measured)** — witext: R≈33,399 rounds, 1.3 MB sent (party 0) · prove_zk: R≈11,431 rounds, 425.6 MB sent (party 0) · prove_nonzk: R≈11,321 rounds, 425.6 MB sent (party 0).

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.942s | — | 1.818s |
| plaindriver (co-noir, no MPC) | — | — | 4.332s | — | — |
| REP3 3-party (ZK) | 0.333s | 3.299s | 19.175s | 0.021s | 17.582s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **9.9×** (loopback compute only).

Other phases: bb vkgen 1.219s.

**Peak memory (ZK)** — bb prove 415 MB · plaindriver prove 1,343 MB · REP3 witext 104 MB · REP3 prove (per party) 5,540 MB.

**Comms (measured)** — witext: R≈67,158 rounds, 2.7 MB sent (party 0) · prove_zk: R≈22,690 rounds, 852.1 MB sent (party 0) · prove_nonzk: R≈22,574 rounds, 852.1 MB sent (party 0).

**Shape**: 260,852 rows (bb) · dyadic 262,144 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.687s | — | 3.502s |
| plaindriver (co-noir, no MPC) | — | — | 8.428s | — | — |
| REP3 3-party (ZK) | 0.657s | 6.127s | 36.770s | 0.021s | 36.511s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **10.0×** (loopback compute only).

Other phases: bb vkgen 2.451s.

**Peak memory (ZK)** — bb prove 812 MB · plaindriver prove 2,599 MB · REP3 witext 199 MB · REP3 prove (per party) 10,483 MB.

**Comms (measured)** — witext: R≈134,676 rounds, 5.4 MB sent (party 0) · prove_zk: R≈45,202 rounds, 1705.1 MB sent (party 0) · prove_nonzk: R≈45,080 rounds, 1705.1 MB sent (party 0).

**Shape**: 523,112 rows (bb) · dyadic 524,288 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 7.507s | — | 6.812s |
| plaindriver (co-noir, no MPC) | — | — | 16.916s | — | — |
| REP3 3-party (ZK) | 1.367s | 15.308s | 77.803s | 0.021s | 77.555s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **10.4×** (loopback compute only).

Other phases: bb vkgen 4.911s.

**Peak memory (ZK)** — bb prove 1,524 MB · plaindriver prove 4,204 MB · REP3 witext 389 MB · REP3 prove (per party) 20,045 MB.

**Comms (measured)** — witext: R≈269,712 rounds, 10.8 MB sent (party 0) · prove_zk: R≈90,220 rounds, 3411.2 MB sent (party 0) · prove_nonzk: R≈90,092 rounds, 3411.1 MB sent (party 0).

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## recursion_zk

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.597s | — | 3.332s |
| plaindriver (co-noir, no MPC) | — | — | 12.665s | — | 11.495s |
| REP3 3-party (ZK) | 0.011s | 0.116s | 76.508s | 0.020s | 75.234s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **21.3×** (loopback compute only).

Other phases: bb vkgen 2.124s · plaindriver solve+prove (ZK) 12.810s.

**Peak memory (ZK)** — bb prove 982 MB · plaindriver prove 3,678 MB · REP3 witext 9 MB · REP3 prove (per party) 19,943 MB.

**Comms (measured)** — witext: R≈3 rounds, 0.0 MB sent (party 0) · prove_zk: R≈38,576 rounds, 3983.0 MB sent (party 0) · prove_nonzk: R≈38,432 rounds, 3983.0 MB sent (party 0).

**Shape**: 703,658 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 13.6%.

## sha256_2e16

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.523s | — | 0.429s |
| plaindriver (co-noir, no MPC) | — | — | 1.341s | — | 1.252s |
| REP3 3-party (ZK) | 0.011s | 1.472s | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.286s.

**Peak memory (ZK)** — bb prove 113 MB · plaindriver prove 291 MB · REP3 witext 29 MB.

**Comms (measured)** — witext: R≈33 rounds, 0.5 MB sent (party 0).

**Shape**: 62,022 rows (bb) · dyadic 65,536 · lookup gates 43,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.876s | — | 0.765s |
| plaindriver (co-noir, no MPC) | — | — | 2.240s | — | 2.079s |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.502s.

**Peak memory (ZK)** — bb prove 213 MB · plaindriver prove 623 MB.

**Shape**: 129,104 rows (bb) · dyadic 131,072 · lookup gates 92,672 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.516s | — | 1.385s |
| plaindriver (co-noir, no MPC) | — | — | 3.807s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.940s.

**Peak memory (ZK)** — bb prove 411 MB · plaindriver prove 1,242 MB.

**Shape**: 259,322 rows (bb) · dyadic 262,144 · lookup gates 188,240 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 2.800s | — | 2.619s |
| plaindriver (co-noir, no MPC) | — | — | 7.136s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 1.896s.

**Peak memory (ZK)** — bb prove 750 MB · plaindriver prove 2,267 MB.

**Shape**: 523,704 rows (bb) · dyadic 524,288 · lookup gates 382,272 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 5.178s | — | 4.981s |
| plaindriver (co-noir, no MPC) | — | — | 14.386s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 3.519s.

**Peak memory (ZK)** — bb prove 1,442 MB · plaindriver prove 3,549 MB.

**Shape**: 1,048,522 rows (bb) · dyadic 1,048,576 · lookup gates 767,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
