# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-29T10:23:53Z
- **host**: mike-box
- **cpu_cores_total**: 192
- **rayon_threads_per_party**: 16
- **co_snarks_commit**: 38bf42c6
- **co_snarks_branch**: mc/update-co-noir
- **co_snarks_worktree**: dirty
- **bb_oracle_path**: /mnt/user-data/mike/.bb-target-src-v5.0.1/bb
- **bb_version_pin**: 5.0.1
- **nargo_version**: nargo version = 1.0.0-beta.22
- **network**: loopback (single host; distance/latency NOT measured here — tiers.csv is a MODEL, not a real-network measurement; see project-docs ch. 24 §3a for the netem v3 follow-up)

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-29-v4/loopback-matrix/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.291s | — | 0.195s |
| plaindriver (co-noir, no MPC) | — | — | 0.886s | — | 0.737s |
| REP3 3-party (ZK) | 0.010s | 0.115s | 14.005s | 0.020s | 13.661s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **48.1×** (loopback compute only).

Other phases: bb vkgen 0.093s · plaindriver solve+prove (ZK) 0.883s.

**Peak memory (ZK)** — bb prove 72 MB · plaindriver prove 238 MB · REP3 witext 29 MB · REP3 prove (per party) 2,547 MB.

**Comms (measured)** — witext: R≈5 rounds, 0.0 MB sent (party 0) · prove_zk: R≈2,425 rounds, 675.9 MB sent (party 0) · prove_nonzk: R≈2,313 rounds, 675.9 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.142s | — | 0.067s |
| plaindriver (co-noir, no MPC) | — | — | 0.184s | — | 0.144s |
| REP3 3-party (ZK) | 0.013s | 0.132s | 0.412s | 0.019s | 0.373s |
| Shamir 3-party (ZK) | — | — | 0.587s | 0.020s | 0.537s |

REP3-prove ÷ bb-prove (ZK): **2.9×** (loopback compute only).

Other phases: bb vkgen 0.040s · plaindriver solve+prove (ZK) 0.181s.

**Peak memory (ZK)** — bb prove 12 MB · plaindriver prove 12 MB · REP3 witext 12 MB · REP3 prove (per party) 42 MB.

**Comms (measured)** — witext: R≈198 rounds, 0.0 MB sent (party 0) · prove_zk: R≈271 rounds, 6.3 MB sent (party 0) · prove_nonzk: R≈197 rounds, 6.3 MB sent (party 0).

**Shape**: 1,412 rows (bb) · dyadic 2,048 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.2%.

## poseidon_2e12

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.172s | — | 0.089s |
| plaindriver (co-noir, no MPC) | — | — | 0.229s | — | 0.188s |
| REP3 3-party (ZK) | 0.013s | 0.150s | 0.561s | 0.021s | 0.510s |
| Shamir 3-party (ZK) | — | — | 0.925s | 0.020s | 0.851s |

REP3-prove ÷ bb-prove (ZK): **3.3×** (loopback compute only).

Other phases: bb vkgen 0.055s.

**Peak memory (ZK)** — bb prove 14 MB · plaindriver prove 18 MB · REP3 witext 11 MB · REP3 prove (per party) 84 MB.

**Comms (measured)** — witext: R≈393 rounds, 0.0 MB sent (party 0) · prove_zk: R≈277 rounds, 12.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 12.5 MB sent (party 0).

**Shape**: 2,822 rows (bb) · dyadic 4,096 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.6%.

## poseidon_2e13

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.222s | — | 0.138s |
| plaindriver (co-noir, no MPC) | — | — | 0.307s | — | 0.267s |
| REP3 3-party (ZK) | 0.019s | 0.201s | 0.806s | 0.020s | 0.774s |
| Shamir 3-party (ZK) | — | — | 1.628s | 0.020s | 1.582s |

REP3-prove ÷ bb-prove (ZK): **3.6×** (loopback compute only).

Other phases: bb vkgen 0.077s.

**Peak memory (ZK)** — bb prove 20 MB · plaindriver prove 43 MB · REP3 witext 14 MB · REP3 prove (per party) 172 MB.

**Comms (measured)** — witext: R≈978 rounds, 0.1 MB sent (party 0) · prove_zk: R≈283 rounds, 25.9 MB sent (party 0) · prove_nonzk: R≈197 rounds, 25.9 MB sent (party 0).

**Shape**: 7,052 rows (bb) · dyadic 8,192 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.8%.

## poseidon_2e14

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.270s | — | 0.205s |
| plaindriver (co-noir, no MPC) | — | — | 0.460s | — | 0.420s |
| REP3 3-party (ZK) | 0.029s | 0.297s | 1.363s | 0.020s | 1.230s |
| Shamir 3-party (ZK) | — | — | 3.124s | 0.020s | 3.175s |

REP3-prove ÷ bb-prove (ZK): **5.0×** (loopback compute only).

Other phases: bb vkgen 0.125s.

**Peak memory (ZK)** — bb prove 36 MB · plaindriver prove 82 MB · REP3 witext 16 MB · REP3 prove (per party) 366 MB.

**Comms (measured)** — witext: R≈2,148 rounds, 0.1 MB sent (party 0) · prove_zk: R≈289 rounds, 52.8 MB sent (party 0) · prove_nonzk: R≈197 rounds, 52.7 MB sent (party 0).

**Shape**: 15,512 rows (bb) · dyadic 16,384 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.8%.

## poseidon_2e15

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.406s | — | 0.309s |
| plaindriver (co-noir, no MPC) | — | — | 0.751s | — | 0.685s |
| REP3 3-party (ZK) | 0.051s | 0.496s | 2.278s | 0.021s | 2.358s |
| Shamir 3-party (ZK) | — | — | 6.073s | 0.020s | 5.715s |

REP3-prove ÷ bb-prove (ZK): **5.6×** (loopback compute only).

Other phases: bb vkgen 0.198s.

**Peak memory (ZK)** — bb prove 81 MB · plaindriver prove 166 MB · REP3 witext 22 MB · REP3 prove (per party) 742 MB.

**Comms (measured)** — witext: R≈4,488 rounds, 0.3 MB sent (party 0) · prove_zk: R≈295 rounds, 106.4 MB sent (party 0) · prove_nonzk: R≈197 rounds, 106.4 MB sent (party 0).

**Shape**: 32,432 rows (bb) · dyadic 32,768 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e16

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.640s | — | 0.526s |
| plaindriver (co-noir, no MPC) | — | — | 1.297s | — | 1.202s |
| REP3 3-party (ZK) | 0.090s | 0.843s | 4.675s | 0.022s | 4.678s |
| Shamir 3-party (ZK) | — | — | 11.531s | 0.020s | 11.040s |

REP3-prove ÷ bb-prove (ZK): **7.3×** (loopback compute only).

Other phases: bb vkgen 0.353s.

**Peak memory (ZK)** — bb prove 128 MB · plaindriver prove 362 MB · REP3 witext 33 MB · REP3 prove (per party) 1,476 MB.

**Comms (measured)** — witext: R≈8,973 rounds, 0.6 MB sent (party 0) · prove_zk: R≈301 rounds, 212.8 MB sent (party 0) · prove_nonzk: R≈197 rounds, 212.8 MB sent (party 0).

**Shape**: 64,862 rows (bb) · dyadic 65,536 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.079s | — | 0.948s |
| plaindriver (co-noir, no MPC) | — | — | 2.247s | — | 2.094s |
| REP3 3-party (ZK) | 0.168s | 1.547s | 8.740s | 0.019s | 8.576s |
| Shamir 3-party (ZK) | — | — | 24.322s | 0.020s | 21.558s |

REP3-prove ÷ bb-prove (ZK): **8.1×** (loopback compute only).

Other phases: bb vkgen 0.660s.

**Peak memory (ZK)** — bb prove 209 MB · plaindriver prove 673 MB · REP3 witext 57 MB · REP3 prove (per party) 3,011 MB.

**Comms (measured)** — witext: R≈17,943 rounds, 1.2 MB sent (party 0) · prove_zk: R≈307 rounds, 425.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 425.5 MB sent (party 0).

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.970s | — | 1.833s |
| plaindriver (co-noir, no MPC) | — | — | 4.191s | — | — |
| REP3 3-party (ZK) | 0.334s | 3.229s | 17.589s | 0.021s | 17.175s |
| Shamir 3-party (ZK) | — | — | 45.646s | 0.019s | 45.218s |

REP3-prove ÷ bb-prove (ZK): **8.9×** (loopback compute only).

Other phases: bb vkgen 1.227s.

**Peak memory (ZK)** — bb prove 415 MB · plaindriver prove 1,390 MB · REP3 witext 103 MB · REP3 prove (per party) 5,450 MB.

**Comms (measured)** — witext: R≈36,078 rounds, 2.4 MB sent (party 0) · prove_zk: R≈313 rounds, 851.9 MB sent (party 0) · prove_nonzk: R≈197 rounds, 851.9 MB sent (party 0).

**Shape**: 260,852 rows (bb) · dyadic 262,144 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.588s | — | 3.462s |
| plaindriver (co-noir, no MPC) | — | — | 7.718s | — | — |
| REP3 3-party (ZK) | 0.663s | 6.335s | 34.345s | 0.019s | 32.810s |
| Shamir 3-party (ZK) | — | — | 95.878s | 0.021s | 91.814s |

REP3-prove ÷ bb-prove (ZK): **9.6×** (loopback compute only).

Other phases: bb vkgen 2.282s.

**Peak memory (ZK)** — bb prove 816 MB · plaindriver prove 2,556 MB · REP3 witext 199 MB · REP3 prove (per party) 10,325 MB.

**Comms (measured)** — witext: R≈72,348 rounds, 4.9 MB sent (party 0) · prove_zk: R≈319 rounds, 1704.8 MB sent (party 0) · prove_nonzk: R≈197 rounds, 1704.7 MB sent (party 0).

**Shape**: 523,112 rows (bb) · dyadic 524,288 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 6.672s | — | 6.511s |
| plaindriver (co-noir, no MPC) | — | — | 15.375s | — | — |
| REP3 3-party (ZK) | 1.334s | 12.483s | 68.904s | 0.020s | 69.391s |
| Shamir 3-party (ZK) | — | — | 194.608s | 0.020s | 190.672s |

REP3-prove ÷ bb-prove (ZK): **10.3×** (loopback compute only).

Other phases: bb vkgen 4.795s.

**Peak memory (ZK)** — bb prove 1,531 MB · plaindriver prove 4,593 MB · REP3 witext 390 MB · REP3 prove (per party) 19,795 MB.

**Comms (measured)** — witext: R≈144,888 rounds, 9.8 MB sent (party 0) · prove_zk: R≈325 rounds, 3410.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 3410.4 MB sent (party 0).

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## recursion_zk

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.572s | — | 3.359s |
| plaindriver (co-noir, no MPC) | — | — | 12.644s | — | 11.408s |
| REP3 3-party (ZK) | 0.013s | 0.115s | 79.534s | 0.024s | 98.677s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **22.3×** (loopback compute only).

Other phases: bb vkgen 2.135s · plaindriver solve+prove (ZK) 12.568s.

**Peak memory (ZK)** — bb prove 985 MB · plaindriver prove 3,689 MB · REP3 witext 9 MB · REP3 prove (per party) 20,093 MB.

**Comms (measured)** — witext: R≈3 rounds, 0.0 MB sent (party 0) · prove_zk: R≈38,576 rounds, 3983.0 MB sent (party 0) · prove_nonzk: R≈38,432 rounds, 3983.0 MB sent (party 0).

**Shape**: 703,658 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 13.6%.

## sha256_2e16

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.534s | — | 0.411s |
| plaindriver (co-noir, no MPC) | — | — | 1.321s | — | 1.222s |
| REP3 3-party (ZK) | 0.010s | 1.475s | 146.045s | 0.021s | 146.776s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **273.5×** (loopback compute only).

Other phases: bb vkgen 0.297s.

**Peak memory (ZK)** — bb prove 110 MB · plaindriver prove 284 MB · REP3 witext 27 MB · REP3 prove (per party) 8,106 MB.

**Comms (measured)** — witext: R≈33 rounds, 0.5 MB sent (party 0) · prove_zk: R≈27,864 rounds, 7697.3 MB sent (party 0) · prove_nonzk: R≈27,758 rounds, 7697.2 MB sent (party 0).

**Shape**: 62,022 rows (bb) · dyadic 65,536 · lookup gates 43,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.881s | — | 0.758s |
| plaindriver (co-noir, no MPC) | — | — | 2.246s | — | 2.094s |
| REP3 3-party (ZK) | 0.011s | 3.000s | 310.750s | 0.020s | 303.953s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **352.7×** (loopback compute only).

Other phases: bb vkgen 0.495s.

**Peak memory (ZK)** — bb prove 209 MB · plaindriver prove 592 MB · REP3 witext 31 MB · REP3 prove (per party) 9,810 MB.

**Comms (measured)** — witext: R≈67 rounds, 1.0 MB sent (party 0) · prove_zk: R≈58,764 rounds, 16390.9 MB sent (party 0) · prove_nonzk: R≈58,652 rounds, 16390.8 MB sent (party 0).

**Shape**: 129,104 rows (bb) · dyadic 131,072 · lookup gates 92,672 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.548s | — | 1.395s |
| plaindriver (co-noir, no MPC) | — | — | 4.006s | — | — |
| REP3 3-party (ZK) | 0.009s | 5.981s | 619.697s | 0.020s | 634.177s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **400.2×** (loopback compute only).

Other phases: bb vkgen 0.924s.

**Peak memory (ZK)** — bb prove 406 MB · plaindriver prove 1,301 MB · REP3 witext 30 MB · REP3 prove (per party) 16,805 MB.

**Comms (measured)** — witext: R≈133 rounds, 2.1 MB sent (party 0) · prove_zk: R≈118,728 rounds, 33276.7 MB sent (party 0) · prove_nonzk: R≈118,610 rounds, 33276.6 MB sent (party 0).

**Shape**: 259,322 rows (bb) · dyadic 262,144 · lookup gates 188,240 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 2.823s | — | 2.692s |
| plaindriver (co-noir, no MPC) | — | — | 7.192s | — | — |
| REP3 3-party (ZK) | 0.009s | 11.841s | 1287.335s | 0.021s | 1270.132s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **456.0×** (loopback compute only).

Other phases: bb vkgen 1.793s.

**Peak memory (ZK)** — bb prove 743 MB · plaindriver prove 2,205 MB · REP3 witext 30 MB · REP3 prove (per party) 21,259 MB.

**Comms (measured)** — witext: R≈267 rounds, 4.3 MB sent (party 0) · prove_zk: R≈240,518 rounds, 67549.7 MB sent (party 0) · prove_nonzk: R≈240,394 rounds, 67549.7 MB sent (party 0).

**Shape**: 523,704 rows (bb) · dyadic 524,288 · lookup gates 382,272 · tables 12 · table rows 33,944 · witness zeros 0.0%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
