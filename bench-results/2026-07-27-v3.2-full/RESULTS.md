# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-27T18:49:00Z
- **host**: mike-box
- **cpu_cores_total**: 192
- **rayon_threads_per_party**: 51
- **co_snarks_commit**: 65d2ac86
- **co_snarks_branch**: mc/update-co-noir
- **co_snarks_worktree**: dirty
- **bb_oracle_path**: /mnt/user-data/mike/.bb-target-src-v5.0.1/bb
- **bb_version_pin**: 5.0.1
- **nargo_version**: nargo version = 1.0.0-beta.22
- **network**: loopback (single host; distance/latency NOT measured here — tiers.csv is a MODEL, not a real-network measurement; see project-docs ch. 24 §3a for the netem v3 follow-up)

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-27-v3.2-full/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.297s | — | 0.200s |
| plaindriver (co-noir, no MPC) | — | — | 1.183s | — | 1.003s |
| REP3 3-party (ZK) | 0.010s | 0.115s | 14.979s | 0.031s | 14.398s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **50.4×** (loopback compute only).

Other phases: bb vkgen 0.116s · plaindriver solve+prove (ZK) 1.141s.

**Peak memory (ZK)** — bb prove 63 MB · plaindriver prove 335 MB · REP3 witext 27 MB · REP3 prove (per party) 3,029 MB.

**Comms (measured)** — witext: R≈5 rounds, 0.0 MB sent (party 0) · prove_zk: R≈2,425 rounds, 675.9 MB sent (party 0) · prove_nonzk: R≈2,313 rounds, 675.9 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.168s | — | 0.078s |
| plaindriver (co-noir, no MPC) | — | — | 0.332s | — | 0.268s |
| REP3 3-party (ZK) | 0.013s | 0.140s | 0.671s | 0.033s | 0.569s |
| Shamir 3-party (ZK) | — | — | 0.804s | 0.032s | 0.744s |

REP3-prove ÷ bb-prove (ZK): **4.0×** (loopback compute only).

Other phases: bb vkgen 0.044s · plaindriver solve+prove (ZK) 0.351s.

**Peak memory (ZK)** — bb prove 14 MB · plaindriver prove 12 MB · REP3 witext 12 MB · REP3 prove (per party) 35 MB.

**Comms (measured)** — witext: R≈198 rounds, 0.0 MB sent (party 0) · prove_zk: R≈271 rounds, 6.3 MB sent (party 0) · prove_nonzk: R≈197 rounds, 6.3 MB sent (party 0).

**Shape**: 1,412 rows (bb) · dyadic 2,048 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.2%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.097s | — | 0.952s |
| plaindriver (co-noir, no MPC) | — | — | 2.218s | — | 1.984s |
| REP3 3-party (ZK) | 0.175s | 1.657s | 9.273s | 0.031s | 9.374s |
| Shamir 3-party (ZK) | — | — | 24.037s | 0.032s | 24.492s |

REP3-prove ÷ bb-prove (ZK): **8.5×** (loopback compute only).

Other phases: bb vkgen 0.695s.

**Peak memory (ZK)** — bb prove 208 MB · plaindriver prove 864 MB · REP3 witext 56 MB · REP3 prove (per party) 3,462 MB.

**Comms (measured)** — witext: R≈17,943 rounds, 1.2 MB sent (party 0) · prove_zk: R≈307 rounds, 425.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 425.5 MB sent (party 0).

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.976s | — | 1.788s |
| plaindriver (co-noir, no MPC) | — | — | 4.033s | — | — |
| REP3 3-party (ZK) | 0.347s | 3.330s | 18.764s | 0.032s | 17.137s |
| Shamir 3-party (ZK) | — | — | 49.148s | 0.030s | 48.377s |

REP3-prove ÷ bb-prove (ZK): **9.5×** (loopback compute only).

Other phases: bb vkgen 1.251s.

**Peak memory (ZK)** — bb prove 412 MB · plaindriver prove 1,876 MB · REP3 witext 104 MB · REP3 prove (per party) 6,598 MB.

**Comms (measured)** — witext: R≈36,078 rounds, 2.4 MB sent (party 0) · prove_zk: R≈313 rounds, 851.9 MB sent (party 0) · prove_nonzk: R≈197 rounds, 851.9 MB sent (party 0).

**Shape**: 260,852 rows (bb) · dyadic 262,144 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.803s | — | 3.505s |
| plaindriver (co-noir, no MPC) | — | — | 6.859s | — | — |
| REP3 3-party (ZK) | 0.677s | 6.669s | 33.962s | 0.032s | 32.636s |
| Shamir 3-party (ZK) | — | — | 100.029s | 0.030s | 99.809s |

REP3-prove ÷ bb-prove (ZK): **8.9×** (loopback compute only).

Other phases: bb vkgen 2.440s.

**Peak memory (ZK)** — bb prove 815 MB · plaindriver prove 3,502 MB · REP3 witext 198 MB · REP3 prove (per party) 11,606 MB.

**Comms (measured)** — witext: R≈72,348 rounds, 4.9 MB sent (party 0) · prove_zk: R≈319 rounds, 1704.8 MB sent (party 0) · prove_nonzk: R≈197 rounds, 1704.7 MB sent (party 0).

**Shape**: 523,112 rows (bb) · dyadic 524,288 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 7.124s | — | 6.824s |
| plaindriver (co-noir, no MPC) | — | — | 12.684s | — | — |
| REP3 3-party (ZK) | 1.327s | 13.116s | 66.357s | 0.031s | 65.993s |
| Shamir 3-party (ZK) | — | — | 195.617s | 0.033s | 190.977s |

REP3-prove ÷ bb-prove (ZK): **9.3×** (loopback compute only).

Other phases: bb vkgen 4.813s.

**Peak memory (ZK)** — bb prove 1,531 MB · plaindriver prove 6,152 MB · REP3 witext 389 MB · REP3 prove (per party) 21,888 MB.

**Comms (measured)** — witext: R≈144,888 rounds, 9.8 MB sent (party 0) · prove_zk: R≈325 rounds, 3410.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 3410.4 MB sent (party 0).

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## recursion_zk

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 3.614s | — | 3.314s |
| plaindriver (co-noir, no MPC) | — | — | 11.296s | — | 10.385s |
| REP3 3-party (ZK) | 0.012s | 0.118s | 72.049s | 0.032s | 73.236s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **19.9×** (loopback compute only).

Other phases: bb vkgen 2.119s · plaindriver solve+prove (ZK) 11.218s.

**Peak memory (ZK)** — bb prove 987 MB · plaindriver prove 4,986 MB · REP3 witext 11 MB · REP3 prove (per party) 21,020 MB.

**Comms (measured)** — witext: R≈3 rounds, 0.0 MB sent (party 0) · prove_zk: R≈38,576 rounds, 3983.0 MB sent (party 0) · prove_nonzk: R≈38,432 rounds, 3983.0 MB sent (party 0).

**Shape**: 703,658 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 13.6%.

## sha256_2e16

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.544s | — | 0.420s |
| plaindriver (co-noir, no MPC) | — | — | 1.565s | — | 1.429s |
| REP3 3-party (ZK) | 0.011s | 1.469s | 160.758s | 0.032s | 158.051s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **295.5×** (loopback compute only).

Other phases: bb vkgen 0.285s.

**Peak memory (ZK)** — bb prove 109 MB · plaindriver prove 364 MB · REP3 witext 30 MB · REP3 prove (per party) 40,612 MB.

**Comms (measured)** — witext: R≈33 rounds, 0.5 MB sent (party 0) · prove_zk: R≈27,447 rounds, 7697.3 MB sent (party 0) · prove_nonzk: R≈27,341 rounds, 7697.2 MB sent (party 0).

**Shape**: 62,022 rows (bb) · dyadic 65,536 · lookup gates 43,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.872s | — | 0.758s |
| plaindriver (co-noir, no MPC) | — | — | 2.467s | — | 2.268s |
| REP3 3-party (ZK) | 0.011s | 3.063s | 346.413s | 0.030s | 355.423s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **397.3×** (loopback compute only).

Other phases: bb vkgen 0.508s.

**Peak memory (ZK)** — bb prove 202 MB · plaindriver prove 714 MB · REP3 witext 28 MB · REP3 prove (per party) 86,026 MB.

**Comms (measured)** — witext: R≈67 rounds, 1.0 MB sent (party 0) · prove_zk: R≈57,841 rounds, 16390.9 MB sent (party 0) · prove_nonzk: R≈57,729 rounds, 16390.8 MB sent (party 0).

**Shape**: 129,104 rows (bb) · dyadic 131,072 · lookup gates 92,672 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e18

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.569s | — | 1.369s |
| plaindriver (co-noir, no MPC) | — | — | 3.869s | — | — |
| REP3 3-party (ZK) | 0.011s | 6.006s | 628.715s | 0.030s | 619.563s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **400.6×** (loopback compute only).

Other phases: bb vkgen 0.989s.

**Peak memory (ZK)** — bb prove 399 MB · plaindriver prove 1,470 MB · REP3 witext 32 MB · REP3 prove (per party) 16,756 MB.

**Comms (measured)** — witext: R≈133 rounds, 2.1 MB sent (party 0) · prove_zk: R≈118,728 rounds, 33276.7 MB sent (party 0) · prove_nonzk: R≈118,610 rounds, 33276.6 MB sent (party 0).

**Shape**: 259,322 rows (bb) · dyadic 262,144 · lookup gates 188,240 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e19

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 2.847s | — | 2.708s |
| plaindriver (co-noir, no MPC) | — | — | 6.889s | — | — |
| REP3 3-party (ZK) | 0.011s | 12.078s | 1237.632s | 0.032s | 1286.543s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **434.7×** (loopback compute only).

Other phases: bb vkgen 1.862s.

**Peak memory (ZK)** — bb prove 745 MB · plaindriver prove 3,086 MB · REP3 witext 30 MB · REP3 prove (per party) 21,258 MB.

**Comms (measured)** — witext: R≈267 rounds, 4.3 MB sent (party 0) · prove_zk: R≈240,518 rounds, 67549.7 MB sent (party 0) · prove_nonzk: R≈240,394 rounds, 67549.7 MB sent (party 0).

**Shape**: 523,704 rows (bb) · dyadic 524,288 · lookup gates 382,272 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## sha256_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 5.519s | — | 4.927s |
| plaindriver (co-noir, no MPC) | — | — | 12.960s | — | — |
| REP3 3-party (ZK) | 0.011s | 23.501s | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 3.629s.

**Peak memory (ZK)** — bb prove 1,442 MB · plaindriver prove 5,085 MB · REP3 witext 30 MB.

**Comms (measured)** — witext: R≈533 rounds, 8.6 MB sent (party 0).

**Shape**: 1,048,522 rows (bb) · dyadic 1,048,576 · lookup gates 767,440 · tables 12 · table rows 33,944 · witness zeros 0.0%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
