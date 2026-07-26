# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-26T21:37:31Z
- **host**: mike-box
- **cpu_cores_total**: 192
- **rayon_threads_per_party**: 51
- **co_snarks_commit**: c5204a03
- **co_snarks_branch**: mc/update-co-noir
- **co_snarks_worktree**: clean
- **bb_oracle_path**: /mnt/user-data/mike/.bb-target-src-v5.0.1/bb
- **bb_version_pin**: 5.0.1
- **nargo_version**: nargo version = 1.0.0-beta.22
- **network**: loopback (single host; distance/latency NOT measured here — tiers.csv is a MODEL, not a real-network measurement; see project-docs ch. 24 §3a for the netem v3 follow-up)

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-26-v3-netem/lan/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.292s | — | 0.205s |
| plaindriver (co-noir, no MPC) | — | — | 1.161s | — | 0.987s |
| REP3 3-party (ZK) | 0.010s | 0.146s | 58.112s | 0.030s | 57.711s |
| Shamir 3-party (ZK) | — | — | — | — | — |

REP3-prove ÷ bb-prove (ZK): **199.0×** (loopback compute only).

Other phases: bb vkgen 0.103s · plaindriver solve+prove (ZK) 1.143s.

**Peak memory (ZK)** — bb prove 67 MB · plaindriver prove 323 MB · REP3 witext 27 MB · REP3 prove (per party) 1,781 MB.

**Comms (measured)** — witext: R≈5 rounds, 0.0 MB sent (party 0) · prove_zk: R≈33,590 rounds, 676.3 MB sent (party 0) · prove_nonzk: R≈33,478 rounds, 676.2 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.063s | — | 0.946s |
| plaindriver (co-noir, no MPC) | — | — | 2.120s | — | 2.027s |
| REP3 3-party (ZK) | 0.172s | 35.871s | 16.946s | 0.031s | 16.768s |
| Shamir 3-party (ZK) | — | — | 31.877s | 0.031s | 31.398s |

REP3-prove ÷ bb-prove (ZK): **15.9×** (loopback compute only).

Other phases: bb vkgen 0.658s.

**Peak memory (ZK)** — bb prove 215 MB · plaindriver prove 855 MB · REP3 witext 56 MB · REP3 prove (per party) 3,467 MB.

**Comms (measured)** — witext: R≈33,399 rounds, 1.3 MB sent (party 0) · prove_zk: R≈307 rounds, 425.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 425.5 MB sent (party 0).

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 7.045s | — | 6.963s |
| plaindriver (co-noir, no MPC) | — | — | 12.709s | — | — |
| REP3 3-party (ZK) | 1.339s | 289.534s | 131.026s | 0.032s | 132.533s |
| Shamir 3-party (ZK) | — | — | 247.400s | 0.029s | 243.459s |

REP3-prove ÷ bb-prove (ZK): **18.6×** (loopback compute only).

Other phases: bb vkgen 5.086s.

**Peak memory (ZK)** — bb prove 1,535 MB · plaindriver prove 6,328 MB · REP3 witext 388 MB · REP3 prove (per party) 21,716 MB.

**Comms (measured)** — witext: R≈269,712 rounds, 10.8 MB sent (party 0) · prove_zk: R≈325 rounds, 3410.5 MB sent (party 0) · prove_nonzk: R≈197 rounds, 3410.4 MB sent (party 0).

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
