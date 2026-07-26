# PLAN 0.5 benchmark — results

**Run provenance** (what produced these numbers — required to compare against another run):

- **started_utc**: 2026-07-26T22:26:50Z
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

Source: `/mnt/user-data/mike/co-snarks/bench-results/2026-07-26-v3-netem/wan/results.csv`  ·  medians across reps of successful rows  ·  loopback only  ·  `—` = not measured (stays modeled in the site).

## bb_sha256_compression

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 0.271s | — | 0.192s |
| plaindriver (co-noir, no MPC) | — | — | 1.124s | — | 0.997s |
| REP3 3-party (ZK) | 0.011s | 0.656s | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.098s · plaindriver solve+prove (ZK) 1.075s.

**Peak memory (ZK)** — bb prove 68 MB · plaindriver prove 306 MB · REP3 witext 26 MB.

**Comms (measured)** — witext: R≈5 rounds, 0.0 MB sent (party 0).

**Shape**: 33,944 rows (bb) · dyadic 65,536 · lookup gates 2,896 · tables 12 · table rows 33,944 · witness zeros 0.0%.

## poseidon_2e17

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 1.074s | — | 0.940s |
| plaindriver (co-noir, no MPC) | — | — | 2.158s | — | 2.079s |
| REP3 3-party (ZK) | 0.174s | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 0.655s.

**Peak memory (ZK)** — bb prove 214 MB · plaindriver prove 830 MB.

**Shape**: 129,722 rows (bb) · dyadic 131,072 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

## poseidon_2e20

| config | split | witext | prove | verify | prove (non-ZK) |
|---|---|---|---|---|---|
| bb (1 prover) | — | — | 7.461s | — | 7.233s |
| plaindriver (co-noir, no MPC) | — | — | 13.178s | — | — |
| REP3 3-party (ZK) | — | — | — | — | — |
| Shamir 3-party (ZK) | — | — | — | — | — |

Other phases: bb vkgen 4.844s.

**Peak memory (ZK)** — bb prove 1,523 MB · plaindriver prove 6,320 MB.

**Shape**: 1,047,632 rows (bb) · dyadic 1,048,576 · lookup gates 0 · tables 0 · table rows 0 · witness zeros 73.9%.

---

Correctness (measured, not here): proofs byte-identical to bb — `compare_mpc.sh`, VK byte-KATs. This file times the honest path only.

Next: bake `site-anchors.json` into the co-SNARK explorer (project-docs ch.22 V7) and redeploy the same artifact URL.
