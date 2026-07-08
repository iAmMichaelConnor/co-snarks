# Chapter 8 — Data-flow diagrams: who holds what, who sends what, when

*ASCII diagrams (render anywhere). Each is followed by a step key. Read
ch. 01 (MPC), ch. 07 (prover stages) first. These depict the co-noir stack as
it exists (ch. 02) plus the Aztec pattern (ch. 04).*

## D1 — Cast of characters and channels

```
                                 ┌──────────────────────────────────────────┐
                                 │            MPC NETWORK (REP3)            │
 ┌──────────┐   shares (files/   │  ┌────────┐   ┌────────┐   ┌────────┐    │
 │   USER   │   encrypted blobs) │  │ Node 0 │═══│ Node 1 │═══│ Node 2 │    │
 │ (owns    │ ─────────────────▶ │  └────────┘   └────────┘   └────────┘    │
 │ secrets) │                    │       ╚═══════════╧═══════════╝          │
 └──────────┘                    │   full TLS mesh, ports 10000-2 in demos  │
      ▲                          └──────────────────────────────────────────┘
      │  identical proof                     │ │ │
      │  (from any/all nodes)                ▼ ▼ ▼
      │                          ┌──────────────────────┐      ┌───────────┐
      └───────────────────────── │ ORCHESTRATOR (opt.)  │ ───▶ │ VERIFIER  │
                                 │ fan-out jobs, check  │      │ (bb, or   │
                                 │ 3 proofs identical,  │      │ in-circuit│
                                 │ verify, forward      │      │ in Aztec) │
                                 └──────────────────────┘      └───────────┘
```

- **User**: owns the secret witness data. Splits it into 3 shares; each share
  alone is uniformly random (ch. 01 §2.2).
- **Nodes**: each receives ONE share (in TACEO:Proof, encrypted under that
  node's public key). Communicate pairwise over TLS during the protocol.
- **Orchestrator** (a convenience, not a trust requirement): job control
  plane. In monty-hall-aztec it's an HTTP/gRPC server; in the CLI demos it's
  just shell scripts. It never sees witness data — only public artifacts.
- **Verifier**: stock bb / the Aztec in-circuit recursive verifier. Sees only
  the finished standard proof.

Trust: any SINGLE node can be fully compromised (read all its data) without
revealing anything. Two colluding nodes break privacy. Nobody can forge a
false proof (soundness comes from the SNARK, not the MPC).

## D2 — Single-owner proof delegation, end to end (the "split-witness" flow)

```
 USER (local machine)                NODE 0            NODE 1            NODE 2
 ────────────────────                ──────            ──────            ──────
 1. nargo execute
    → full witness w (clear)
 2. sample random w¹,w²;
    w⁰ = w − w¹ − w²
    REP3 shares: s₀=(w⁰,w²)
                 s₁=(w¹,w⁰)  ── s₀ ──▶ holds s₀
                 s₂=(w²,w¹)  ── s₁ ─────────────────▶ holds s₁
                             ── s₂ ──────────────────────────────────▶ holds s₂
 3. (everyone also gets the PUBLIC circuit.json + CRS + network config)

 4.                          ┌─────────── MPC PROVING (see D4) ───────────┐
                             │  ~25+ communication rounds between nodes   │
                             └──────────────┬──────────────┬──────────────┘
                                            │              │
 5.                              proof π  ◀─┴─  proof π  ◀─┴─  proof π
    ◀───────── π (identical from each; compare bytes to detect faults) ────
 6. verify π with stock bb / hand to Aztec PXE (D6)
```

Key properties: step 1–2 happen entirely on the user's machine — the network
never sees w. Step 4's transcript between nodes consists of shares and opened
proof elements only. Step 5: all three π are byte-identical (determinism,
ch. 01 §4.5).

**Variant — multi-user inputs**: each user runs split-input on their own
Prover.toml fields; nodes (or a merge step) combine share-maps
(`merge-input-shares`), then witness extension itself runs under MPC (D3).

## D3 — MPC witness extension (when inputs, not the witness, are shared)

```
 NODES 0,1,2 (lockstep, each holds an input-share map)
 ─────────────────────────────────────────────────────
 for each ACIR opcode in circuit order:
   AssertZero / linear algebra  → local share arithmetic          (no comms)
   share × share multiplication → 1 batched reshare round         (1 round)
   RANGE / bit ops              → A2B conversion (Yao/binary)     (heavy)
   Poseidon2 / MSM / EcAdd      → field-native MPC gadgets        (cheap)
   SHA/Blake/AES                → binary-circuit gadgets          (heavy)
   Brillig (unconstrained)      → co-brillig VM on shares
                                  (ToRadix only for blackboxes! ch. 06)
 output: each node holds its REP3 share of the FULL witness vector
```

## D4 — Inside MPC proving: one Fiat–Shamir round (the universal pattern)

```
   NODE 0                    NODE 1                    NODE 2
   ──────                    ──────                    ──────
   compute share of          compute share of          compute share of
   round output R            round output R            round output R
   (commitment = local       (same)                    (same)
    MSM → point-share;
    univariate coeffs, ...)
        │                        │                         │
        └────────┬───────────────┴───────────┬─────────────┘
                 │   broadcast shares of R   │        ◀── 1 round: "open"
                 ▼                           ▼
   R is now PUBLIC at every node (R is proof content — leaks nothing extra)
                 │
   every node LOCALLY hashes transcript ‖ R  →  challenge c   (identical)
                 │
   continue: next round's computation uses shares + PUBLIC c
```

The whole prover = this pattern ~30 times (oink commitments, 25 sumcheck
rounds, Gemini folds/evals, Shplonk, KZG), plus interleaved share×share
multiplication rounds inside sumcheck and batch inversions (ch. 07 §5).

## D5 — REP3 multiplication (the micro-primitive, for completeness)

```
   x = x₀+x₁+x₂,  y = y₀+y₁+y₂.  Node i holds (xᵢ, xᵢ₋₁) and (yᵢ, yᵢ₋₁).

   Node i locally: zᵢ = xᵢyᵢ + xᵢyᵢ₋₁ + xᵢ₋₁yᵢ + (PRFᵢ − PRFᵢ₋₁)   ← no comms
                                                  └── fresh zero-share ──┘
   Σᵢ zᵢ = xy   (all 9 cross-terms covered exactly once)

   Node i ── zᵢ ──▶ Node i+1        ← ONE message each: restores replication
   Node i now holds (zᵢ, zᵢ₋₁)  =  REP3 share of xy.
```

## D6 — The Aztec "private shared state" end-to-end (target pattern, per ch. 04)

```
 USER/PXE            ORCHESTRATOR              MPC NODES (×3)           AZTEC
 ────────            ────────────              ──────────────           ─────
 1. encrypt input
    shares, one per
    node pubkey ───▶ 2. fan out job ─────────▶ 3. decrypt own share
                        (gRPC/HTTP)               witext + prove (D3,D4)
                                                  state shares → own DB
                     5. check 3 proofs      ◀─ 4. return π + public
                        byte-identical;          commitments (+ MPC-made
                        verify π locally         nullifier when spending)
 6. receive π +
    public inputs ◀──┘
 7. push π (458 F) + vk (115 F)
    into PXE capsule stack
 8. call contract private fn ──────────────────────────────────────▶ 9. pop capsules;
                                                                        verify_proof_with_type(
                                                                          vk, π, PIs, vk_hash,
                                                                          6 /*HONK_ZK*/)
                                                                        = in-circuit UH verifier;
                                                                        state commitment stored
                                                                        as note; π never on-chain
```

Steps 1 and 7–9 are the parts that don't exist yet in reusable form (the
monty-hall demo stubbed them); steps 2–6 exist in monty-hall-aztec against
the old stack. The co-snark proof is *witness data* to the private function —
it is folded into the user's client-side proof and never published (ch. 07 §6).

## D7 — Who learns what (privacy summary)

| Data | User | Node i | Orchestrator | Public/chain |
|---|---|---|---|---|
| Witness / user secrets | ✔ (own) | share only | — | — |
| MPC-held state (PSS pattern) | — | share only | — | commitment only |
| Circuit, VK, CRS | ✔ | ✔ | ✔ | ✔ |
| Fiat–Shamir transcript / challenges | ✔ | ✔ | ✔ | (derivable from π) |
| Finished proof π | ✔ | ✔ | ✔ | NOT published (witness to Aztec private fn) |
| What π itself reveals about the witness | — with ZK flavor; potentially >0 with non-ZK | ← same | ← same | ← same |
