//! Comms-free level scheduler and round-attribution analysis for the ACVM
//! witness-extension solve loop.
//!
//! This is a *pure local analysis* over the **public** circuit structure: it
//! reads witness *indices* and which opcode produces each witness, never a
//! witness *value*. It performs no network I/O and inspects no MPC state, so it
//! can be run identically by every party (and by the plain driver) without
//! leaking anything.
//!
//! Two things are produced:
//!
//! * [`schedule_levels`] — Pass 1 of the two-pass level-scheduled solve. It
//!   walks the opcode stream in order, maintaining `produced_at[witness]`
//!   (initial ABI/input witnesses live at level 0), and assigns each opcode
//!   `level = 1 + max(produced_at[inputs])`, recording `produced_at` for its
//!   outputs. Opcodes that share a level are provably mutually independent (no
//!   output of one is an input of another). The executor batches shared products
//!   within a level; equation solves still run serially.
//!
//! * [`attribute_rounds`] — a taint analysis that replays the arithmetic
//!   solver's control flow on a `shared`/`public` lattice (every witness
//!   derived from a private input is `shared`) and models the arithmetic network
//!   rounds the serial solve pays, split across shared×shared multiplications
//!   (`solve_mul_term`) and shared-coefficient divisions/inversions
//!   (`solve_equation`). It then computes the round count the level-batched
//!   solve pays (products batched; equation solves serial), which sizes the round-collapse
//!   factor `f` for the current executor.
//!
//! ## Which opcode kinds are precisely modelled vs treated as barriers
//!
//! * **`AssertZero`** — precisely modelled. Referenced witnesses (with non-zero
//!   coefficient) that are already produced are inputs; the single remaining
//!   referenced witness is the output the opcode solves for.
//! * **`BrilligCall`** — precisely modelled as an opaque multi-output producer:
//!   inputs are every witness referenced by the input expressions and the
//!   predicate; outputs are the declared output witnesses.
//! * **`BlackBoxFuncCall`** — precisely modelled as a multi-output producer:
//!   inputs are `get_input_witnesses()`, outputs are `get_outputs_vec()`.
//! * **`MemoryInit` / `MemoryOp`** — treated as a conservative **level
//!   barrier**. A dynamic (possibly shared) read/write index can alias any slot
//!   of the block, and that aliasing cannot be resolved from witness indices
//!   alone, so a memory opcode flushes the current level and forces a fresh one,
//!   with everything after it ordered strictly later. Safe but conservative.
//! * **`Call`** and any future kind — treated as a level barrier (the serial
//!   solver does not support `Call` at all; a barrier keeps the analysis sound
//!   if one ever appears).

use acir::{
    AcirField,
    acir_field::GenericFieldElement,
    circuit::{
        Opcode,
        brillig::{BrilligInputs, BrilligOutputs},
    },
    native_types::Expression,
};
use ark_ff::PrimeField;
use std::collections::{HashMap, HashSet};

/// Whether an opcode kind is modelled precisely or as a conservative barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modelling {
    /// Dependencies derived exactly from the opcode's witness indices.
    Precise,
    /// Conservative fallback: the opcode is its own level and orders everything
    /// before it strictly before everything after it.
    Barrier,
}

/// Per-opcode-kind tallies gathered during scheduling.
#[derive(Default, Debug, Clone)]
pub struct KindCounts {
    pub assert_zero: usize,
    pub blackbox: usize,
    pub brillig: usize,
    pub memory_init: usize,
    pub memory_op: usize,
    pub call: usize,
    /// Opcodes whose dependencies were modelled precisely.
    pub modelled_precise: usize,
    /// Opcodes handled via the conservative barrier fallback.
    pub barriered: usize,
}

/// Static per-opcode dependency facts derived by the scheduler.
#[derive(Debug, Clone)]
pub struct OpInfo {
    /// Witness indices this opcode reads (already produced when reached).
    pub inputs: Vec<u32>,
    /// Witness indices this opcode first produces.
    pub outputs: Vec<u32>,
    /// The assigned dependency level (1-based; 0 is reserved for ABI inputs).
    pub level: usize,
    pub modelling: Modelling,
}

/// Result of Pass 1: the opcode DAG grouped into independent levels.
pub struct LevelSchedule {
    /// Opcode indices grouped by level, in ascending level order. Within a
    /// level, indices are in original opcode order.
    pub levels: Vec<Vec<usize>>,
    /// Per-opcode dependency facts, indexed by opcode position.
    pub op_info: Vec<OpInfo>,
    pub num_opcodes: usize,
    pub kinds: KindCounts,
    /// Set of witness indices that are never produced by any opcode (the ABI /
    /// input witnesses that live at level 0).
    pub initial_witnesses: HashSet<u32>,
}

impl LevelSchedule {
    /// DAG depth = number of non-empty levels.
    pub fn depth(&self) -> usize {
        self.levels.len()
    }

    /// Number of opcodes per level, in level order.
    pub fn width_histogram(&self) -> Vec<usize> {
        self.levels.iter().map(|l| l.len()).collect()
    }

    pub fn max_width(&self) -> usize {
        self.levels.iter().map(|l| l.len()).max().unwrap_or(0)
    }

    pub fn mean_width(&self) -> f64 {
        if self.levels.is_empty() {
            0.0
        } else {
            self.num_opcodes as f64 / self.levels.len() as f64
        }
    }

    /// A valid topological execution order: level-major, original opcode order
    /// within each level. Feeding this to the serial solver produces the same
    /// witness as the original order (every producer precedes its consumers).
    pub fn flatten_level_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.num_opcodes);
        for level in &self.levels {
            order.extend_from_slice(level);
        }
        order
    }
}

/// Collect the witness indices referenced (with non-zero coefficient) by an
/// `AssertZero` expression. A zero coefficient means the term is skipped by the
/// solver, so the witness is not actually read.
fn assert_zero_witnesses<F: PrimeField>(expr: &Expression<GenericFieldElement<F>>) -> Vec<u32> {
    let mut out = Vec::new();
    for (c, l, r) in &expr.mul_terms {
        if !c.is_zero() {
            out.push(l.0);
            out.push(r.0);
        }
    }
    for (q, w) in &expr.linear_combinations {
        if !q.is_zero() {
            out.push(w.0);
        }
    }
    out
}

/// Witness indices referenced by a Brillig input expression.
fn expr_witnesses<F: PrimeField>(expr: &Expression<GenericFieldElement<F>>, out: &mut Vec<u32>) {
    for (_, l, r) in &expr.mul_terms {
        out.push(l.0);
        out.push(r.0);
    }
    for (_, w) in &expr.linear_combinations {
        out.push(w.0);
    }
}

/// Input/output witness indices for a `BrilligCall`.
fn brillig_io<F: PrimeField>(
    inputs: &[BrilligInputs<GenericFieldElement<F>>],
    outputs: &[BrilligOutputs],
    predicate: &Expression<GenericFieldElement<F>>,
) -> (Vec<u32>, Vec<u32>) {
    let mut ins = Vec::new();
    expr_witnesses(predicate, &mut ins);
    for input in inputs {
        match input {
            BrilligInputs::Single(expr) => expr_witnesses(expr, &mut ins),
            BrilligInputs::Array(arr) => {
                for expr in arr {
                    expr_witnesses(expr, &mut ins);
                }
            }
            BrilligInputs::MemoryArray(_) => {}
        }
    }
    let mut outs = Vec::new();
    for output in outputs {
        match output {
            BrilligOutputs::Simple(w) => outs.push(w.0),
            BrilligOutputs::Array(arr) => outs.extend(arr.iter().map(|w| w.0)),
        }
    }
    (ins, outs)
}

/// Pass 1: assign every opcode a dependency level from the public circuit.
///
/// `initial` is the set of ABI witness indices that are already populated in the
/// witness map before the solve begins (the private + public parameters). They
/// live at level 0; without seeding them the first opcode that reads an input
/// would misclassify it as an output.
pub fn schedule_levels<F: PrimeField>(
    opcodes: &[Opcode<GenericFieldElement<F>>],
    initial: &HashSet<u32>,
) -> LevelSchedule {
    let mut produced_at: HashMap<u32, usize> = HashMap::new();
    let mut initial_sorted: Vec<u32> = initial.iter().copied().collect();
    initial_sorted.sort_unstable();
    for w in &initial_sorted {
        produced_at.insert(*w, 0);
    }
    let mut kinds = KindCounts::default();
    let mut op_info: Vec<OpInfo> = Vec::with_capacity(opcodes.len());

    // Largest level assigned so far, and a floor that barriers push forward:
    // every opcode after a barrier must sit strictly above `barrier_floor`.
    let mut max_level = 0usize;
    let mut barrier_floor = 0usize;

    for opcode in opcodes {
        // Gather (inputs, outputs, modelling) for this opcode.
        let (inputs, outputs, modelling): (Vec<u32>, Vec<u32>, Modelling) = match opcode {
            Opcode::AssertZero(expr) => {
                kinds.assert_zero += 1;
                let referenced = assert_zero_witnesses(expr);
                let mut ins = Vec::new();
                let mut outs = Vec::new();
                for w in &referenced {
                    if produced_at.contains_key(w) {
                        ins.push(*w);
                    } else {
                        // Not yet produced: this opcode solves for it (unless it
                        // is an ABI input, which we reconcile after the walk).
                        outs.push(*w);
                    }
                }
                (ins, outs, Modelling::Precise)
            }
            Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                kinds.brillig += 1;
                let (ins, outs) = brillig_io(inputs, outputs, predicate);
                (ins, outs, Modelling::Precise)
            }
            Opcode::BlackBoxFuncCall(bb) => {
                kinds.blackbox += 1;
                let ins = bb.get_input_witnesses().into_iter().map(|w| w.0).collect();
                let outs = bb.get_outputs_vec().into_iter().map(|w| w.0).collect();
                (ins, outs, Modelling::Precise)
            }
            Opcode::MemoryInit { init, .. } => {
                kinds.memory_init += 1;
                (
                    init.iter().map(|w| w.0).collect(),
                    Vec::new(),
                    Modelling::Barrier,
                )
            }
            Opcode::MemoryOp { op, .. } => {
                kinds.memory_op += 1;
                // Both the index and the value witness participate; the read
                // target (op.value) is an output on a read.
                let ins = vec![op.index.0];
                let outs = vec![op.value.0];
                (ins, outs, Modelling::Barrier)
            }
            Opcode::Call { .. } => {
                kinds.call += 1;
                (Vec::new(), Vec::new(), Modelling::Barrier)
            }
        };

        let level = match modelling {
            Modelling::Precise => {
                kinds.modelled_precise += 1;
                let mut lvl = 1usize;
                for w in &inputs {
                    if let Some(&pl) = produced_at.get(w) {
                        lvl = lvl.max(pl + 1);
                    }
                    // Inputs not in `produced_at` are level-0 ABI witnesses and
                    // contribute the baseline `1`.
                }
                if lvl <= barrier_floor {
                    lvl = barrier_floor + 1;
                }
                lvl
            }
            Modelling::Barrier => {
                kinds.barriered += 1;
                // A barrier must come after everything scheduled so far.
                let lvl = max_level + 1;
                barrier_floor = lvl;
                lvl
            }
        };

        for w in &outputs {
            produced_at.entry(*w).or_insert(level);
        }
        max_level = max_level.max(level);

        op_info.push(OpInfo {
            inputs,
            outputs,
            level,
            modelling,
        });
    }

    // Group opcodes by level, dropping any empty levels a barrier jump created.
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); max_level + 1];
    for (i, info) in op_info.iter().enumerate() {
        buckets[info.level].push(i);
    }
    let levels: Vec<Vec<usize>> = buckets
        .into_iter()
        .skip(1)
        .filter(|l| !l.is_empty())
        .collect();

    // ABI / input witnesses live at level 0.
    let initial_witnesses: HashSet<u32> = initial.clone();

    LevelSchedule {
        levels,
        op_info,
        num_opcodes: opcodes.len(),
        kinds,
        initial_witnesses,
    }
}

/// The kind of `solve_equation` a single-unknown `AssertZero` resolves to, on
/// the shared/public taint lattice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SolveKind {
    /// No remaining unknown (pure assertion) — no `solve_equation` call.
    Assertion,
    /// public coeff, public const — local, 0 rounds, public result.
    LocalPublic,
    /// public coeff, shared const — `div_shared_by_public`, 0 rounds, shared.
    LocalShared,
    /// shared coeff, public const — `div_public_by_shared` = 1 inv round.
    Inv,
    /// shared coeff, shared const — `div` = inv (1 round) + mul (1 round).
    Div,
}

/// Simulate `simplify_expression` + `solve_equation` on the taint lattice for
/// one `AssertZero`, returning the number of shared×shared `mul` rounds it pays,
/// the division kind, and the produced witness with its taint (if any).
fn simulate_assert_zero<F: PrimeField>(
    expr: &Expression<GenericFieldElement<F>>,
    known: &HashMap<u32, bool>,
) -> (usize, SolveKind, Option<(u32, bool)>) {
    let mut mul_rounds = 0usize;
    let mut qc_shared = false;
    // (coeff_is_shared, witness) for each still-unknown linear term.
    let mut unknown: Vec<(bool, u32)> = Vec::new();

    for (c, l, r) in &expr.mul_terms {
        if c.is_zero() {
            continue;
        }
        match (known.get(&l.0), known.get(&r.0)) {
            (Some(&ls), Some(&rs)) => {
                // solve_mul_term with both operands known.
                let res_shared = if ls && rs {
                    mul_rounds += 1; // one shared×shared reshare
                    true
                } else {
                    ls || rs // shared×public (or public×public) is local
                };
                qc_shared |= res_shared;
            }
            (Some(&ls), None) => unknown.push((ls, r.0)), // coeff = the known lhs
            (None, Some(&rs)) => unknown.push((rs, l.0)), // coeff = the known rhs
            (None, None) => {
                // Two unknowns in a product: not solvable by the serial solver
                // either. Record both as unknown so scheduling stays sound.
                unknown.push((false, l.0));
                unknown.push((false, r.0));
            }
        }
    }

    for (q, w) in &expr.linear_combinations {
        if q.is_zero() {
            continue;
        }
        match known.get(&w.0) {
            Some(&ws) => qc_shared |= ws,       // solve_linear_term folds into q_c
            None => unknown.push((false, w.0)), // public coefficient
        }
    }

    // Merge duplicate unknown entries for the same witness (coeff shared if any
    // contribution is shared) so a witness appearing in several terms counts once.
    unknown.sort_by_key(|(_, w)| *w);
    unknown.dedup_by(|a, b| {
        if a.1 == b.1 {
            b.0 |= a.0;
            true
        } else {
            false
        }
    });

    if unknown.is_empty() {
        return (mul_rounds, SolveKind::Assertion, None);
    }
    // For a well-formed circuit exactly one unknown remains here.
    let (coeff_shared, w) = unknown[0];
    let (kind, out_shared) = match (coeff_shared, qc_shared) {
        (false, false) => (SolveKind::LocalPublic, false),
        (false, true) => (SolveKind::LocalShared, true),
        (true, false) => (SolveKind::Inv, true),
        (true, true) => (SolveKind::Div, true),
    };
    (mul_rounds, kind, Some((w, out_shared)))
}

/// Arithmetic round attribution for the serial and level-batched solvers.
/// Black-box, Brillig, memory, and final output-opening rounds are excluded.
#[derive(Debug, Clone)]
pub struct RoundAttribution {
    /// shared×shared `solve_mul_term` calls (each = 1 reshare round).
    pub mul_rounds: usize,
    /// `solve_equation` with shared coeff / public const (`div_public_by_shared`
    /// = one `inv`/`mul_open` round each).
    pub inv_rounds: usize,
    /// `solve_equation` with shared coeff / shared const (`div` = `inv` + `mul`,
    /// i.e. 2 rounds each).
    pub div_rounds: usize,
    /// Total serial rounds = mul_rounds + inv_rounds + 2·div_rounds.
    pub serial_rounds: usize,
    /// Rounds for batched products followed by serial equation solves.
    pub batched_rounds: usize,
    /// DAG depth (number of levels).
    pub depth: usize,
    /// Total `AssertZero` opcodes that actually solved for a witness.
    pub solve_equation_calls: usize,
    /// Largest number of shared×shared products batchable in a single level.
    pub max_muls_per_level: usize,
}

impl RoundAttribution {
    /// Round-collapse factor against DAG depth: `f = serial_rounds / depth`.
    pub fn f_depth(&self) -> f64 {
        if self.depth == 0 {
            0.0
        } else {
            self.serial_rounds as f64 / self.depth as f64
        }
    }

    /// Round-collapse factor against the actual batched round count.
    pub fn f_batched(&self) -> f64 {
        if self.batched_rounds == 0 {
            0.0
        } else {
            self.serial_rounds as f64 / self.batched_rounds as f64
        }
    }
}

/// Replay the arithmetic solver on the taint lattice, level by level, counting
/// serial and level-batched arithmetic rounds. Only products are batched;
/// inversions and divisions remain serial within each level.
///
/// `shared_initial` is the set of ABI witness indices that are private (shared)
/// under the MPC protocol; every witness derived from them becomes shared.
pub fn attribute_rounds<F: PrimeField>(
    opcodes: &[Opcode<GenericFieldElement<F>>],
    schedule: &LevelSchedule,
    shared_initial: &HashSet<u32>,
) -> RoundAttribution {
    // Seed the taint of every ABI/input witness. Sort first so we never iterate
    // a hash-based collection directly (order is irrelevant to the result).
    let mut known: HashMap<u32, bool> = HashMap::new();
    let mut initial_sorted: Vec<u32> = schedule.initial_witnesses.iter().copied().collect();
    initial_sorted.sort_unstable();
    for w in &initial_sorted {
        known.insert(*w, shared_initial.contains(w));
    }

    let mut mul_rounds = 0usize;
    let mut inv_rounds = 0usize;
    let mut div_rounds = 0usize;
    let mut batched_rounds = 0usize;
    let mut solve_equation_calls = 0usize;
    let mut max_muls_per_level = 0usize;

    for level in &schedule.levels {
        let mut lvl_mul = false;
        let mut lvl_inv = 0usize;
        let mut lvl_div = 0usize;
        let mut lvl_mul_count = 0usize;
        // Outputs are committed only after the whole level, matching the fact
        // that opcodes in a level are independent.
        let mut pending: Vec<(u32, bool)> = Vec::new();

        for &op_idx in level {
            match &opcodes[op_idx] {
                Opcode::AssertZero(expr) => {
                    let (mc, kind, out) = simulate_assert_zero(expr, &known);
                    mul_rounds += mc;
                    lvl_mul_count += mc;
                    if mc > 0 {
                        lvl_mul = true;
                    }
                    match kind {
                        SolveKind::Inv => {
                            inv_rounds += 1;
                            lvl_inv += 1;
                            solve_equation_calls += 1;
                        }
                        SolveKind::Div => {
                            div_rounds += 1;
                            lvl_div += 1;
                            solve_equation_calls += 1;
                        }
                        SolveKind::LocalPublic | SolveKind::LocalShared => {
                            solve_equation_calls += 1;
                        }
                        SolveKind::Assertion => {}
                    }
                    if let Some(o) = out {
                        pending.push(o);
                    }
                }
                Opcode::BrilligCall { .. }
                | Opcode::BlackBoxFuncCall(_)
                | Opcode::MemoryOp { .. } => {
                    // Opaque multi-output producers: outputs become shared if any
                    // input is shared. Their own internal rounds (if any) are not
                    // part of the AssertZero arithmetic attribution.
                    let info = &schedule.op_info[op_idx];
                    let any_shared = info
                        .inputs
                        .iter()
                        .any(|w| known.get(w).copied().unwrap_or(false));
                    for &w in &info.outputs {
                        pending.push((w, any_shared));
                    }
                }
                Opcode::MemoryInit { .. } | Opcode::Call { .. } => {}
            }
        }

        for (w, t) in pending {
            known.insert(w, t);
        }

        // solve_level batches products, then calls finish_assert_zero serially.
        batched_rounds += usize::from(lvl_mul) + lvl_inv + 2 * lvl_div;
        max_muls_per_level = max_muls_per_level.max(lvl_mul_count);
    }

    let serial_rounds = mul_rounds + inv_rounds + 2 * div_rounds;
    RoundAttribution {
        mul_rounds,
        inv_rounds,
        div_rounds,
        serial_rounds,
        batched_rounds,
        depth: schedule.depth(),
        solve_equation_calls,
        max_muls_per_level,
    }
}

/// Format a compact, human-readable diagnostics report for a circuit's opcode
/// stream. `initial` is the set of all ABI witness indices (private + public);
/// `shared_initial` is the subset that is private (shared under the protocol).
pub fn format_report<F: PrimeField>(
    label: &str,
    opcodes: &[Opcode<GenericFieldElement<F>>],
    initial: &HashSet<u32>,
    shared_initial: &HashSet<u32>,
) -> String {
    let schedule = schedule_levels(opcodes, initial);
    let attr = attribute_rounds(opcodes, &schedule, shared_initial);
    let widths = schedule.width_histogram();

    // Compress the width histogram: count how many levels share each width.
    let mut width_counts: HashMap<usize, usize> = HashMap::new();
    for w in &widths {
        *width_counts.entry(*w).or_insert(0) += 1;
    }
    let mut width_pairs: Vec<(usize, usize)> = width_counts.into_iter().collect();
    width_pairs.sort_unstable();

    let mut s = String::new();
    s.push_str(&format!("=== witext level analysis: {label} ===\n"));
    s.push_str(&format!("  opcodes:            {}\n", schedule.num_opcodes));
    s.push_str(&format!(
        "  kinds:              assert_zero={} blackbox={} brillig={} mem_init={} mem_op={} call={}\n",
        schedule.kinds.assert_zero,
        schedule.kinds.blackbox,
        schedule.kinds.brillig,
        schedule.kinds.memory_init,
        schedule.kinds.memory_op,
        schedule.kinds.call,
    ));
    s.push_str(&format!(
        "  modelling:          precise={} barriered={}\n",
        schedule.kinds.modelled_precise, schedule.kinds.barriered,
    ));
    s.push_str(&format!("  DAG depth (levels): {}\n", schedule.depth()));
    s.push_str(&format!(
        "  width:              max={} mean={:.2}\n",
        schedule.max_width(),
        schedule.mean_width(),
    ));
    s.push_str("  width histogram (width x #levels):\n");
    for (w, count) in &width_pairs {
        s.push_str(&format!("      width {w:>4}: {count} levels\n"));
    }
    s.push_str("  round attribution (serial):\n");
    s.push_str(&format!(
        "      shared×shared mul rounds: {}\n",
        attr.mul_rounds
    ));
    s.push_str(&format!(
        "      div_public_by_shared (inv) rounds: {}\n",
        attr.inv_rounds
    ));
    s.push_str(&format!(
        "      div shared/shared (inv+mul) ops: {} ({} rounds)\n",
        attr.div_rounds,
        2 * attr.div_rounds
    ));
    s.push_str(&format!(
        "      SERIAL ROUNDS total:      {}\n",
        attr.serial_rounds
    ));
    s.push_str(&format!(
        "      max shared×shared muls in one level: {}\n",
        attr.max_muls_per_level
    ));
    s.push_str(&format!(
        "  batched arithmetic rounds: {}\n",
        attr.batched_rounds
    ));
    s.push_str(&format!(
        "  round-collapse factor f: serial/batched = {:.3}   (serial/depth = {:.3})\n",
        attr.f_batched(),
        attr.f_depth(),
    ));
    s
}
