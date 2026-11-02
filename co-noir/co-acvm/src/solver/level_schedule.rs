//! Grouping of a circuit's opcodes into levels of mutually independent opcodes, for
//! [`CoSolver::set_level_scheduling`](super::CoSolver::set_level_scheduling).
//!
//! The levels are computed from the public circuit structure only (which opcode reads and which
//! produces which witness), never from witness values, so all parties compute the same levels.

use acir::{
    AcirField,
    acir_field::GenericFieldElement,
    circuit::{
        Opcode,
        brillig::{BrilligInputs, BrilligOutputs},
    },
    native_types::{Expression, Witness},
};
use ark_ff::PrimeField;
use std::collections::HashMap;

/// The witnesses an expression reads.
fn expression_witnesses<F: PrimeField>(
    expr: &Expression<GenericFieldElement<F>>,
) -> impl Iterator<Item = Witness> + '_ {
    expr.mul_terms
        .iter()
        .filter(|(c, _, _)| !c.is_zero())
        .flat_map(|(_, l, r)| [*l, *r])
        .chain(
            expr.linear_combinations
                .iter()
                .filter(|(c, _)| !c.is_zero())
                .map(|(_, w)| *w),
        )
}

/// Groups the opcodes into levels: an opcode's level is one more than the highest level of an
/// opcode producing one of its inputs, and the witnesses in `initial` (known before solving) are
/// at level 0. Opcodes of the same level do not depend on each other, so solving the levels in
/// order, and the opcodes of a level in any order, gives the same witness as solving the opcodes
/// in circuit order. Returns the opcode indices per level, in circuit order within a level.
///
/// - An `AssertZero` reads its known witnesses and produces the (at most one) unknown one.
/// - A Brillig call reads the witnesses of its input expressions and predicate and produces its
///   outputs; a black-box call reads its input witnesses and produces its outputs.
/// - Memory opcodes (and any other opcode) are barriers: a dynamic index may access any element
///   of a block, which the witness indices do not show, so such an opcode gets a level above all
///   previous opcodes, and all later opcodes are above it. This also orders Brillig calls that
///   read a memory block after the memory opcodes before them.
pub(super) fn schedule_levels<F: PrimeField>(
    opcodes: &[Opcode<GenericFieldElement<F>>],
    initial: impl IntoIterator<Item = Witness>,
) -> Vec<Vec<usize>> {
    let mut produced_at: HashMap<Witness, usize> = initial.into_iter().map(|w| (w, 0)).collect();
    let mut levels: Vec<Vec<usize>> = Vec::new();
    // The lowest level an opcode may get: above the last barrier.
    let mut lowest = 1;

    for (index, opcode) in opcodes.iter().enumerate() {
        let (inputs, outputs, barrier): (Vec<Witness>, Vec<Witness>, bool) = match opcode {
            Opcode::AssertZero(expr) => {
                let (inputs, outputs) =
                    expression_witnesses(expr).partition(|w| produced_at.contains_key(w));
                (inputs, outputs, false)
            }
            Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                let mut reads = expression_witnesses(predicate).collect::<Vec<_>>();
                for input in inputs {
                    match input {
                        BrilligInputs::Single(expr) => reads.extend(expression_witnesses(expr)),
                        BrilligInputs::Array(exprs) => {
                            reads.extend(exprs.iter().flat_map(expression_witnesses))
                        }
                        BrilligInputs::MemoryArray(_) => {}
                    }
                }
                let writes = outputs
                    .iter()
                    .flat_map(|output| match output {
                        BrilligOutputs::Simple(w) => std::slice::from_ref(w),
                        BrilligOutputs::Array(ws) => ws.as_slice(),
                    })
                    .copied()
                    .collect();
                (reads, writes, false)
            }
            Opcode::BlackBoxFuncCall(call) => (
                call.get_input_witnesses().into_iter().collect(),
                call.get_outputs_vec(),
                false,
            ),
            Opcode::MemoryOp { op, .. } => (vec![], vec![op.value], true),
            _ => (vec![], vec![], true),
        };

        let level = if barrier {
            levels.len() + 1
        } else {
            inputs
                .iter()
                .filter_map(|w| produced_at.get(w))
                .map(|level| level + 1)
                .fold(lowest, usize::max)
        };
        if barrier {
            lowest = level + 1;
        }
        for w in outputs {
            produced_at.entry(w).or_insert(level);
        }
        if levels.len() < level {
            levels.resize_with(level, Vec::new);
        }
        levels[level - 1].push(index);
    }
    // A barrier leaves the level below it empty if no opcode reached it.
    levels.retain(|level| !level.is_empty());
    levels
}

#[cfg(test)]
mod tests {
    use super::*;
    use acir::circuit::opcodes::{BlockId, MemOp};

    type F = GenericFieldElement<ark_bn254::Fr>;

    fn w(i: u32) -> Witness {
        Witness(i)
    }

    /// w_out = w_l * w_r
    fn mul(l: u32, r: u32, out: u32) -> Opcode<F> {
        Opcode::AssertZero(Expression {
            mul_terms: vec![(F::one(), w(l), w(r))],
            linear_combinations: vec![(-F::one(), w(out))],
            q_c: F::zero(),
        })
    }

    #[test]
    fn independent_opcodes_share_a_level() {
        // w2 = w0 * w1 and w3 = w0 * w0 are independent; w4 = w2 * w3 needs both; w5 = w1 * w1
        // only needs an input.
        let opcodes = [mul(0, 1, 2), mul(0, 0, 3), mul(2, 3, 4), mul(1, 1, 5)];
        let levels = schedule_levels(&opcodes, [w(0), w(1)]);
        assert_eq!(levels, vec![vec![0, 1, 3], vec![2]]);
    }

    #[test]
    fn memory_opcodes_are_barriers() {
        let read = Opcode::MemoryOp {
            block_id: BlockId::new(0),
            op: MemOp::read_at_mem_index(w(0), w(3)),
        };
        // w2 = w0 * w1 | read w3 = block[w0] | w4 = w0 * w0 | w5 = w3 * w3
        let opcodes = [mul(0, 1, 2), read, mul(0, 0, 4), mul(3, 3, 5)];
        let levels = schedule_levels(&opcodes, [w(0), w(1)]);
        assert_eq!(levels, vec![vec![0], vec![1], vec![2, 3]]);
    }
}
