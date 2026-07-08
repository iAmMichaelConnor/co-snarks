use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    circuit::opcodes::{BlockId, MemOp, MemOpKind},
    native_types::Witness,
};
use ark_ff::PrimeField;

use super::{CoAcvmResult, CoSolver};

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    pub(super) fn solve_memory_init_block(
        &mut self,
        block_id: BlockId,
        init: &[Witness],
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving memory init block {}", block_id.0);
        if self.memory_access.get(block_id.0.into()).is_some() {
            //there is already a block? This should no be possible
            tracing::error!("There is already a block for id {}", block_id.0);
            Err(eyre::eyre!(
                "There is already a block for id {}",
                block_id.0
            ))?;
        }
        // let get all witnesses
        let witness_map = self.witness();
        let init = init
            .iter()
            .map(|witness| witness_map.get(witness).cloned())
            .collect::<Option<Vec<_>>>()
            .ok_or(eyre::eyre!(
                "tried to write not initialized witness to memory - this is a  bug"
            ))?;
        let lut = self.driver.init_lut_by_acvm_type(init);
        self.memory_access.insert(block_id.0.into(), lut);
        Ok(())
    }

    pub(super) fn solve_memory_op(&mut self, block_id: BlockId, op: &MemOp) -> CoAcvmResult<()> {
        tracing::trace!("solving memory op {:?}", op);
        let index = self.witness().get(&op.index).cloned().ok_or(eyre::eyre!(
            "tried to read not initialized index witness for mem op - this is a bug"
        ))?;
        match op.operation {
            MemOpKind::Read => {
                // read the value from the LUT
                tracing::trace!("reading value from LUT");
                let lut = self
                    .memory_access
                    .get(block_id.0.into())
                    .ok_or(eyre::eyre!(
                        "tried to access block {} but not present",
                        block_id.0
                    ))?;
                let value = self.driver.read_lut_by_acvm_type(index, lut)?;

                self.witness().insert(op.value, value);
            }
            MemOpKind::Write => {
                // write value to LUT
                tracing::trace!("writing value to LUT");
                let value = self.witness().get(&op.value).cloned().ok_or(eyre::eyre!(
                    "tried to write not initialized witness to memory - this is a bug"
                ))?;
                let lut = self
                    .memory_access
                    .get_mut(block_id.0.into())
                    .ok_or(eyre::eyre!(
                        "tried to access block {} but not present",
                        block_id.0
                    ))?;

                self.driver.write_lut_by_acvm_type(index, value, lut)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::solver::PlainCoSolver;
    use acir::{
        circuit::opcodes::{BlockId, MemOp, MemOpKind},
        native_types::Witness,
    };

    /// Regression test for noir-claude #696 ("MemoryOp on uninitialized block"): a
    /// `MemoryOp` referencing a `block_id` that was never `MemoryInit`'d must return a
    /// structured error, not panic/read out-of-bounds. co-noir already guards this (see
    /// the `.ok_or(eyre::eyre!(...))` on `self.memory_access.get(...)` below) - this test
    /// pins that behaviour down as a regression guard.
    #[test]
    fn memory_read_on_uninitialized_block_returns_err() {
        let mut solver = PlainCoSolver::<ark_bn254::Fr>::new_for_test();
        solver
            .witness()
            .insert(Witness(0), ark_bn254::Fr::from(0u64));
        let op = MemOp {
            operation: MemOpKind::Read,
            index: Witness(0),
            value: Witness(1),
        };
        // Block 5 was never initialized via `MemoryInit`.
        let result = solver.solve_memory_op(BlockId(5), &op);
        assert!(result.is_err(), "expected a structured error, got Ok");
    }

    #[test]
    fn memory_write_on_uninitialized_block_returns_err() {
        let mut solver = PlainCoSolver::<ark_bn254::Fr>::new_for_test();
        solver
            .witness()
            .insert(Witness(0), ark_bn254::Fr::from(0u64));
        solver
            .witness()
            .insert(Witness(1), ark_bn254::Fr::from(7u64));
        let op = MemOp {
            operation: MemOpKind::Write,
            index: Witness(0),
            value: Witness(1),
        };
        let result = solver.solve_memory_op(BlockId(5), &op);
        assert!(result.is_err(), "expected a structured error, got Ok");
    }

    /// Regression test for noir-claude #697 ("duplicate MemoryInit block_id"):
    /// initializing the same `block_id` twice must return a structured error instead of
    /// silently overwriting the block (or panicking). co-noir already guards this (see
    /// the `self.memory_access.get(...).is_some()` check below) - this test pins that
    /// behaviour down as a regression guard.
    #[test]
    fn duplicate_memory_init_returns_err() {
        let mut solver = PlainCoSolver::<ark_bn254::Fr>::new_for_test();
        solver
            .witness()
            .insert(Witness(0), ark_bn254::Fr::from(1u64));

        solver
            .solve_memory_init_block(BlockId(3), &[Witness(0)])
            .expect("first init of block 3 must succeed");

        let result = solver.solve_memory_init_block(BlockId(3), &[Witness(0)]);
        assert!(
            result.is_err(),
            "expected a structured error on duplicate MemoryInit, got Ok"
        );
    }
}
