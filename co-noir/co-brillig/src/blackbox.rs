use acir::BlackBoxFunc;
use ark_ff::PrimeField;
use brillig::{BitSize, BlackBoxOp, HeapArray, IntegerBitSize, MemoryAddress};
use eyre::Context;

use crate::{CoBrilligVM, mpc::BrilligDriver};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn handle_blackbox(&mut self, blackbox_op: BlackBoxOp) -> eyre::Result<()> {
        match blackbox_op {
            BlackBoxOp::ToRadix {
                input,
                radix,
                output_pointer,
                num_limbs,
                output_bits,
            } => self.handle_to_radix(input, radix, output_pointer, num_limbs, output_bits)?,
            BlackBoxOp::EcdsaSecp256k1 {
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            } => self.handle_ecdsa(
                BlackBoxFunc::EcdsaSecp256k1,
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            )?,
            BlackBoxOp::EcdsaSecp256r1 {
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            } => self.handle_ecdsa(
                BlackBoxFunc::EcdsaSecp256r1,
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            )?,
            x => eyre::bail!("unsupported Brillig blackbox {x}"),
        }
        self.increment_program_counter();
        Ok(())
    }

    fn handle_to_radix(
        &mut self,
        input: MemoryAddress,
        radix: MemoryAddress,
        output_pointer: MemoryAddress,
        num_limbs: MemoryAddress,
        output_bits: MemoryAddress,
    ) -> eyre::Result<()> {
        let input = self
            .memory
            .try_read_field(input)
            .context("while getting field for ToRadix")?;
        let radix = self
            .memory
            .try_read_int(radix, IntegerBitSize::U32)
            .context("while getting radix for ToRadix")?;
        let num_limbs = self.memory.try_read_usize(num_limbs)?;
        let output_bits = self
            .memory
            .try_read_int(output_bits, IntegerBitSize::U1)
            .context("while getting output_bits for ToRadix")?;
        let output_bits = T::try_into_bool(output_bits).expect("output_bits must be a public");

        let limbs = self.driver.to_radix(input, radix, num_limbs, output_bits)?;
        let mem_offset = self.memory.read_ref(output_pointer)?;
        self.memory.write_slice(mem_offset, &limbs)?;
        Ok(())
    }

    /// Reads a heap array of public bytes.
    fn read_public_bytes<const N: usize>(
        &self,
        func: BlackBoxFunc,
        array: HeapArray,
    ) -> eyre::Result<[u8; N]> {
        let values = self.memory.read_heap_array(array)?;
        if values.len() != N {
            eyre::bail!(
                "{}: expected {N} bytes, but got {}",
                func.name(),
                values.len()
            );
        }
        let mut bytes = [0u8; N];
        for (byte, value) in bytes.iter_mut().zip(values) {
            if !T::is_public(value.clone()) {
                eyre::bail!(
                    "{} on secret-shared inputs is not supported in Brillig",
                    func.name()
                );
            }
            // Bytes are u8 integers, which is also the bit size of characters.
            let value = T::try_into_char(value).with_context(|| func.name().to_string())?;
            *byte = u8::try_from(value).expect("u8 integers are converted to chars below 256");
        }
        Ok(bytes)
    }

    fn handle_ecdsa(
        &mut self,
        func: BlackBoxFunc,
        hashed_msg: HeapArray,
        public_key_x: HeapArray,
        public_key_y: HeapArray,
        signature: HeapArray,
        result: MemoryAddress,
    ) -> eyre::Result<()> {
        let hashed_msg = self.read_public_bytes::<32>(func, hashed_msg)?;
        let public_key_x = self.read_public_bytes::<32>(func, public_key_x)?;
        let public_key_y = self.read_public_bytes::<32>(func, public_key_y)?;
        let signature = self.read_public_bytes::<64>(func, signature)?;
        let verify = match func {
            BlackBoxFunc::EcdsaSecp256k1 => acvm::blackbox_solver::ecdsa_secp256k1_verify,
            BlackBoxFunc::EcdsaSecp256r1 => acvm::blackbox_solver::ecdsa_secp256r1_verify,
            _ => unreachable!("only called for the ECDSA blackboxes"),
        };
        let is_valid = verify(&hashed_msg, &public_key_x, &public_key_y, &signature)?;
        self.memory.write(
            result,
            T::public_value(F::from(is_valid), BitSize::Integer(IntegerBitSize::U1)),
        )?;
        Ok(())
    }
}
