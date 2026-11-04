//! A test helper that evaluates the circuits of [`super::circuits::GarbledCircuits`] on
//! cleartext bits.

use super::{
    circuits::FancyBinaryConstant,
    fancy::{Fancy, FancyBinary, GcError},
};

/// A cleartext wire of [`CleartextBinaryEvaluator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CleartextBit(pub(crate) bool);

/// Evaluates a binary circuit on cleartext bits, without garbling or networking, and counts its
/// AND gates. With free XOR, the AND gates are what a garbled circuit costs: the garblers send
/// two blocks per AND gate.
#[derive(Default)]
pub(crate) struct CleartextBinaryEvaluator {
    /// The number of AND gates evaluated so far.
    pub(crate) num_and_gates: usize,
}

impl Fancy for CleartextBinaryEvaluator {
    type Item = CleartextBit;

    fn constant(&mut self, x: u16) -> Result<Self::Item, GcError> {
        Ok(CleartextBit(x & 1 == 1))
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, GcError> {
        Ok(Some(x.0 as u16))
    }
}

impl FancyBinary for CleartextBinaryEvaluator {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError> {
        Ok(CleartextBit(x.0 ^ y.0))
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError> {
        self.num_and_gates += 1;
        Ok(CleartextBit(x.0 & y.0))
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, GcError> {
        Ok(CleartextBit(!x.0))
    }
}

impl FancyBinaryConstant for CleartextBinaryEvaluator {
    fn const_zero(&mut self) -> Result<Self::Item, GcError> {
        Ok(CleartextBit(false))
    }

    fn const_one(&mut self) -> Result<Self::Item, GcError> {
        Ok(CleartextBit(true))
    }
}
