//! R1CS constraint-matrix types.
//!
//! These types were provided by `ark-relations` 0.5 as
//! `ark_relations::r1cs::{Matrix, ConstraintMatrices}`. `ark-relations` 0.6
//! replaced the `r1cs` module with the generalized `gr1cs` module and dropped
//! `ConstraintMatrices`, so we define these (pure-data) types here instead.

use ark_ff::Field;

/// A sparse representation of constraint matrices. Each row of the matrix is
/// represented as a vector of `(coefficient, variable_index)` pairs.
pub type Matrix<F> = Vec<Vec<(F, usize)>>;

/// The A, B and C matrices of a Rank-One `ConstraintSystem`.
/// Also contains metadata on the structure of the constraint system
/// and the matrices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintMatrices<F: Field> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,

    /// The A constraint matrix.
    pub a: Matrix<F>,
    /// The B constraint matrix.
    pub b: Matrix<F>,
    /// The C constraint matrix.
    pub c: Matrix<F>,
}
