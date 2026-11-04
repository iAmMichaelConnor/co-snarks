pub mod entities;
pub mod polynomial;
pub mod shared_polynomial;

/// Minimum number of coefficients per rayon task in the element-wise polynomial operations.
/// Shorter polynomials are processed on the calling thread.
pub(crate) const PAR_MIN_LEN: usize = 1 << 12;
