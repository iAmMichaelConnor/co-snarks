pub mod co_oink_prover;
pub mod types;

// execute_log_derivative_inverse_round: n for inv and n for mult
pub const CRAND_PAIRS_FACTOR_N: usize = 2;
// execute_grand_product_computation_round:
//      compute_grand_product:
//      1 batched mul_many over the 4 num/denom factor pairs: (domain_size - 1) * 4
//      1 array_prod_inner_mul_many over {numerator, denominator}: (domain_size - 1) * 8 + 4
//      misc: (domain_size - 1) * 4
pub const CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE: usize = 4 + 8 + 4;
pub const CRAND_PAIRS_CONST: usize = 4;
