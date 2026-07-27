use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{AcirField, acir_field::GenericFieldElement, native_types::Expression};
use ark_ff::PrimeField;

use crate::solver::solver_utils;

use super::{CoAcvmResult, CoSolver};

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    fn evaluate_mul_terms(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        acc: &mut Expression<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("evaluating mul terms for simplification");
        if expr.mul_terms.is_empty() {
            tracing::trace!("no mul term. we are done");
            Ok(())
        } else {
            for mul in expr.mul_terms.iter() {
                let (c, lhs, rhs) = mul;
                tracing::trace!("looking at mul term {c} * _{} * _{}", lhs.0, rhs.0);
                if c.is_zero() {
                    tracing::trace!("c is zero. We can skip this mul term");
                } else {
                    match (
                        self.witness().get(lhs).cloned(),
                        self.witness().get(rhs).cloned(),
                    ) {
                        // we could batch this multiplication but our currently planned network design
                        // should solve this without batching
                        (Some(lhs), Some(rhs)) => {
                            tracing::trace!("solving mul term...");
                            let solved = self.driver.solve_mul_term(c.into_repr(), lhs, rhs)?;
                            self.driver.add_assign(&mut acc.q_c, solved);
                        }
                        (Some(lhs), None) => {
                            tracing::trace!("partially solving mul term...");
                            let partly_solved = self.driver.mul_with_public(c.into_repr(), lhs);
                            acc.linear_combinations.push((partly_solved, *rhs));
                        }
                        (None, Some(rhs)) => {
                            tracing::trace!("partially solving mul term...");
                            let partly_solved = self.driver.mul_with_public(c.into_repr(), rhs);
                            acc.linear_combinations.push((partly_solved, *lhs));
                        }
                        (None, None) => Err(eyre::eyre!(
                            "two unknowns in evaluate mul term. Not solvable for expr: {:?}",
                            expr
                        ))?,
                    };
                    tracing::trace!("after eval mul term: {acc:?}");
                }
            }
            Ok(())
        }
    }

    fn evaluate_linear_terms(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        acc: &mut Expression<T::AcvmType>,
    ) {
        for term in expr.linear_combinations.iter() {
            let (q_l, w_l) = term;
            tracing::trace!("looking at linear term: {q_l} * _{}..", w_l.0);
            if let Some(w_l) = self.witness().get(w_l).cloned() {
                tracing::trace!("is known! reduce it");
                self.driver
                    .solve_linear_term(q_l.into_repr(), w_l, &mut acc.q_c);
            } else {
                tracing::trace!("is unknown!");
                acc.linear_combinations
                    .push((T::AcvmType::from(q_l.into_repr()), *w_l))
            }
        }
    }

    pub(crate) fn simplify_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<Expression<T::AcvmType>> {
        tracing::trace!("simplifying expression...");
        // default implementation not exposed if we not have AcirField trait bound
        let mut simplified = Expression {
            mul_terms: vec![],
            linear_combinations: vec![],
            q_c: T::public_zero(),
        };
        // evaluate mul terms
        self.evaluate_mul_terms(expr, &mut simplified)?;
        // evaluate linear terms
        self.evaluate_linear_terms(expr, &mut simplified);
        // add constants
        self.driver
            .add_assign_with_public(expr.q_c.into_repr(), &mut simplified.q_c);

        Ok(simplified)
    }

    pub(super) fn solve_assert_zero(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        //first evaluate the already existing terms
        tracing::trace!(
            "solving assert zero: {}",
            solver_utils::expr_to_string(expr)
        );
        let simplified = self.simplify_expression(expr)?;
        tracing::trace!("simplified expr:     {:?}", simplified);
        // if we are here, we do not have any mul terms
        debug_assert!(simplified.mul_terms.is_empty());
        debug_assert!(
            simplified.linear_combinations.len() <= 4,
            "we need to simplify!!!"
        );
        // also if we are here and have more than one linear combination, we
        // cannot solve the expression
        if simplified.linear_combinations.is_empty() {
            // we are done
            tracing::trace!("nothing to do for us");
            Ok(())
        } else if simplified.linear_combinations.len() == 1 {
            //we can solve it!
            tracing::trace!("solving equation...");
            let (q_l, w_l) = simplified.linear_combinations[0].clone();
            let witness = self.driver.solve_equation(q_l, simplified.q_c)?;
            self.witness().insert(w_l, witness);
            tracing::trace!("we did it!");
            Ok(())
        } else {
            Err(eyre::eyre!(
                "too many unknowns. not solvable for expression: {:?}",
                expr
            ))?
        }
    }

    /// Level-batched counterpart of [`Self::evaluate_mul_terms`]. Instead of
    /// issuing each shared×shared product's network round immediately, the
    /// `(c, lhs, rhs)` triples are appended to `pending` for the caller to solve
    /// in one batched round across the whole level. Mixed public/shared and
    /// public/public products stay on the local path (no round), exactly as the
    /// serial evaluator handles them. Returns the number of products appended so
    /// the caller knows how many batched results to fold back into `acc.q_c`.
    ///
    /// The independence of a level (guaranteed by the scheduler) is what makes
    /// deferral sound: no product in `pending` uses another product's result as
    /// an operand, so their order of resolution does not matter.
    fn evaluate_mul_terms_deferred(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        acc: &mut Expression<T::AcvmType>,
        pending: &mut Vec<(F, T::AcvmType, T::AcvmType)>,
    ) -> CoAcvmResult<usize> {
        let mut deferred = 0usize;
        for (c, lhs, rhs) in expr.mul_terms.iter() {
            if c.is_zero() {
                continue;
            }
            match (
                self.witness().get(lhs).cloned(),
                self.witness().get(rhs).cloned(),
            ) {
                (Some(lhs), Some(rhs)) => {
                    if T::is_shared(&lhs) && T::is_shared(&rhs) {
                        // Defer the reshare to the level-wide batch.
                        pending.push((c.into_repr(), lhs, rhs));
                        deferred += 1;
                    } else {
                        // At most one operand is shared -> local, no round.
                        let solved = self.driver.solve_mul_term(c.into_repr(), lhs, rhs)?;
                        self.driver.add_assign(&mut acc.q_c, solved);
                    }
                }
                (Some(lhs), None) => {
                    let partly_solved = self.driver.mul_with_public(c.into_repr(), lhs);
                    acc.linear_combinations.push((partly_solved, *rhs));
                }
                (None, Some(rhs)) => {
                    let partly_solved = self.driver.mul_with_public(c.into_repr(), rhs);
                    acc.linear_combinations.push((partly_solved, *lhs));
                }
                (None, None) => Err(eyre::eyre!(
                    "two unknowns in evaluate mul term. Not solvable for expr: {:?}",
                    expr
                ))?,
            }
        }
        Ok(deferred)
    }

    /// Pass-2 pre-simplification for level-batched solving. Reduces `expr` into
    /// an accumulator exactly like [`Self::simplify_expression`], but defers the
    /// shared×shared products into `pending`. Returns the accumulator (whose
    /// `q_c` is still missing the deferred products) and the number of deferred
    /// products, which the caller folds back after the batched round resolves.
    pub(super) fn presimplify_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        pending: &mut Vec<(F, T::AcvmType, T::AcvmType)>,
    ) -> CoAcvmResult<(Expression<T::AcvmType>, usize)> {
        let mut simplified = Expression {
            mul_terms: vec![],
            linear_combinations: vec![],
            q_c: T::public_zero(),
        };
        let deferred = self.evaluate_mul_terms_deferred(expr, &mut simplified, pending)?;
        self.evaluate_linear_terms(expr, &mut simplified);
        self.driver
            .add_assign_with_public(expr.q_c.into_repr(), &mut simplified.q_c);
        Ok((simplified, deferred))
    }

    /// The tail of [`Self::solve_assert_zero`]: given a fully simplified
    /// expression (all mul terms resolved into `q_c`), solve the single
    /// remaining unknown (if any) and insert it into the witness map. Shared by
    /// the serial and level-batched solve paths so both finish identically.
    pub(super) fn finish_assert_zero(
        &mut self,
        simplified: Expression<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        debug_assert!(simplified.mul_terms.is_empty());
        debug_assert!(
            simplified.linear_combinations.len() <= 4,
            "we need to simplify!!!"
        );
        if simplified.linear_combinations.is_empty() {
            Ok(())
        } else if simplified.linear_combinations.len() == 1 {
            let (q_l, w_l) = simplified.linear_combinations[0].clone();
            let witness = self.driver.solve_equation(q_l, simplified.q_c)?;
            self.witness().insert(w_l, witness);
            Ok(())
        } else {
            Err(eyre::eyre!(
                "too many unknowns. not solvable for simplified expression"
            ))?
        }
    }

    pub(crate) fn evaluate_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<T::AcvmType> {
        Ok(self
            .simplify_expression(expr)?
            .to_const()
            .cloned()
            .ok_or(eyre::eyre!(
                "cannot evaluate expression to const - has unknown"
            ))?)
    }
}
