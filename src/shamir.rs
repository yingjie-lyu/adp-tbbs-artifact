//! Shamir sharing over `Z_q` and Lagrange interpolation at zero.

use crate::algebra::Scalar;

pub fn evaluate<S: Scalar>(coefficients: &[S], point: &S) -> S {
    coefficients
        .iter()
        .rev()
        .fold(S::zero(), |acc, coefficient| {
            acc.mul(point).add(coefficient)
        })
}

pub fn evaluate_at<S: Scalar>(coefficients: &[S], id: usize) -> S {
    evaluate(coefficients, &S::from_u64(id as u64))
}

/// `lambda_{i,Q}` such that `sum_{i in Q} lambda_i * f(i) = f(0)` for `deg f < |Q|`.
pub fn lagrange_at_zero<S: Scalar>(id: usize, quorum: &[usize]) -> Option<S> {
    let xi = S::from_u64(id as u64);
    let mut numerator = S::one();
    let mut denominator = S::one();
    for peer in quorum {
        if *peer == id {
            continue;
        }
        let xj = S::from_u64(*peer as u64);
        numerator = numerator.mul(&xj);
        denominator = denominator.mul(&xj.sub(&xi));
    }
    denominator.invert().map(|inverse| numerator.mul(&inverse))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls381::Scalar255;

    #[test]
    fn interpolation_reconstructs_the_constant_term() {
        let coefficients = vec![
            Scalar255::from_u64(17),
            Scalar255::from_u64(3),
            Scalar255::from_u64(9),
        ];
        let quorum = [1usize, 3, 7];
        let mut sum = Scalar255::zero();
        for id in quorum {
            let lambda = lagrange_at_zero::<Scalar255>(id, &quorum).unwrap();
            sum = sum.add(&lambda.mul(&evaluate_at(&coefficients, id)));
        }
        assert_eq!(sum, Scalar255::from_u64(17));
    }
}
