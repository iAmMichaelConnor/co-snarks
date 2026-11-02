use std::embedded_curve_ops::{
    embedded_curve_add, EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul,
};

// Curve operations under a condition carry it as their predicate. A disabled operation returns
// (0, 0) without evaluating its operands, which therefore need not be valid points or scalars.
fn main(
    enable: bool,
    point1: EmbeddedCurvePoint,
    point2: EmbeddedCurvePoint,
    scalar: EmbeddedCurveScalar,
    invalid_point1: EmbeddedCurvePoint,
    invalid_point2: EmbeddedCurvePoint,
    invalid_scalar: EmbeddedCurveScalar,
) -> pub [EmbeddedCurvePoint; 4] {
    let mut result = [EmbeddedCurvePoint::point_at_infinity(); 4];
    if enable {
        result[0] = embedded_curve_add(point1, point2);
        result[1] = multi_scalar_mul([point1], [scalar]);
    }
    if !enable {
        result[2] = embedded_curve_add(invalid_point1, invalid_point2);
        result[3] = multi_scalar_mul([invalid_point1], [invalid_scalar]);
    }
    result
}
