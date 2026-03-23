//! Theta-coordinate arithmetic ported from the Julia SQIsignIQO implementation.

use alloc::{vec, vec::Vec};

use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::xonly::{ladder3pt_affine, x_dbl, Proj1, XOnlyError};
use crate::crypto::isogeny::field::{Fp, Fp2, FpError};

pub type Result<T> = core::result::Result<T, ThetaError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThetaError {
    Field(FpError),
    XOnly(XOnlyError),
    NotProductThetaNull,
    MissingSquareRoot,
    PointLiftFailed,
    StrategyExhausted,
}

impl From<FpError> for ThetaError {
    fn from(value: FpError) -> Self {
        Self::Field(value)
    }
}

impl From<XOnlyError> for ThetaError {
    fn from(value: XOnlyError) -> Self {
        Self::XOnly(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThetaDim1 {
    pub a: Fp2,
    pub b: Fp2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThetaPtLv2 {
    pub a: Fp2,
    pub b: Fp2,
    pub c: Fp2,
    pub d: Fp2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThetaNullLv2 {
    pub a: Fp2,
    pub b: Fp2,
    pub c: Fp2,
    pub d: Fp2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThetaCouplePoint {
    pub p1: Proj1,
    pub p2: Proj1,
}

const EVEN_INDICES: [(usize, usize); 10] = [
    (0, 0),
    (0, 1),
    (0, 2),
    (0, 3),
    (1, 0),
    (1, 2),
    (2, 0),
    (2, 1),
    (3, 0),
    (3, 3),
];

const SPLITTING_MAPS: [((usize, usize), [i8; 16]); 9] = [
    ((0, 2), [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0]),
    ((3, 3), [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]),
    ((0, 3), [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1]),
    (
        (2, 1),
        [1, 1, 1, 1, 1, -1, 1, -1, 1, -1, -1, 1, 1, 1, -1, -1],
    ),
    ((0, 1), [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, -1, 0, 0]),
    ((1, 2), [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]),
    (
        (2, 0),
        [1, 1, 1, 1, 1, -1, 1, -1, 1, -1, -1, 1, -1, -1, 1, 1],
    ),
    (
        (3, 0),
        [1, 1, 1, 1, 1, -1, 1, -1, 1, 1, -1, -1, -1, 1, 1, -1],
    ),
    (
        (1, 0),
        [1, 1, 1, 1, 1, -1, -1, 1, 1, 1, -1, -1, -1, 1, -1, 1],
    ),
];

impl ThetaDim1 {
    pub const fn new(a: Fp2, b: Fp2) -> Self {
        Self { a, b }
    }
}

impl ThetaPtLv2 {
    pub const fn new(a: Fp2, b: Fp2, c: Fp2, d: Fp2) -> Self {
        Self { a, b, c, d }
    }

    pub fn square(&self) -> [Fp2; 4] {
        [
            self.a.square(),
            self.b.square(),
            self.c.square(),
            self.d.square(),
        ]
    }
}

impl ThetaNullLv2 {
    pub const fn new(a: Fp2, b: Fp2, c: Fp2, d: Fp2) -> Self {
        Self { a, b, c, d }
    }

    pub fn square(&self) -> [Fp2; 4] {
        [
            self.a.square(),
            self.b.square(),
            self.c.square(),
            self.d.square(),
        ]
    }

    pub fn precomputation(&self) -> Result<[Fp2; 6]> {
        let [ad, bd, cd, dd] = hadamard(self.square())?;
        let [inv_b, inv_c, inv_d, inv_bd, inv_cd, inv_dd] =
            batched_inversion([self.b, self.c, self.d, bd, cd, dd])?;
        Ok([
            self.a.mul(&inv_b)?,
            self.a.mul(&inv_c)?,
            self.a.mul(&inv_d)?,
            ad.mul(&inv_bd)?,
            ad.mul(&inv_cd)?,
            ad.mul(&inv_dd)?,
        ])
    }
}

pub fn hadamard(values: [Fp2; 4]) -> Result<[Fp2; 4]> {
    let ad = values[0]
        .add(&values[1])?
        .add(&values[2])?
        .add(&values[3])?;
    let bd = values[0]
        .sub(&values[1])?
        .add(&values[2])?
        .sub(&values[3])?;
    let cd = values[0]
        .add(&values[1])?
        .sub(&values[2])?
        .sub(&values[3])?;
    let dd = values[0]
        .sub(&values[1])?
        .sub(&values[2])?
        .add(&values[3])?;
    Ok([ad, bd, cd, dd])
}

pub fn theta_double(tnull: &ThetaNullLv2, point: &ThetaPtLv2) -> Result<ThetaPtLv2> {
    let [lam1, lam2, lam3, lamd1, lamd2, lamd3] = tnull.precomputation()?;
    let [x, y, z, w] = hadamard(point.square())?;
    let x2 = x.square();
    let y2 = lamd1.mul(&y.square())?;
    let z2 = lamd2.mul(&z.square())?;
    let w2 = lamd3.mul(&w.square())?;
    let [xd, yd, zd, wd] = hadamard([x2, y2, z2, w2])?;
    Ok(ThetaPtLv2::new(
        xd,
        lam1.mul(&yd)?,
        lam2.mul(&zd)?,
        lam3.mul(&wd)?,
    ))
}

pub fn theta_diff_add(
    tnull: &ThetaNullLv2,
    p: &ThetaPtLv2,
    q: &ThetaPtLv2,
    p_minus_q: &ThetaPtLv2,
) -> Result<ThetaPtLv2> {
    let [_, _, _, lamd1, lamd2, lamd3] = tnull.precomputation()?;
    let [xp, yp, zp, wp] = hadamard(p.square())?;
    let [xq, yq, zq, wq] = hadamard(q.square())?;
    let xpq = xp.mul(&xq)?;
    let ypq = lamd1.mul(&yp.mul(&yq)?)?;
    let zpq = lamd2.mul(&zp.mul(&zq)?)?;
    let wpq = lamd3.mul(&wp.mul(&wq)?)?;
    let [xpq, ypq, zpq, wpq] = hadamard([xpq, ypq, zpq, wpq])?;
    let xy_pmq = p_minus_q.a.mul(&p_minus_q.b)?;
    let zw_pmq = p_minus_q.c.mul(&p_minus_q.d)?;
    Ok(ThetaPtLv2::new(
        xpq.mul(&zw_pmq)?.mul(&p_minus_q.b)?,
        ypq.mul(&zw_pmq)?.mul(&p_minus_q.a)?,
        zpq.mul(&xy_pmq)?.mul(&p_minus_q.d)?,
        wpq.mul(&xy_pmq)?.mul(&p_minus_q.c)?,
    ))
}

pub fn theta_double_iter(
    tnull: &ThetaNullLv2,
    mut point: ThetaPtLv2,
    e: usize,
) -> Result<ThetaPtLv2> {
    for _ in 0..e {
        point = theta_double(tnull, &point)?;
    }
    Ok(point)
}

pub fn theta_ladder(tnull: &ThetaNullLv2, scalar: u64, point: ThetaPtLv2) -> Result<ThetaPtLv2> {
    if scalar == 0 {
        return Ok(ThetaPtLv2::new(tnull.a, tnull.b, tnull.c, tnull.d));
    }
    if scalar == 1 {
        return Ok(point);
    }
    if scalar == 2 {
        return theta_double(tnull, &point);
    }

    let mut b = 1u64 << (63 - scalar.leading_zeros());
    b >>= 1;

    let mut p0 = point;
    let mut p1 = theta_double(tnull, &point)?;
    while b != 0 {
        if scalar & b == 0 {
            p1 = theta_diff_add(tnull, &p0, &p1, &point)?;
            p0 = theta_double(tnull, &p0)?;
        } else {
            p0 = theta_diff_add(tnull, &p0, &p1, &point)?;
            p1 = theta_double(tnull, &p1)?;
        }
        b >>= 1;
    }
    Ok(p0)
}

pub fn product_theta_null(t1: ThetaDim1, t2: ThetaDim1) -> ThetaNullLv2 {
    ThetaNullLv2::new(
        t1.a.mul(&t2.a).expect("matching modulus"),
        t1.b.mul(&t2.a).expect("matching modulus"),
        t1.a.mul(&t2.b).expect("matching modulus"),
        t1.b.mul(&t2.b).expect("matching modulus"),
    )
}

pub fn product_theta_pt(t1: ThetaDim1, t2: ThetaDim1) -> ThetaPtLv2 {
    ThetaPtLv2::new(
        t1.a.mul(&t2.a).expect("matching modulus"),
        t1.b.mul(&t2.a).expect("matching modulus"),
        t1.a.mul(&t2.b).expect("matching modulus"),
        t1.b.mul(&t2.b).expect("matching modulus"),
    )
}

pub fn theta_to_montgomery(tnull: ThetaDim1) -> Result<Proj1> {
    let a2 = tnull.a.square();
    let b2 = tnull.b.square();
    let t1 = a2.add(&b2)?;
    let t2 = a2.sub(&b2)?;
    let x = t1.square().add(&t2.square())?.neg();
    let z = t1.mul(&t2)?;
    Ok(Proj1 { x, z })
}

pub fn theta_point_to_montgomery(tnull: ThetaDim1, point: ThetaDim1) -> Result<Proj1> {
    let av = tnull.a.mul(&point.b)?;
    let bu = tnull.b.mul(&point.a)?;
    Ok(Proj1 {
        x: av.add(&bu)?,
        z: av.sub(&bu)?,
    })
}

pub fn montgomery_point_to_theta(tnull: ThetaDim1, point: Proj1) -> Result<ThetaDim1> {
    Ok(ThetaDim1::new(
        tnull.a.mul(&point.x.sub(&point.z)?)?,
        tnull.b.mul(&point.x.add(&point.z)?)?,
    ))
}

pub fn apply_base_change_point(point: ThetaPtLv2, matrix: [Fp2; 16]) -> Result<ThetaPtLv2> {
    let coords = [point.a, point.b, point.c, point.d];
    let out = apply_base_change(coords, matrix)?;
    Ok(ThetaPtLv2::new(out[0], out[1], out[2], out[3]))
}

pub fn apply_base_change_null(point: ThetaNullLv2, matrix: [Fp2; 16]) -> Result<ThetaNullLv2> {
    let coords = [point.a, point.b, point.c, point.d];
    let out = apply_base_change(coords, matrix)?;
    Ok(ThetaNullLv2::new(out[0], out[1], out[2], out[3]))
}

pub fn splitting_isomorphism(
    tnull: ThetaNullLv2,
    image_points: &[ThetaPtLv2],
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let matrix = compute_splitting_matrix(tnull)?;
    let mapped_null = apply_base_change_null(tnull, matrix)?;
    let mut mapped_points = Vec::with_capacity(image_points.len());
    for point in image_points {
        mapped_points.push(apply_base_change_point(*point, matrix)?);
    }
    Ok((mapped_null, mapped_points))
}

pub fn theta_couple_double(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    point: ThetaCouplePoint,
) -> Result<ThetaCouplePoint> {
    Ok(ThetaCouplePoint {
        p1: x_dbl(curve1, &point.p1)?,
        p2: x_dbl(curve2, &point.p2)?,
    })
}

pub fn theta_couple_double_iter(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    mut point: ThetaCouplePoint,
    e: usize,
) -> Result<ThetaCouplePoint> {
    for _ in 0..e {
        point = theta_couple_double(curve1, curve2, point)?;
    }
    Ok(point)
}

pub fn get_base_submatrix(curve: &MontgomeryCurve, point: Proj1) -> Result<[Fp2; 4]> {
    let point2 = x_dbl(curve, &point)?;
    let x = point.x;
    let z = point.z;
    let u = point2.x;
    let w = point2.z;
    let wx = w.mul(&x)?;
    let wz = w.mul(&z)?;
    let ux = u.mul(&x)?;
    let uz = u.mul(&z)?;
    let det = wx.sub(&uz)?;
    let [det_inv, z_inv] = batched_inversion([det, z])?;
    let d = uz.mul(&det_inv)?;
    let a = d.neg();
    let b = wz.mul(&det_inv)?.neg();
    let c = ux.mul(&det_inv)?.sub(&x.mul(&z_inv)?)?;
    Ok([a, b, c, d])
}

pub fn get_base_matrix(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    t1: ThetaCouplePoint,
    t2: ThetaCouplePoint,
) -> Result<[Fp2; 16]> {
    let [g00_1, g01_1, g10_1, g11_1] = get_base_submatrix(curve1, t1.p1)?;
    let [g00_2, g01_2, g10_2, g11_2] = get_base_submatrix(curve2, t1.p2)?;
    let [h00_1, _, h10_1, _] = get_base_submatrix(curve1, t2.p1)?;
    let [h00_2, h01_2, h10_2, h11_2] = get_base_submatrix(curve2, t2.p2)?;

    let gh00_1 = g00_1.mul(&h00_1)?.add(&g01_1.mul(&h10_1)?)?;
    let gh10_1 = g10_1.mul(&h00_1)?.add(&g11_1.mul(&h10_1)?)?;
    let gh00_2 = g00_2.mul(&h00_2)?.add(&g01_2.mul(&h10_2)?)?;
    let gh10_2 = g10_2.mul(&h00_2)?.add(&g11_2.mul(&h10_2)?)?;

    let modulus = *curve1.modulus();
    let zero = Fp2::zero(&modulus);
    let one = Fp2::one(&modulus);
    let mut a = one;
    let mut b = zero;
    let mut c = zero;
    let mut d = zero;

    for (x0, x1, y0, y1) in [
        (g00_1, g10_1, g00_2, g10_2),
        (h00_1, h10_1, h00_2, h10_2),
        (gh00_1, gh10_1, gh00_2, gh10_2),
    ] {
        a = a.add(&x0.mul(&y0)?)?;
        b = b.add(&x0.mul(&y1)?)?;
        c = c.add(&x1.mul(&y0)?)?;
        d = d.add(&x1.mul(&y1)?)?;
    }

    let a1 = h00_2.mul(&a)?.add(&h01_2.mul(&b)?)?;
    let b1 = h10_2.mul(&a)?.add(&h11_2.mul(&b)?)?;
    let c1 = h00_2.mul(&c)?.add(&h01_2.mul(&d)?)?;
    let d1 = h10_2.mul(&c)?.add(&h11_2.mul(&d)?)?;

    let a2 = g00_1.mul(&a)?.add(&g01_1.mul(&c)?)?;
    let b2 = g00_1.mul(&b)?.add(&g01_1.mul(&d)?)?;
    let c2 = g10_1.mul(&a)?.add(&g11_1.mul(&c)?)?;
    let d2 = g10_1.mul(&b)?.add(&g11_1.mul(&d)?)?;

    let a3 = g00_1.mul(&a1)?.add(&g01_1.mul(&c1)?)?;
    let b3 = g00_1.mul(&b1)?.add(&g01_1.mul(&d1)?)?;
    let c3 = g10_1.mul(&a1)?.add(&g11_1.mul(&c1)?)?;
    let d3 = g10_1.mul(&b1)?.add(&g11_1.mul(&d1)?)?;

    Ok([a, b, c, d, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3])
}

pub fn base_change_couple_point(point: ThetaCouplePoint, matrix: [Fp2; 16]) -> Result<ThetaPtLv2> {
    let x1 = point.p1.x;
    let z1 = point.p1.z;
    let x2 = point.p2.x;
    let z2 = point.p2.z;
    apply_base_change_point(
        ThetaPtLv2::new(x1.mul(&x2)?, x1.mul(&z2)?, z1.mul(&x2)?, z1.mul(&z2)?),
        matrix,
    )
}

pub fn gluing_codomain(t1: ThetaPtLv2, t2: ThetaPtLv2) -> Result<(ThetaNullLv2, Fp2, Fp2, usize)> {
    let xaxbycyd = hadamard(t1.square())?;
    let zazbtytd = hadamard(t2.square())?;
    let mut zero_idx = 0usize;
    while zero_idx < 4 && !xaxbycyd[zero_idx].is_zero() {
        zero_idx += 1;
    }
    if zero_idx == 4 {
        return Err(ThetaError::NotProductThetaNull);
    }
    let t1v = zazbtytd[1 ^ zero_idx];
    let t2v = xaxbycyd[2 ^ zero_idx];
    let t3v = zazbtytd[3 ^ zero_idx];
    let t4v = xaxbycyd[3 ^ zero_idx];
    let [inv_t1, inv_t2, inv_t3, inv_t4] = batched_inversion([t1v, t2v, t3v, t4v])?;

    let modulus = *t1.a.modulus();
    let zero = Fp2::zero(&modulus);
    let one = Fp2::one(&modulus);
    let mut abcd = [zero; 4];
    abcd[0 ^ zero_idx] = zero;
    abcd[1 ^ zero_idx] = t1v.mul(&inv_t3)?;
    abcd[2 ^ zero_idx] = t2v.mul(&inv_t4)?;
    abcd[3 ^ zero_idx] = one;

    let a_inverse = t3v.mul(&inv_t1)?;
    let b_inverse = t4v.mul(&inv_t2)?;
    let [a, b, c, d] = hadamard(abcd)?;
    Ok((
        ThetaNullLv2::new(a, b, c, d),
        a_inverse,
        b_inverse,
        zero_idx,
    ))
}

pub fn gluing_image(
    point: ThetaPtLv2,
    point_plus_t: ThetaPtLv2,
    a_inv: Fp2,
    b_inv: Fp2,
    zero_idx: usize,
) -> Result<ThetaPtLv2> {
    let axbyczdt = hadamard(point.square())?;
    let aybxctdz = hadamard(point_plus_t.square())?;

    let y = axbyczdt[1 ^ zero_idx].mul(&a_inv)?;
    let z = axbyczdt[2 ^ zero_idx].mul(&b_inv)?;
    let t = axbyczdt[3 ^ zero_idx];

    let zb = aybxctdz[3 ^ zero_idx];
    let tb = aybxctdz[2 ^ zero_idx].mul(&b_inv)?;
    let lam = if !z.is_zero() {
        z.mul(&zb.invert()?)?
    } else {
        t.mul(&tb.invert()?)?
    };

    let xb = aybxctdz[1 ^ zero_idx].mul(&a_inv)?;
    let x = xb.mul(&lam)?;

    let modulus = *point.a.modulus();
    let zero = Fp2::zero(&modulus);
    let mut xyzt = [zero; 4];
    xyzt[0 ^ zero_idx] = x;
    xyzt[1 ^ zero_idx] = y;
    xyzt[2 ^ zero_idx] = z;
    xyzt[3 ^ zero_idx] = t;
    let [a, b, c, d] = hadamard(xyzt)?;
    Ok(ThetaPtLv2::new(a, b, c, d))
}

pub fn gluing_isogeny(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    t1_8: ThetaCouplePoint,
    t2_8: ThetaCouplePoint,
    _p1q1p2q2: ThetaCouplePoint,
    image_points: &[ThetaCouplePoint],
    n: usize,
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let t1_4 = theta_couple_double(curve1, curve2, t1_8)?;
    let t2_4 = theta_couple_double(curve1, curve2, t2_8)?;
    let matrix = get_base_matrix(curve1, curve2, t1_4, t2_4)?;

    let t1 = base_change_couple_point(t1_8, matrix)?;
    let t2 = base_change_couple_point(t2_8, matrix)?;
    let (codomain, a_inv, b_inv, zero_idx) = gluing_codomain(t1, t2)?;

    let mut images = Vec::with_capacity(image_points.len());
    for (index, point) in image_points.iter().enumerate() {
        let pt = if index + 2 == image_points.len() {
            ThetaCouplePoint {
                p1: scalar_x_add_one(curve1, point.p1, n)?,
                p2: scalar_x_add_one(curve2, point.p2, n)?,
            }
        } else if index + 1 == image_points.len() {
            ThetaCouplePoint {
                p1: ladder3pt_proj(curve1, n, point.p1, image_points[image_points.len() - 2].p1)?,
                p2: ladder3pt_proj(curve2, n, point.p2, image_points[image_points.len() - 2].p2)?,
            }
        } else {
            ThetaCouplePoint {
                p1: x_add_sub_affine(curve1, point.p1, t1_4.p1)?,
                p2: x_add_sub_affine(curve2, point.p2, t1_4.p2)?,
            }
        };
        let p_theta = base_change_couple_point(*point, matrix)?;
        let pt_theta = base_change_couple_point(pt, matrix)?;
        images.push(gluing_image(p_theta, pt_theta, a_inv, b_inv, zero_idx)?);
    }

    Ok((codomain, images))
}

pub fn two_two_isogeny_8torsion(
    domain: ThetaNullLv2,
    t1: ThetaPtLv2,
    t2: ThetaPtLv2,
    image_points: &[ThetaPtLv2],
    apply_hadamard: bool,
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let [x_a, x_b, _, _] = hadamard(t1.square())?;
    let [z_a, t_b, z_c, t_d] = hadamard(t2.square())?;

    let [x_a_inv, z_a_inv, t_b_inv] = batched_inversion([x_a, z_a, t_b])?;
    let modulus = *domain.a.modulus();
    let a = Fp2::one(&modulus);
    let b = x_b.mul(&x_a_inv)?;
    let c = z_c.mul(&z_a_inv)?;
    let d = t_d.mul(&t_b_inv)?.mul(&b)?;

    let [_, _, _, bb_inv, cc_inv, dd_inv] = domain.precomputation()?;
    let b_inv = bb_inv.mul(&b)?;
    let c_inv = cc_inv.mul(&c)?;
    let d_inv = dd_inv.mul(&d)?;

    let codomain = if apply_hadamard {
        let [a, b, c, d] = hadamard([a, b, c, d])?;
        ThetaNullLv2::new(a, b, c, d)
    } else {
        ThetaNullLv2::new(a, b, c, d)
    };

    let mut images = Vec::with_capacity(image_points.len());
    for point in image_points {
        let [x, y, z, t] = hadamard(point.square())?;
        let y = y.mul(&b_inv)?;
        let z = z.mul(&c_inv)?;
        let t = t.mul(&d_inv)?;
        let mapped = if apply_hadamard {
            let [x, y, z, t] = hadamard([x, y, z, t])?;
            ThetaPtLv2::new(x, y, z, t)
        } else {
            ThetaPtLv2::new(x, y, z, t)
        };
        images.push(mapped);
    }
    Ok((codomain, images))
}

pub fn two_two_isogeny_8torsion_to_product(
    _domain: ThetaNullLv2,
    t1: ThetaPtLv2,
    t2: ThetaPtLv2,
    image_points: &[ThetaPtLv2],
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let [x_a, x_b, _, _] = hadamard(hadamard(t1.square())?)?;
    let [z_a, t_b, z_c, t_d] = hadamard(hadamard(t2.square())?)?;

    let [x_a_inv, z_a_inv, t_b_inv, x_b_inv, z_c_inv, t_d_inv] =
        batched_inversion([x_a, z_a, t_b, x_b, z_c, t_d])?;

    let modulus = *t1.a.modulus();
    let a = Fp2::one(&modulus);
    let b = x_b.mul(&x_a_inv)?;
    let c = z_c.mul(&z_a_inv)?;
    let d = t_d.mul(&t_b_inv)?.mul(&b)?;
    let b_inv = x_b_inv.mul(&x_a)?;
    let c_inv = z_c_inv.mul(&z_a)?;
    let d_inv = t_d_inv.mul(&t_b)?.mul(&b_inv)?;

    let mut images = Vec::with_capacity(image_points.len());
    for point in image_points {
        let [x, y, z, t] = hadamard(hadamard(point.square())?)?;
        images.push(ThetaPtLv2::new(
            x,
            y.mul(&b_inv)?,
            z.mul(&c_inv)?,
            t.mul(&d_inv)?,
        ));
    }
    Ok((ThetaNullLv2::new(a, b, c, d), images))
}

pub fn two_two_isogeny_4torsion(
    domain: ThetaNullLv2,
    t1: ThetaPtLv2,
    image_points: &[ThetaPtLv2],
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let [aa, bb, cc, dd] = hadamard(domain.square())?;
    let [x_ab, _, x_cd, _] = hadamard(t1.square())?;
    let [aa_inv, bb_inv, cc_inv, dd_inv] = batched_inversion([aa, bb, cc, dd])?;

    let modulus = *domain.a.modulus();
    let a = Fp2::one(&modulus);
    let b = bb
        .mul(&aa_inv)?
        .sqrt()
        .ok_or(ThetaError::MissingSquareRoot)?;
    let c = cc
        .mul(&aa_inv)?
        .sqrt()
        .ok_or(ThetaError::MissingSquareRoot)?;
    let d = x_cd.mul(&b)?.mul(&x_ab.mul(&c)?.invert()?)?;

    let b_inv = aa.mul(&bb_inv)?.mul(&b)?;
    let c_inv = aa.mul(&cc_inv)?.mul(&c)?;
    let d_inv = aa.mul(&dd_inv)?.mul(&d)?;

    let mut images = Vec::with_capacity(image_points.len());
    for point in image_points {
        let [x, y, z, t] = hadamard(point.square())?;
        let [x, y, z, t] = hadamard([x, y.mul(&b_inv)?, z.mul(&c_inv)?, t.mul(&d_inv)?])?;
        images.push(ThetaPtLv2::new(x, y, z, t));
    }
    Ok((ThetaNullLv2::new(a, b, c, d), images))
}

pub fn two_two_isogeny_2torsion(
    domain: ThetaNullLv2,
    image_points: &[ThetaPtLv2],
) -> Result<(ThetaNullLv2, Vec<ThetaPtLv2>)> {
    let [aa, bb, cc, dd] = hadamard(hadamard(domain.square())?)?;
    let [aa_inv, bb_inv, cc_inv, dd_inv] = batched_inversion([aa, bb, cc, dd])?;

    let modulus = *domain.a.modulus();
    let a = Fp2::one(&modulus);
    let b = bb
        .mul(&aa_inv)?
        .sqrt()
        .ok_or(ThetaError::MissingSquareRoot)?;
    let c = cc
        .mul(&aa_inv)?
        .sqrt()
        .ok_or(ThetaError::MissingSquareRoot)?;
    let d = dd
        .mul(&aa_inv)?
        .sqrt()
        .ok_or(ThetaError::MissingSquareRoot)?;

    let b_inv = aa.mul(&bb_inv)?.mul(&b)?;
    let c_inv = aa.mul(&cc_inv)?.mul(&c)?;
    let d_inv = aa.mul(&dd_inv)?.mul(&d)?;

    let mut images = Vec::with_capacity(image_points.len());
    for point in image_points {
        let [x, y, z, t] = hadamard(point.square())?;
        images.push(ThetaPtLv2::new(
            x,
            y.mul(&b_inv)?,
            z.mul(&c_inv)?,
            t.mul(&d_inv)?,
        ));
    }
    Ok((ThetaNullLv2::new(a, b, c, d), images))
}

pub fn theta_product_isogeny_tail_no_strategy(
    mut domain: ThetaNullLv2,
    mut image_points: Vec<ThetaPtLv2>,
    n: usize,
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    if image_points.len() < 2 {
        return Err(ThetaError::NotProductThetaNull);
    }
    for k in 1..n {
        let tp1 = theta_double_iter(&domain, image_points[image_points.len() - 2], n - k - 1)?;
        let tp2 = theta_double_iter(&domain, image_points[image_points.len() - 1], n - k - 1)?;
        if k == n.saturating_sub(2) {
            let (next_domain, next_images) =
                two_two_isogeny_8torsion(domain, tp1, tp2, &image_points, false)?;
            domain = next_domain;
            image_points = next_images;
        } else if k == n.saturating_sub(1) {
            image_points.pop();
            image_points.pop();
            let (next_domain, next_images) =
                two_two_isogeny_8torsion_to_product(domain, tp1, tp2, &image_points)?;
            domain = next_domain;
            image_points = next_images;
        } else {
            let (next_domain, next_images) =
                two_two_isogeny_8torsion(domain, tp1, tp2, &image_points, true)?;
            domain = next_domain;
            image_points = next_images;
        }
    }
    let (domain, image_points) = splitting_isomorphism(domain, &image_points)?;
    split_to_product(domain, &image_points)
}

pub fn theta_product_isogeny_no_strategy(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    p1p2: ThetaCouplePoint,
    q1q2: ThetaCouplePoint,
    p1q1p2q2: ThetaCouplePoint,
    mut image_points: Vec<ThetaCouplePoint>,
    n: usize,
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    image_points.push(p1p2);
    image_points.push(q1q2);

    let p1p2_8 = theta_couple_double_iter(curve1, curve2, p1p2, n.saturating_sub(1))?;
    let q1q2_8 = theta_couple_double_iter(curve1, curve2, q1q2, n.saturating_sub(1))?;
    let (domain, image_points) =
        gluing_isogeny(curve1, curve2, p1p2_8, q1q2_8, p1q1p2q2, &image_points, n)?;
    theta_product_isogeny_tail_no_strategy(domain, image_points, n)
}

pub fn theta_product_isogeny(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    p1p2: ThetaCouplePoint,
    q1q2: ThetaCouplePoint,
    p1q1p2q2: ThetaCouplePoint,
    mut image_points: Vec<ThetaCouplePoint>,
    n: usize,
    strategy: &[usize],
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    image_points.push(p1p2);
    image_points.push(q1q2);

    let ker1 = theta_couple_double_iter(curve1, curve2, p1p2, n.saturating_sub(1))?;
    let ker2 = theta_couple_double_iter(curve1, curve2, q1q2, n.saturating_sub(1))?;
    let (mut domain, mut image_points) =
        gluing_isogeny(curve1, curve2, ker1, ker2, p1q1p2q2, &image_points, n)?;

    let mut strategy_idx = 0usize;
    let mut level = Vec::new();
    level.push(0usize);

    for k in 1..n {
        let mut prev = level.iter().sum::<usize>();
        let mut ker1 = image_points[image_points.len() - 2];
        let mut ker2 = image_points[image_points.len() - 1];

        while prev != (n - 1 - k) {
            let step = *strategy
                .get(strategy_idx)
                .ok_or(ThetaError::StrategyExhausted)?;
            level.push(step);
            ker1 = theta_double_iter(&domain, ker1, step)?;
            ker2 = theta_double_iter(&domain, ker2, step)?;
            image_points.push(ker1);
            image_points.push(ker2);
            prev += step;
            strategy_idx += 1;
        }

        image_points.pop();
        image_points.pop();
        level.pop();

        if k == n - 2 {
            let (next_domain, next_images) =
                two_two_isogeny_8torsion(domain, ker1, ker2, &image_points, false)?;
            domain = next_domain;
            image_points = next_images;
        } else if k == n - 1 {
            let (next_domain, next_images) =
                two_two_isogeny_8torsion_to_product(domain, ker1, ker2, &image_points)?;
            domain = next_domain;
            image_points = next_images;
        } else {
            let (next_domain, next_images) =
                two_two_isogeny_8torsion(domain, ker1, ker2, &image_points, true)?;
            domain = next_domain;
            image_points = next_images;
        }
    }

    let (domain, image_points) = splitting_isomorphism(domain, &image_points)?;
    split_to_product(domain, &image_points)
}

pub fn theta_product_isogeny_tail_sqrt_no_strategy(
    mut domain: ThetaNullLv2,
    mut image_points: Vec<ThetaPtLv2>,
    n: usize,
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    if image_points.len() < 2 {
        return Err(ThetaError::NotProductThetaNull);
    }
    if n < 2 {
        let (domain, image_points) = splitting_isomorphism(domain, &image_points)?;
        return split_to_product(domain, &image_points);
    }

    for k in 1..n.saturating_sub(2) {
        let tp1 = theta_double_iter(&domain, image_points[image_points.len() - 2], n - k - 3)?;
        let tp2 = theta_double_iter(&domain, image_points[image_points.len() - 1], n - k - 3)?;
        let (next_domain, next_images) =
            two_two_isogeny_8torsion(domain, tp1, tp2, &image_points, true)?;
        domain = next_domain;
        image_points = next_images;
    }

    let t1 = image_points.pop().ok_or(ThetaError::NotProductThetaNull)?;
    let (domain, image_points) = two_two_isogeny_4torsion(domain, t1, &image_points)?;
    let (domain, image_points) = two_two_isogeny_2torsion(domain, &image_points)?;
    let (domain, image_points) = splitting_isomorphism(domain, &image_points)?;
    split_to_product(domain, &image_points)
}

pub fn theta_product_isogeny_sqrt_no_strategy(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    p1p2: ThetaCouplePoint,
    q1q2: ThetaCouplePoint,
    p1q1p2q2: ThetaCouplePoint,
    mut image_points: Vec<ThetaCouplePoint>,
    n: usize,
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    image_points.push(p1p2);
    image_points.push(q1q2);

    let p1p2_8 = theta_couple_double_iter(curve1, curve2, p1p2, n.saturating_sub(3))?;
    let q1q2_8 = theta_couple_double_iter(curve1, curve2, q1q2, n.saturating_sub(3))?;
    let (domain, image_points) = gluing_isogeny(
        curve1,
        curve2,
        p1p2_8,
        q1q2_8,
        p1q1p2q2,
        &image_points,
        n.saturating_sub(2),
    )?;
    theta_product_isogeny_tail_sqrt_no_strategy(domain, image_points, n)
}

pub fn theta_product_isogeny_sqrt(
    curve1: &MontgomeryCurve,
    curve2: &MontgomeryCurve,
    p1p2: ThetaCouplePoint,
    q1q2: ThetaCouplePoint,
    p1q1p2q2: ThetaCouplePoint,
    mut image_points: Vec<ThetaCouplePoint>,
    n: usize,
    strategy: &[usize],
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    image_points.push(p1p2);
    image_points.push(q1q2);

    let ker1 = theta_couple_double_iter(curve1, curve2, p1p2, n.saturating_sub(3))?;
    let ker2 = theta_couple_double_iter(curve1, curve2, q1q2, n.saturating_sub(3))?;
    let (mut domain, mut image_points) = gluing_isogeny(
        curve1,
        curve2,
        ker1,
        ker2,
        p1q1p2q2,
        &image_points,
        n.saturating_sub(2),
    )?;

    let mut strategy_idx = 0usize;
    let mut level = Vec::new();
    level.push(0usize);

    for k in 1..n.saturating_sub(2) {
        let mut prev = level.iter().sum::<usize>();
        let mut ker1 = image_points[image_points.len() - 2];
        let mut ker2 = image_points[image_points.len() - 1];

        while prev != (n - k - 3) {
            let step = *strategy
                .get(strategy_idx)
                .ok_or(ThetaError::StrategyExhausted)?;
            level.push(step);
            ker1 = theta_double_iter(&domain, ker1, step)?;
            ker2 = theta_double_iter(&domain, ker2, step)?;
            image_points.push(ker1);
            image_points.push(ker2);
            prev += step;
            strategy_idx += 1;
        }
        image_points.pop();
        image_points.pop();
        level.pop();

        if k == n - 3 {
            image_points.push(ker1);
        }
        let (next_domain, next_images) =
            two_two_isogeny_8torsion(domain, ker1, ker2, &image_points, true)?;
        domain = next_domain;
        image_points = next_images;
    }

    let t1 = image_points.pop().ok_or(ThetaError::NotProductThetaNull)?;
    let (domain, image_points) = two_two_isogeny_4torsion(domain, t1, &image_points)?;
    let (domain, image_points) = two_two_isogeny_2torsion(domain, &image_points)?;
    let (domain, image_points) = splitting_isomorphism(domain, &image_points)?;
    split_to_product(domain, &image_points)
}

pub fn split_theta_point(point: ThetaPtLv2) -> (ThetaDim1, ThetaDim1) {
    (
        ThetaDim1::new(point.a, point.b),
        ThetaDim1::new(point.b, point.d),
    )
}

pub fn split_theta_null(point: ThetaNullLv2) -> (ThetaDim1, ThetaDim1) {
    (
        ThetaDim1::new(point.a, point.b),
        ThetaDim1::new(point.b, point.d),
    )
}

pub fn split_to_product(
    tnull: ThetaNullLv2,
    image_points: &[ThetaPtLv2],
) -> Result<([Proj1; 2], Vec<ThetaCouplePoint>)> {
    let (o1, o2) = split_theta_null(tnull);
    let e1 = theta_to_montgomery(o1)?;
    let e2 = theta_to_montgomery(o2)?;
    let mut images = Vec::with_capacity(image_points.len());
    for point in image_points {
        let (p1, p2) = split_theta_point(*point);
        images.push(ThetaCouplePoint {
            p1: theta_point_to_montgomery(o1, p1)?,
            p2: theta_point_to_montgomery(o2, p2)?,
        });
    }
    Ok(([e1, e2], images))
}

fn batched_inversion<const N: usize>(values: [Fp2; N]) -> Result<[Fp2; N]> {
    let modulus = *values[0].modulus();
    let mut prefixes = [Fp2::one(&modulus); N];
    let mut acc = Fp2::one(&modulus);
    for (index, value) in values.iter().enumerate() {
        prefixes[index] = acc;
        acc = acc.mul(value)?;
    }
    let mut inv_acc = acc.invert()?;
    let mut out = [Fp2::zero(&modulus); N];
    for index in (0..N).rev() {
        out[index] = inv_acc.mul(&prefixes[index])?;
        inv_acc = inv_acc.mul(&values[index])?;
    }
    Ok(out)
}

fn scalar_x_add_one(curve: &MontgomeryCurve, point: Proj1, power: usize) -> Result<Proj1> {
    let lifted = lift_proj_to_point(curve, point)?;
    let scalar = scalar_pow2_plus_one(power);
    let mapped = curve
        .scalar_mul(&lifted, &scalar)
        .map_err(|_| ThetaError::PointLiftFailed)?;
    if mapped.is_infinity() {
        return Ok(Proj1::identity(curve.modulus()));
    }
    Ok(Proj1::affine_x(mapped.x))
}

fn ladder3pt_proj(curve: &MontgomeryCurve, power: usize, p: Proj1, q: Proj1) -> Result<Proj1> {
    let p_lift = lift_proj_to_point(curve, p)?;
    let q_lift = lift_proj_to_point(curve, q)?;
    let scalar = scalar_pow2(power);
    Ok(ladder3pt_affine(curve, &scalar, &p_lift, &q_lift)?)
}

fn x_add_sub_affine(curve: &MontgomeryCurve, lhs: Proj1, rhs: Proj1) -> Result<Proj1> {
    let lhs = lift_proj_to_point(curve, lhs)?;
    let rhs = lift_proj_to_point(curve, rhs)?;
    let sum = curve
        .add(&lhs, &rhs)
        .map_err(|_| ThetaError::PointLiftFailed)?;
    if sum.is_infinity() {
        return Ok(Proj1::identity(curve.modulus()));
    }
    Ok(Proj1::affine_x(sum.x))
}

fn lift_proj_to_point(curve: &MontgomeryCurve, point: Proj1) -> Result<CurvePoint> {
    if point.is_identity() {
        return Ok(curve.identity());
    }
    let x = point.to_affine_x()?;
    let rhs = curve.rhs(&x).map_err(|_| ThetaError::PointLiftFailed)?;
    let y = rhs.sqrt().ok_or(ThetaError::PointLiftFailed)?;
    Ok(CurvePoint::affine(x, y))
}

fn scalar_pow2(power: usize) -> Vec<u64> {
    let limbs = (power / 64) + 1;
    let mut out = vec![0u64; limbs];
    out[power / 64] |= 1u64 << (power % 64);
    out
}

fn scalar_pow2_plus_one(power: usize) -> Vec<u64> {
    let mut out = scalar_pow2(power);
    out[0] |= 1;
    out
}

fn level_22_constants_sqr(tnull: ThetaNullLv2, chi: usize, i: usize) -> Result<Fp2> {
    let coords = [tnull.a, tnull.b, tnull.c, tnull.d];
    let mut acc = Fp2::zero(tnull.a.modulus());
    for t in 0..4 {
        let sign = chi_eval(chi, t);
        let term = coords[t].mul(&coords[i ^ t])?;
        acc = if sign == 1 {
            acc.add(&term)?
        } else {
            acc.sub(&term)?
        };
    }
    Ok(acc)
}

fn identify_even_index(tnull: ThetaNullLv2) -> Result<(usize, usize)> {
    for (chi, i) in EVEN_INDICES {
        if level_22_constants_sqr(tnull, chi, i)?.is_zero() {
            return Ok((chi, i));
        }
    }
    Err(ThetaError::NotProductThetaNull)
}

fn compute_splitting_matrix(tnull: ThetaNullLv2) -> Result<[Fp2; 16]> {
    let key = identify_even_index(tnull)?;
    let modulus = *tnull.a.modulus();
    if key == (0, 0) {
        let one = Fp2::one(&modulus);
        let minus_one = one.neg();
        let zeta = Fp2::new(Fp::zero(&modulus), Fp::one(&modulus))?;
        let minus_zeta = zeta.neg();
        return Ok([
            one, zeta, one, zeta, one, minus_zeta, minus_one, zeta, one, zeta, minus_one,
            minus_zeta, minus_one, zeta, minus_one, zeta,
        ]);
    }
    SPLITTING_MAPS
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, matrix)| convert_splitting_matrix(&modulus, *matrix))
        .ok_or(ThetaError::NotProductThetaNull)
}

fn chi_eval(chi: usize, t: usize) -> i8 {
    match (chi, t) {
        (0, _) => 1,
        (1, 0 | 2) => 1,
        (1, 1 | 3) => -1,
        (2, 0 | 1) => 1,
        (2, 2 | 3) => -1,
        (3, 0 | 3) => 1,
        (3, 1 | 2) => -1,
        _ => 1,
    }
}

fn apply_base_change(coords: [Fp2; 4], matrix: [Fp2; 16]) -> Result<[Fp2; 4]> {
    let modulus = *coords[0].modulus();
    let mut out = [Fp2::zero(&modulus); 4];
    for row in 0..4 {
        let mut acc = Fp2::zero(&modulus);
        for col in 0..4 {
            let coeff = matrix[row * 4 + col];
            if coeff.is_zero() {
                continue;
            }
            acc = acc.add(&coeff.mul(&coords[col])?)?;
        }
        out[row] = acc;
    }
    Ok(out)
}

fn convert_splitting_matrix(
    modulus: &crate::crypto::isogeny::field::FpModulus,
    matrix: [i8; 16],
) -> [Fp2; 16] {
    let zero = Fp2::zero(modulus);
    let one = Fp2::one(modulus);
    let minus_one = one.neg();
    let mut out = [zero; 16];
    for (index, coeff) in matrix.into_iter().enumerate() {
        out[index] = match coeff {
            1 => one,
            -1 => minus_one,
            _ => zero,
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        gluing_isogeny, hadamard, product_theta_null, product_theta_pt, split_theta_point,
        split_to_product, splitting_isomorphism, theta_diff_add, theta_double, theta_double_iter,
        theta_ladder, theta_point_to_montgomery, theta_product_isogeny,
        theta_product_isogeny_no_strategy, theta_to_montgomery, ThetaCouplePoint, ThetaDim1,
        ThetaNullLv2, ThetaPtLv2,
    };
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::curve::xonly::{x_of_difference, Proj1};
    use crate::crypto::isogeny::field::{Fp, Fp2, FpModulus};

    fn fp2(modulus: &FpModulus, c0: u64, c1: u64) -> Fp2 {
        Fp2::new(Fp::from_u64(modulus, c0), Fp::from_u64(modulus, c1)).unwrap()
    }

    fn modulus19() -> FpModulus {
        FpModulus::from_u64(19).unwrap()
    }

    fn curve19() -> MontgomeryCurve {
        MontgomeryCurve::new(fp2(&modulus19(), 5, 0)).unwrap()
    }

    fn proj_eq(lhs: Proj1, rhs: Proj1) -> bool {
        if lhs.is_identity() || rhs.is_identity() {
            return lhs.is_identity() == rhs.is_identity();
        }
        lhs.x.mul(&rhs.z).unwrap() == rhs.x.mul(&lhs.z).unwrap()
    }

    fn enumerate_curve_points(curve: &MontgomeryCurve) -> Vec<CurvePoint> {
        let modulus = *curve.modulus();
        let mut points = Vec::new();
        for x0 in 0..19u64 {
            for y0 in 0..19u64 {
                let point = CurvePoint::affine(fp2(&modulus, x0, 0), fp2(&modulus, y0, 0));
                if curve.validate_point(&point).is_ok() {
                    points.push(point);
                }
            }
        }
        points
    }

    fn find_gluing_instance(
        curve1: &MontgomeryCurve,
        curve2: &MontgomeryCurve,
    ) -> Option<(ThetaCouplePoint, ThetaCouplePoint, ThetaCouplePoint)> {
        let points1 = enumerate_curve_points(curve1);
        let points2 = enumerate_curve_points(curve2);
        for p1 in points1
            .iter()
            .copied()
            .filter(|point: &CurvePoint| !point.is_infinity())
            .take(8)
        {
            for q1 in points1
                .iter()
                .copied()
                .filter(|point: &CurvePoint| !point.is_infinity())
                .take(8)
            {
                if p1 == q1 {
                    continue;
                }
                for p2 in points2
                    .iter()
                    .copied()
                    .filter(|point: &CurvePoint| !point.is_infinity())
                    .take(8)
                {
                    for q2 in points2
                        .iter()
                        .copied()
                        .filter(|point: &CurvePoint| !point.is_infinity())
                        .take(8)
                    {
                        if p2 == q2 {
                            continue;
                        }
                        let t1 = ThetaCouplePoint {
                            p1: Proj1::from_point(&p1).ok()?,
                            p2: Proj1::from_point(&p2).ok()?,
                        };
                        let t2 = ThetaCouplePoint {
                            p1: Proj1::from_point(&q1).ok()?,
                            p2: Proj1::from_point(&q2).ok()?,
                        };
                        let diff = ThetaCouplePoint {
                            p1: x_of_difference(curve1, &p1, &q1).ok()?,
                            p2: x_of_difference(curve2, &p2, &q2).ok()?,
                        };
                        if gluing_isogeny(curve1, curve2, t1, t2, diff, &[t1, t2], 1).is_ok() {
                            return Some((t1, t2, diff));
                        }
                    }
                }
            }
        }
        None
    }

    fn find_product_instance(
        curve1: &MontgomeryCurve,
        curve2: &MontgomeryCurve,
    ) -> Option<(ThetaCouplePoint, ThetaCouplePoint, ThetaCouplePoint)> {
        let points1 = enumerate_curve_points(curve1);
        let points2 = enumerate_curve_points(curve2);
        for p1 in points1
            .iter()
            .copied()
            .filter(|point: &CurvePoint| !point.is_infinity())
            .take(10)
        {
            for q1 in points1
                .iter()
                .copied()
                .filter(|point: &CurvePoint| !point.is_infinity())
                .take(10)
            {
                if p1 == q1 {
                    continue;
                }
                for p2 in points2
                    .iter()
                    .copied()
                    .filter(|point: &CurvePoint| !point.is_infinity())
                    .take(10)
                {
                    for q2 in points2
                        .iter()
                        .copied()
                        .filter(|point: &CurvePoint| !point.is_infinity())
                        .take(10)
                    {
                        if p2 == q2 {
                            continue;
                        }
                        let t1 = ThetaCouplePoint {
                            p1: Proj1::from_point(&p1).ok()?,
                            p2: Proj1::from_point(&p2).ok()?,
                        };
                        let t2 = ThetaCouplePoint {
                            p1: Proj1::from_point(&q1).ok()?,
                            p2: Proj1::from_point(&q2).ok()?,
                        };
                        let diff = ThetaCouplePoint {
                            p1: x_of_difference(curve1, &p1, &q1).ok()?,
                            p2: x_of_difference(curve2, &p2, &q2).ok()?,
                        };
                        if theta_product_isogeny_no_strategy(
                            curve1,
                            curve2,
                            t1,
                            t2,
                            diff,
                            Vec::new(),
                            1,
                        )
                        .is_ok()
                        {
                            return Some((t1, t2, diff));
                        }
                    }
                }
            }
        }
        None
    }

    #[test]
    fn hadamard_is_involutive_up_to_factor_four() {
        let modulus = modulus19();
        let values = [
            fp2(&modulus, 1, 0),
            fp2(&modulus, 2, 0),
            fp2(&modulus, 3, 0),
            fp2(&modulus, 4, 0),
        ];
        let once = hadamard(values).unwrap();
        let twice = hadamard(once).unwrap();
        let four = Fp2::from_u64(&modulus, 4);
        assert_eq!(twice[0], values[0].mul(&four).unwrap());
        assert_eq!(twice[1], values[1].mul(&four).unwrap());
        assert_eq!(twice[2], values[2].mul(&four).unwrap());
        assert_eq!(twice[3], values[3].mul(&four).unwrap());
    }

    #[test]
    fn theta_ladder_matches_double_iter_for_small_scalars() {
        let modulus = modulus19();
        let tnull = ThetaNullLv2::new(
            fp2(&modulus, 1, 0),
            fp2(&modulus, 2, 0),
            fp2(&modulus, 3, 0),
            fp2(&modulus, 4, 0),
        );
        let point = ThetaPtLv2::new(
            fp2(&modulus, 5, 0),
            fp2(&modulus, 6, 0),
            fp2(&modulus, 7, 0),
            fp2(&modulus, 8, 0),
        );
        let doubled = theta_double(&tnull, &point).unwrap();
        assert_eq!(theta_ladder(&tnull, 2, point).unwrap(), doubled);
        assert_eq!(theta_double_iter(&tnull, point, 1).unwrap(), doubled);
    }

    #[test]
    fn product_theta_splits_back_to_montgomery_coordinates() {
        let modulus = modulus19();
        let t1 = ThetaDim1::new(fp2(&modulus, 1, 0), fp2(&modulus, 2, 0));
        let t2 = ThetaDim1::new(fp2(&modulus, 3, 0), fp2(&modulus, 4, 0));
        let null = product_theta_null(t1, t2);
        let point = product_theta_pt(t1, t2);
        let ([e1, e2], images) = split_to_product(null, &[point]).unwrap();
        let (p1, p2) = split_theta_point(point);
        assert!(proj_eq(e1, theta_to_montgomery(t1).unwrap()));
        assert!(proj_eq(e2, theta_to_montgomery(t2).unwrap()));
        assert!(proj_eq(
            images[0].p1,
            theta_point_to_montgomery(t1, p1).unwrap()
        ));
        assert!(proj_eq(
            images[0].p2,
            theta_point_to_montgomery(t2, p2).unwrap()
        ));
    }

    #[test]
    fn splitting_isomorphism_preserves_point_count() {
        let modulus = modulus19();
        let t1 = ThetaDim1::new(fp2(&modulus, 1, 0), fp2(&modulus, 2, 0));
        let t2 = ThetaDim1::new(fp2(&modulus, 3, 0), fp2(&modulus, 4, 0));
        let null = product_theta_null(t1, t2);
        let point = product_theta_pt(t1, t2);
        let (_mapped_null, mapped_points) = splitting_isomorphism(null, &[point]).unwrap();
        assert_eq!(mapped_points.len(), 1);
    }

    #[test]
    fn theta_diff_add_returns_structured_point() {
        let modulus = modulus19();
        let tnull = ThetaNullLv2::new(
            fp2(&modulus, 1, 0),
            fp2(&modulus, 2, 0),
            fp2(&modulus, 3, 0),
            fp2(&modulus, 4, 0),
        );
        let p = ThetaPtLv2::new(
            fp2(&modulus, 5, 0),
            fp2(&modulus, 6, 0),
            fp2(&modulus, 7, 0),
            fp2(&modulus, 8, 0),
        );
        let q = ThetaPtLv2::new(
            fp2(&modulus, 9, 0),
            fp2(&modulus, 10, 0),
            fp2(&modulus, 11, 0),
            fp2(&modulus, 12, 0),
        );
        let _ = theta_diff_add(&tnull, &p, &q, &p).unwrap();
    }

    #[test]
    fn gluing_isogeny_smoke_search_finds_small_instance() {
        let curve1 = curve19();
        let curve2 = curve19();
        let (t1, t2, diff) = find_gluing_instance(&curve1, &curve2).unwrap();
        let (_domain, images) =
            gluing_isogeny(&curve1, &curve2, t1, t2, diff, &[t1, t2], 1).unwrap();
        assert_eq!(images.len(), 2);
    }

    #[test]
    fn theta_product_isogeny_no_strategy_smoke_search_finds_small_instance() {
        let curve1 = curve19();
        let curve2 = curve19();
        let (t1, t2, diff) = find_product_instance(&curve1, &curve2).unwrap();
        let (_codomain, images) =
            theta_product_isogeny_no_strategy(&curve1, &curve2, t1, t2, diff, Vec::new(), 1)
                .unwrap();
        assert!(!images.is_empty());
    }

    #[test]
    fn theta_product_isogeny_strategy_matches_no_strategy_for_n1() {
        let curve1 = curve19();
        let curve2 = curve19();
        let (t1, t2, diff) = find_product_instance(&curve1, &curve2).unwrap();
        let direct =
            theta_product_isogeny_no_strategy(&curve1, &curve2, t1, t2, diff, Vec::new(), 1)
                .unwrap();
        let strategic =
            theta_product_isogeny(&curve1, &curve2, t1, t2, diff, Vec::new(), 1, &[]).unwrap();
        assert_eq!(strategic, direct);
    }
}
