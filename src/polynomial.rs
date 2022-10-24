use bls12_381::Scalar;
use ff::Field;

#[derive(Clone, Debug, PartialEq, Eq)]

/// Polynomial are extensively used in commitments and revocation. They are obtained when considering
/// attributes as the roots of said polynomial.
/// This structure implements polynomial arithmetic where coefficients are in Z/pZ.
/// Coefficients are given in a vector in increasing order. Addition, subtraction, multiplication and
/// division are implemented.
pub struct Polynomial {
    pub(crate) coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Given coefficients as scalar already, simply considers it as a polynomial
    pub fn from_coeffs(coefficients: &[Scalar]) -> Self {
        Polynomial {
            coefficients: coefficients.to_owned(),
        }
    }

    /// Given a set of attributes X' = { x1, x2, ..., xn}
    /// Computes the coefficients for the polynomial (X - x1)(X - x2) ... (X - xn)
    /// The coefficient of the polynomial c1X c2X^i + ... + c(i-1)X^(i-1) + ciX^i  are given in a vector.
    pub fn from_roots(roots: &Vec<Scalar>) -> Self {
        compute_polynomial(roots)
    }

    /// To make testing easy we allow the user to give coefficients of the polynomial like in the
    /// from_coeffs but given as integers
    pub fn from_integers(coeffs: &[u64]) -> Self {
        let coefficients = coeffs
            .iter()
            .map(|n| Scalar::from(*n))
            .collect::<Vec<Scalar>>();
        Polynomial { coefficients }
    }

    /// Returns p(x)=0
    pub fn zero() -> Self {
        Polynomial {
            coefficients: vec![Scalar::zero()],
        }
    }

    /// Returns p(x)=1
    pub fn one() -> Self {
        Polynomial {
            coefficients: vec![Scalar::one()],
        }
    }

    /// Using Horner's method for evaluating polynomial for a given element in Z/pZ
    #[allow(non_snake_case, dead_code)]
    pub fn evaluate_polynomial(&self, value: &Scalar) -> Scalar {
        let len = self.coefficients.len();
        let mut result = self.coefficients[len - 1];
        for i in (0..=len - 2).rev() {
            result = result * value + self.coefficients[i];
        }
        result
    }

    /// Returns the degree of the polynomial, degree(x+1) = 1
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Normalizes the coefficients, removing trailing zeroes
    pub fn normalize(&mut self) {
        let zero = Scalar::zero();
        let mut last_non_zero = 0;
        for i in 0..self.coefficients.len() {
            if self.coefficients[self.coefficients.len() - i - 1].ne(&zero) {
                last_non_zero = self.coefficients.len() - i;
                break;
            }
        }
        self.coefficients
            .drain(last_non_zero..self.coefficients.len());
        if self.coefficients.is_empty() {
            self.coefficients.push(Scalar::zero());
        }
    }

    /// Returns if p(x)=0
    pub fn is_zero(&self) -> bool {
        let mut res = true;
        for element in &self.coefficients {
            //If an element is not zero therefore the polynomial is not zero
            if element.is_zero().unwrap_u8() == 0 {
                res = false;
            }
        }
        res
    }

    /// Returns the `i`-th coefficient
    pub fn get(&self, i: usize) -> Option<&Scalar> {
        self.coefficients.get(self.degree() - i - 1)
    }

    /// Computes the extended Euclidean Algorithm st. on input a,b univariate polynomials you compute :
    /// g, the GCD of a and b
    /// u,v, as in au + bv = g
    ///
    /// Used to create an opening on disjoint sets to find the two polynomials u and v st. au + bv = 1
    /// since a and b do not share any common root
    pub fn extended_gcd(a: &Polynomial, b: &Polynomial) -> (Polynomial, Polynomial, Polynomial) {
        let mut s = Polynomial::zero();
        let mut old_s = Polynomial::one();
        let mut t = Polynomial::one();
        let mut old_t = Polynomial::zero();
        let mut r = b.clone();
        let mut old_r = a.clone();

        while !r.is_zero() {
            let (quo, _rem) = old_r.clone() / r.clone();

            let mut tmp = old_r.clone();
            tmp -= &(&quo * &r);
            old_r = r;
            r = tmp;

            let mut tmp = old_s.clone();
            tmp -= &(&quo * &s);
            old_s = s;
            s = tmp;

            let mut tmp = old_t.clone();
            tmp -= &(&quo * &t);
            old_t = t;
            t = tmp;
        }
        (old_r, old_s, old_t)
    }

    /// Given a polynomial in which the leading coefficient is not 1, reduces all coefficients by
    /// the multiplicative inverse of the leading coefficient
    #[allow(dead_code)]
    fn make_univariate(&mut self) {
        if !self.coefficients[self.degree()].eq(&Scalar::zero()) {
            let high_coeff = self.coefficients[self.degree()].invert().unwrap();

            for i in 0..self.coefficients.len() {
                self.coefficients[i] *= high_coeff;
            }
        }
    }
}

impl std::ops::AddAssign<&Polynomial> for Polynomial {
    /// Adds the rhs polynomial to the lhs polynomial
    fn add_assign(&mut self, rhs: &Polynomial) {
        for n in 0..std::cmp::max(self.coefficients.len(), rhs.coefficients.len()) {
            if n >= self.coefficients.len() {
                self.coefficients.push(rhs.coefficients[n]);
            } else if n < self.coefficients.len() && n < rhs.coefficients.len() {
                self.coefficients[n] += rhs.coefficients[n];
            }
        }
        self.normalize();
    }
}

impl std::ops::SubAssign<&Polynomial> for Polynomial {
    /// Subtracts the rhs polynomial to the lhs polynomial
    fn sub_assign(&mut self, rhs: &Polynomial) {
        for n in 0..std::cmp::max(self.coefficients.len(), rhs.coefficients.len()) {
            if n >= self.coefficients.len() {
                self.coefficients.push(-rhs.coefficients[n]);
            } else if n < self.coefficients.len() && n < rhs.coefficients.len() {
                self.coefficients[n] -= rhs.coefficients[n];
            }
        }
        self.normalize();
    }
}

impl std::ops::Mul<&Polynomial> for &Polynomial {
    type Output = Polynomial;
    /// Borrows the polynomial and computes the multiplication of the two polynomials
    /// With n the degree of the lhs and m the degree of the rhs. Computed polynomial is of degree
    /// n + m
    fn mul(self, rhs: &Polynomial) -> Self::Output {
        let mut mul: Vec<Scalar> = std::iter::repeat(Scalar::zero())
            .take(self.coefficients.len() + rhs.coefficients.len() - 1)
            .collect();
        for n in 0..self.coefficients.len() {
            for m in 0..rhs.coefficients.len() {
                mul[n + m] += self.coefficients[n] * rhs.coefficients[m];
            }
        }
        let mut res = Polynomial { coefficients: mul };
        res.normalize();
        res
    }
}

impl std::ops::Mul<&Scalar> for &Polynomial {
    type Output = Polynomial;
    /// Multiplies all coefficients of the polynomial by a scalar
    fn mul(self, rhs: &Scalar) -> Self::Output {
        if rhs == &Scalar::zero() {
            Polynomial::zero()
        } else {
            Polynomial {
                coefficients: self
                    .coefficients
                    .iter()
                    .map(|v| v * rhs)
                    .collect::<Vec<_>>(),
            }
        }
    }
}

impl std::ops::Div for Polynomial {
    type Output = (Polynomial, Polynomial);

    /// Computes polynomial division. Result is two polynomials, the quotient and the remainder
    fn div(self, rhs: Polynomial) -> Self::Output {
        assert!(!rhs.is_zero());

        if rhs.degree() > self.degree() {
            return (
                Polynomial {
                    coefficients: vec![Scalar::zero()],
                },
                rhs,
            );
        }
        let mut remainder = self.clone();
        let mut quotient = Polynomial::from_integers(&[]);
        let highest_degree_coeff_inv = rhs.coefficients[rhs.degree()].invert().unwrap();
        let rem_degree = self.degree();
        let div_degree = rhs.degree();
        for i in (div_degree..=rem_degree).rev() {
            if remainder.coefficients[i].is_zero().unwrap_u8() == 1 {
                quotient.coefficients.push(Scalar::zero());
                continue;
            }
            let q = highest_degree_coeff_inv * remainder.coefficients[i];
            for j in 0..div_degree {
                remainder.coefficients[i - div_degree + j] -= rhs.coefficients[j] * q;
            }
            quotient.coefficients.push(q);
        }
        quotient.normalize();
        quotient.coefficients.reverse();
        for _ in div_degree..=rem_degree {
            remainder.coefficients.pop();
        }
        (quotient, remainder)
    }
}

/// Given a set of attributes X' = { x1, x2, ..., xn}
/// Computes the coefficients for the polynomial (X - x1)(X - x2) ... (X - xn)
pub fn compute_polynomial(roots: &Vec<Scalar>) -> Polynomial {
    let mut x_i = Vec::with_capacity(roots.len());
    for root in roots.iter() {
        x_i.push(Polynomial::from_coeffs(&[-root, Scalar::one()]));
    }

    let mut poly = x_i[0].clone();
    for i in x_i.iter().take(roots.len()).skip(1) {
        poly = &poly * i;
    }
    poly
}

#[cfg(test)]
mod test {
    use crate::mercurial_signatures::random_z_star_p;
    use crate::polynomial::Polynomial;
    use bls12_381::Scalar;

    #[test]
    fn test_poly_add() {
        let mut p246 = Polynomial::from_integers(&[1, 2, 3]);
        p246 += &Polynomial::from_integers(&[1, 2, 3]);
        assert_eq!(p246, Polynomial::from_integers(&[2, 4, 6]));

        let mut p24645 = Polynomial::from_integers(&[1, 2, 3]);
        p24645 += &Polynomial::from_integers(&[1, 2, 3, 4, 5]);
        assert_eq!(p24645, Polynomial::from_integers(&[2, 4, 6, 4, 5]));

        let mut p24646 = Polynomial::from_integers(&[1, 2, 3, 4, 6]);
        p24646 += &Polynomial::from_integers(&[1, 2, 3]);
        assert_eq!(p24646, Polynomial::from_integers(&[2, 4, 6, 4, 6]));
    }

    #[test]
    fn test_poly_sub() {
        let mut p0 = Polynomial::from_integers(&[1, 2, 3]);
        p0 -= &Polynomial::from_integers(&[1, 2, 3]);
        assert_eq!(p0, Polynomial::from_integers(&[0]));

        let mut p003 = Polynomial::from_integers(&[1, 2, 3]);
        p003 -= &Polynomial::from_integers(&[1, 2]);
        assert_eq!(p003, Polynomial::from_integers(&[0, 0, 3]));
    }

    #[test]
    fn test_poly_mul() {
        assert_eq!(
            &Polynomial::from_integers(&[6, 10, 0, 5]) * &Polynomial::from_integers(&[4, 2, 1]),
            Polynomial::from_integers(&[24, 52, 26, 30, 10, 5])
        );
        assert_eq!(
            &Polynomial::from_integers(&[2, 1, 0, 7, 3])
                * &Polynomial::from_integers(&[1, 0, 2, 1, 1]),
            Polynomial::from_integers(&[2, 1, 4, 11, 6, 15, 13, 10, 3])
        );
    }

    #[test]
    fn test_div() {
        fn do_test(n: Polynomial, d: Polynomial) {
            let (q, r) = n.clone() / d.clone();
            let mut n2 = &q * &d;
            n2 += &r;
            if n.degree() > d.degree() {
                assert_eq!(n, n2);
            }
        }
        do_test(
            Polynomial::from_integers(&[1]),
            Polynomial::from_integers(&[1, 1]),
        );
        do_test(
            Polynomial::from_integers(&[1, 1]),
            Polynomial::from_integers(&[1, 1]),
        );
        do_test(
            Polynomial::from_integers(&[1, 2, 1]),
            Polynomial::from_integers(&[1, 1]),
        );
        do_test(
            Polynomial::from_integers(&[1, 2, 1, 2, 5, 8, 1, 9]),
            Polynomial::from_integers(&[1, 1, 5, 4]),
        );
        do_test(
            Polynomial::from_integers(&[1, 2, 7, 12, 5, 8, 1, 9]),
            Polynomial::from_integers(&[45, 32, 5, 4]),
        );
    }

    #[test]
    fn evaluate_at_root_give_zero() {
        let att = random_z_star_p();
        let attributes = vec![
            att.clone(),
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
        ];
        let polynomial = Polynomial::from_roots(&attributes);
        let value = polynomial.evaluate_polynomial(&att);
        assert_eq!(value, Scalar::zero());
    }

    #[test]
    fn normalize_polynomial() {
        let mut p1 = Polynomial::from_integers(&vec![1, 0, 0, 0]);
        p1.normalize();
        assert_eq!(p1, Polynomial::from_integers(&vec![1]));
    }

    #[test]
    fn bezout_identity_holds() {
        let p1 = Polynomial::from_roots(&vec![
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
        ]);
        let p2 = Polynomial::from_roots(&vec![
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
        ]);

        let (gcd, q_1, q_2) = Polynomial::extended_gcd(&p1, &p2);
        let mut tmp = &p1 * &q_1;
        tmp += &(&p2 * &q_2);
        assert_eq!(gcd, tmp);
    }
}
