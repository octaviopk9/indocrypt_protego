use crate::mercurial_signatures::random_z_star_p;
use crate::polynomial::*;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use crypto_bigint::U256;

/// Bilinear group generator, order of the curve and generator of both groups
#[derive(Clone)]
pub struct BG {
    _p: U256, //uses crypto_bigint crate to store a 256 bit number
    pub(crate) p1: G1Projective,
    pub(crate) p2: G2Projective,
}

impl BG {
    /// Provides the order of the curve and instantiates the generator of the groups, chosen by the
    /// bls12-381 crate
    pub fn bg_gen() -> BG {
        BG {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            p1: G1Projective::generator(),
            p2: G2Projective::generator(),
        }
    }
}

/// This structure represents all information returned by the commit function. It includes the commit
/// itself and opening information. Depending on the type of opening we have an additional value s'
/// that is represented as Option<> here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitAndOpenInformation {
    pub c: G1Projective,
    pub opening_type: bool,
    pub r: Scalar,
    pub s_prime: Option<Scalar>,
}

/// Setup for commitments and openings on subsets and disjoint sets. The s raised to the power i
/// represented in G1 and G2 are used in polynomial evaluations.
#[derive(Clone)]
pub struct SCDS {
    bg: BG,
    pub(crate) q: usize, //Upper bound for the cardinality of committed sets
    pub(crate) s_i_in_g1: Vec<G1Projective>, //of length q
    pub(crate) s_i_in_g2: Vec<G2Projective>,
    _td: Option<Scalar>, // Scalar is an element in Zp, represents the trapdoor
}

impl SCDS {
    /// Instantiates the bilinear group and s^i in G1 and G2
    pub fn setup(q: usize) -> SCDS {
        let bg = BG::bg_gen();
        let original_s = random_z_star_p();
        let mut s = original_s;
        let mut s_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut s_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_s_in_g1 = bg.p1 * s;
            let new_s_in_g2 = bg.p2 * s;
            s_i_in_g1.push(new_s_in_g1);
            s_i_in_g2.push(new_s_in_g2);
            s *= original_s;
        }
        SCDS {
            bg,
            q,
            s_i_in_g1,
            s_i_in_g2,
            _td: None,
        }
    }
    /// Used in the web prototype to ensure to recreate the public parameters from the random
    /// elements obtained at server launch
    pub fn setup_with_imposed_random(q: usize, original_s: Scalar) -> SCDS {
        let bg = BG::bg_gen();
        let mut s = original_s;
        let mut s_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut s_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_s_in_g1 = bg.p1 * s;
            let new_s_in_g2 = bg.p2 * s;
            s_i_in_g1.push(new_s_in_g1);
            s_i_in_g2.push(new_s_in_g2);
            s *= original_s;
        }
        SCDS {
            bg,
            q,
            s_i_in_g1,
            s_i_in_g2,
            _td: None,
        }
    }
    /// Also returns trapdoor
    #[allow(dead_code)]
    fn t_setup(q: usize) -> SCDS {
        let bg = BG::bg_gen();
        let original_s = random_z_star_p();
        let mut s = original_s;
        let mut s_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut s_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_s_in_g1 = bg.p1 * s;
            let new_s_in_g2 = bg.p2 * s;
            s_i_in_g1.push(new_s_in_g1);
            s_i_in_g2.push(new_s_in_g2);
            s *= original_s;
        }
        SCDS {
            bg,
            q,
            s_i_in_g1,
            s_i_in_g2,
            _td: Some(original_s),
        }
    }

    /// Proofs of exponentiation can be computed by the client to reduce the computations and pairings
    /// done by the server. It consists of a polynomial division and evaluation of the quotient.
    pub fn proof_of_exponentiation(
        &self,
        attributes: &Vec<Scalar>,
        alpha: &Scalar,
    ) -> (G2Projective, G2Projective) {
        let monic_polynomial = Polynomial::from_roots(attributes);
        let q = self.evaluate_monic_polynomial_for_p2(&monic_polynomial);
        let divisor = Polynomial::from_coeffs(&[*alpha, Scalar::one()]);
        let (h_x, _beta) = monic_polynomial / divisor;
        let pi_q = self.evaluate_monic_polynomial_for_p2(&h_x);
        (pi_q, q)
    }

    /*
      Here we consider that true corresponds to the 1 in the reference paper, and false for 0
    */
    /// Commits a set of attributes
    pub fn commit(&self, attributes: &Vec<Scalar>) -> Result<CommitAndOpenInformation, ()> {
        if attributes.len() > self.q {
            return Result::Err(());
        }

        let r = random_z_star_p();
        for s_prime in attributes {
            if self.bg.p1 * s_prime == self.s_i_in_g1[0] {
                let res = CommitAndOpenInformation {
                    c: self.bg.p1 * r,
                    opening_type: true,
                    r,
                    s_prime: Option::Some(*s_prime),
                };
                return Result::Ok(res);
            }
        }

        let evaluated_polynomial = Polynomial::from_roots(attributes);
        let evaluated_point = self.evaluate_monic_polynomial_for_p1(&evaluated_polynomial);
        let res = CommitAndOpenInformation {
            c: evaluated_point * r,
            opening_type: false,
            r,
            s_prime: Option::None,
        };
        Result::Ok(res)
    }

    /// In the first version of commit, the random value is generated during the algorithm and discarded
    /// after. But to obtain a credential we want to commit using the user secret key as the random value
    pub fn commit_with_imposed_randomizer(
        &self,
        attributes: &Vec<Scalar>,
        randomizer: &Scalar,
    ) -> Result<CommitAndOpenInformation, ()> {
        if attributes.len() > self.q {
            return Result::Err(());
        }
        for s_prime in attributes {
            if self.bg.p1 * s_prime == self.s_i_in_g1[0] {
                let res = CommitAndOpenInformation {
                    c: self.bg.p1 * randomizer,
                    opening_type: true,
                    r: *randomizer,
                    s_prime: Option::Some(*s_prime),
                };
                return Result::Ok(res);
            }
        }

        let evaluated_polynomial = Polynomial::from_roots(attributes);
        let evaluated_point = self.evaluate_monic_polynomial_for_p1(&evaluated_polynomial);
        let res = CommitAndOpenInformation {
            c: evaluated_point * randomizer,
            opening_type: false,
            r: *randomizer,
            s_prime: Option::None,
        };
        Result::Ok(res)
    }

    /// Evaluates if the commitment was performed correctly
    pub fn open(
        &self,
        attributes: &Vec<Scalar>,
        opening_information: &CommitAndOpenInformation,
    ) -> bool {
        if opening_information.opening_type
            && self.bg.p1 * opening_information.s_prime.unwrap() == self.s_i_in_g1[0]
        {
            return opening_information.c == self.bg.p1 * opening_information.r;
        }
        let evaluated_polynomial = Polynomial::from_roots(attributes);
        let evaluated_point = self.evaluate_monic_polynomial_for_p1(&evaluated_polynomial);
        opening_information.c == evaluated_point * opening_information.r
    }

    /// Creates an opening on a subset of attributes.
    pub fn open_ss(
        &self,
        attributes: &Vec<Scalar>,
        attributes_subset: &Vec<Scalar>,
        opening_information: &CommitAndOpenInformation,
    ) -> Option<G1Projective> {
        if !self.open(attributes, opening_information) || !is_subset(attributes, attributes_subset)
        {
            return Option::None;
        }
        if opening_information.opening_type
            && !attributes_subset.contains(&opening_information.s_prime.unwrap())
        {
            let polynomial = Polynomial::from_roots(attributes_subset);
            let evaluated_polynomial =
                polynomial.evaluate_polynomial(&opening_information.s_prime.unwrap());
            return Option::Some(opening_information.c * evaluated_polynomial);
        }
        if !opening_information.opening_type {
            let polynomial = Polynomial::from_roots(attributes);
            let subset = Polynomial::from_roots(attributes_subset);
            let (wit_poly, _remainder) = polynomial / subset;
            let witness = self.evaluate_monic_polynomial_for_p1(&wit_poly);
            return Option::Some(witness * opening_information.r);
        }
        Option::None
    }

    /// Verifies that the witness is valid and generated on a subset of user's attributes
    pub fn verify_ss(
        &self,
        commit: &G1Projective,
        subset: &Vec<Scalar>,
        wit: &Option<G1Projective>,
        poe: Option<(G2Projective, G2Projective)>,
        alpha: &Option<Scalar>,
    ) -> bool {
        if subset.is_empty() {
            return true;
        }
        if wit.is_none() {
            return false;
        }
        for element in subset {
            if self.bg.p1 * element == self.s_i_in_g1[0] {
                return wit.is_none();
            }
        }
        let subset_poly = Polynomial::from_roots(subset);
        if poe.is_none() {
            let evaluated_point = self.evaluate_monic_polynomial_for_p2(&subset_poly);
            return pairing(
                &G1Affine::from(&wit.unwrap()),
                &G2Affine::from(&evaluated_point),
            ) == pairing(&G1Affine::from(commit), &G2Affine::from(&self.s_i_in_g2[0]));
        }

        let alpha = alpha.unwrap();
        let (pi_q, q) = (poe.unwrap().0, poe.unwrap().1);
        let divisor = Polynomial::from_coeffs(&[alpha, Scalar::one()]);
        let (_, beta) = subset_poly / divisor;
        let divisor = Polynomial::from_coeffs(&[alpha, Scalar::one()]);
        pairing(
            &G1Affine::from(self.evaluate_monic_polynomial_for_p1(&divisor)),
            &G2Affine::from(pi_q),
        ) + pairing(
            &G1Affine::from(self.evaluate_monic_polynomial_for_p1(&beta)),
            &G2Affine::from(self.s_i_in_g2[0]),
        ) == pairing(&G1Affine::from(self.s_i_in_g1[0]), &G2Affine::from(q))
            && pairing(&G1Affine::from(wit.unwrap()), &G2Affine::from(q))
                == pairing(&G1Affine::from(commit), &G2Affine::from(&self.s_i_in_g2[0]))
    }

    /// Generates an opening on a set of attributes disjoint of attributes owned by the user
    /// It was found that when the polynomial extended GCD computed, the GCD is the GCD multiplied
    /// by a scalar. Thus we have to make it univariate. That's why for the w_0 and w_1 we
    /// multiply them by the inverse of the gcd, which mathematically is 1.
    pub fn open_ds(
        &self,
        attributes: &Vec<Scalar>,
        disjoint_set: &Vec<Scalar>,
        opening_information: &CommitAndOpenInformation,
    ) -> Option<(G2Projective, G1Projective)> {
        if !is_disjoint(attributes, disjoint_set) {
            return Option::None;
        }
        let gamma = random_z_star_p();
        if opening_information.opening_type {
            if disjoint_set.contains(&opening_information.s_prime.unwrap()) {
                return Option::None;
            }
            let w_0 = self.bg.p2 * gamma;
            let w_1 = self.bg.p1;
            return Option::Some((w_0, w_1));
        }
        let attributes_poly = Polynomial::from_roots(attributes);
        let disjoint_poly = Polynomial::from_roots(disjoint_set);
        let (gcd, q_1, q_2) = Polynomial::extended_gcd(&attributes_poly, &disjoint_poly);

        let mut tmp = &attributes_poly * &q_1;
        tmp += &(&disjoint_poly * &q_2);
        assert_eq!(gcd, tmp);

        let mut w_0 = self.evaluate_monic_polynomial_for_p2(&disjoint_poly) * gamma;
        w_0 = self.evaluate_monic_polynomial_for_p2(&q_1) + w_0;
        w_0 *= opening_information.r.invert().unwrap();
        w_0 *= gcd.coefficients[0].invert().unwrap();

        let mut w_1 = self.evaluate_monic_polynomial_for_p1(&attributes_poly) * gamma;
        w_1 = self.evaluate_monic_polynomial_for_p1(&q_2) - w_1;
        w_1 *= gcd.coefficients[0].invert().unwrap();
        Option::Some((w_0, w_1))
    }

    /// Verifies the validity of the witness on the disjoint set of attributes
    /// When programming the pairing it was found that, to make the equation hold we have to
    /// put s² on the right hand side of the equation. It is not an issue since s²P1 and s²P2 are
    /// in the CRS.
    pub fn verify_ds(
        &self,
        commit: &G1Projective,
        disjoint_set: &Vec<Scalar>,
        wit: &Option<(G2Projective, G1Projective)>,
        poe: &Option<(G2Projective, G2Projective)>,
        alpha: &Option<Scalar>,
    ) -> bool {
        if disjoint_set.is_empty() {
            return true;
        }
        if wit.is_none() {
            return false;
        }
        let (w_0, w_1) = wit.unwrap();
        for element in disjoint_set {
            if self.bg.p1 * element == self.s_i_in_g1[0] {
                return wit.is_none();
            }
        }

        let disjoint_poly = Polynomial::from_roots(disjoint_set);
        if poe.is_none() {
            let evaluated_point = self.evaluate_monic_polynomial_for_p2(&disjoint_poly);
            return pairing(&G1Affine::from(commit), &G2Affine::from(w_0))
                + pairing(&G1Affine::from(w_1), &G2Affine::from(evaluated_point))
                == pairing(
                    &G1Affine::from(self.s_i_in_g1[1]),
                    &G2Affine::from(self.bg.p2),
                );
        }

        let alpha = alpha.unwrap();
        let (pi_q, q) = (poe.unwrap().0, poe.unwrap().1);
        let divisor = Polynomial::from_coeffs(&[alpha, Scalar::one()]);
        let (_, beta) = disjoint_poly / divisor;
        let divisor = Polynomial::from_coeffs(&[alpha, Scalar::one()]);
        pairing(
            &G1Affine::from(self.evaluate_monic_polynomial_for_p1(&divisor)),
            &G2Affine::from(pi_q),
        ) + pairing(
            &G1Affine::from(self.evaluate_monic_polynomial_for_p1(&beta)),
            &G2Affine::from(self.s_i_in_g2[0]),
        ) == pairing(&G1Affine::from(self.s_i_in_g1[0]), &G2Affine::from(q))
            && pairing(&G1Affine::from(commit), &G2Affine::from(w_0))
                + pairing(&G1Affine::from(&w_1), &G2Affine::from(&q))
                == pairing(
                    &G1Affine::from(self.s_i_in_g1[1]),
                    &G2Affine::from(self.bg.p2),
                )
    }

    /// For a group generator P, Ch_X(s)P can be efficiently computed (eg,using Fast Fourier Transform)
    /// when given (s^i)P for i=0 to |X| but not s.
    /// Since Ch_X(s)P = sum((c_i * s^i)P) for i=0 to n with n the degree of the monic polynomial.
    pub fn evaluate_monic_polynomial_for_p1(&self, poly: &Polynomial) -> G1Projective {
        let mut res_eval = G1Projective::identity();
        for (i, &coeff) in poly.coefficients.iter().enumerate() {
            res_eval += self.s_i_in_g1[i] * coeff;
        }
        res_eval
    }

    pub fn evaluate_monic_polynomial_for_p2(&self, poly: &Polynomial) -> G2Projective {
        let mut res_eval = G2Projective::identity();
        for (i, &coeff) in poly.coefficients.iter().enumerate() {
            res_eval += self.s_i_in_g2[i] * coeff;
        }
        res_eval
    }
}

/// Verifies  that all elements from subset are also present in the given attributes. Returns true if
/// all elements are contained in attributes. Returns false if any of the conditions fail
/// or if the subset is empty.
fn is_subset(attributes: &[Scalar], subset: &[Scalar]) -> bool {
    for element in subset {
        if !attributes.contains(element) {
            return false;
        }
    }
    !subset.is_empty()
}

/// Verifies that the intersection between attributes and the supposedly disjoint set is void of any
/// elements. Returns true if the two set do not share any element. Returns false if the condition fails
///
/// of if the disjoint set is empty.
fn is_disjoint(attributes: &[Scalar], disjoint_set: &[Scalar]) -> bool {
    for element in disjoint_set {
        if attributes.contains(element) {
            return false;
        }
    }
    !disjoint_set.is_empty()
}

#[cfg(test)]
mod test {
    use super::*;

    /*
      First we setup the crs, generate randomly a set of attributes, commit and we verify the right type
      of opening is used in this scenario
    */
    #[test]
    fn commit_and_open() {
        let scds = SCDS::setup(10);
        let attributes = vec![random_z_star_p(), random_z_star_p(), random_z_star_p()];
        let commit = scds.commit(&attributes);
        assert_eq!(scds.open(&attributes, &commit.unwrap()), true);
    }

    #[test]
    fn remainder_of_subset_div_is_zero() {
        let att_1 = random_z_star_p();
        let att_2 = random_z_star_p();
        let attributes = vec![att_1.clone(), att_2.clone(), random_z_star_p()];
        let subset = vec![att_1.clone(), att_2.clone()];

        let polynomial = Polynomial::from_roots(&attributes);
        let subset = Polynomial::from_roots(&subset);
        let (_wit_poly, remainder) = polynomial / subset;
        assert_eq!(remainder.is_zero(), true);
    }

    /*
        We generate a witness of a right opening of a subset of the attributes. We verify the witness is
        correct according to the complete set of attributes and the CRS.
    */
    #[test]
    fn verify_subset_without_proof_of_exponentiation() {
        let scds = SCDS::setup(10);
        let att_1 = random_z_star_p();
        let att_2 = random_z_star_p();
        let attributes = vec![att_1.clone(), att_2.clone(), random_z_star_p()];
        let commit = scds.commit(&attributes).unwrap();
        let subset = vec![att_1.clone(), att_2.clone()];
        let wit = scds.open_ss(&attributes, &subset, &commit);
        assert_eq!(
            scds.verify_ss(&commit.c, &subset, &wit, Option::None, &None),
            true
        );
    }

    #[test]
    fn verify_subset_with_proof_of_exponentiation() {
        let scds = SCDS::setup(10);
        let att_1 = random_z_star_p();
        let att_2 = random_z_star_p();
        let attributes = vec![att_1.clone(), att_2.clone(), random_z_star_p()];
        let commit = scds.commit(&attributes).unwrap();
        let subset = vec![att_1.clone(), att_2.clone()];
        let wit = scds.open_ss(&attributes, &subset, &commit);
        let alpha = random_z_star_p();
        let proof_of_exponentiation = scds.proof_of_exponentiation(&subset, &alpha);
        assert_eq!(
            scds.verify_ss(
                &commit.c,
                &subset,
                &wit,
                Option::Some(proof_of_exponentiation),
                &Some(alpha)
            ),
            true
        );
    }

    #[test]
    fn verify_disjoint_set_without_proof_of_exponentiation() {
        let scds = SCDS::setup(10);
        let attributes = vec![random_z_star_p(), random_z_star_p(), random_z_star_p()];
        let commit = scds.commit(&attributes).unwrap();
        let disjoint_set = vec![random_z_star_p(), random_z_star_p()];
        let wit = scds.open_ds(&attributes, &disjoint_set, &commit);
        assert_eq!(
            scds.verify_ds(
                &commit.c,
                &disjoint_set,
                &wit,
                &Option::None,
                &Some(random_z_star_p())
            ),
            true
        );
    }

    //Works only if the disjoint set is not co-prime with the attributes, like in the case where it's a
    // subset, which shouldn't
    #[test]
    fn verify_disjoint_set_with_proof_of_exponentiation() {
        let scds = SCDS::setup(10);
        let attributes = vec![
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
            random_z_star_p(),
        ];
        let commit = scds.commit(&attributes).unwrap();
        let disjoint_set = vec![random_z_star_p(), random_z_star_p()];
        let wit = scds.open_ds(&attributes, &disjoint_set, &commit);
        let alpha = random_z_star_p();
        let proof_of_exponentiation = scds.proof_of_exponentiation(&disjoint_set, &alpha);
        assert_eq!(
            scds.verify_ds(
                &commit.c,
                &disjoint_set,
                &wit,
                &Option::Some(proof_of_exponentiation),
                &Some(alpha)
            ),
            true
        );
    }
}
