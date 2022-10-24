use crate::mercurial_signatures::random_z_star_p;
use crate::polynomial::*;
use crate::scds::BG;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
#[derive(Eq, PartialEq, Clone)]
pub struct NonMemberShipWitness {
    pub(crate) point: G2Projective,
    pub(crate) d: Scalar, // remainder of the polynomial division
}

/// This structure contains some elements that are computed and kept updated by the revocation entity
/// throughout the execution of the algorithms. pi_rev and aux_rev are used to compute non membership
/// witnesses
#[derive(Clone)]
pub struct RevocationList {
    pub(crate) pi_rev: G1Projective,
    pub(crate) wit_list: Vec<NonMemberShipWitness>,
    nym_list: Vec<Scalar>,
    pub(crate) aux_rev: Vec<Scalar>,
}

/// All elements necessary and known by the revocation entity. The multiplication of b raised to
/// the power i by generator of G1 and G2 is used for evaluating polynomials without knowing b.
#[derive(Clone)]
pub struct RevocationAccumulator {
    pub(crate) bg: BG,
    pub(crate) q: usize, //Upper bound for the cardinality of committed sets
    pub(crate) b_i_in_g1: Vec<G1Projective>,
    //of length q
    pub b_i_in_g2: Vec<G2Projective>,
    pub b: Scalar,
    pub(crate) rev_list: RevocationList,
}

impl RevocationAccumulator {
    /// Commits on RNYM list and instantiates the list of non membership witnesses for non revoked
    /// witnesses
    #[allow(non_snake_case)]
    fn r_setup(&mut self, rsk: &Scalar, NYM: &Vec<Scalar>, RNYM: Vec<Scalar>) {
        self.commit(RNYM, rsk);
        for nym in NYM {
            self.rev_list
                .wit_list
                .push(self.non_membership_witness(nym).unwrap());
        }
    }

    /// On input of the list of non revoked nym and a given nym. Will either revoke or reverse
    /// the revocation of the nym. Depending on b being respectively true or false.
    #[allow(non_snake_case, dead_code)]
    pub fn revoke(&mut self, NYM: &mut Vec<Scalar>, nym: &Scalar, b: bool, rsk: &Scalar) {
        if b {
            self.rev_list.aux_rev.push(*nym);
            self.add(rsk, nym);
            let index_of_nym = NYM.iter().position(|x| *x == *nym).unwrap();
            NYM.remove(index_of_nym);
        } else {
            let index_of_nym = self.rev_list.aux_rev.iter().position(|x| *x == *nym);
            if index_of_nym.is_some() {
                self.rev_list.aux_rev.remove(index_of_nym.unwrap());
                self.del(rsk, nym);
                NYM.push(*nym);
            }
        }
        self.rev_list.wit_list = vec![];
        for nym in NYM {
            self.rev_list
                .wit_list
                .push(self.non_membership_witness(nym).unwrap());
        }
    }

    /// Fully setups the revocation entity, including the elements necessary for the computation
    /// and also the state of the revocation accumulator, for the (non) revoked nym.
    #[allow(non_snake_case)]
    pub fn full_setup(
        q: usize,
        rsk: &Scalar,
        NYM: &Vec<Scalar>,
        RNYM: Vec<Scalar>,
    ) -> RevocationAccumulator {
        let bg = BG::bg_gen();
        let original_b = random_z_star_p();
        let mut b = original_b;
        let mut b_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut b_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_b_in_g1 = bg.p1 * b;
            let new_b_in_g2 = bg.p2 * b;
            b_i_in_g1.push(new_b_in_g1);
            b_i_in_g2.push(new_b_in_g2);
            b *= original_b;
        }
        let mut accumulator = RevocationAccumulator {
            bg,
            b,
            q,
            b_i_in_g1,
            b_i_in_g2,
            rev_list: RevocationList {
                pi_rev: G1Projective::generator(),
                wit_list: vec![],
                nym_list: NYM.clone(),
                aux_rev: vec![],
            },
        };
        accumulator.r_setup(rsk, NYM, RNYM); //Will instantiate the wit_list and aux_rev
        accumulator
    }
    /// Used in the web prototype to ensure to recreate the public parameters from the random
    /// elements obtained at server launch
    #[allow(non_snake_case)]
    pub fn full_setup_with_imposed_random(
        q: usize,
        rsk: &Scalar,
        NYM: &Vec<Scalar>,
        RNYM: Vec<Scalar>,
        original_b: Scalar,
    ) -> RevocationAccumulator {
        let bg = BG::bg_gen();
        let mut b = original_b;
        let mut b_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut b_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_b_in_g1 = bg.p1 * b;
            let new_b_in_g2 = bg.p2 * b;
            b_i_in_g1.push(new_b_in_g1);
            b_i_in_g2.push(new_b_in_g2);
            b *= original_b;
        }
        let mut accumulator = RevocationAccumulator {
            bg,
            b,
            q,
            b_i_in_g1,
            b_i_in_g2,
            rev_list: RevocationList {
                pi_rev: G1Projective::generator(),
                wit_list: vec![],
                nym_list: NYM.clone(),
                aux_rev: vec![],
            },
        };
        accumulator.r_setup(rsk, NYM, RNYM); //Will instantiate the wit_list and aux_rev
        accumulator
    }

    /// Setups the elements necessary for the computation but does not update the state of the accumulator.
    #[allow(non_snake_case)]
    pub fn setup(q: usize) -> RevocationAccumulator {
        let bg = BG::bg_gen();
        let original_b = random_z_star_p();
        let mut b = original_b;
        let mut b_i_in_g1: Vec<G1Projective> = Vec::with_capacity(q);
        let mut b_i_in_g2: Vec<G2Projective> = Vec::with_capacity(q);
        for _ in 0..q {
            let new_b_in_g1 = bg.p1 * b;
            let new_b_in_g2 = bg.p2 * b;
            b_i_in_g1.push(new_b_in_g1);
            b_i_in_g2.push(new_b_in_g2);
            b *= original_b;
        }
        RevocationAccumulator {
            bg,
            b,
            q,
            b_i_in_g1,
            b_i_in_g2,
            rev_list: RevocationList {
                pi_rev: G1Projective::generator(),
                wit_list: vec![],
                nym_list: vec![],
                aux_rev: vec![],
            },
        }
    }

    /// Updates the pi_rev and aux_rev of the accumulator.
    fn commit(&mut self, roots: Vec<Scalar>, rsk: &Scalar) {
        if roots.len() > self.q {
            panic!("Too much roots provided for curren configuration of accumulator");
        }
        for b_prime in &roots {
            if self.bg.p1 * b_prime == self.b_i_in_g1[0] {
                panic!("Unexpected element in provided roots");
            }
        }

        let polynomial_from_attributes = Polynomial::from_roots(&roots);
        let evaluated_polynomial =
            self.evaluate_monic_polynomial_for_p1(&polynomial_from_attributes);
        let res = evaluated_polynomial * rsk;
        self.rev_list.pi_rev = res;
        self.rev_list.aux_rev = roots;
    }

    /// Computes the non membership witness for the given nym considering actual state of the
    /// accumulator. Will fail and result in None if the nym is revoked.
    pub fn non_membership_witness(&self, nym: &Scalar) -> Option<NonMemberShipWitness> {
        if self.rev_list.aux_rev.contains(nym) {
            return None;
        }
        let divisor = Polynomial::from_coeffs(&[self.b, *nym]);
        let polynomial_from_attributes = Polynomial::from_roots(&self.rev_list.aux_rev);
        let (q_x, d) = polynomial_from_attributes / divisor;
        let evaluated_point = self.evaluate_monic_polynomial_for_p2(&q_x);
        let wit = NonMemberShipWitness {
            point: evaluated_point,
            d: d.coefficients[d.degree()], //divisor should consist of only one element
        };
        Some(wit)
    }

    /// Goes through the list of non-revoked nyms and accesses the corresponding witness
    pub fn get_witness(&self, nym: &Scalar) -> Option<NonMemberShipWitness> {
        if self.rev_list.nym_list.contains(nym) {
            let index_of_nym = self.rev_list.nym_list.iter().position(|&x| x == *nym);
            return Some(self.rev_list.wit_list[index_of_nym.unwrap()].clone());
        }
        None
    }

    /// Verifies the witness is valid for input nym
    pub fn verify_witness(
        &self,
        nym: &Scalar,
        witness: &NonMemberShipWitness,
        rpk: &G2Projective,
    ) -> bool {
        let (wit_1, wit_2) = (witness.point, witness.d);
        let first_pairing = pairing(&G1Affine::from(self.rev_list.pi_rev), &G2Affine::from(rpk));
        let second_pairing = pairing(
            &G1Affine::from(
                self.evaluate_monic_polynomial_for_p1(&Polynomial::from_coeffs(&[self.b, *nym])),
            ),
            &G2Affine::from(wit_1),
        );
        let third_pairing = pairing(
            &G1Affine::from(self.b_i_in_g1[0] * wit_2),
            &G2Affine::from(self.b_i_in_g2[0]),
        );
        first_pairing.eq(&(second_pairing + third_pairing))
    }

    /// Verifies the witness is valid for input nym and randomized accumulator state
    pub fn verify_witness_randomized(
        &self,
        pi_rev_prime: G1Projective,
        c_4: G1Projective,
        witness: &NonMemberShipWitness,
        rpk: &G2Projective,
    ) -> bool {
        let (wit_1, wit_2) = (witness.point, witness.d);
        let first_pairing = pairing(&G1Affine::from(pi_rev_prime), &G2Affine::from(rpk));
        let second_pairing = pairing(&G1Affine::from(c_4), &G2Affine::from(wit_1));
        let third_pairing = pairing(
            &G1Affine::from(self.b_i_in_g1[0] * wit_2),
            &G2Affine::from(self.b_i_in_g2[0]),
        );
        first_pairing.eq(&(second_pairing + third_pairing))
    }

    /// Adds a nym to aux_rev
    pub fn add(&mut self, rsk: &Scalar, nym: &Scalar) {
        self.rev_list.aux_rev.push(*nym);
        self.commit(self.rev_list.aux_rev.clone(), rsk)
    }

    /// Deletes a nym from aux_rev
    pub fn del(&mut self, rsk: &Scalar, nym: &Scalar) {
        //Finds first occurrence of nym in the vector and deletes it
        let index_of_nym = self.rev_list.aux_rev.iter().position(|x| x == nym).unwrap();
        self.rev_list.aux_rev.remove(index_of_nym);
        self.commit(self.rev_list.aux_rev.clone(), rsk);
    }

    /// For a group generator P, Ch_X(s)P can be efficiently computed (eg,using Fast Fourier Transform)
    /// when given (s^i)P for i=0 to |X| but not s.
    /// Since Ch_X(s)P = sum((c_i * s^i)P) for i=0 to n with n the degree of the monic polynomial.
    pub fn evaluate_monic_polynomial_for_p1(&self, poly: &Polynomial) -> G1Projective {
        let mut res_eval = G1Projective::identity();
        for (i, &coeff) in poly.coefficients.iter().enumerate() {
            res_eval += self.b_i_in_g1[i] * coeff;
        }
        res_eval
    }

    pub fn evaluate_monic_polynomial_for_p2(&self, poly: &Polynomial) -> G2Projective {
        let mut res_eval = G2Projective::identity();
        for (i, &coeff) in poly.coefficients.iter().enumerate() {
            res_eval += self.b_i_in_g2[i] * coeff;
        }
        res_eval
    }
}

#[cfg(test)]
mod test {
    use crate::mercurial_signatures::random_z_star_p;
    use crate::revocation_accumulator::RevocationAccumulator;

    #[test]
    #[allow(non_snake_case)]
    fn revocation_test() {
        let rsk = random_z_star_p();
        let nym_1 = random_z_star_p();
        let nym_2 = random_z_star_p();
        let nym_3 = random_z_star_p();
        let nym_4 = random_z_star_p();
        let NYM = vec![nym_3.clone()];
        let RNYM = vec![nym_1.clone(), nym_2.clone(), nym_4.clone()];
        let accumulator = RevocationAccumulator::full_setup(10, &rsk, &NYM, RNYM);
        let rpk = accumulator.b_i_in_g2[0] * rsk.invert().unwrap();
        let non_mem_wit = accumulator.non_membership_witness(&nym_3).unwrap();
        assert_eq!(accumulator.verify_witness(&nym_3, &non_mem_wit, &rpk), true);
    }

    #[test]
    #[should_panic]
    #[allow(non_snake_case)]
    fn revocation_after_adding_should_fail() {
        let rsk = random_z_star_p();
        let nym_1 = random_z_star_p();
        let nym_2 = random_z_star_p();
        let nym_3 = random_z_star_p();
        let nym_4 = random_z_star_p();
        let NYM = vec![nym_3.clone()];
        let RNYM = vec![nym_1.clone(), nym_2.clone(), nym_4.clone()];
        let mut accumulator = RevocationAccumulator::full_setup(10, &rsk, &NYM, RNYM);
        let rpk = accumulator.b_i_in_g2[0] * rsk.invert().unwrap();

        accumulator.add(&rsk, &nym_3);

        let non_mem_wit = accumulator.non_membership_witness(&nym_3).unwrap();
        assert_eq!(
            accumulator.verify_witness(&nym_3, &non_mem_wit, &rpk),
            false
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn revocation_after_adding_and_deleting() {
        let rsk = random_z_star_p();
        let nym_1 = random_z_star_p();
        let nym_2 = random_z_star_p();
        let nym_3 = random_z_star_p();
        let nym_4 = random_z_star_p();
        let NYM = vec![nym_3.clone()];
        let RNYM = vec![nym_1.clone(), nym_2.clone(), nym_4.clone()];
        let mut accumulator = RevocationAccumulator::full_setup(10, &rsk, &NYM, RNYM);
        let rpk = accumulator.b_i_in_g2[0] * rsk.invert().unwrap();

        accumulator.add(&rsk, &nym_3);
        accumulator.del(&rsk, &nym_3);

        let non_mem_wit = accumulator.non_membership_witness(&nym_3).unwrap();
        assert_eq!(accumulator.verify_witness(&nym_3, &non_mem_wit, &rpk), true);
    }
}
