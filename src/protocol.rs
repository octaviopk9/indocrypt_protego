use crate::key_gen::{
    AuthorityKey, OrganisationKey, Protego, RevocationAccumulatorKey, UserKey, VerifierKey,
};
use crate::mercurial_signatures::random_z_star_p;
use crate::polynomial::Polynomial;
use crate::revocation_accumulator::{NonMemberShipWitness, RevocationAccumulator};
use crate::{
    digest_into_scalar, Auditing, CommitAndOpenInformation, EncryptedKey, ExtProof,
    MercurialSignature, MercurialSignatureBis, MercurialSignatureScheme, Proof, Scalar, CRS, SCDS,
};
use blake3::Hash;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};

/// The credential is returned at the end of the obtain algorithm. The C1 is contained in the commitment
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub commitment: CommitAndOpenInformation, //C1 + O
    pub c_4: G1Projective,                    //C2
    pub c_5: G1Projective,                    //C3
    pub signature: MercurialSignature,
    pub r_4: Scalar,
    pub nym: Scalar,
}

/// In order to test the protocol without involving the overhead of network communications and
/// hardware differences we consider a entity that simulates all the parties in the protocol.
/// This structure knows all the keys, including the secret ones and owns the CRS.
#[allow(dead_code)]
#[derive(Clone)]
pub struct MockProtocol {
    pub pp: Protego,
    pub authority_key: AuthorityKey,
    pub user_key: UserKey,
    pub revocation_key: RevocationAccumulatorKey,
    pub org_key: OrganisationKey,
    pub signer_hiding: CRS,
    pub verifier_key: Option<VerifierKey>,
}

/// We decided to encapsulate all the elements returned at the end of the showing to avoid confusion
/// by giving a namespace to these elements.
#[allow(dead_code)]
pub struct Omega {
    enc: Option<EncryptedKey>,
    t_1: G2Projective,
    t_2: G2Projective,
    t_3: G2Projective,
    opk_prime: [G2Projective; PKSIZE],
    message_prime: Vec<G1Projective>,
    signature_prime: MercurialSignature,
    subset_witness: Option<G1Projective>,
    disjoint_witness: Option<(G2Projective, G1Projective)>,
    rev_wit_prime: Option<NonMemberShipWitness>,
    pi_rev_prime: Option<G1Projective>,
    pi_one: Option<Proof>, //In the first version, using a signer hiding NIZK
    verifier_signature: Option<MercurialSignatureBis>, //In version 2 where the user randomizes consistently the signature and opk
    pi_two: Option<(Scalar, Scalar, Scalar)>,
    poe_one: Option<(G2Projective, G2Projective)>,
    poe_two: Option<(G2Projective, G2Projective)>,
    a_1: G1Projective,
    a_2: G1Projective,
    a_3: G1Projective,
    a_4: G1Projective,
    a_5: G1Projective,
    z_1: Scalar,
    z_2: Scalar,
    z_3: Scalar,
    z_4: Scalar,
    z_5: Scalar,
}

/// Signature length
const PKSIZE: usize = 7;

#[allow(dead_code, non_snake_case)]
impl MockProtocol {
    /// Setup the public parameters but doesn't instantiate the revoked nyms
    pub fn setup(scds_len: usize, rev_acc_len: usize) -> Self {
        let pp = Protego::setup(scds_len, rev_acc_len);
        let authority_key = pp.aak_gen();
        let user_key = pp.uk_gen();
        let revocation_key = pp.rak_gen();
        let org_key = pp.ok_gen();
        let signer_hiding = CRS::PGen();
        let verifier_key = pp.vk_gen();

        MockProtocol {
            pp,
            authority_key,
            user_key,
            revocation_key,
            org_key,
            signer_hiding,
            verifier_key: Some(verifier_key),
        }
    }

    /// Fully instantiates the public parameters and keys. Includes the revocation elements as well
    /// as the organisation keys that are took from a set of organisation key.
    #[allow(clippy::too_many_arguments)]
    pub fn full_setup_with_imposed_randomized(
        scds_len: usize,
        rev_acc_len: usize,
        NYM: &Vec<Scalar>,
        RNYM: Vec<Scalar>,
        osk: &[Scalar],
        opk: &[G2Projective],
        verifier_sk: [Scalar; 7],
        random_elements: [Scalar; 8],
    ) -> Self {
        let mut pp = Protego::setup_with_imposed_random(scds_len, rev_acc_len, random_elements[0]);
        let authority_key = Protego::aak_gen_with_imposed_random(random_elements[1]);
        let user_key = Protego::uk_gen_with_imposed_random(random_elements[2], random_elements[3]);
        let mut revocation_key = pp.rak_gen_with_imposed_random(random_elements[4]);

        let signer_hiding = CRS::PGen_with_imposed_random(random_elements[5]);
        let org_key = OrganisationKey {
            osk: osk.to_owned(),
            opk: opk.to_owned(),
        };

        let vsk = verifier_sk.to_vec();
        let mut vpk = vec![];
        for i in &vsk {
            vpk.push(G1Projective::generator() * i);
        }
        let verifier_key = VerifierKey { vsk, vpk };

        pp.scds_pp = SCDS::setup_with_imposed_random(scds_len, random_elements[6]);

        pp.revocation_pp = RevocationAccumulator::full_setup_with_imposed_random(
            rev_acc_len,
            &revocation_key.rsk,
            NYM,
            RNYM,
            random_elements[7],
        );
        let rpk = pp.revocation_pp.b_i_in_g2[0] * revocation_key.rsk.invert().unwrap();
        revocation_key.rpk = rpk;

        MockProtocol {
            pp,
            authority_key,
            user_key,
            revocation_key,
            org_key,
            signer_hiding,
            verifier_key: Some(verifier_key),
        }
    }

    pub fn full_setup(
        scds_len: usize,
        rev_acc_len: usize,
        NYM: &Vec<Scalar>,
        RNYM: Vec<Scalar>,
        osk: &Vec<Scalar>,
        opk: &Vec<G2Projective>,
    ) -> Self {
        let mut pp = Protego::setup(scds_len, rev_acc_len);
        let authority_key = pp.aak_gen();
        let user_key = pp.uk_gen();
        let mut revocation_key = pp.rak_gen();
        let signer_hiding = CRS::PGen();
        let org_key = OrganisationKey {
            osk: osk.to_owned(),
            opk: opk.to_owned(),
        };
        let verifier_key = pp.vk_gen();

        pp.revocation_pp =
            RevocationAccumulator::full_setup(rev_acc_len, &revocation_key.rsk, NYM, RNYM);
        let rpk = pp.revocation_pp.b_i_in_g2[0] * revocation_key.rsk.invert().unwrap();
        revocation_key.rpk = rpk;

        MockProtocol {
            pp,
            authority_key,
            user_key,
            revocation_key,
            org_key,
            signer_hiding,
            verifier_key: Some(verifier_key),
        }
    }

    /// On user request, given a set of attributes and a nym requests for a credential
    pub fn obtain(&self, attributes: &Vec<Scalar>, nym: &Scalar) -> Credential {
        let p1 = G1Projective::generator();
        let r_1 = random_z_star_p();
        let r_2 = random_z_star_p();
        let r_3 = random_z_star_p();
        let a_1 = p1 * r_1;
        let a_2 = p1 * r_2;
        let a_3 = self.pp.Q * r_3;

        let c_4 = self
            .pp
            .revocation_pp
            .evaluate_monic_polynomial_for_p1(&Polynomial::from_coeffs(&[
                self.pp.revocation_pp.b,
                *nym,
            ]))
            * self.user_key.usk_2;
        let c_5 = self.pp.Q * self.user_key.usk_2;
        let e = self.hash_elements_in_obtain_and_issue(&a_1, &a_2, &a_3, &c_5);

        let z_1 = r_1 + e * self.user_key.usk_1;
        let z_2 = r_2 + e * self.user_key.usk_2;
        let z_3 = r_3 + e * self.user_key.usk_2;
        let commitment = self
            .pp
            .scds_pp
            .commit_with_imposed_randomizer(attributes, &self.user_key.usk_1)
            .unwrap();

        let r_4 = random_z_star_p();
        let c_2 = commitment.c * r_4;

        let sigma = (commitment.c, c_2, c_4, c_5, a_1, a_2, a_3, z_1, z_2, z_3);
        let signature = self.issue(attributes, nym, &sigma).unwrap();
        let message = vec![
            commitment.c,
            c_2,
            p1,
            c_4,
            c_5,
            self.user_key.upk_1,
            self.authority_key.apk,
        ];
        assert!(
            self.pp
                .signature_pp
                .verify(&self.org_key.opk, &message, &signature));
        Credential {
            commitment,
            c_4,
            c_5,
            signature,
            r_4,
            nym: *nym,
        }
    }

    /// After verification of the validity of the user sent informations signs the message which
    /// will become part of the credential
    pub fn issue(
        &self,
        attributes: &Vec<Scalar>,
        nym: &Scalar,
        sigma: &(
            G1Projective,
            G1Projective,
            G1Projective,
            G1Projective,
            G1Projective,
            G1Projective,
            G1Projective,
            Scalar,
            Scalar,
            Scalar,
        ),
    ) -> Result<MercurialSignature, ()> {
        let p1 = G1Projective::generator();
        let (c_1, c_2, c_4, c_5, a_1, a_2, a_3, z_1, z_2, z_3) = sigma;
        let e = self.hash_elements_in_obtain_and_issue(a_1, a_2, a_3, c_5);

        assert_eq!(p1 * z_1, (a_1 + (self.user_key.upk_1 * e)));
        assert_eq!(p1 * z_2, (a_2 + (self.user_key.upk_2 * e)));
        assert_eq!(self.pp.Q * z_3, (a_3 + (c_5 * e)));

        let pairing_1 = pairing(&G1Affine::from(c_1), &G2Affine::generator());
        let pairing_2 = pairing(
            &G1Affine::from(self.user_key.upk_1),
            &G2Affine::from(
                self.pp
                    .scds_pp
                    .evaluate_monic_polynomial_for_p2(&Polynomial::from_roots(attributes)),
            ),
        );
        if pairing_1.ne(&pairing_2) {
            let mut test = false;
            for i in attributes {
                if p1 * i == self.pp.scds_pp.s_i_in_g1[0] {
                    test = true
                }
            }
            if test {
                return Err(());
            }
        }

        let pairing_3 = pairing(&G1Affine::from(c_4), &G2Affine::generator());
        let pairing_4 = pairing(
            &G1Affine::from(self.user_key.upk_2),
            &G2Affine::from(self.pp.revocation_pp.evaluate_monic_polynomial_for_p2(
                &Polynomial::from_coeffs(&[self.pp.revocation_pp.b, *nym]),
            )),
        );

        if pairing_3.ne(&pairing_4) {
            return Err(());
        }
        let message = vec![
            *c_1,
            *c_2,
            p1,
            *c_4,
            *c_5,
            self.user_key.upk_1,
            self.authority_key.apk,
        ];
        let signature = self.pp.signature_pp.sign(&self.org_key.osk, &message);
        Result::Ok(signature)
    }

    /// Performs a showing of the credential, either for a subset commit or a disjoint set one
    /// Showing is complete and includes revocation, auditing components while remaining hiding
    /// tx is the hash of a transaction to bound the showing and a transaction
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &self,
        mut cred: Credential,
        attributes: &Vec<Scalar>,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        pi: &ExtProof,
        tx: &Hash,
        nym: &Scalar,
        rho: &Scalar,
        gamma: &Scalar,
        poe: bool,
        revocation: bool,
        audit: bool,
    ) -> (Omega, Vec<[G2Projective; PKSIZE]>) {
        let p1 = G1Projective::generator();
        //Initialisation of random values
        let alpha = random_z_star_p();
        let beta = random_z_star_p();
        let mu = random_z_star_p();
        let tau = random_z_star_p();
        let r_1 = random_z_star_p();
        let r_2 = random_z_star_p();
        let r_3 = random_z_star_p();
        let r_4 = random_z_star_p();
        let r_5 = random_z_star_p();
        //End of random draws
        let message = vec![
            cred.commitment.c,
            cred.commitment.c * cred.r_4,
            p1,
            cred.c_4,
            cred.c_5,
            self.user_key.upk_1,
            self.authority_key.apk,
        ];
        //Both message prime and signature_prime compose the credential prime

        let rand = alpha * rho + beta * gamma;
        let (message_prime, signature_prime) =
            MercurialSignatureScheme::change_rep(&message, &cred.signature, &mu, &rand);

        let pi_1 = self.signer_hiding.ZKEval(pi, alpha, beta, org_keys.len());

        let opk_randomized = MercurialSignatureScheme::convert_pk(&self.org_key.opk, &rand);
        let mut opk_prime: [G2Projective; PKSIZE] = Default::default();
        opk_prime.copy_from_slice(&opk_randomized.as_slice()[0..]);

        cred.commitment.r *= mu;
        cred.commitment.c *= mu;
        let subset_witness = self
            .pp
            .scds_pp
            .open_ss(attributes, subset, &cred.commitment);
        let disjoint_witness = self
            .pp
            .scds_pp
            .open_ds(attributes, disjoint, &cred.commitment);
        let mut revocation_witness = None;
        let mut rev_wit_prime = None;
        //If revocation is required, will fetch the non-membership witness or compute it
        if revocation {
            revocation_witness = self.pp.revocation_pp.get_witness(nym);
            if revocation_witness.is_none() {
                revocation_witness = self.pp.revocation_pp.non_membership_witness(nym);
            }
            rev_wit_prime = Some(NonMemberShipWitness {
                point: revocation_witness.as_ref().unwrap().point * tau,
                d: revocation_witness.as_ref().unwrap().d * self.user_key.usk_2 * mu * tau,
            });
        }
        let a_1 = message_prime[0] * r_1;
        let a_2 = p1 * r_2;
        let a_3 = self.pp.revocation_pp.rev_list.pi_rev * r_3;
        let a_4 = self.pp.Q * r_4;
        let a_5 = p1 * r_5;
        let tmp = self.user_key.usk_2 * mu * tau;
        let mut pi_rev_prime: Option<G1Projective> = None;
        if revocation {
            pi_rev_prime = Some(self.pp.revocation_pp.rev_list.pi_rev * tmp);
        }
        let t_1 = G2Projective::generator() * beta;
        let tmp = beta * mu;
        let t_2 = G2Projective::generator() * tmp;

        let mut t_3 = G2Projective::generator();
        let mut pi_2: Option<(Scalar, Scalar, Scalar)> = None;
        let enc: Option<EncryptedKey> = None;
        //If audit is required, compute the audit proof and t_3
        if audit {
            let (enc, alpha) = Auditing::audit_enc(&self.user_key, &self.authority_key);
            let tmp = beta * alpha;
            t_3 = G2Projective::generator() * tmp;
            pi_2 = Some(Auditing::audit_prv(
                &enc,
                &alpha,
                &self.user_key,
                &self.authority_key,
            ));
        }
        let e = self.hash_elements_in_showing_and_verification(
            subset,
            disjoint,
            org_keys,
            tx,
            &pi_1,
            &message_prime,
            &signature_prime,
            &mut opk_prime,
            &a_1,
            &a_2,
            &a_3,
            &a_4,
            &a_5,
            &t_1,
            &t_2,
            &t_3,
        );

        let z_1 = r_1 + e * cred.r_4;
        let z_2 = r_2 + e * mu;
        let z_3 = r_3 + e * (self.user_key.usk_2 * mu * tau);
        let z_4 = r_4 + e * (self.user_key.usk_2 * mu);
        //Additionnal component, if revocation is not used, pairing and equalities including z_5 are not performed
        let mut z_5 = Scalar::zero();
        if revocation {
            z_5 = r_5 + e * (self.user_key.usk_2 * mu * tau * revocation_witness.unwrap().d);
        }
        let mut poe_1 = None;
        let mut poe_2 = None;
        if poe {
            if !subset.is_empty() {
                poe_1 = Some(self.pp.scds_pp.proof_of_exponentiation(subset, &e));
            }
            if !disjoint.is_empty() {
                poe_2 = Some(self.pp.scds_pp.proof_of_exponentiation(disjoint, &e));
            }
        }
        let omega = Omega {
            enc,
            t_1,
            t_2,
            t_3,
            opk_prime,
            message_prime,
            signature_prime,
            subset_witness,
            disjoint_witness,
            rev_wit_prime,
            pi_rev_prime,
            pi_one: Some(pi_1),
            verifier_signature: None,
            pi_two: pi_2,
            poe_one: poe_1,
            poe_two: poe_2,
            a_1,
            a_2,
            a_3,
            a_4,
            a_5,
            z_1,
            z_2,
            z_3,
            z_4,
            z_5,
        };
        (omega, org_keys.clone())
    }

    /// The verifier performs validity checks on the showing results
    pub fn verify(
        &mut self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        tx: &Hash,
        omega: &mut Omega,
    ) -> bool {
        let mut test = true;
        let (c_1, c_2, c_3, c_4, c_5, c_6, c_7) = (
            omega.message_prime[0],
            omega.message_prime[1],
            omega.message_prime[2],
            omega.message_prime[3],
            omega.message_prime[4],
            omega.message_prime[5],
            omega.message_prime[6],
        );
        let e = self.hash_elements_in_showing_and_verification(
            subset,
            disjoint,
            org_keys,
            tx,
            omega.pi_one.as_ref().unwrap(),
            &omega.message_prime,
            &omega.signature_prime,
            &mut omega.opk_prime,
            &omega.a_1,
            &omega.a_2,
            &omega.a_3,
            &omega.a_4,
            &omega.a_5,
            &omega.t_1,
            &omega.t_2,
            &omega.t_3,
        );
        if !((c_1 * omega.z_1 == omega.a_1 + (c_2 * e))
            || (G1Projective::generator() * omega.z_2 == omega.a_2 + (c_3 * e))
            || (self.pp.Q * omega.z_4 == omega.a_4 + (c_5 * e)))
        {
            test = false;
        }
        // Checks if revocation was performed in the showing proof
        if omega.pi_rev_prime.is_some() {
            if !(self.pp.revocation_pp.rev_list.pi_rev * omega.z_3
                == omega.a_3 + (omega.pi_rev_prime.unwrap() * e)
                || (G1Projective::generator() * omega.z_5
                    == omega.a_5
                        + (G1Projective::generator()
                            * (omega.rev_wit_prime.as_ref().unwrap().d * e))))
            {
                test = false;
            }
            if !(self.pp.revocation_pp.verify_witness_randomized(
                omega.pi_rev_prime.unwrap(),
                c_4,
                omega.rev_wit_prime.as_ref().unwrap(),
                &self.revocation_key.rpk,
            )) {
                test = false;
            }
        }
        // Checks if audit was performed in the showing proof
        if omega.enc.is_some() {
            let pi_two = &omega.pi_two.unwrap();
            if !(Auditing::audit_verify(
                &self.authority_key,
                omega.enc.as_ref().unwrap(),
                &pi_two.0,
                &pi_two.1,
                &pi_two.2,
            )) {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_1),
                &G2Affine::from(&omega.t_2),
            ) == (pairing(&G1Affine::from(c_6), &G2Affine::from(&omega.t_1))
                + pairing(&G1Affine::from(c_7), &G2Affine::from(&omega.t_3))))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_2),
            ) == pairing(&G1Affine::from(c_3), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_1),
            ) == pairing(&G1Affine::generator(), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
        }
        if !(self.signer_hiding.PRVer(
            org_keys,
            &omega.opk_prime,
            omega.pi_one.as_ref().unwrap(),
            org_keys.len(),
        )) {
            test = false;
        }
        if !(self.pp.signature_pp.verify(
            omega.opk_prime.as_ref(),
            &omega.message_prime,
            &omega.signature_prime,
        )) {
            test = false;
        }
        if !(self.pp.scds_pp.verify_ss(
            &c_1,
            subset,
            &omega.subset_witness,
            omega.poe_one,
            &Some(e),
        )) {
            test = false;
        }

        if !(self.pp.scds_pp.verify_ds(
            &c_1,
            disjoint,
            &omega.disjoint_witness,
            &omega.poe_two,
            &Some(e),
        )) {
            test = false;
        }
        test
    }

    /// Full showing, signer hiding done by randomizing issuer access policy
    #[allow(clippy::too_many_arguments)]
    pub fn show_no_nizk(
        &self,
        mut cred: Credential,
        attributes: &Vec<Scalar>,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        verifier_access_policy: &[MercurialSignatureBis], //Verifier signed org_keys
        tx: &Hash,
        nym: &Scalar,
        index: i32,
        poe: bool,
        revocation: bool,
        audit: bool,
    ) -> (Omega, Vec<[G2Projective; PKSIZE]>) {
        let p1 = G1Projective::generator();
        //Initialisation of random values
        let beta = random_z_star_p();
        let mu = random_z_star_p();
        let rho = random_z_star_p();
        let tau = random_z_star_p();
        let r_1 = random_z_star_p();
        let r_2 = random_z_star_p();
        let r_3 = random_z_star_p();
        let r_4 = random_z_star_p();
        let r_5 = random_z_star_p();
        //End of random draws
        let message = vec![
            cred.commitment.c,
            cred.commitment.c * cred.r_4,
            p1,
            cred.c_4,
            cred.c_5,
            self.user_key.upk_1,
            self.authority_key.apk,
        ];
        //Both message prime and signature_prime compose the credential prime
        let (message_prime, signature_prime) =
            MercurialSignatureScheme::change_rep(&message, &cred.signature, &mu, &rho);

        let opk_randomized = MercurialSignatureScheme::convert_pk(&self.org_key.opk, &rho);
        let mut opk_prime: [G2Projective; PKSIZE] = Default::default();
        opk_prime.copy_from_slice(&opk_randomized.as_slice()[0..]);

        //Difference from version with NIZK
        let issuer_signature_randomized = MercurialSignatureScheme::convert_sig_bis(
            &verifier_access_policy[index as usize],
            &rho,
        );
        cred.commitment.r *= mu;
        cred.commitment.c *= mu;
        let subset_witness = self
            .pp
            .scds_pp
            .open_ss(attributes, subset, &cred.commitment);
        let disjoint_witness = self
            .pp
            .scds_pp
            .open_ds(attributes, disjoint, &cred.commitment);
        let mut revocation_witness = None;
        let mut rev_wit_prime = None;
        // If revocation is required, fetches or compute the non-membership witness
        if revocation {
            revocation_witness = self.pp.revocation_pp.get_witness(nym);
            if revocation_witness.is_none() {
                revocation_witness = self.pp.revocation_pp.non_membership_witness(nym);
            }
            rev_wit_prime = Some(NonMemberShipWitness {
                point: revocation_witness.as_ref().unwrap().point * tau,
                d: revocation_witness.as_ref().unwrap().d * self.user_key.usk_2 * mu * tau,
            });
        }
        let a_1 = message_prime[0] * r_1;
        let a_2 = p1 * r_2;
        let a_3 = self.pp.revocation_pp.rev_list.pi_rev * r_3;
        let a_4 = self.pp.Q * r_4;
        let a_5 = p1 * r_5;
        let tmp = self.user_key.usk_2 * mu * tau;
        let mut pi_rev_prime: Option<G1Projective> = None;
        if revocation {
            pi_rev_prime = Some(self.pp.revocation_pp.rev_list.pi_rev * tmp);
        }
        let t_1 = G2Projective::generator() * beta;
        let tmp = beta * mu;
        let t_2 = G2Projective::generator() * tmp;

        let mut t_3 = G2Projective::generator();
        let mut pi_2: Option<(Scalar, Scalar, Scalar)> = None;
        let enc: Option<EncryptedKey> = None;
        // if audit is required compute the auditing proof
        if audit {
            let (enc, alpha) = Auditing::audit_enc(&self.user_key, &self.authority_key);
            let tmp = beta * alpha;
            t_3 = G2Projective::generator() * tmp;
            pi_2 = Some(Auditing::audit_prv(
                &enc,
                &alpha,
                &self.user_key,
                &self.authority_key,
            ));
        }

        let e = self.hash_elements_in_showing_and_verification_without_nizk(
            subset,
            disjoint,
            org_keys,
            tx,
            &issuer_signature_randomized,
            &message_prime,
            &signature_prime,
            &mut opk_prime,
            &a_1,
            &a_2,
            &a_3,
            &a_4,
            &a_5,
            &t_1,
            &t_2,
            &t_3,
        );

        let z_1 = r_1 + e * cred.r_4;
        let z_2 = r_2 + e * mu;
        let z_3 = r_3 + e * (self.user_key.usk_2 * mu * tau);
        let z_4 = r_4 + e * (self.user_key.usk_2 * mu);
        //If revocation is not used z_5 is not verified against any other pairing
        let mut z_5 = Scalar::zero();
        if revocation {
            z_5 =
                r_5 + e * (self.user_key.usk_2 * mu * tau * revocation_witness.as_ref().unwrap().d);
        }
        let mut poe_1 = None;
        let mut poe_2 = None;
        if poe {
            if !subset.is_empty() {
                poe_1 = Some(self.pp.scds_pp.proof_of_exponentiation(subset, &e));
            }
            if !disjoint.is_empty() {
                poe_2 = Some(self.pp.scds_pp.proof_of_exponentiation(disjoint, &e));
            }
        }
        let omega = Omega {
            enc,
            t_1,
            t_2,
            t_3,
            opk_prime,
            message_prime,
            signature_prime,
            subset_witness,
            disjoint_witness,
            rev_wit_prime,
            pi_rev_prime,
            pi_one: None,
            verifier_signature: Some(issuer_signature_randomized),
            pi_two: pi_2,
            poe_one: poe_1,
            poe_two: poe_2,
            a_1,
            a_2,
            a_3,
            a_4,
            a_5,
            z_1,
            z_2,
            z_3,
            z_4,
            z_5,
        };
        (omega, org_keys.clone())
    }

    /// Verification of a showing, signer hiding done by randomizing issuer access policy
    pub fn verify_no_nizk(
        &mut self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        tx: &Hash,
        omega: &mut Omega,
        vpk: &[G1Projective],
    ) -> bool {
        let mut test = true;
        let (c_1, c_2, c_3, c_4, c_5, c_6, c_7) = (
            omega.message_prime[0],
            omega.message_prime[1],
            omega.message_prime[2],
            omega.message_prime[3],
            omega.message_prime[4],
            omega.message_prime[5],
            omega.message_prime[6],
        );
        let e = self.hash_elements_in_showing_and_verification_without_nizk(
            subset,
            disjoint,
            org_keys,
            tx,
            omega.verifier_signature.as_ref().unwrap(),
            &omega.message_prime,
            &omega.signature_prime,
            &mut omega.opk_prime,
            &omega.a_1,
            &omega.a_2,
            &omega.a_3,
            &omega.a_4,
            &omega.a_5,
            &omega.t_1,
            &omega.t_2,
            &omega.t_3,
        );
        if !((c_1 * omega.z_1 == omega.a_1 + (c_2 * e))
            || (G1Projective::generator() * omega.z_2 == omega.a_2 + (c_3 * e))
            || (self.pp.Q * omega.z_4 == omega.a_4 + (c_5 * e)))
        {
            test = false;
        }
        // if revocation was not computed in the showing proof does not verify it
        if omega.pi_rev_prime.is_some() {
            if !(self.pp.revocation_pp.rev_list.pi_rev * omega.z_3
                == omega.a_3 + (omega.pi_rev_prime.unwrap() * e)
                || (G1Projective::generator() * omega.z_5
                    == omega.a_5
                        + (G1Projective::generator()
                            * (omega.rev_wit_prime.as_ref().unwrap().d * e))))
            {
                test = false;
            }
            if !(self.pp.revocation_pp.verify_witness_randomized(
                omega.pi_rev_prime.unwrap(),
                c_4,
                omega.rev_wit_prime.as_ref().unwrap(),
                &self.revocation_key.rpk,
            )) {
                test = false;
            }
        }
        if omega.enc.is_some() {
            let pi_two = &omega.pi_two.unwrap();
            if !(Auditing::audit_verify(
                &self.authority_key,
                omega.enc.as_ref().unwrap(),
                &pi_two.0,
                &pi_two.1,
                &pi_two.2,
            )) {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_1),
                &G2Affine::from(&omega.t_2),
            ) == (pairing(&G1Affine::from(c_6), &G2Affine::from(&omega.t_1))
                + pairing(&G1Affine::from(c_7), &G2Affine::from(&omega.t_3))))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_2),
            ) == pairing(&G1Affine::from(c_3), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_1),
            ) == pairing(&G1Affine::generator(), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
        }
        if !(self.pp.signature_pp.verify_bis(
            vpk,
            omega.opk_prime.as_ref(),
            omega.verifier_signature.as_ref().unwrap(),
        )) {
            test = false;
        }
        if !(self.pp.signature_pp.verify(
            omega.opk_prime.as_ref(),
            &omega.message_prime,
            &omega.signature_prime,
        )) {
            test = false;
        }
        if !(self.pp.scds_pp.verify_ss(
            &c_1,
            subset,
            &omega.subset_witness,
            omega.poe_one,
            &Some(e),
        )) {
            test = false;
        }
        if !(self.pp.scds_pp.verify_ds(
            &c_1,
            disjoint,
            &omega.disjoint_witness,
            &omega.poe_two,
            &Some(e),
        )) {
            test = false;
        }
        test
    }

    /// Version of show without computation of any element to hide the signer
    #[allow(clippy::too_many_arguments)]
    pub fn show_no_signer_hiding(
        &self,
        mut cred: Credential,
        attributes: &Vec<Scalar>,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        tx: &Hash,
        nym: &Scalar,
        poe: bool,
        revocation: bool,
        audit: bool,
    ) -> Omega {
        let p1 = G1Projective::generator();
        //Initialisation of random values
        let beta = random_z_star_p();
        let mu = random_z_star_p();
        let rho = random_z_star_p();
        let tau = random_z_star_p();
        let r_1 = random_z_star_p();
        let r_2 = random_z_star_p();
        let r_3 = random_z_star_p();
        let r_4 = random_z_star_p();
        let r_5 = random_z_star_p();
        //End of random draws
        let message = vec![
            cred.commitment.c,
            cred.commitment.c * cred.r_4,
            p1,
            cred.c_4,
            cred.c_5,
            self.user_key.upk_1,
            self.authority_key.apk,
        ];
        //Both message prime and signature_prime compose the credential prime
        let (message_prime, signature_prime) =
            MercurialSignatureScheme::change_rep(&message, &cred.signature, &mu, &rho);

        let opk_randomized = MercurialSignatureScheme::convert_pk(&self.org_key.opk, &rho);
        let mut opk_prime: [G2Projective; PKSIZE] = Default::default();
        opk_prime.copy_from_slice(&opk_randomized.as_slice()[0..]);

        cred.commitment.r *= mu;
        cred.commitment.c *= mu;
        let subset_witness = self
            .pp
            .scds_pp
            .open_ss(attributes, subset, &cred.commitment);
        let disjoint_witness = self
            .pp
            .scds_pp
            .open_ds(attributes, disjoint, &cred.commitment);
        let mut revocation_witness = None;
        let mut rev_wit_prime = None;
        // If revocation is required, fetches or compute the non-membership witness
        if revocation {
            revocation_witness = self.pp.revocation_pp.get_witness(nym);
            if revocation_witness.is_none() {
                revocation_witness = self.pp.revocation_pp.non_membership_witness(nym);
            }
            rev_wit_prime = Some(NonMemberShipWitness {
                point: revocation_witness.as_ref().unwrap().point * tau,
                d: revocation_witness.as_ref().unwrap().d * self.user_key.usk_2 * mu * tau,
            });
        }
        let a_1 = message_prime[0] * r_1;
        let a_2 = p1 * r_2;
        let a_3 = self.pp.revocation_pp.rev_list.pi_rev * r_3;
        let a_4 = self.pp.Q * r_4;
        let a_5 = p1 * r_5;
        let tmp = self.user_key.usk_2 * mu * tau;
        let mut pi_rev_prime: Option<G1Projective> = None;
        if revocation {
            pi_rev_prime = Some(self.pp.revocation_pp.rev_list.pi_rev * tmp);
        }
        let t_1 = G2Projective::generator() * beta;
        let tmp = beta * mu;
        let t_2 = G2Projective::generator() * tmp;

        let mut t_3 = G2Projective::generator();
        let mut pi_2: Option<(Scalar, Scalar, Scalar)> = None;
        let enc: Option<EncryptedKey> = None;
        // if audit is required compute the auditing proof
        if audit {
            let (enc, alpha) = Auditing::audit_enc(&self.user_key, &self.authority_key);
            let tmp = beta * alpha;
            t_3 = G2Projective::generator() * tmp;
            pi_2 = Some(Auditing::audit_prv(
                &enc,
                &alpha,
                &self.user_key,
                &self.authority_key,
            ));
        }

        let e = self.hash_elements_in_showing_and_verification_no_signer_hiding(
            subset,
            disjoint,
            tx,
            &message_prime,
            &signature_prime,
            &mut opk_prime,
            &a_1,
            &a_2,
            &a_3,
            &a_4,
            &a_5,
            &t_1,
            &t_2,
            &t_3,
        );

        let z_1 = r_1 + e * cred.r_4;
        let z_2 = r_2 + e * mu;
        let z_3 = r_3 + e * (self.user_key.usk_2 * mu * tau);
        let z_4 = r_4 + e * (self.user_key.usk_2 * mu);
        //If revocation is not used z_5 is not verified against any other pairing
        let mut z_5 = Scalar::zero();
        if revocation {
            z_5 =
                r_5 + e * (self.user_key.usk_2 * mu * tau * revocation_witness.as_ref().unwrap().d);
        }
        let mut poe_1 = None;
        let mut poe_2 = None;
        if poe {
            if !subset.is_empty() {
                poe_1 = Some(self.pp.scds_pp.proof_of_exponentiation(subset, &e));
            }
            if !disjoint.is_empty() {
                poe_2 = Some(self.pp.scds_pp.proof_of_exponentiation(disjoint, &e));
            }
        }
        Omega {
            enc,
            t_1,
            t_2,
            t_3,
            opk_prime,
            message_prime,
            signature_prime,
            subset_witness,
            disjoint_witness,
            rev_wit_prime,
            pi_rev_prime,
            pi_one: None,
            verifier_signature: None,
            pi_two: pi_2,
            poe_one: poe_1,
            poe_two: poe_2,
            a_1,
            a_2,
            a_3,
            a_4,
            a_5,
            z_1,
            z_2,
            z_3,
            z_4,
            z_5,
        }
    }

    /// Verification of a showing, no signer hiding component verified
    #[allow(clippy::too_many_arguments)]
    pub fn verify_no_signer_hiding(
        &mut self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        tx: &Hash,
        omega: &mut Omega,
    ) -> bool {
        let mut test = true;
        let (c_1, c_2, c_3, c_4, c_5, c_6, c_7) = (
            omega.message_prime[0],
            omega.message_prime[1],
            omega.message_prime[2],
            omega.message_prime[3],
            omega.message_prime[4],
            omega.message_prime[5],
            omega.message_prime[6],
        );
        let e = self.hash_elements_in_showing_and_verification_no_signer_hiding(
            subset,
            disjoint,
            tx,
            &omega.message_prime,
            &omega.signature_prime,
            &mut omega.opk_prime,
            &omega.a_1,
            &omega.a_2,
            &omega.a_3,
            &omega.a_4,
            &omega.a_5,
            &omega.t_1,
            &omega.t_2,
            &omega.t_3,
        );
        if !((c_1 * omega.z_1 == omega.a_1 + (c_2 * e))
            || (G1Projective::generator() * omega.z_2 == omega.a_2 + (c_3 * e))
            || (self.pp.Q * omega.z_4 == omega.a_4 + (c_5 * e)))
        {
            test = false;
        }
        // if revocation was not computed in the showing proof does not verify it
        if omega.pi_rev_prime.is_some() {
            if !(self.pp.revocation_pp.rev_list.pi_rev * omega.z_3
                == omega.a_3 + (omega.pi_rev_prime.unwrap() * e)
                || (G1Projective::generator() * omega.z_5
                    == omega.a_5
                        + (G1Projective::generator()
                            * (omega.rev_wit_prime.as_ref().unwrap().d * e))))
            {
                test = false;
            }
            if !(self.pp.revocation_pp.verify_witness_randomized(
                omega.pi_rev_prime.unwrap(),
                c_4,
                omega.rev_wit_prime.as_ref().unwrap(),
                &self.revocation_key.rpk,
            )) {
                test = false;
            }
        }
        if omega.enc.is_some() {
            let pi_two = &omega.pi_two.unwrap();
            if !(Auditing::audit_verify(
                &self.authority_key,
                omega.enc.as_ref().unwrap(),
                &pi_two.0,
                &pi_two.1,
                &pi_two.2,
            )) {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_1),
                &G2Affine::from(&omega.t_2),
            ) == (pairing(&G1Affine::from(c_6), &G2Affine::from(&omega.t_1))
                + pairing(&G1Affine::from(c_7), &G2Affine::from(&omega.t_3))))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_2),
            ) == pairing(&G1Affine::from(c_3), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
            if !(pairing(
                &G1Affine::from(omega.enc.as_ref().unwrap().enc_2),
                &G2Affine::from(&omega.t_1),
            ) == pairing(&G1Affine::generator(), &G2Affine::from(&omega.t_3)))
            {
                test = false;
            }
        }
        if !(self.pp.signature_pp.verify(
            omega.opk_prime.as_ref(),
            &omega.message_prime,
            &omega.signature_prime,
        )) {
            test = false;
        }
        if !(self.pp.scds_pp.verify_ss(
            &c_1,
            subset,
            &omega.subset_witness,
            omega.poe_one,
            &Some(e),
        )) {
            test = false;
        }
        if !(self.pp.scds_pp.verify_ds(
            &c_1,
            disjoint,
            &omega.disjoint_witness,
            &omega.poe_two,
            &Some(e),
        )) {
            test = false;
        }
        test
    }
    /// Extracted hash of elements in obtain, performed as well in issue but by another party
    pub fn hash_elements_in_obtain_and_issue(
        &self,
        a_1: &G1Projective,
        a_2: &G1Projective,
        a_3: &G1Projective,
        c_5: &G1Projective,
    ) -> Scalar {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&G1Affine::from(self.user_key.upk_1).to_compressed());
        hasher.update(&G1Affine::from(self.user_key.upk_2).to_compressed());
        hasher.update(&G1Affine::from(c_5).to_compressed());
        hasher.update(&G1Affine::from(a_1).to_compressed());
        hasher.update(&G1Affine::from(a_2).to_compressed());
        hasher.update(&G1Affine::from(a_3).to_compressed());

        let value_before_modulus = hasher.finalize();
        let e: Scalar = digest_into_scalar(value_before_modulus);
        e
    }

    /// Extracted hash of elements in show, performed as well in verify but by another party
    #[allow(clippy::too_many_arguments)]
    fn hash_elements_in_showing_and_verification(
        &self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        tx: &Hash,
        pi_one: &Proof,
        message_prime: &Vec<G1Projective>,
        signature_prime: &MercurialSignature,
        opk_prime: &mut [G2Projective; PKSIZE],
        a_1: &G1Projective,
        a_2: &G1Projective,
        a_3: &G1Projective,
        a_4: &G1Projective,
        a_5: &G1Projective,
        t_1: &G2Projective,
        t_2: &G2Projective,
        t_3: &G2Projective,
    ) -> Scalar {
        //Hashing
        let mut hasher = blake3::Hasher::new();
        for &subset_element in subset {
            hasher.update(&subset_element.to_bytes());
        }
        for &disjoint_element in disjoint {
            hasher.update(&disjoint_element.to_bytes());
        }
        for i in org_keys {
            for j in i.iter().take(6) {
                hasher.update(&G2Affine::from(j).to_compressed());
            }
        }
        hasher.update(&G1Affine::from(self.authority_key.apk).to_compressed());
        hasher.update(tx.as_bytes());
        //Add pi_1 to the hashed part
        for i in 0..pi_one.a1.len() {
            for j in 0..PKSIZE {
                hasher.update(&G2Affine::from(pi_one.a1[i][j]).to_compressed());
            }
        }
        for &element in &pi_one.z {
            hasher.update(&G1Affine::from(&element).to_compressed());
        }

        for &element in &pi_one.d1 {
            hasher.update(&G1Affine::from(&element).to_compressed());
        }
        hasher.update(&G1Affine::from(a_1).to_compressed());
        hasher.update(&G1Affine::from(a_2).to_compressed());
        hasher.update(&G1Affine::from(a_3).to_compressed());
        hasher.update(&G1Affine::from(a_4).to_compressed());
        hasher.update(&G1Affine::from(a_5).to_compressed());
        hasher.update(&G2Affine::from(t_1).to_compressed());
        hasher.update(&G2Affine::from(t_2).to_compressed());
        hasher.update(&G2Affine::from(t_3).to_compressed());
        for i in opk_prime {
            hasher.update(&G2Affine::from(*i).to_compressed());
        }
        for &element in message_prime {
            hasher.update(&G1Affine::from(&element).to_compressed());
        }
        hasher.update(&G1Affine::from(signature_prime.Z).to_compressed());
        hasher.update(&G1Affine::from(signature_prime.Y).to_compressed());
        hasher.update(&G2Affine::from(signature_prime.Y_2).to_compressed());
        let value_before_mod = hasher.finalize();
        digest_into_scalar(value_before_mod)
    }

    #[allow(clippy::too_many_arguments)]
    fn hash_elements_in_showing_and_verification_without_nizk(
        &self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        org_keys: &Vec<[G2Projective; PKSIZE]>,
        tx: &Hash,
        issuer_signature_randomized: &MercurialSignatureBis,
        message_prime: &Vec<G1Projective>,
        signature_prime: &MercurialSignature,
        opk_prime: &mut [G2Projective; PKSIZE],
        a_1: &G1Projective,
        a_2: &G1Projective,
        a_3: &G1Projective,
        a_4: &G1Projective,
        a_5: &G1Projective,
        t_1: &G2Projective,
        t_2: &G2Projective,
        t_3: &G2Projective,
    ) -> Scalar {
        //Hashing
        let mut hasher = blake3::Hasher::new();
        for &subset_element in subset {
            hasher.update(&subset_element.to_bytes());
        }
        for &disjoint_element in disjoint {
            hasher.update(&disjoint_element.to_bytes());
        }
        for i in org_keys {
            for j in i.iter().take(6) {
                hasher.update(&G2Affine::from(j).to_compressed());
            }
        }
        hasher.update(&G1Affine::from(self.authority_key.apk).to_compressed());
        hasher.update(tx.as_bytes());
        hasher.update(&G2Affine::from(issuer_signature_randomized.Y).to_compressed());
        hasher.update(&G2Affine::from(issuer_signature_randomized.Z).to_compressed());
        hasher.update(&G1Affine::from(issuer_signature_randomized.Y_2).to_compressed());
        hasher.update(&G1Affine::from(a_1).to_compressed());
        hasher.update(&G1Affine::from(a_2).to_compressed());
        hasher.update(&G1Affine::from(a_3).to_compressed());
        hasher.update(&G1Affine::from(a_4).to_compressed());
        hasher.update(&G1Affine::from(a_5).to_compressed());
        hasher.update(&G2Affine::from(t_1).to_compressed());
        hasher.update(&G2Affine::from(t_2).to_compressed());
        hasher.update(&G2Affine::from(t_3).to_compressed());
        for i in opk_prime.iter().take(6) {
            hasher.update(&G2Affine::from(i).to_compressed());
        }
        for &element in message_prime {
            hasher.update(&G1Affine::from(element).to_compressed());
        }
        hasher.update(&G1Affine::from(signature_prime.Z).to_compressed());
        hasher.update(&G1Affine::from(signature_prime.Y).to_compressed());
        hasher.update(&G2Affine::from(signature_prime.Y_2).to_compressed());
        let value_before_mod = hasher.finalize();
        digest_into_scalar(value_before_mod)
    }

    #[allow(clippy::too_many_arguments)]
    fn hash_elements_in_showing_and_verification_no_signer_hiding(
        &self,
        subset: &Vec<Scalar>,
        disjoint: &Vec<Scalar>,
        tx: &Hash,
        message_prime: &Vec<G1Projective>,
        signature_prime: &MercurialSignature,
        opk_prime: &mut [G2Projective; PKSIZE],
        a_1: &G1Projective,
        a_2: &G1Projective,
        a_3: &G1Projective,
        a_4: &G1Projective,
        a_5: &G1Projective,
        t_1: &G2Projective,
        t_2: &G2Projective,
        t_3: &G2Projective,
    ) -> Scalar {
        //Hashing
        let mut hasher = blake3::Hasher::new();
        for &subset_element in subset {
            hasher.update(&subset_element.to_bytes());
        }
        for &disjoint_element in disjoint {
            hasher.update(&disjoint_element.to_bytes());
        }
        hasher.update(&G1Affine::from(self.authority_key.apk).to_compressed());
        hasher.update(tx.as_bytes());
        hasher.update(&G1Affine::from(a_1).to_compressed());
        hasher.update(&G1Affine::from(a_2).to_compressed());
        hasher.update(&G1Affine::from(a_3).to_compressed());
        hasher.update(&G1Affine::from(a_4).to_compressed());
        hasher.update(&G1Affine::from(a_5).to_compressed());
        hasher.update(&G2Affine::from(t_1).to_compressed());
        hasher.update(&G2Affine::from(t_2).to_compressed());
        hasher.update(&G2Affine::from(t_3).to_compressed());
        for i in opk_prime.iter().take(6) {
            hasher.update(&G2Affine::from(i).to_compressed());
        }
        for &element in message_prime {
            hasher.update(&G1Affine::from(element).to_compressed());
        }
        hasher.update(&G1Affine::from(signature_prime.Z).to_compressed());
        hasher.update(&G1Affine::from(signature_prime.Y).to_compressed());
        hasher.update(&G2Affine::from(signature_prime.Y_2).to_compressed());
        let value_before_mod = hasher.finalize();
        digest_into_scalar(value_before_mod)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mercurial_signatures::random_z_star_p;
    use blake3::Hasher;

    #[test]
    fn obtain_and_issue() {
        let mock = MockProtocol::setup(4, 4);
        let attributes = vec![random_z_star_p(), random_z_star_p(), random_z_star_p()];
        let nym = random_z_star_p();
        mock.obtain(&attributes, &nym);
    }

    #[test]
    #[allow(non_snake_case, dead_code)]
    fn show_and_verify() {
        //Initialisation of attributes and (non)revoked nym
        let signer = MercurialSignatureScheme::new(7);
        let att_1 = random_z_star_p();
        let att_2 = random_z_star_p();
        let attributes = vec![att_1.clone(), att_2.clone(), random_z_star_p()];
        let subset = vec![att_1.clone(), att_2.clone()];
        let disjoint = vec![random_z_star_p(), random_z_star_p()];

        let nym_1 = random_z_star_p();
        let nym_2 = random_z_star_p();
        let nym_3 = random_z_star_p();
        let nym_4 = random_z_star_p();
        let NYM = vec![nym_3.clone()];
        let RNYM = vec![nym_1.clone(), nym_2.clone(), nym_4.clone()];

        //Create a set of organisation keys, in this test we consider the signing organisation to be
        //the third of the set
        let n = 5; //Size of confidentiality set of organisation keys
        let mut org_keys: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        unsafe {
            org_keys.set_len(n);
        }

        let mut mock_organisation_secret_key: Vec<Scalar> = vec![];
        let mut mock_organisation_public_key: Vec<G2Projective> = vec![];
        for i in 0..n {
            let pki = signer.key_gen();
            //The mock protocol organisation key belong to the set of organisation keys
            if i == 2 {
                mock_organisation_secret_key = pki.0.clone();
                mock_organisation_public_key = pki.1.clone();
            }
            for j in 0..PKSIZE {
                org_keys[i][j] = pki.1[j];
            }
        }

        //Fake transaction hash
        let mut hasher = Hasher::new();
        hasher.update(&G1Affine::generator().to_compressed());
        let tx = hasher.finalize();

        //Full initialisation of the party that plays all the roles in the transaction
        let mut mock = MockProtocol::full_setup(
            10,
            10,
            &NYM,
            RNYM,
            &mock_organisation_secret_key,
            &mock_organisation_public_key,
        );

        let index = 2;
        let mut x1: [G2Projective; PKSIZE] = Default::default();
        let mut x2: [G2Projective; PKSIZE] = Default::default();
        let rho = random_z_star_p();
        let gamma = random_z_star_p();
        for i in 0..PKSIZE {
            x1[i] = org_keys[index][i] * rho;
            x2[i] = org_keys[index][i] * gamma;
        }
        let pi = mock
            .signer_hiding
            .PPro(&org_keys, &x1, &x2, rho, gamma, n, index);

        let cred = mock.obtain(&attributes, &nym_3);
        let (mut omega, mut org_keys) = mock.show(
            cred,
            &attributes,
            &subset,
            &disjoint,
            &mut org_keys,
            &pi,
            &tx,
            &nym_3,
            &rho,
            &gamma,
            true,
            true,
            true,
        );
        assert_eq!(
            true,
            mock.verify(&subset, &disjoint, &mut org_keys, &tx, &mut omega)
        );
    }

    #[test]
    #[allow(non_snake_case, dead_code)]
    /*
       This version of show and verify doesn't hide the signer with the same way as the previous one
       that requires a lot of pairings computations. Instead randomizes a signature and opk
       using the issuer access policy
    */
    fn show_and_verify_version_two() {
        //Initialisation of attributes and (non)revoked nym
        let signer = MercurialSignatureScheme::new(7);
        let att_1 = random_z_star_p();
        let att_2 = random_z_star_p();
        let attributes = vec![att_1.clone(), att_2.clone(), random_z_star_p()];
        let subset = vec![att_1.clone(), att_2.clone()];
        let disjoint = vec![random_z_star_p(), random_z_star_p()];

        let nym_1 = random_z_star_p();
        let nym_2 = random_z_star_p();
        let nym_3 = random_z_star_p();
        let nym_4 = random_z_star_p();
        let NYM = vec![nym_3.clone()];
        let RNYM = vec![nym_1.clone(), nym_2.clone(), nym_4.clone()];

        //Create a set of organisation keys, in this test we consider the signing organisation to be
        //the third of the set
        let n = 3; //Size of confidentiality set of organisation keys
        let mut org_keys: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        unsafe {
            org_keys.set_len(n);
        }

        let mut mock_organisation_secret_key: Vec<Scalar> = vec![];
        let mut mock_organisation_public_key: Vec<G2Projective> = vec![];
        for i in 0..n {
            let pki = signer.key_gen();
            //The mock protocol organisation key belong to the set of organisation keys
            if i == 2 {
                mock_organisation_secret_key = pki.0.clone();
                mock_organisation_public_key = pki.1.clone();
            }
            for j in 0..PKSIZE {
                org_keys[i][j] = pki.1[j];
            }
        }

        // A verifier creates an access policy by signing the organisation keys
        let (vsk, vpk) = signer.key_gen_bis();
        let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
        for i in 0..org_keys.len() {
            verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
        }

        //Fake transaction hash
        let mut hasher = Hasher::new();
        hasher.update(&G1Affine::generator().to_compressed());
        let tx = hasher.finalize();

        //Full initialisation of the party that plays all the roles in the transaction
        let mut mock = MockProtocol::full_setup(
            10,
            10,
            &NYM,
            RNYM,
            &mock_organisation_secret_key,
            &mock_organisation_public_key,
        );

        let cred = mock.obtain(&attributes, &nym_3);
        let (mut omega, mut org_keys) = mock.show_no_nizk(
            cred,
            &attributes,
            &subset,
            &disjoint,
            &mut org_keys,
            &verifier_access_policy,
            &tx,
            &nym_3,
            2,
            true,
            true,
            true,
        );
        assert_eq!(
            true,
            mock.verify_no_nizk(&subset, &disjoint, &mut org_keys, &tx, &mut omega, &vpk)
        );
    }
}
