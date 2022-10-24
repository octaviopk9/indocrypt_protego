use crate::mercurial_signatures::random_z_star_p;
use crate::revocation_accumulator::RevocationAccumulator;
use crate::{G2Projective, MercurialSignatureScheme, Scalar, SCDS};
use bls12_381::G1Projective;
/// Authority secret and public key. In several algorithms only the secret or public key is used,
/// still we decide to store them together for the semantic. In real world scenario we would
/// separate them.
#[allow(dead_code)]
#[derive(Clone)]
pub struct AuthorityKey {
    pub(crate) ask: Scalar,
    pub(crate) apk: G1Projective,
}

/// User secret and public keys
#[allow(dead_code)]
#[derive(Clone)]
pub struct UserKey {
    pub usk_1: Scalar,
    pub usk_2: Scalar,
    pub(crate) upk_1: G1Projective,
    pub(crate) upk_2: G1Projective,
}

/// The relation between rsk and rpk is a little bit different than the other ones. The rpk is used
/// to cancel out the rsk associated in the computation of the revocation proof in the pairing
#[allow(dead_code)]
#[derive(Clone)]
pub struct RevocationAccumulatorKey {
    pub(crate) rsk: Scalar,
    pub(crate) rpk: G2Projective,
}

/// osk and opk are keys belonging to one organisation among a set of organisation keys
#[allow(non_snake_case, dead_code)]
#[derive(Clone)]
pub struct OrganisationKey {
    pub osk: Vec<Scalar>,
    pub opk: Vec<G2Projective>,
}

/// This set of key is additional and used to replace the NIZK for signer hiding by the addition
/// of another round of signature on the issuer access policy.
#[allow(non_snake_case, dead_code)]
#[derive(Clone)]
pub struct VerifierKey {
    pub vsk: Vec<Scalar>,
    pub vpk: Vec<G1Projective>,
}

/// In this structure we find the different elements present in the key generation algorithm.
#[allow(non_snake_case, dead_code)]
#[derive(Clone)]
pub struct Protego {
    pub Q: G1Projective,
    pub revocation_pp: RevocationAccumulator,
    pub scds_pp: SCDS,
    pub(crate) signature_pp: MercurialSignatureScheme,
}

impl Protego {
    /// Generation of the public parameters
    pub fn setup(scds_len: usize, rev_acc_len: usize) -> Self {
        let rand = random_z_star_p();
        let random_point = G1Projective::generator() * rand;

        let revocation_pp = RevocationAccumulator::setup(rev_acc_len);
        let scds_pp = SCDS::setup(scds_len);
        let signature_pp = MercurialSignatureScheme::new(7);

        Protego {
            Q: random_point,
            revocation_pp,
            scds_pp,
            signature_pp,
        }
    }
    /// Setup used for the web client with the random elements generated at server launch
    pub fn setup_with_imposed_random(scds_len: usize, rev_acc_len: usize, rand: Scalar) -> Self {
        let random_point = G1Projective::generator() * rand;

        let revocation_pp = RevocationAccumulator::setup(rev_acc_len);
        let scds_pp = SCDS::setup(scds_len);
        let signature_pp = MercurialSignatureScheme::new(7);

        Protego {
            Q: random_point,
            revocation_pp,
            scds_pp,
            signature_pp,
        }
    }

    /// Organisation keys generation
    pub fn ok_gen(&self) -> OrganisationKey {
        let (osk, opk) = self.signature_pp.key_gen();
        OrganisationKey { osk, opk }
    }
    /// Verifier keys generation
    pub fn vk_gen(&self) -> VerifierKey {
        let (vsk, vpk) = self.signature_pp.key_gen_bis();
        VerifierKey { vsk, vpk }
    }

    /// User keys generation
    pub fn uk_gen(&self) -> UserKey {
        let usk_1 = random_z_star_p();
        let usk_2 = random_z_star_p();
        let upk_1 = G1Projective::generator() * usk_1;
        let upk_2 = G1Projective::generator() * usk_2;

        UserKey {
            usk_1,
            usk_2,
            upk_1,
            upk_2,
        }
    }
    /// Setup used for the web client with the random elements generated at server launch
    pub fn uk_gen_with_imposed_random(usk_1: Scalar, usk_2: Scalar) -> UserKey {
        let upk_1 = G1Projective::generator() * usk_1;
        let upk_2 = G1Projective::generator() * usk_2;

        UserKey {
            usk_1,
            usk_2,
            upk_1,
            upk_2,
        }
    }

    /// Authority (as in auditing part) keys generation
    pub fn aak_gen(&self) -> AuthorityKey {
        let ask = random_z_star_p();
        let apk = G1Projective::generator() * ask;

        AuthorityKey { ask, apk }
    }
    /// Setup used for the web client with the random elements generated at server launch
    pub fn aak_gen_with_imposed_random(ask: Scalar) -> AuthorityKey {
        let apk = G1Projective::generator() * ask;

        AuthorityKey { ask, apk }
    }

    /// Revocation entity keys generation
    pub fn rak_gen(&self) -> RevocationAccumulatorKey {
        let rsk = random_z_star_p();
        let rpk = self.revocation_pp.b_i_in_g2[0] * rsk.invert().unwrap();

        RevocationAccumulatorKey { rsk, rpk }
    }
    /// Setup used for the web client with the random elements generated at server launch
    pub fn rak_gen_with_imposed_random(&self, rsk: Scalar) -> RevocationAccumulatorKey {
        let rpk = self.revocation_pp.b_i_in_g2[0] * rsk.invert().unwrap();

        RevocationAccumulatorKey { rsk, rpk }
    }
}
