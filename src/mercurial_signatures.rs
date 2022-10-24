use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use crypto_bigint::U256;
use ff::Field;

/// Implementation of mercurial signature using the bls12-381 elliptic curve
#[derive(Debug, Clone, Copy)]
pub struct MercurialSignatureScheme {
    _p: U256, // order of the groups, p
    l: usize, // lengths of keys and messages
    p_1: G1Projective,
    p_2: G2Projective,
}

/// Mercurial signatures are computed in the signing algorithm for a given message
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MercurialSignature {
    pub Z: G1Projective,
    pub Y: G1Projective,
    pub Y_2: G2Projective,
}

/// This mercurial signature is computed when the signed messages has its elements in G2
#[allow(non_snake_case, non_camel_case_types)]
pub struct MercurialSignatureBis {
    pub(crate) Z: G2Projective,
    pub(crate) Y: G2Projective,
    pub(crate) Y_2: G1Projective,
}

/// Computes a random number in Zp\{0} mod q in potentially variable time (insignificant probability)
/// Retry as long as it equals 0, but it has insignificant probability each time
pub fn random_z_star_p() -> Scalar {
    let rng = rand::thread_rng();
    let mut random = Scalar::random(rng);
    while !random.is_zero().unwrap_u8() == 0 {
        let rng = rand::thread_rng();
        random = Scalar::random(rng);
    }
    random
}

/// Computes a random number, zero being a possibility
pub fn random_z_p() -> bls12_381::Scalar {
    let rng = rand::thread_rng();
    Scalar::random(rng)
}

impl MercurialSignatureScheme {
    /// This structure only contains elements necessary for computations, l is the maximum length
    /// possible of messages
    pub fn new(el: usize) -> MercurialSignatureScheme {
        MercurialSignatureScheme {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            l: el,
            p_1: G1Projective::generator(),
            p_2: G2Projective::generator(),
        }
    }

    /// Key generation of the signing party
    pub fn key_gen(&self) -> (Vec<Scalar>, Vec<G2Projective>) {
        let mut pk: Vec<G2Projective> = Vec::with_capacity(self.l);
        let mut sk: Vec<Scalar> = Vec::with_capacity(self.l);

        for _ in 0..(self.l as u64) {
            let x_i = random_z_star_p();
            let p_x = self.p_2 * x_i;
            pk.push(p_x);
            sk.push(x_i);
        }
        (sk, pk)
    }

    /// Key generation of the signing party, public key in G1, used to sign messages with elements in G2
    pub fn key_gen_bis(&self) -> (Vec<Scalar>, Vec<G1Projective>) {
        let mut pk: Vec<G1Projective> = Vec::with_capacity(self.l);
        let mut sk: Vec<Scalar> = Vec::with_capacity(self.l);

        for _ in 0..(self.l as u64) {
            let x_i = random_z_star_p();
            let p_x = self.p_1 * x_i;
            pk.push(p_x);
            sk.push(x_i);
        }
        (sk, pk)
    }

    /// Generate a vector of l elements in G1, chosen randomly
    /// Doesn't correspond to a part of the scheme but it is useful to test the Sign algorithm
    pub fn random_message(&self) -> Vec<G1Projective> {
        let mut message: Vec<G1Projective> = Vec::with_capacity(self.l);
        for _ in 0..(self.l as u64) {
            let random_scalar = random_z_star_p();
            let element_m = self.p_1 * random_scalar;
            message.push(element_m);
        }
        message
    }

    /// Produces a random message with elements in G2
    pub fn random_message_bis(&self) -> Vec<G2Projective> {
        let mut message: Vec<G2Projective> = Vec::with_capacity(self.l);
        for _ in 0..(self.l as u64) {
            let random_scalar = random_z_star_p();
            let element_m = self.p_2 * random_scalar;
            message.push(element_m);
        }
        message
    }

    /// Signing algorithm. The message signed is a vector of elements in G1
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign(&self, sk: &[Scalar], message: &[G1Projective]) -> MercurialSignature {
        let y = random_z_star_p();
        let inv_y = y.invert().unwrap(); // outputs the multiplicative inverse of y
        let mut Z = message[0] * sk[0]; // To instantiate Z properly
        for i in 1..self.l {
            Z += message[i] * sk[i];
        }
        Z *= y;
        let Y = self.p_1 * inv_y;
        let Y_2 = self.p_2 * inv_y;
        MercurialSignature { Z, Y, Y_2 }
    }

    /// Signing algorithm. The message signed is a vector of elements in G2
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_elements_in_G2(
        &self,
        sk: &[Scalar],
        message: &[G2Projective],
    ) -> MercurialSignatureBis {
        let y = random_z_star_p();
        let inv_y = y.invert().unwrap(); // outputs the multiplicative inverse of y
        let mut Z = message[0] * sk[0]; // To instantiate Z properly
        for i in 1..self.l {
            Z += message[i] * sk[i];
        }
        Z *= y;
        let Y = self.p_2 * inv_y;
        let Y_2 = self.p_1 * inv_y;
        MercurialSignatureBis { Z, Y, Y_2 }
    }

    /// Verification algorithm. The message signed is a vector of elements in G1
    pub fn verify(
        &self,
        pk: &[G2Projective],
        message: &[G1Projective],
        sigma: &MercurialSignature,
    ) -> bool {
        let mut pair_1 = pairing(&G1Affine::from(message[0]), &G2Affine::from(pk[0]));
        for i in 1..self.l {
            pair_1 += pairing(&G1Affine::from(message[i]), &G2Affine::from(pk[i]));
        }
        let pair_2 = pairing(&G1Affine::from(sigma.Z), &G2Affine::from(sigma.Y_2));
        let pair_3 = pairing(&G1Affine::from(sigma.Y), &G2Affine::from(self.p_2));
        let pair_4 = pairing(&G1Affine::from(self.p_1), &G2Affine::from(sigma.Y_2));

        pair_1.eq(&pair_2) && pair_3.eq(&pair_4)
    }

    /// Verify when the message is composed of elements in G2
    pub fn verify_bis(
        &self,
        pk: &[G1Projective],
        message: &[G2Projective],
        sigma: &MercurialSignatureBis,
    ) -> bool {
        let mut pair_1 = pairing(&G1Affine::from(pk[0]), &G2Affine::from(message[0]));
        for i in 1..self.l {
            pair_1 += pairing(&G1Affine::from(pk[i]), &G2Affine::from(message[i]));
        }
        let pair_2 = pairing(&G1Affine::from(sigma.Y_2), &G2Affine::from(sigma.Z));
        let pair_3 = pairing(&G1Affine::from(self.p_1), &G2Affine::from(sigma.Y));
        let pair_4 = pairing(&G1Affine::from(sigma.Y_2), &G2Affine::from(self.p_2));

        pair_1.eq(&pair_2) && pair_3.eq(&pair_4)
    }

    /// Randomizes the secret key using rho, an element of Zp
    pub fn convert_sk(sk: &Vec<Scalar>, rho: &Scalar) -> Vec<Scalar> {
        let mut sk_converted: Vec<Scalar> = Vec::with_capacity(sk.len());
        for &val in sk {
            sk_converted.push(rho * val);
        }
        sk_converted
    }

    /// Randomizes the public key using rho, an element of Zp
    pub fn convert_pk(pk: &Vec<G2Projective>, rho: &Scalar) -> Vec<G2Projective> {
        let mut pk_converted: Vec<G2Projective> = Vec::with_capacity(pk.len());
        for &val in pk {
            pk_converted.push(val * rho);
        }
        pk_converted
    }

    /// Randomizes the public key using rho, an element of Zp. If public key is in G1
    pub fn convert_pk_bis(pk: &Vec<G1Projective>, rho: &Scalar) -> Vec<G1Projective> {
        let mut pk_converted: Vec<G1Projective> = Vec::with_capacity(pk.len());
        for &val in pk {
            pk_converted.push(val * rho);
        }
        pk_converted
    }

    /// Randomizes the generated signature using the same rho
    pub fn convert_sig(sigma: &MercurialSignature, rho: &Scalar) -> MercurialSignature {
        let psi = random_z_star_p();
        let psi_inv = psi.invert().unwrap(); //Multiplicative invert of psi
        let rand = psi * rho;
        let new_z = sigma.Z * rand;
        let new_y = sigma.Y * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        MercurialSignature {
            Z: new_z,
            Y: new_y,
            Y_2: new_y_hat,
        }
    }

    /// Randomizes the generated signature using the same rho
    pub fn convert_sig_bis(sigma: &MercurialSignatureBis, rho: &Scalar) -> MercurialSignatureBis {
        let psi = random_z_star_p();
        let psi_inv = psi.invert().unwrap(); //Multiplicative invert of psi
        let rand = psi * rho;
        let new_z = sigma.Z * rand;
        let new_y = sigma.Y * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        MercurialSignatureBis {
            Z: new_z,
            Y: new_y,
            Y_2: new_y_hat,
        }
    }

    /// Randomizes consistently the signature and the signed message so the signature verification
    /// holds for the randomized message
    pub fn change_rep(
        message: &Vec<G1Projective>,
        sigma: &MercurialSignature,
        mu: &Scalar,
        rho: &Scalar,
    ) -> (Vec<G1Projective>, MercurialSignature) {
        let psi = random_z_star_p();
        let psi_inv = psi.invert().unwrap(); // multiplicative inverse of psi
        let mut new_message: Vec<G1Projective> = Vec::with_capacity(message.len());
        for &element in message {
            new_message.push(element * mu);
        }
        let rand1 = psi * mu * rho;
        let new_z = sigma.Z * rand1; // psi * mu * rho
        let new_y = sigma.Y * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        let new_signature = MercurialSignature {
            Z: new_z,
            Y: new_y,
            Y_2: new_y_hat,
        };
        (new_message, new_signature)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn do_protocol_correctly() {
        let scheme = MercurialSignatureScheme::new(9);
        let (sk, pk) = scheme.key_gen();
        let message = scheme.random_message();
        let signature = scheme.sign(&sk, &message);
        assert_eq!(scheme.verify(&pk, &message, &signature), true);
    }

    #[test]
    fn do_protocol_correctly_v_2() {
        let scheme = MercurialSignatureScheme::new(9);
        let (sk, pk) = scheme.key_gen_bis();
        let message = scheme.random_message_bis();
        let signature = scheme.sign_elements_in_G2(&sk, &message);
        let rho = random_z_star_p();
        let converted_pk = MercurialSignatureScheme::convert_pk_bis(&pk, &rho);
        let converted_signature = MercurialSignatureScheme::convert_sig_bis(&signature, &rho);
        assert_eq!(
            scheme.verify_bis(&converted_pk, &message, &converted_signature),
            true
        );
    }
    #[test]
    fn do_protocol_with_conversion() {
        let scheme = MercurialSignatureScheme::new(9);
        let (sk, pk) = scheme.key_gen();
        let message = scheme.random_message();
        let _signature = scheme.sign(&sk, &message);

        let randomizer_value = random_z_star_p();
        let sk = MercurialSignatureScheme::convert_sk(&sk, &randomizer_value);
        let pk = MercurialSignatureScheme::convert_pk(&pk, &randomizer_value);
        let signature = scheme.sign(&sk, &message);
        assert_eq!(scheme.verify(&pk, &message, &signature), true);
    }

    #[test]
    fn do_protocol_with_signature_conversion() {
        let scheme = MercurialSignatureScheme::new(9);
        let (sk, pk) = scheme.key_gen();
        let message = scheme.random_message();
        let signature = scheme.sign(&sk, &message);
        let rho = random_z_star_p();
        let converted_pk = MercurialSignatureScheme::convert_pk(&pk, &rho);
        let converted_signature = MercurialSignatureScheme::convert_sig(&signature, &rho);
        assert_eq!(
            scheme.verify(&converted_pk, &message, &converted_signature),
            true
        );
    }

    #[test]
    fn do_protocol_with_rep_change() {
        let scheme = MercurialSignatureScheme::new(9);
        let (sk, pk) = scheme.key_gen();
        let message = scheme.random_message();
        let signature = scheme.sign(&sk, &message);

        let rho = random_z_star_p();
        let pk = MercurialSignatureScheme::convert_pk(&pk, &rho);
        let mu = random_z_star_p();
        let (message, signature) =
            MercurialSignatureScheme::change_rep(&message, &signature, &mu, &rho);

        assert_eq!(scheme.verify(&pk, &message, &signature), true);
    }
}
