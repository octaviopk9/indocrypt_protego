use bn::{pairing, Fr, Group, G1, G2};
use crypto_bigint::{Encoding, U256, U512};
use rand::thread_rng;

/// Using Barreto-Naehrig (BN) curve construction for mercurial signatures.
pub struct MercurialSignatureSchemeBn {
    _p: U256, // order of the groups, p
    l: usize, // lengths of keys and messages
    p_1: G1,
    p_2: G2,
}

/// Mercurial signatures are computed in the signing algorithm for a given message
#[allow(non_snake_case, non_camel_case_types)]
pub struct MercurialSignatureBn {
    Z: G1,
    Y: G1,
    Y_2: G2,
}

/// Computes a random number in Zp\{0} mod q in potentially variable time (insignificant probability)
/// Retry as long as it equals 0, but it has insignificant probability each time
pub fn bn_random_z_star_p() -> Fr {
    let rng = thread_rng();
    let mut bigint: U512 = U512::random(rng);
    while bigint.is_zero().unwrap_u8() == 1 {
        let rng = thread_rng();
        bigint = U512::random(rng);
    }
    Fr::interpret(&bigint.to_le_bytes())
}

impl MercurialSignatureSchemeBn {
    /// This structure only contains elements necessary for computations, they are implementation dependent
    pub fn bn_new(el: usize) -> MercurialSignatureSchemeBn {
        MercurialSignatureSchemeBn {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            l: el,
            p_1: G1::one(),
            p_2: G2::one(),
        }
    }

    /// Key generation of the signing party
    pub fn bn_key_gen(&self) -> (Vec<Fr>, Vec<G2>) {
        let mut pk: Vec<G2> = Vec::with_capacity(self.l);
        let mut sk: Vec<Fr> = Vec::with_capacity(self.l);

        for _ in 0..(self.l as u64) {
            let x_i = bn_random_z_star_p();
            let p_x = self.p_2 * x_i;
            pk.push(p_x);
            sk.push(x_i);
        }
        (sk, pk)
    }

    /// Generate a vector of l elements in G1, chosen randomly
    /// Doesn't correspond to a part of the scheme but it is useful to test the Sign algorithm
    pub fn bn_random_message(&self) -> Vec<G1> {
        let mut message: Vec<G1> = Vec::with_capacity(self.l);
        for _ in 0..(self.l as u64) {
            let random_scalar = bn_random_z_star_p();
            let element_m = self.p_1 * random_scalar;
            message.push(element_m);
        }
        message
    }

    /// Signing algorithm. The message signed is a vector of elements in G1
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn bn_sign(&self, sk: &[Fr], message: &[G1]) -> MercurialSignatureBn {
        let y = bn_random_z_star_p();
        let inv_y = y.inverse().unwrap(); // outputs the multiplicative inverse of y
        let mut Z = message[0] * sk[0]; // To instantiate Z properly
        for i in 1..self.l {
            Z = Z + (message[i] * sk[i]);
        }
        Z = Z * y;
        let Y = self.p_1 * inv_y;
        let Y_2 = self.p_2 * inv_y;
        MercurialSignatureBn { Z, Y, Y_2 }
    }

    /// Verifies a signature using the signer public key
    pub fn bn_verify(&self, pk: &[G2], message: &[G1], sigma: &MercurialSignatureBn) -> bool {
        let mut pair_1 = pairing(message[0], pk[0]);
        for i in 1..self.l {
            // We do not multiply 2 points here, library chose to use multiplicative notation for Gt
            pair_1 = pair_1 * (pairing(message[i], pk[i]));
        }
        let pair_2 = pairing(sigma.Z, sigma.Y_2);
        let pair_3 = pairing(sigma.Y, self.p_2);
        let pair_4 = pairing(self.p_1, sigma.Y_2);

        pair_1.eq(&pair_2) && pair_3.eq(&pair_4)
    }

    /// Randomizes the secret key using rho, an element of Zp
    pub fn bn_convert_sk(sk: &Vec<Fr>, rho: &Fr) -> Vec<Fr> {
        let mut sk_converted: Vec<Fr> = Vec::with_capacity(sk.len());
        for i in sk {
            sk_converted.push(*rho * *i);
        }
        sk_converted
    }
    /// Randomizes the public key using rho, an element of Zp
    pub fn bn_convert_pk(pk: &Vec<G2>, rho: &Fr) -> Vec<G2> {
        let mut pk_converted: Vec<G2> = Vec::with_capacity(pk.len());
        for i in pk {
            pk_converted.push(*i * *rho);
        }
        pk_converted
    }

    /// Randomizes the generated signature using the same rho
    pub fn bn_convert_sig(sigma: &MercurialSignatureBn, rho: &Fr) -> MercurialSignatureBn {
        let psi = bn_random_z_star_p();
        let psi_inv = psi.inverse().unwrap(); //Multiplicative invert of psi
        let new_z = sigma.Z * psi * *rho;
        let new_y = sigma.Y * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        MercurialSignatureBn {
            Z: new_z,
            Y: new_y,
            Y_2: new_y_hat,
        }
    }

    /// Randomizes consistently the signature and the signed message so the signature verification
    /// holds for the randomized message
    pub fn bn_change_rep(
        message: &Vec<G1>,
        sigma: &MercurialSignatureBn,
        mu: &Fr,
        rho: &Fr,
    ) -> (Vec<G1>, MercurialSignatureBn) {
        let psi = bn_random_z_star_p();
        let psi_inv = psi.inverse().unwrap(); // multiplicative inverse of psi
        let mut new_message: Vec<G1> = Vec::with_capacity(message.len());
        for i in message {
            new_message.push(*i * *mu);
        }
        let new_z = sigma.Z * psi * *mu * *rho;
        let new_y = sigma.Y * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        let new_signature = MercurialSignatureBn {
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
        let scheme = MercurialSignatureSchemeBn::bn_new(9);
        let (sk, pk) = scheme.bn_key_gen();
        let message = scheme.bn_random_message();
        let signature = scheme.bn_sign(&sk, &message);
        assert_eq!(scheme.bn_verify(&pk, &message, &signature), true);
    }

    #[test]
    fn do_protocol_with_conversion() {
        let scheme = MercurialSignatureSchemeBn::bn_new(9);
        let (sk, pk) = scheme.bn_key_gen();
        let message = scheme.bn_random_message();
        let _signature = scheme.bn_sign(&sk, &message);

        let randomizer_value = bn_random_z_star_p();
        let sk = MercurialSignatureSchemeBn::bn_convert_sk(&sk, &randomizer_value);
        let pk = MercurialSignatureSchemeBn::bn_convert_pk(&pk, &randomizer_value);
        let signature = scheme.bn_sign(&sk, &message);
        assert_eq!(scheme.bn_verify(&pk, &message, &signature), true);
    }

    #[test]
    fn do_protocol_with_rep_change() {
        let scheme = MercurialSignatureSchemeBn::bn_new(9);
        let (sk, pk) = scheme.bn_key_gen();
        let message = scheme.bn_random_message();
        let signature = scheme.bn_sign(&sk, &message);

        let rho = bn_random_z_star_p();
        let pk = MercurialSignatureSchemeBn::bn_convert_pk(&pk, &rho);
        let mu = bn_random_z_star_p();
        let (message, signature) =
            MercurialSignatureSchemeBn::bn_change_rep(&message, &signature, &mu, &rho);

        assert_eq!(scheme.bn_verify(&pk, &message, &signature), true);
    }
}
