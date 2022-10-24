use crate::key_gen::{AuthorityKey, UserKey};
use crate::mercurial_signatures::random_z_p;
use blake3;
use blake3::Hash;
use bls12_381::{G1Affine, G1Projective, Scalar};
use crypto_bigint::{Encoding, U256};

/// The structure corresponds to the El-Gamal encryption of the user public key under the authority
/// public key. This encrypted key can then be unciphered by the authority to link an user to the
/// showing, while keeping the user hidden from external parties.
pub struct EncryptedKey {
    pub(crate) enc_1: G1Projective, //upk + alpha*apk
    pub(crate) enc_2: G1Projective, // alpha * P1
}

/// Auditing functions do not rely on CRS public parameters. The structure is empty but the functions
/// will have the prefix auditing this way, allowing us to know what kind of work we are doing
#[allow(dead_code)]
pub struct Auditing {}

impl Default for Auditing {
    fn default() -> Self {
        Self::new()
    }
}
impl Auditing {
    pub fn new() -> Auditing {
        Auditing {}
    }

    /// Encrypts the user's public key under authority's public key. In this implementation secret
    /// and public keys are together, meaning, secret keys are also passed,to the function, but,
    /// they are ignored.
    pub fn audit_enc(upk: &UserKey, apk: &AuthorityKey) -> (EncryptedKey, Scalar) {
        let alpha = random_z_p();
        let enc_1 = upk.upk_1 + (apk.apk * alpha);
        let enc_2 = G1Projective::generator() * alpha;
        let enc = EncryptedKey { enc_1, enc_2 };
        (enc, alpha)
    }

    /// El-Gamal's decryption of the encrypted key
    pub fn audit_dec(enc: &EncryptedKey, ak: &AuthorityKey) -> G1Projective {
        enc.enc_1 - (enc.enc_2 * ak.ask)
    }

    /// Takes as input an encrypted key, shared secret alpha, an user's secret key usk and an
    /// auditor's public key apk. User then computes a proof of Enc being the correct encryption of
    /// it's public key under authority's public key.
    ///
    /// Generated proof is a triplet of elements in Z/pZ
    pub fn audit_prv(
        enc: &EncryptedKey,
        alpha: &Scalar,
        usk: &UserKey,
        apk: &AuthorityKey,
    ) -> (Scalar, Scalar, Scalar) {
        let r1 = random_z_p();
        let r2 = random_z_p();
        let com_1 = (G1Projective::generator() * r1) + (apk.apk * r2);
        let com_2 = G1Projective::generator() * r2;

        //Hashing the elements
        let mut hasher = blake3::Hasher::new();
        hasher.update(&G1Affine::from(com_1).to_compressed());
        hasher.update(&G1Affine::from(com_2).to_compressed());
        hasher.update(&G1Affine::from(enc.enc_1).to_compressed());
        hasher.update(&G1Affine::from(enc.enc_2).to_compressed());

        let value_before_modulus = hasher.finalize();
        let c: Scalar = digest_into_scalar(value_before_modulus);

        let z_1 = r1 + (c * usk.usk_1);
        let z_2 = r2 + (c * alpha);
        (c, z_1, z_2)
    }

    /// Takes as input an auditor's public key apk and a proof enc of the correct encryption of a
    /// user's public key under apk and outputs 1 iff the proof verifies.
    pub fn audit_verify(
        apk: &AuthorityKey,
        enc: &EncryptedKey,
        c: &Scalar,
        z_1: &Scalar,
        z_2: &Scalar,
    ) -> bool {
        let com_1 = (G1Projective::generator() * z_1) + (apk.apk * z_2) - (enc.enc_1 * c);
        let com_2 = (G1Projective::generator() * z_2) - (enc.enc_2 * c);

        //Hashing the elements
        let mut hasher = blake3::Hasher::new();
        hasher.update(&G1Affine::from(com_1).to_compressed());
        hasher.update(&G1Affine::from(com_2).to_compressed());
        hasher.update(&G1Affine::from(enc.enc_1).to_compressed());
        hasher.update(&G1Affine::from(enc.enc_2).to_compressed());

        let value_before_modulus = hasher.finalize();
        let c_prime: Scalar = digest_into_scalar(value_before_modulus);

        c_prime.eq(c)
    }
}

/// In AuditPRV and AuditVerify we use an hash function however we have this issue :
/// The hash function outputs elements over 256 bits. However, scalars are defined
/// over Zp with p << 2^256. Therefore we need to apply a modulus to the digest to be sure that
/// we have a canonical input every time.
/// We use the crate crypto bigint : we transform the digest into a bigint, apply modulus on the
/// bigint and generate a scalar from the little endian bitwise representation of the bigint.
pub fn digest_into_scalar(value_before_modulus: Hash) -> Scalar {
    let p = U256::from_be_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let bigint: U256 = U256::from_be_slice(value_before_modulus.as_bytes());
    let value_mod_p: U256 = bigint.reduce(&p).unwrap();
    if U256::is_zero(&value_mod_p).unwrap_u8() == 1 {
        return Scalar::from_bytes(&bigint.to_le_bytes()).unwrap();
    }
    let resulting_scalar: Scalar = Scalar::from_bytes(&value_mod_p.to_le_bytes()).unwrap();
    resulting_scalar
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key_gen::Protego;

    /*
      Description of the interactions :
          1) We generate the user and authorities keys
          2) We encode the upk under apk
          3) We generate a proof of good encoding
          4) We verify the proof
    */
    #[test]
    fn do_protocol_correctly() {
        //First step
        let key_generator = Protego::setup(1, 1);
        let user_keys = key_generator.uk_gen();
        let authority_keys = key_generator.aak_gen();

        //Second step
        let (enc, alpha) = Auditing::audit_enc(&user_keys, &authority_keys);

        //Third step
        let (c, z_1, z_2) = Auditing::audit_prv(&enc, &alpha, &user_keys, &authority_keys);

        //Fourth step
        let verify = Auditing::audit_verify(&authority_keys, &enc, &c, &z_1, &z_2);
        assert_eq!(verify, true);
    }
    #[test]
    fn do_enc_dec() {
        //First step
        let key_generator = Protego::setup(1, 1);
        let user_keys = key_generator.uk_gen();
        let authority_keys = key_generator.aak_gen();

        //Second step
        let (enc, _alpha) = Auditing::audit_enc(&user_keys, &authority_keys);

        //Third step
        let upk = Auditing::audit_dec(&enc, &authority_keys);

        //Fourth step
        assert_eq!(upk, user_keys.upk_1);
    }
}
