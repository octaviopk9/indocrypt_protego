#[allow(unused_imports)]
use crate::mercurial_signatures::{random_z_p, random_z_star_p, MercurialSignatureScheme};
use crate::scds::BG;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
/// Signature length
const PKSIZE: usize = 7;

/// In addition of the usual bilinear group elements we consider an additional point and an optional
/// trapdoor
#[derive(Clone)]
pub struct CRS {
    bg: BG,
    z: G1Projective,
    _z: Option<Scalar>,
}

/// Initial proof computed once by the user, it's a combination of two proofs with the same shared
/// randomness.
pub struct ExtProof {
    pub(crate) a1: Vec<[G2Projective; PKSIZE]>,
    pub(crate) a2: Vec<[G2Projective; PKSIZE]>,
    pub(crate) d1: Vec<G1Projective>,
    pub(crate) d2: Vec<G1Projective>,
    pub(crate) z: Vec<G1Projective>,
    pub(crate) zz: G2Projective,
}

/// Modified proof, obtained by randomizing the ExtProof so it looks fresh, unlinkable to the previous one
pub struct Proof {
    pub(crate) a1: Vec<[G2Projective; PKSIZE]>,
    pub(crate) d1: Vec<G1Projective>,
    pub(crate) z: Vec<G1Projective>,
    pub(crate) zz: G2Projective,
}

#[allow(non_snake_case, non_camel_case_types)]
impl CRS {
    /// Setup the CRS for the NIZK, trapdoor is discarded
    pub fn PGen() -> CRS {
        let bg = BG::bg_gen();
        let z1 = random_z_p();
        let z = bg.p1 * z1;
        CRS { bg, z, _z: None }
    }

    pub fn PGen_with_imposed_random(z1: Scalar) -> CRS {
        let bg = BG::bg_gen();
        let z = bg.p1 * z1;
        CRS { bg, z, _z: None }
    }

    /// Setup the CRS for the NIZK, trapdoor is returned and not destroyed
    pub fn TPGen() -> CRS {
        let bg = BG::bg_gen();
        let z1 = random_z_p();
        let z = bg.p1 * z1;
        CRS {
            bg,
            z,
            _z: Some(z1),
        }
    }

    /// Computes two NIZK proofs sharing the same randomness for statements:
    /// x1 = w1*org_keys\[index\] and x2 = w2*org_keys\[index\]
    #[allow(clippy::too_many_arguments)]
    pub fn PPro(
        &self,
        org_keys: &[[G2Projective; PKSIZE]],
        x1: &[G2Projective; PKSIZE],
        x2: &[G2Projective; PKSIZE],
        w1: Scalar,
        w2: Scalar,
        n: usize,
        index: usize,
    ) -> ExtProof {
        //index is s.t xi = wi*org_keys[index]
        let mut a1: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        let mut a2: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        let mut d1_g1: Vec<G1Projective> = Vec::with_capacity(n);
        let mut d2_g1: Vec<G1Projective> = Vec::with_capacity(n);
        let mut z_g1: Vec<G1Projective> = Vec::with_capacity(n);
        let mut z_zp: Vec<Scalar> = Vec::with_capacity(n);
        let mut d1_zp: Vec<Scalar> = Vec::with_capacity(n);
        let mut d2_zp: Vec<Scalar> = Vec::with_capacity(n);

        //We are sure that we will access each of those n elements and use them, no more
        unsafe {
            a1.set_len(n);
            a2.set_len(n);
            d1_g1.set_len(n);
            d2_g1.set_len(n);
            z_g1.set_len(n);
            z_zp.set_len(n);
            d1_zp.set_len(n);
            d2_zp.set_len(n);
        }

        let mut z_sum = G1Projective::identity();

        // for all keys that are not the randomized one do
        for i in 0..n {
            if i != index {
                let d1i = random_z_star_p();
                d1_zp[i] = d1i;
                let d2i = random_z_star_p();
                d2_zp[i] = d2i;
                let zi = random_z_star_p();
                z_zp[i] = zi;
                let zgi = self.bg.p1 * zi;
                z_g1[i] = zgi;
                z_sum += zgi;
                d1_g1[i] = self.bg.p1 * d1i;
                d2_g1[i] = self.bg.p1 * d2i;
                for j in 0..PKSIZE {
                    a1[i][j] = (org_keys[i][j] * d1_zp[i]) - (x1[j] * z_zp[i]);
                    a2[i][j] = (org_keys[i][j] * d2_zp[i]) - (x2[j] * z_zp[i]);
                }
            }
        }
        let delta = random_z_star_p();
        d1_zp[index] = random_z_star_p();
        d2_zp[index] = random_z_star_p();
        z_g1[index] = (self.z * delta) - z_sum;

        // compute "a" and "d" for the witness
        let r1 = random_z_star_p();
        let r2 = random_z_star_p();
        for j in 0..PKSIZE {
            a1[index][j] = org_keys[index][j] * r1;
            a2[index][j] = org_keys[index][j] * r2;
        }
        d1_g1[index] = z_g1[index] * w1 + (self.bg.p1 * r1);
        d2_g1[index] = z_g1[index] * w2 + (self.bg.p1 * r2);

        let zz = self.bg.p2 * delta;

        ExtProof {
            a1,
            d1: d1_g1,
            a2,
            d2: d2_g1,
            z: z_g1,
            zz,
        }
    }

    /// User randomizes its extended proof to obtain a fresh NIZK to hide the credential issuer
    pub fn ZKEval(&self, pi: &ExtProof, alpha: Scalar, beta: Scalar, n: usize) -> Proof {
        let mut a1: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        let mut d1: Vec<G1Projective> = Vec::with_capacity(n);
        let mut z: Vec<G1Projective> = Vec::with_capacity(n);

        unsafe {
            a1.set_len(n);
            d1.set_len(n);
            z.set_len(n);
        }

        let delta = random_z_star_p();
        let zz = pi.zz * delta;
        let rand1 = delta * alpha;
        let rand2 = delta * beta;

        for i in 0..n {
            z[i] = pi.z[i] * delta;
            d1[i] = pi.d1[i] * rand1 + pi.d2[i] * rand2;
            for j in 0..PKSIZE {
                a1[i][j] = pi.a1[i][j] * rand1 + pi.a2[i][j] * rand2;
            }
        }

        Proof { a1, d1, z, zz }
    }

    /// Verifies the pairings in accordance of the given proof. If the proof was honestly generated
    /// the pairings hold for all organization keys, including the one that signed the showing.
    pub fn PRVer(
        &self,
        org_keys: &[[G2Projective; PKSIZE]],
        x: &[G2Projective; PKSIZE],
        pi: &Proof,
        n: usize,
    ) -> bool {
        let mut z_sum = G1Projective::identity();
        for &point in &pi.z {
            z_sum += point;
        }
        //Checks if e(z,Z2) = e(z_sum,1)
        let pair_1 = pairing(&G1Affine::from(self.z), &G2Affine::from(pi.zz));
        let pair_2 = pairing(&G1Affine::from(z_sum), &G2Affine::from(self.bg.p2));
        if pair_1.ne(&pair_2) {
            return false;
        }
        //Checks the rest of the paring equations
        for (i, orgkeys) in org_keys.iter().enumerate().take(n) {
            for (j, key) in x.iter().enumerate().take(PKSIZE) {
                let pair_1 = pairing(&G1Affine::from(pi.d1[i]), &G2Affine::from(orgkeys[j]));
                let pair_2 = pairing(&G1Affine::from(pi.z[i]), &G2Affine::from(key));
                let pair_3 = pairing(&G1Affine::from(self.bg.p1), &G2Affine::from(pi.a1[i][j]));
                let pair_res = pair_2 + pair_3;
                if pair_1.ne(&pair_res) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn do_nizk_length_5() {
        let n = 5;
        let protego_scheme = CRS::PGen();
        let scheme = MercurialSignatureScheme::new(PKSIZE);
        let mut org_keys: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        unsafe {
            org_keys.set_len(n);
        }
        //generate a set of random keys
        for i in 0..n {
            let pki = scheme.key_gen().1;
            for j in 0..PKSIZE {
                org_keys[i][j] = pki[j];
            }
        }
        //randomize the key for given index
        let index = 4;
        let mut x1: [G2Projective; PKSIZE] = Default::default();
        let mut x2: [G2Projective; PKSIZE] = Default::default();
        let rho = random_z_star_p();
        let gamma = random_z_star_p();
        for i in 0..PKSIZE {
            x1[i] = org_keys[index][i] * rho;
            x2[i] = org_keys[index][i] * gamma;
        }
        let pi = protego_scheme.PPro(&org_keys, &x1, &x2, rho, gamma, n, index);

        let alpha = random_z_star_p();
        let beta = random_z_star_p();
        /*
        let pi_short = Proof {
            a1: pi.a1,
            d1: pi.d1,
            z: pi.z,
            zz: pi.zz,
        };

        let verify1 = protego_scheme.PRVer(&org_keys, &x1, &pi_short, n);
        assert_eq!(verify1, true);
        */
        let zkeval = protego_scheme.ZKEval(&pi, alpha, beta, n);

        let mut x: [G2Projective; PKSIZE] = Default::default();
        let rand = alpha * rho + beta * gamma;
        for i in 0..PKSIZE {
            x[i] = org_keys[index][i] * rand;
        }

        let verify = protego_scheme.PRVer(&org_keys, &x, &zkeval, n);
        assert_eq!(verify, true);
    }
}

/// In order to compute PPro once at server launch we need to have a structure that can be copied / cloned
/// so it can be moved to the closure created by the server. Vec cannot be copied or cloned so we can
/// deconstruct them into their components. So for each vector we create 5 of their components that will
/// be reconstructed in the extended proof used in the NIZK (ZKEval)
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct ExtProofSerializableFor5Organisations {
    pub(crate) a1_1: [G2Projective; PKSIZE],
    pub(crate) a1_2: [G2Projective; PKSIZE],
    pub(crate) a1_3: [G2Projective; PKSIZE],
    pub(crate) a1_4: [G2Projective; PKSIZE],
    pub(crate) a1_5: [G2Projective; PKSIZE],
    pub(crate) a2_1: [G2Projective; PKSIZE],
    pub(crate) a2_2: [G2Projective; PKSIZE],
    pub(crate) a2_3: [G2Projective; PKSIZE],
    pub(crate) a2_4: [G2Projective; PKSIZE],
    pub(crate) a2_5: [G2Projective; PKSIZE],
    pub(crate) d1_1: G1Projective,
    pub(crate) d1_2: G1Projective,
    pub(crate) d1_3: G1Projective,
    pub(crate) d1_4: G1Projective,
    pub(crate) d1_5: G1Projective,
    pub(crate) d2_1: G1Projective,
    pub(crate) d2_2: G1Projective,
    pub(crate) d2_3: G1Projective,
    pub(crate) d2_4: G1Projective,
    pub(crate) d2_5: G1Projective,
    pub(crate) z_1: G1Projective,
    pub(crate) z_2: G1Projective,
    pub(crate) z_3: G1Projective,
    pub(crate) z_4: G1Projective,
    pub(crate) z_5: G1Projective,
    pub(crate) zz: G2Projective,
}

/// Serialize / Deserialize from the structure that can be serialized and the one we use in our code
impl ExtProofSerializableFor5Organisations {
    pub fn to_ext_proof(&self) -> ExtProof {
        ExtProof {
            a1: vec![self.a1_1, self.a1_2, self.a1_3, self.a1_4, self.a1_5],
            a2: vec![self.a2_1, self.a2_2, self.a2_3, self.a2_4, self.a2_5],
            d1: vec![self.d1_1, self.d1_2, self.d1_3, self.d1_4, self.d1_5],
            d2: vec![self.d2_1, self.d2_2, self.d2_3, self.d2_4, self.d2_5],
            z: vec![self.z_1, self.z_2, self.z_3, self.z_4, self.z_5],
            zz: self.zz,
        }
    }

    pub fn from_ext_proof(ext_proof: &ExtProof) -> ExtProofSerializableFor5Organisations {
        ExtProofSerializableFor5Organisations {
            a1_1: ext_proof.a1[0],
            a1_2: ext_proof.a1[1],
            a1_3: ext_proof.a1[2],
            a1_4: ext_proof.a1[3],
            a1_5: ext_proof.a1[4],
            a2_1: ext_proof.a2[0],
            a2_2: ext_proof.a2[1],
            a2_3: ext_proof.a2[2],
            a2_4: ext_proof.a2[3],
            a2_5: ext_proof.a2[4],
            d1_1: ext_proof.d1[0],
            d1_2: ext_proof.d1[1],
            d1_3: ext_proof.d1[2],
            d1_4: ext_proof.d1[3],
            d1_5: ext_proof.d1[4],
            d2_1: ext_proof.d2[0],
            d2_2: ext_proof.d2[1],
            d2_3: ext_proof.d2[2],
            d2_4: ext_proof.d2[3],
            d2_5: ext_proof.d2[4],
            z_1: ext_proof.z[0],
            z_2: ext_proof.z[1],
            z_3: ext_proof.z[2],
            z_4: ext_proof.z[3],
            z_5: ext_proof.z[4],
            zz: ext_proof.zz,
        }
    }
}
