//! Benching of the functionnalities are performed with bencher crate. They can
//! be run using 'cargo bench'. However, they can take several dozens of minutes
//! to run exhaustively (depending on the hardware).

use blake3::Hasher;
use bls12_381::{G1Affine, G1Projective, G2Projective, Scalar};
use bn::{Fr, G1};
use criterion::{criterion_group, criterion_main, Criterion};
use protego::key_gen::{AuthorityKey, Protego, UserKey};
use protego::polynomial::Polynomial;
use protego::protocol::MockProtocol;
use protego::revocation_accumulator::RevocationAccumulator;
use protego::{
    random_z_star_p, Auditing, EncryptedKey, MercurialSignature, MercurialSignatureBis,
    MercurialSignatureScheme, MercurialSignatureSchemeBn, CRS, SCDS,
};

/// Signature length
const PKSIZE: usize = 7;

/// The benchmarks are functions defined here and you pass their name to a macro named criterion_group!
/// Here we define different benchmarks, in this file they are organised by category such as audit,
/// signature, etc...
/// To run the benchmark generation you have to have exactly one criterion_group! defined (there
/// are several written at the end of the file)

/* Bench of mercurial signatures, using bn library for computations */
// given all element just computes the signature of a message
pub fn sign_messages_bn(message: &Vec<G1>, scheme: &MercurialSignatureSchemeBn, sk: &Vec<Fr>) {
    let _signature = scheme.bn_sign(sk, message);
}

pub fn bn_sign_7_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureSchemeBn::bn_new(7);
    let (sk, _pk) = scheme.bn_key_gen();
    let message = scheme.bn_random_message();
    c.bench_function("Sign 7 attributes with BN curve", |b| {
        b.iter(|| {
            sign_messages_bn(&message, &scheme, &sk);
        })
    });
}

pub fn bn_sign_10_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureSchemeBn::bn_new(10);
    let (sk, _pk) = scheme.bn_key_gen();
    let message = scheme.bn_random_message();
    c.bench_function("Sign 10 attributes with BN curve", |b| {
        b.iter(|| {
            sign_messages_bn(&message, &scheme, &sk);
        })
    });
}
pub fn bn_sign_100_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureSchemeBn::bn_new(100);
    let (sk, _pk) = scheme.bn_key_gen();
    let message = scheme.bn_random_message();
    c.bench_function("Sign 100 attributes with BN curve", |b| {
        b.iter(|| {
            sign_messages_bn(&message, &scheme, &sk);
        })
    });
}

/* Bench of mercurial signatures, using bls12_381 library for computations */

//Randomize message and signature before verifying
pub fn do_prot_with_change_representation(
    message: &Vec<G1Projective>,
    _scheme: &MercurialSignatureScheme,
    pk: &Vec<G2Projective>,
    signature: &MercurialSignature,
) {
    let mu = random_z_star_p();
    let rho = random_z_star_p();
    let _pk = MercurialSignatureScheme::convert_pk(&pk, &rho);
    let (_message, _signature) =
        MercurialSignatureScheme::change_rep(message, signature, &mu, &rho);
}

// Only checks the pairings
pub fn do_verification(
    message: &Vec<G1Projective>,
    scheme: &MercurialSignatureScheme,
    pk: &Vec<G2Projective>,
    signature: &MercurialSignature,
) -> bool {
    scheme.verify(pk, message, signature)
}

// given all element just computes the signature of a message
pub fn sign_messages(
    message: &Vec<G1Projective>,
    scheme: &MercurialSignatureScheme,
    sk: &Vec<Scalar>,
) {
    let _signature = scheme.sign(sk, message);
}

pub fn change_representation_sign_verify_7(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(7);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Change representation of signature on 7 elements", |b| {
        b.iter(|| do_prot_with_change_representation(&message, &scheme, &pk, &signature))
    });
}

pub fn change_representation_sign_verify_10(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(10);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Change representation of signature on 10 elements", |b| {
        b.iter(|| do_prot_with_change_representation(&message, &scheme, &pk, &signature))
    });
}

pub fn change_representation_sign_verify_100(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(100);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Change representation of signature on 100 elements", |b| {
        b.iter(|| do_prot_with_change_representation(&message, &scheme, &pk, &signature))
    });
}

pub fn signature_verification_7_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(7);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Signature verification for 7 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn signature_verification_10_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(10);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Signature verification for 10 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn signature_verification_100_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(100);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("Signature verification for 100 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn sign_7_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(7);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("Signature on 7 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk);
        })
    });
}

pub fn sign_10_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(10);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("Signature on 10 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk);
        })
    });
}

pub fn sign_100_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(100);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("Signature on 100 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk);
        })
    });
}

/* Benching of auditing functionalities */
//Encrypts the user public key under the authority public key
fn do_encryption(ukeys: &UserKey, akeys: &AuthorityKey) {
    let (_enc, _alpha) = Auditing::audit_enc(ukeys, akeys);
}

//Decrypts the previously encrypted user key
fn do_decryption(enc: &EncryptedKey, akeys: &AuthorityKey) {
    let _upk = Auditing::audit_dec(enc, akeys);
}

//Generates a proof of good encryption of the user key under authority's
fn do_gen_proof(enc: &EncryptedKey, alpha: &Scalar, usk: &UserKey, apk: &AuthorityKey) {
    let (_c, _z_1, _z_2) = Auditing::audit_prv(&enc, &alpha, &usk, &apk);
}

//Verifies the proof of good encryption
pub fn do_proof_verification(
    apk: &AuthorityKey,
    enc: &EncryptedKey,
    c: &Scalar,
    z_1: &Scalar,
    z_2: &Scalar,
) {
    let _verify = Auditing::audit_verify(&apk, &enc, &c, &z_1, &z_2);
}

//Applies the previously defined functions
pub fn audit_encryption(c: &mut Criterion) {
    let key_generator = Protego::setup(1, 1);
    let user_keys = key_generator.uk_gen();
    let authority_keys = key_generator.aak_gen();

    c.bench_function("Encryption of user key under authority key", |b| {
        b.iter(|| {
            do_encryption(&user_keys, &authority_keys);
        })
    });
}

pub fn audit_decryption(c: &mut Criterion) {
    let key_generator = Protego::setup(1, 1);
    let user_keys = key_generator.uk_gen();
    let authority_keys = key_generator.aak_gen();
    let (enc, _alpha) = Auditing::audit_enc(&user_keys, &authority_keys);

    c.bench_function("Decryption of user key under authority key", |b| {
        b.iter(|| {
            do_decryption(&enc, &authority_keys);
        })
    });
}

pub fn audit_gen_proof(c: &mut Criterion) {
    let key_generator = Protego::setup(1, 1);
    let user_keys = key_generator.uk_gen();
    let authority_keys = key_generator.aak_gen();
    let (enc, alpha) = Auditing::audit_enc(&user_keys, &authority_keys);

    c.bench_function("Audit Proof Generation", |b| {
        b.iter(|| {
            do_gen_proof(&enc, &alpha, &user_keys, &authority_keys);
        })
    });
}

pub fn audit_proof_verification(c1: &mut Criterion) {
    let key_generator = Protego::setup(1, 1);
    let user_keys = key_generator.uk_gen();
    let authority_keys = key_generator.aak_gen();
    let (enc, alpha) = Auditing::audit_enc(&user_keys, &authority_keys);
    let (c, z_1, z_2) = Auditing::audit_prv(&enc, &alpha, &user_keys, &authority_keys);

    c1.bench_function("Audit Proof Verification", |b| {
        b.iter(|| {
            do_proof_verification(&authority_keys, &enc, &c, &z_1, &z_2);
        })
    });
}

pub fn commit_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    c.bench_function("Commitment generation on 10 attributes", |b| {
        b.iter(|| {
            let _commit = scds.commit(&attributes);
        })
    });
}

pub fn commit_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }
    c.bench_function("Commitment generation on 100 attributes", |b| {
        b.iter(|| {
            let _commit = scds.commit(&attributes);
        })
    });
}

pub fn generate_proof_of_exponentiation_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(21);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..10 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    let alpha = random_z_star_p();
    c.bench_function("PoE generation for 10 attributes", |b| {
        b.iter(|| {
            let _proof_of_exponentiation = scds.proof_of_exponentiation(&subset, &alpha);
        })
    });
}

pub fn generate_proof_of_exponentiation_number_of_attributes_4(c: &mut Criterion) {
    let scds = SCDS::setup(15);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    let alpha = random_z_star_p();
    c.bench_function("PoE generation for 4 attributes", |b| {
        b.iter(|| {
            let _proof_of_exponentiation = scds.proof_of_exponentiation(&subset, &alpha);
        })
    });
}

pub fn open_subset_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    c.bench_function("Witness generation of selective disclosure of 4 attributes for a credential that has 10 attributes",
                     |b| b.iter(|| {
                            let _wit = scds.open_ss(&attributes, &subset, &commit);
                        }));
}

pub fn open_subset_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..96 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    c.bench_function("Witness generation of selective disclosure of 4 attributes for a credential that has 100 attributes",
                     |b| b.iter(|| {
                            let _wit = scds.open_ss(&attributes, &subset, &commit);
                        }));
}

pub fn verify_subset_with_poe_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ss(&attributes, &subset, &commit);
    let alpha = random_z_star_p();
    let proof_of_exponentiation = scds.proof_of_exponentiation(&subset, &alpha);
    c.bench_function("Verify subset of 4 attributes among 10 with PoE", |b| {
        b.iter(|| {
            scds.verify_ss(
                &commit.c,
                &subset,
                &wit,
                Option::Some(proof_of_exponentiation),
                &Some(alpha),
            );
        })
    });
}

pub fn verify_subset_with_poe_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..96 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ss(&attributes, &subset, &commit);
    let alpha = random_z_star_p();
    let proof_of_exponentiation = scds.proof_of_exponentiation(&subset, &alpha);
    c.bench_function("Verify subset of 4 attributes among 100 with PoE", |b| {
        b.iter(|| {
            scds.verify_ss(
                &commit.c,
                &subset,
                &wit,
                Option::Some(proof_of_exponentiation),
                &Some(alpha),
            );
        })
    });
}

pub fn verify_subset_without_poe_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ss(&attributes, &subset, &commit);
    c.bench_function("Verify subset of 4 attributes among 10 without PoE", |b| {
        b.iter(|| {
            scds.verify_ss(&commit.c, &subset, &wit, Option::None, &None);
        })
    });
}

pub fn verify_subset_without_poe_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..96 {
        attributes.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ss(&attributes, &subset, &commit);
    c.bench_function("Verify subset of 4 attributes among 100 without PoE", |b| {
        b.iter(|| {
            scds.verify_ss(&commit.c, &subset, &wit, Option::None, &None);
        })
    });
}

pub fn open_disjoint_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    c.bench_function("Witness generation of disjoint set of 4 attributes for a credential that has 10 attributes",
                     |b| b.iter(|| {
                         let _wit = scds.open_ds(&attributes, &disjoint, &commit);
                     }));
}

pub fn open_disjoint_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    c.bench_function("Witness generation of disjoint set of 4 attributes for a credential that has 100 attributes",
                     |b| b.iter(|| {
                         let _wit = scds.open_ds(&attributes, &disjoint, &commit);
                     }));
}

pub fn verify_disjoint_with_poe_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ds(&attributes, &disjoint, &commit);
    let alpha = random_z_star_p();
    let proof_of_exponentiation = scds.proof_of_exponentiation(&disjoint, &alpha);
    c.bench_function(
        "Verify disjoint set of 4 attributes among 10 with PoE",
        |b| {
            b.iter(|| {
                scds.verify_ds(
                    &commit.c,
                    &disjoint,
                    &wit,
                    &Option::Some(proof_of_exponentiation),
                    &Some(alpha),
                );
            })
        },
    );
}

pub fn verify_disjoint_with_poe_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ds(&attributes, &disjoint, &commit);
    let alpha = random_z_star_p();
    let proof_of_exponentiation = scds.proof_of_exponentiation(&disjoint, &alpha);
    c.bench_function(
        "Verify disjoint set of 4 attributes among 100 with PoE",
        |b| {
            b.iter(|| {
                scds.verify_ds(
                    &commit.c,
                    &disjoint,
                    &wit,
                    &Option::Some(proof_of_exponentiation),
                    &Some(alpha),
                );
            })
        },
    );
}

pub fn verify_disjoint_without_poe_number_of_attributes_10(c: &mut Criterion) {
    let scds = SCDS::setup(11);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ds(&attributes, &disjoint, &commit);
    c.bench_function(
        "Verify disjoint set of 4 attributes among 10 without PoE",
        |b| {
            b.iter(|| {
                scds.verify_ds(&commit.c, &disjoint, &wit, &Option::None, &None);
            })
        },
    );
}

pub fn verify_disjoint_without_poe_number_of_attributes_100(c: &mut Criterion) {
    let scds = SCDS::setup(101);
    let mut attributes = vec![];
    let mut disjoint = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }
    for _ in 0..4 {
        disjoint.push(random_z_star_p());
    }
    let commit = scds.commit(&attributes).unwrap();
    let wit = scds.open_ds(&attributes, &disjoint, &commit);
    c.bench_function(
        "Verify disjoint set of 4 attributes among 100 without PoE",
        |b| {
            b.iter(|| {
                scds.verify_ds(&commit.c, &disjoint, &wit, &Option::None, &None);
            })
        },
    );
}

//Obtain algorithm fully taken from protocol crate to isolate the issue part
#[allow(non_snake_case)]
pub fn issue_on_10_attributes(c: &mut Criterion) {
    let mut attributes = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
    let signer = MercurialSignatureScheme::new(PKSIZE);
    let pki = signer.key_gen();
    let mock_organisation_secret_key = pki.0.clone();
    let mock_organisation_public_key = pki.1.clone();

    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        10,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );

    //Obtain algorithm, can be found in the protocol.rs crate
    let p1 = G1Projective::generator();
    let r_1 = random_z_star_p();
    let r_2 = random_z_star_p();
    let r_3 = random_z_star_p();
    let a_1 = p1 * r_1;
    let a_2 = p1 * r_2;
    let a_3 = mock.pp.Q * r_3;

    let c_4 = mock
        .pp
        .revocation_pp
        .evaluate_monic_polynomial_for_p1(&Polynomial::from_coeffs(&vec![
            mock.pp.revocation_pp.b,
            nym.clone(),
        ]))
        * mock.user_key.usk_2;
    let c_5 = mock.pp.Q * mock.user_key.usk_2;
    let e = mock.hash_elements_in_obtain_and_issue(&a_1, &a_2, &a_3, &c_5);

    let z_1 = r_1 + e * mock.user_key.usk_1;
    let z_2 = r_2 + e * mock.user_key.usk_2;
    let z_3 = r_3 + e * mock.user_key.usk_2;
    let commitment = mock
        .pp
        .scds_pp
        .commit_with_imposed_randomizer(&attributes, &mock.user_key.usk_1)
        .unwrap();

    let r_4 = random_z_star_p();
    let c_2 = commitment.c * r_4;

    let sigma = (commitment.c, c_2, c_4, c_5, a_1, a_2, a_3, z_1, z_2, z_3);

    c.bench_function("Issue on 10 attributes", |b| {
        b.iter(|| {
            let _signature = mock.issue(&attributes, &nym, &sigma).unwrap();
        })
    });
}

#[allow(non_snake_case)]
pub fn issue_on_100_attributes(c: &mut Criterion) {
    let mut attributes = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

    let signer = MercurialSignatureScheme::new(PKSIZE);
    let pki = signer.key_gen();
    let mock_organisation_secret_key = pki.0.clone();
    let mock_organisation_public_key = pki.1.clone();

    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        101,
        10,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );

    //Obtain algorithm, can be found in the protocol.rs crate
    let p1 = G1Projective::generator();
    let r_1 = random_z_star_p();
    let r_2 = random_z_star_p();
    let r_3 = random_z_star_p();
    let a_1 = p1 * r_1;
    let a_2 = p1 * r_2;
    let a_3 = mock.pp.Q * r_3;

    let c_4 = mock
        .pp
        .revocation_pp
        .evaluate_monic_polynomial_for_p1(&Polynomial::from_coeffs(&vec![
            mock.pp.revocation_pp.b,
            nym.clone(),
        ]))
        * mock.user_key.usk_2;
    let c_5 = mock.pp.Q * mock.user_key.usk_2;
    let e = mock.hash_elements_in_obtain_and_issue(&a_1, &a_2, &a_3, &c_5);

    let z_1 = r_1 + e * mock.user_key.usk_1;
    let z_2 = r_2 + e * mock.user_key.usk_2;
    let z_3 = r_3 + e * mock.user_key.usk_2;
    let commitment = mock
        .pp
        .scds_pp
        .commit_with_imposed_randomizer(&attributes, &mock.user_key.usk_1)
        .unwrap();

    let r_4 = random_z_star_p();
    let c_2 = commitment.c * r_4;

    let sigma = (commitment.c, c_2, c_4, c_5, a_1, a_2, a_3, z_1, z_2, z_3);

    c.bench_function("Issue on 100 attributes", |b| {
        b.iter(|| {
            let _signature = mock.issue(&attributes, &nym, &sigma).unwrap();
        })
    });
}

pub fn obtain_and_issue_10_attributes(c: &mut Criterion) {
    let mut attributes = vec![];
    for _ in 0..10 {
        attributes.push(random_z_star_p());
    }
    let mock = MockProtocol::setup(11, 4);
    let nym = random_z_star_p();
    c.bench_function("Obtain and issue on 10 attributes", |b| {
        b.iter(|| {
            mock.obtain(&attributes, &nym);
        })
    });
}

pub fn obtain_and_issue_100_attributes(c: &mut Criterion) {
    let mut attributes = vec![];
    for _ in 0..100 {
        attributes.push(random_z_star_p());
    }
    let mock = MockProtocol::setup(101, 4);
    let nym = random_z_star_p();
    c.bench_function("Obtain and issue on 100 attributes", |b| {
        b.iter(|| {
            mock.obtain(&attributes, &nym);
        })
    });
}

#[allow(non_snake_case)]
fn show_with_nizk_2_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..2 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..8 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
    let mock = MockProtocol::full_setup(
        11,
        11,
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
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego: Show with a selective disclosure of 2 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let mut _omega = mock.show(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &pi,
                    &tx,
                    &nym,
                    &rho,
                    &gamma,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}

#[allow(non_snake_case)]
fn show_with_nizk_4_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
    let mock = MockProtocol::full_setup(
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego: Show with a selective disclosure of 4 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let mut _omega = mock.show(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &pi,
                    &tx,
                    &nym,
                    &rho,
                    &gamma,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}

#[allow(non_snake_case)]
fn show_with_nizk_6_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..6 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..4 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
    let mock = MockProtocol::full_setup(
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego: Show with a selective disclosure of 6 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let mut _omega = mock.show(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &pi,
                    &tx,
                    &nym,
                    &rho,
                    &gamma,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}

#[allow(non_snake_case)]
fn show_with_nizk_8_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..8 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..2 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
    let mock = MockProtocol::full_setup(
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego: Show with a selective disclosure of 8 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let mut _omega = mock.show(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &pi,
                    &tx,
                    &nym,
                    &rho,
                    &gamma,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}

#[allow(non_snake_case)]
fn show_with_nizk_10_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..10 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
    let mock = MockProtocol::full_setup(
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego: Show with a selective disclosure of 10 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let mut _omega = mock.show(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &pi,
                    &tx,
                    &nym,
                    &rho,
                    &gamma,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}

#[allow(non_snake_case)]
fn verify_with_nizk_2_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..2 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..8 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, mut org_keys) = mock.show(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &pi,
        &tx,
        &nym,
        &rho,
        &gamma,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego: Verify with a selective disclosure of 2 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify(&subset, &vec![], &mut org_keys, &tx, &mut omega);
            })
        },
    );
}

#[allow(non_snake_case)]
fn verify_with_nizk_4_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, mut org_keys) = mock.show(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &pi,
        &tx,
        &nym,
        &rho,
        &gamma,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego: Verify with a selective disclosure of 4 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify(&subset, &vec![], &mut org_keys, &tx, &mut omega);
            })
        },
    );
}

#[allow(non_snake_case)]
fn verify_with_nizk_6_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..6 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..4 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, mut org_keys) = mock.show(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &pi,
        &tx,
        &nym,
        &rho,
        &gamma,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego: Verify with a selective disclosure of 6 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify(&subset, &vec![], &mut org_keys, &tx, &mut omega);
            })
        },
    );
}

#[allow(non_snake_case)]
fn verify_with_nizk_8_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..8 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..2 {
        attributes.push(random_z_star_p());
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, mut org_keys) = mock.show(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &pi,
        &tx,
        &nym,
        &rho,
        &gamma,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego: Verify with a selective disclosure of 8 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify(&subset, &vec![], &mut org_keys, &tx, &mut omega);
            })
        },
    );
}

#[allow(non_snake_case)]
fn verify_with_nizk_10_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];

    for _ in 0..10 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }

    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];

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
        11,
        11,
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

    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, mut org_keys) = mock.show(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &pi,
        &tx,
        &nym,
        &rho,
        &gamma,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego: Verify with a selective disclosure of 10 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify(&subset, &vec![], &mut org_keys, &tx, &mut omega);
            })
        },
    );
}

#[allow(non_snake_case)]
pub fn revocation_non_membership_generation_10_revoked_nyms(c: &mut Criterion) {
    let rsk = random_z_star_p();
    let nym_3 = random_z_star_p();
    let NYM = vec![nym_3.clone()];
    let mut RNYM = vec![];
    for _ in 0..10 {
        RNYM.push(random_z_star_p());
    }
    let accumulator = RevocationAccumulator::full_setup(11, &rsk, &NYM, RNYM);
    c.bench_function(
        "Revocation: non membership witness generation for 10 revoked nyms",
        |b| {
            b.iter(|| {
                let _non_mem_wit = accumulator.non_membership_witness(&nym_3);
            });
        },
    );
}
#[allow(non_snake_case)]
pub fn revocation_non_membership_verification_10_revoked_nyms(c: &mut Criterion) {
    let rsk = random_z_star_p();
    let nym_3 = random_z_star_p();
    let NYM = vec![nym_3.clone()];
    let mut RNYM = vec![];
    for _ in 0..10 {
        RNYM.push(random_z_star_p());
    }
    let accumulator = RevocationAccumulator::full_setup(11, &rsk, &NYM, RNYM);
    let rpk = accumulator.b_i_in_g2[0] * rsk.invert().unwrap();
    let non_mem_wit = accumulator.non_membership_witness(&nym_3).unwrap();
    c.bench_function(
        "Revocation: non membership witness verification for 10 revoked nyms",
        |b| {
            b.iter(|| {
                accumulator.verify_witness(&nym_3, &non_mem_wit, &rpk);
            });
        },
    );
}
#[allow(non_snake_case)]
pub fn revocation_non_membership_generation_100_revoked_nyms(c: &mut Criterion) {
    let rsk = random_z_star_p();
    let nym_3 = random_z_star_p();
    let NYM = vec![nym_3.clone()];
    let mut RNYM = vec![];
    for _ in 0..100 {
        RNYM.push(random_z_star_p());
    }
    let accumulator = RevocationAccumulator::full_setup(101, &rsk, &NYM, RNYM);
    c.bench_function(
        "Revocation: non membership witness generation for 100 revoked nyms",
        |b| {
            b.iter(|| {
                let _non_mem_wit = accumulator.non_membership_witness(&nym_3);
            });
        },
    );
}

#[allow(non_snake_case)]
pub fn revocation_non_membership_verification_100_revoked_nyms(c: &mut Criterion) {
    let rsk = random_z_star_p();
    let nym_3 = random_z_star_p();
    let NYM = vec![nym_3.clone()];
    let mut RNYM = vec![];
    for _ in 0..10 {
        RNYM.push(random_z_star_p());
    }
    let accumulator = RevocationAccumulator::full_setup(101, &rsk, &NYM, RNYM);
    let rpk = accumulator.b_i_in_g2[0] * rsk.invert().unwrap();
    let non_mem_wit = accumulator.non_membership_witness(&nym_3).unwrap();
    c.bench_function(
        "Revocation: non membership witness verification for 100 revoked nyms",
        |b| {
            b.iter(|| {
                accumulator.verify_witness(&nym_3, &non_mem_wit, &rpk);
            });
        },
    );
}

pub fn nizk_proof_generation_5_organisations(c: &mut Criterion) {
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
    c.bench_function(
        "Malleable NIZK: Proof generation for 5 organisations",
        |b| {
            b.iter(|| {
                let _pi = protego_scheme.PPro(&org_keys, &x1, &x2, rho, gamma, n, index);
            });
        },
    );
}

pub fn nizk_proof_generation_10_organisations(c: &mut Criterion) {
    let n = 10;
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
    c.bench_function(
        "Malleable NIZK: Proof generation for 10 organisations",
        |b| {
            b.iter(|| {
                let _pi = protego_scheme.PPro(&org_keys, &x1, &x2, rho, gamma, n, index);
            });
        },
    );
}

pub fn zkeval_5_organisations(c: &mut Criterion) {
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

    c.bench_function("Malleable NIZK: ZkEval for 5 organisations", |b| {
        b.iter(|| {
            let _zkeval = protego_scheme.ZKEval(&pi, alpha, beta, n);
        });
    });
}

pub fn zkeval_10_organisations(c: &mut Criterion) {
    let n = 10;
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

    c.bench_function("Malleable NIZK: ZkEval for 10 organisations", |b| {
        b.iter(|| {
            let _zkeval = protego_scheme.ZKEval(&pi, alpha, beta, n);
        });
    });
}

pub fn nizk_proof_verification_5_organisations(c: &mut Criterion) {
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

    let zkeval = protego_scheme.ZKEval(&pi, alpha, beta, n);

    let mut x: [G2Projective; PKSIZE] = Default::default();
    let rand = alpha * rho + beta * gamma;
    for i in 0..PKSIZE {
        x[i] = org_keys[index][i] * rand;
    }
    c.bench_function("Malleable NIZK: Verification for 5 organisations", |b| {
        b.iter(|| {
            let _verify = protego_scheme.PRVer(&org_keys, &x, &zkeval, n);
        });
    });
}

pub fn nizk_proof_verification_10_organisations(c: &mut Criterion) {
    let n = 10;
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

    let zkeval = protego_scheme.ZKEval(&pi, alpha, beta, n);

    let mut x: [G2Projective; PKSIZE] = Default::default();
    let rand = alpha * rho + beta * gamma;
    for i in 0..PKSIZE {
        x[i] = org_keys[index][i] * rand;
    }
    c.bench_function("Malleable NIZK: Verification for 10 organisations", |b| {
        b.iter(|| {
            let _verify = protego_scheme.PRVer(&org_keys, &x, &zkeval, n);
        });
    });
}

//Benchmark of proof without NIZK
#[allow(non_snake_case)]
fn show_without_nizk_2_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..2 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..8 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
    // A verifier creates an access policy by signing the organisation keys
    let (vsk, _vpk) = signer.key_gen_bis();
    let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
    for i in 0..org_keys.len() {
        verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
    }
    //Fake transaction hash
    let mut hasher = Hasher::new();
    hasher.update(&G1Affine::generator().to_compressed());
    let tx = hasher.finalize();
    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego Duo: Show with a selective disclosure of 2 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let _omega = mock.show_no_nizk(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &verifier_access_policy,
                    &tx,
                    &nym,
                    2,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}
#[allow(non_snake_case)]
fn show_without_nizk_4_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
    // A verifier creates an access policy by signing the organisation keys
    let (vsk, _vpk) = signer.key_gen_bis();
    let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
    for i in 0..org_keys.len() {
        verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
    }
    //Fake transaction hash
    let mut hasher = Hasher::new();
    hasher.update(&G1Affine::generator().to_compressed());
    let tx = hasher.finalize();
    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego Duo: Show with a selective disclosure of 4 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let _omega = mock.show_no_nizk(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &verifier_access_policy,
                    &tx,
                    &nym,
                    2,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}
#[allow(non_snake_case)]
fn show_without_nizk_6_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..6 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..4 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
    // A verifier creates an access policy by signing the organisation keys
    let (vsk, _vpk) = signer.key_gen_bis();
    let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
    for i in 0..org_keys.len() {
        verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
    }
    //Fake transaction hash
    let mut hasher = Hasher::new();
    hasher.update(&G1Affine::generator().to_compressed());
    let tx = hasher.finalize();
    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego Duo: Show with a selective disclosure of 6 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let _omega = mock.show_no_nizk(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &verifier_access_policy,
                    &tx,
                    &nym,
                    2,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}
#[allow(non_snake_case)]
fn show_without_nizk_8_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..8 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..2 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
    // A verifier creates an access policy by signing the organisation keys
    let (vsk, _vpk) = signer.key_gen_bis();
    let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
    for i in 0..org_keys.len() {
        verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
    }
    //Fake transaction hash
    let mut hasher = Hasher::new();
    hasher.update(&G1Affine::generator().to_compressed());
    let tx = hasher.finalize();
    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego Duo: Show with a selective disclosure of 8 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let _omega = mock.show_no_nizk(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &verifier_access_policy,
                    &tx,
                    &nym,
                    2,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}
#[allow(non_snake_case)]
fn show_without_nizk_10_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..10 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
    // A verifier creates an access policy by signing the organisation keys
    let (vsk, _vpk) = signer.key_gen_bis();
    let mut verifier_access_policy: Vec<MercurialSignatureBis> = vec![];
    for i in 0..org_keys.len() {
        verifier_access_policy.push(signer.sign_elements_in_G2(&vsk, &org_keys[i].to_vec()));
    }
    //Fake transaction hash
    let mut hasher = Hasher::new();
    hasher.update(&G1Affine::generator().to_compressed());
    let tx = hasher.finalize();
    //Full initialisation of the party that plays all the roles in the transaction
    let mock = MockProtocol::full_setup(
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    c.bench_function(
        "Protego Duo: Show with a selective disclosure of 10 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                let (_omega, _org_keys2) = mock.show_no_nizk(
                    cred.clone(),
                    &attributes,
                    &subset,
                    &vec![],
                    &mut org_keys,
                    &verifier_access_policy,
                    &tx,
                    &nym,
                    2,
                    true,
                    true,
                    true,
                );
            })
        },
    );
}
#[allow(non_snake_case)]
fn verify_without_nizk_2_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..2 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..8 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, _org_keys2) = mock.show_no_nizk(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &verifier_access_policy,
        &tx,
        &nym,
        2,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego Duo: Verify with a selective disclosure of 2 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify_no_nizk(&subset, &vec![], &mut org_keys, &tx, &mut omega, &vpk);
            })
        },
    );
}
#[allow(non_snake_case)]
fn verify_without_nizk_4_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..4 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..6 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, _org_keys2) = mock.show_no_nizk(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &verifier_access_policy,
        &tx,
        &nym,
        2,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego Duo: Verify with a selective disclosure of 4 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify_no_nizk(&subset, &vec![], &mut org_keys, &tx, &mut omega, &vpk);
            })
        },
    );
}
#[allow(non_snake_case)]
fn verify_without_nizk_6_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..6 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..4 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, _org_keys2) = mock.show_no_nizk(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &verifier_access_policy,
        &tx,
        &nym,
        2,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego Duo: Verify with a selective disclosure of 6 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify_no_nizk(&subset, &vec![], &mut org_keys, &tx, &mut omega, &vpk);
            })
        },
    );
}
#[allow(non_snake_case)]
fn verify_without_nizk_8_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..8 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    for _ in 0..2 {
        attributes.push(random_z_star_p());
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, _org_keys2) = mock.show_no_nizk(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &verifier_access_policy,
        &tx,
        &nym,
        2,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego Duo: Verify with a selective disclosure of 8 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify_no_nizk(&subset, &vec![], &mut org_keys, &tx, &mut omega, &vpk);
            })
        },
    );
}
#[allow(non_snake_case)]
fn verify_without_nizk_10_attributes(c: &mut Criterion) {
    //Initialisation of attributes and (non)revoked nym
    let signer = MercurialSignatureScheme::new(7);
    let mut attributes = vec![];
    let mut subset = vec![];
    for _ in 0..10 {
        let tmp = random_z_star_p();
        attributes.push(tmp.clone());
        subset.push(tmp);
    }
    let nym = random_z_star_p();
    let NYM = vec![nym.clone()];
    let RNYM = vec![
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
        random_z_star_p(),
    ];
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
        11,
        11,
        &NYM,
        RNYM,
        &mock_organisation_secret_key,
        &mock_organisation_public_key,
    );
    let cred = mock.obtain(&attributes, &nym);
    let (mut omega, _org_keys2) = mock.show_no_nizk(
        cred,
        &attributes,
        &subset,
        &vec![],
        &mut org_keys,
        &verifier_access_policy,
        &tx,
        &nym,
        2,
        true,
        true,
        true,
    );
    c.bench_function(
        "Protego Duo: Verify with a selective disclosure of 10 attributes for a credential that has 10 attributes",
        |b| {
            b.iter(|| {
                mock.verify_no_nizk(&subset, &vec![], &mut org_keys, &tx, &mut omega, &vpk);
            })
        },
    );
}

//To benchmark signatures using bls uncomment the following instruction and comment the others
/*criterion_group!(
    benches,
    signature_verification_7_attributes,
    signature_verification_10_attributes,
    signature_verification_100_attributes,
    sign_7_attributes,
    sign_10_attributes,
    sign_100_attributes,
    change_representation_sign_verify_7,
    change_representation_sign_verify_10,
    change_representation_sign_verify_100
);*/

//To benchmark signatures using bn curve uncomment the following instruction and comment the others
/*criterion_group!(
    benches,
    bn_sign_7_attributes,
    bn_sign_10_attributes,
    bn_sign_100_attributes
);*/

// To benchmark the audit part, uncomment the following instruction and comment the others
/*criterion_group!(
    benches,
    audit_encryption,
    audit_decryption,
    audit_gen_proof,
    audit_proof_verification
);*/

//To benchmark set commitment uncomment the following instruction and comment the others
/*criterion_group!(
    benches,
    commit_number_of_attributes_10,
    commit_number_of_attributes_100,
    generate_proof_of_exponentiation_number_of_attributes_10,
    generate_proof_of_exponentiation_number_of_attributes_4,
    open_subset_number_of_attributes_4,
    open_subset_number_of_attributes_10,
    open_subset_number_of_attributes_100,
    verify_subset_with_poe_number_of_attributes_4,
    verify_subset_with_poe_number_of_attributes_10,
    verify_subset_with_poe_number_of_attributes_100,
    verify_subset_without_poe_number_of_attributes_4,
    verify_subset_without_poe_number_of_attributes_10,
    verify_subset_without_poe_number_of_attributes_100
);*/

/*criterion_group!(
    benches,
    open_disjoint_number_of_attributes_4,
    open_disjoint_number_of_attributes_10,
    open_disjoint_number_of_attributes_100,
    verify_disjoint_with_poe_number_of_attributes_4,
    verify_disjoint_with_poe_number_of_attributes_10,
    verify_disjoint_with_poe_number_of_attributes_100,
    verify_disjoint_without_poe_number_of_attributes_4,
    verify_disjoint_without_poe_number_of_attributes_10,
    verify_disjoint_without_poe_number_of_attributes_100
);*/

//To benchmark Protego and Protego Duo uncomment the following instruction and comment the others
/*criterion_group!(
    benches,
    issue_on_10_attributes,
    obtain_and_issue_10_attributes,
    show_with_nizk_2_attributes,
    show_with_nizk_4_attributes,
    show_with_nizk_6_attributes,
    show_with_nizk_8_attributes,
    show_with_nizk_10_attributes,
    verify_with_nizk_2_attributes,
    verify_with_nizk_4_attributes,
    verify_with_nizk_6_attributes,
    verify_with_nizk_8_attributes,
    verify_with_nizk_10_attributes,
    show_without_nizk_2_attributes,
    show_without_nizk_4_attributes,
    show_without_nizk_6_attributes,
    show_without_nizk_8_attributes,
    show_without_nizk_10_attributes,
    verify_without_nizk_2_attributes,
    verify_without_nizk_4_attributes,
    verify_without_nizk_6_attributes,
    verify_without_nizk_8_attributes,
    verify_without_nizk_10_attributes,
);*/

//To benchmark the results provided in the paper uncomment the following and comment the others
criterion_group!(
    benches,
    bn_sign_7_attributes,
    bn_sign_10_attributes,
    bn_sign_100_attributes,
    sign_7_attributes,
    sign_10_attributes,
    sign_100_attributes,
    signature_verification_7_attributes,
    signature_verification_10_attributes,
    signature_verification_100_attributes,
    change_representation_sign_verify_7,
    change_representation_sign_verify_10,
    change_representation_sign_verify_100,
    audit_gen_proof,
    audit_proof_verification,
    nizk_proof_generation_5_organisations,
    nizk_proof_generation_10_organisations,
    nizk_proof_verification_5_organisations,
    nizk_proof_verification_10_organisations,
    zkeval_5_organisations,
    zkeval_10_organisations,
    revocation_non_membership_generation_10_revoked_nyms,
    revocation_non_membership_generation_100_revoked_nyms,
    revocation_non_membership_verification_10_revoked_nyms,
    revocation_non_membership_verification_100_revoked_nyms,
    issue_on_10_attributes,
    issue_on_100_attributes,
    obtain_and_issue_10_attributes,
    obtain_and_issue_100_attributes,
    show_with_nizk_2_attributes,
    show_with_nizk_4_attributes,
    show_with_nizk_6_attributes,
    show_with_nizk_8_attributes,
    show_with_nizk_10_attributes,
    verify_with_nizk_2_attributes,
    verify_with_nizk_4_attributes,
    verify_with_nizk_6_attributes,
    verify_with_nizk_8_attributes,
    verify_with_nizk_10_attributes,
    show_without_nizk_2_attributes,
    show_without_nizk_4_attributes,
    show_without_nizk_6_attributes,
    show_without_nizk_8_attributes,
    show_without_nizk_10_attributes,
    verify_without_nizk_2_attributes,
    verify_without_nizk_4_attributes,
    verify_without_nizk_6_attributes,
    verify_without_nizk_8_attributes,
    verify_without_nizk_10_attributes,
);

criterion_main!(benches);
