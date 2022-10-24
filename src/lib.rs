//!
//! This library implements [Protego](https://eprint.iacr.org/2022/661), an
//! attribute-based anonymous credential scheme based on Structure-Preserving
//! Signatures on Equivalence Classes.
//!
//! The Mercurial signatures implemented follow the specification given in E.
//! Crites' PhD dissertation as described in [Section
//! 3.1](https://repository.library.brown.edu/studio/item/bdr:918764/). Two
//! implementations are provided with this library. The first one is based on
//! Barreto-Naehrig curves and is due to Michael Burkhart. The second one, used
//! in Protego, is based on the BLS12-381 crate and is based on Burkhart's
//! [implementation](https://github.com/burkh4rt/Mercurial-Signatures).

extern crate bencher;
extern crate blake3;
extern crate bls12_381;
extern crate bn;
extern crate crypto_bigint;
extern crate ff;
extern crate rand;

pub use blake3::hash;
pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
pub use crypto_bigint::U256;
pub use ff::Field;

pub mod audit;
pub mod key_gen;
pub mod merc_signatures_using_bn;
pub mod mercurial_signatures;
pub mod nizk;
pub mod polynomial;
pub mod protocol;
pub mod revocation_accumulator;
pub mod scds;

pub use crate::audit::*;
pub use crate::merc_signatures_using_bn::*;
pub use crate::mercurial_signatures::*;
pub use crate::nizk::*;
pub use crate::scds::*;
