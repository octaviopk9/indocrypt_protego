# Protego

Library associated with the paper "Protego: Efficient, Revocable and Auditable Anonymous Credentials with Applications to Hyperledger Fabric", a paper accepted at INDOCRYPT2022. Implemented by @JeDeschamps and @octaviopk9

Disclaimer: This implementation has not been reviewed or audited beyond the authors' scrutiny. It is a prototype implementation, developed for academic purposes to validate the algorithms and protocols presented in the related paper. Some sub-routines are naive implementations whose sole purpose is to provide feasibility results. Therefore, this implementation is not intended to be used "as it is" in production and you should use it at your own risk if you wish to do so.

## Introduction

This implementation provides the main algorithms for Protego and Protego Duo. These algorithms are:

- Key generation of the different parties
- Mercurial signatures 
- Revocation accumulator
- Auditing
- Set commitment scheme
- Basic polynomial arithmetic (used in set commitments and revocation)
- Obtain and Issue, Show and Verify algorithms : these algorithms are run by the same entity at the moment in this implementation
- NIZK (implements the issuer-hiding NIZK proof used in Protego)

The protocol.rs file contains a structure we called MockProtocol which acts as the user, issuer, verifier, auditor, revocation authority.
It knows every key and can perform any public algorithm. This structure is helpful to simulate a credential issuing and usage without adding communication overhead. In a real world scenario such entity does not exist, keys and algorithms are split between users and various organisations that communicate over the network.

Each part of the scheme is defined in its respective crate, with relevant tests associated.

## Usage and Documentation
We work with a rustc 1.52.0-nightly as suggested by the bls12-381 library to avoid security issues coming with compiler optimizations.

To test the library simply clone it, and run 'cargo test --package protego --lib'

To run the benchmarks run 'cargo bench' or just 'bench'

Benchmarks are based on Criterion, a benchmarking library. This library will print on your console but for extensive statistical results with plots and easy to navigate, Criterion will generate an HTML report under 'target/criterion/report/index.html' in the project folder. Criterion runs the code you give it a varying amount of iterations, depending on the execution time of every run. In our case it tends to run every function 100 times.

To generate the library's documentation run 'cargo doc --open'

## BLS12-381
In this project you can find an implementation of mercurial signatures using a Barreto-Naehrig curve and the bls12-381. We ran performance test on both of these (equivalent) implementations and concluded that we would use the latter for our implementation as confirmed the performance improvements offered by the bls12-381 curve.

The bls12-381 is a pairing-friendly elliptic curve providing 128-bit security. 
This crate allows us to work easily with scalar in Z*, elements in G1, G2 and implements an easy-to-use Ate pairing. It overrides arithmetic operators for all these elements.

We opt to use the representation of points in G1 and G2 through their projective coordinates, although they use more memory the overhead is not problematic. This choice was made since multiplication of a point (in G1 or G2) in its affine coordinates results in a point in their projective coordinates. To avoid casting back those elements to their affine coordinates every time we don't use them. The casts are only done when necessary, ie, when points are given as parameters to the pairing function.