#![allow(non_snake_case)]
use std::ops::Mul;

use super::u8msm;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::{CryptoRng, RngCore};

pub struct CommitmentKey<G: CurveGroup> {
    pub vec_G: Vec<G::Affine>,
    pub H: G::Affine,
}

pub fn setup<G: CurveGroup>(csrng: &mut (impl RngCore + CryptoRng), d: usize) -> CommitmentKey<G> {
    CommitmentKey {
        vec_G: (0..d).map(|_| G::Affine::rand(csrng)).collect(),
        H: G::Affine::rand(csrng),
    }
}

pub fn commit<G: CurveGroup>(ck: &CommitmentKey<G>, scalars: &[G::ScalarField]) -> G {
    G::msm_unchecked(&ck.vec_G, &scalars)
}

/// Commit to `scalars`. Return commitment and blinder.
pub fn commit_hiding<G: CurveGroup>(csrng: &mut (impl RngCore + CryptoRng), ck: &CommitmentKey<G>, scalars: &[G::ScalarField]) -> (G, G::ScalarField) {
    let blinder = G::ScalarField::rand(csrng);
    let C = G::msm_unchecked(&ck.vec_G, &scalars) + ck.H.mul(blinder);
    (C, blinder)
}

pub fn commit_u8<G: CurveGroup>(ck: &CommitmentKey<G>, u8scalars: &[u8]) -> G {
    u8msm::u8msm(&ck.vec_G, u8scalars)
}
