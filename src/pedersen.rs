#![allow(non_snake_case)]
use std::ops::Mul;

use super::u8msm;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::{CryptoRng, RngCore};

pub struct CommitmentKey<G: CurveGroup> {
    pub vec_G: Vec<G::Affine>,
    pub H: G::Affine,
    pub G: G::Affine,
}

pub fn setup<G: CurveGroup>(csrng: &mut (impl RngCore + CryptoRng), d: usize) -> CommitmentKey<G> {
    CommitmentKey {
        // vec_G: (0..d).map(|_| G::Affine::generator()).collect(),
        vec_G: (0..d).map(|_| G::Affine::rand(csrng)).collect(),
        H: G::Affine::rand(csrng),
        G: G::Affine::rand(csrng),
    }
}

pub fn commit<G: CurveGroup>(ck: &CommitmentKey<G>, scalars: &[G::ScalarField]) -> G {
    G::msm_unchecked(&ck.vec_G, scalars)
}

/// Commit to `scalars`. Return commitment and blinder.
pub fn commit_hiding<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    ck: &CommitmentKey<G>,
    scalars: &[G::ScalarField],
) -> (G, G::ScalarField) {
    let blinder = G::ScalarField::rand(csrng);
    let C = if scalars.len() == 1 {
        ck.G.mul(scalars[0]) + ck.H.mul(blinder)
    } else {
        G::msm_unchecked(&ck.vec_G, scalars) + ck.H.mul(blinder)
    };
    (C, blinder)
}

pub fn commit_u8<G: CurveGroup>(ck: &CommitmentKey<G>, u8scalars: &[u8]) -> G {
    u8msm::u8msm(&ck.vec_G, u8scalars)
}

pub fn commit_hiding_u8<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    ck: &CommitmentKey<G>,
    u8scalars: &[u8],
) -> (G, G::ScalarField) {
    let blinder = G::ScalarField::rand(csrng);
    let C = if u8scalars.len() == 1 {
        ck.G.mul(G::ScalarField::from(u8scalars[0])) + ck.H.mul(blinder)
    } else {
        u8msm::u8msm::<G>(&ck.vec_G, u8scalars) + ck.H.mul(blinder)
    };
    (C, blinder)
}
