use super::u8msm;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::{CryptoRng, RngCore};

pub fn setup<G: CurveGroup>(csrng: &mut (impl RngCore + CryptoRng), d: usize) -> Vec<G::Affine> {
    (0..d).map(|_| G::Affine::rand(csrng)).collect()
}

pub fn commit<G: CurveGroup>(ck: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    G::msm_unchecked(&ck, &scalars)
}

// fn commit_sparse_u8<G: CurveGroup>(ck: &[G::Affine], scalars: &SparseVec<u8>) -> G {
//     let mut short_ck = Vec::new();
//     let mut short_scalars = Vec::new();
//     for (&i, &s) in scalars {
//         short_ck.push(ck[i]);
//         short_scalars.push(s)
//     }
//     commit_u8(&short_ck, &short_scalars)
// }

// pub fn commit_sparse<G: CurveGroup>(ck: &[G::Affine], scalars: &SparseVec<G::ScalarField>) -> G {
//     let mut short_ck = Vec::new();
//     let mut short_scalars = Vec::new();
//     for (&i, &s) in scalars {
//         short_ck.push(ck[i]);
//         short_scalars.push(s)
//     }
//     commit(&short_ck, &short_scalars)
// }

pub fn commit_u8<G: CurveGroup>(ck: &[G::Affine], u8scalars: &[u8]) -> G {
    u8msm::u8msm(ck, u8scalars)
}
