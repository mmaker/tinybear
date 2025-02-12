use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use nimue::{Arthur, Merlin, ProofResult};
use rand::{CryptoRng, RngCore};

use crate::pedersen::CommitmentKey;
use crate::prover::aes_prove;
use crate::sigma::{self, SigmaProof};
use crate::verifier::{aes_verify, AesCipherInstance, AeskeySchInstance};
use crate::witness::cipher::AesCipherWitness;
use crate::witness::keyschedule::AesKeySchWitness;
use crate::{umsm, witness::registry};

pub use crate::traits::*;

#[inline]
pub fn aes128_prove<'a, G: CurveGroup>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    message_opening: G::ScalarField,
    key: &[u8; 16],
    key_opening: G::ScalarField,
) -> ProofResult<&'a [u8]> {
    let witness =
        AesCipherWitness::<G::ScalarField, 11, 4>::new(message, key, message_opening, key_opening);
    aes_prove::<G, SigmaProof<G>, 11>(merlin, ck, &witness)
}

#[inline]
pub fn aes128ks_prove<'a, G: CurveGroup>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    key: [u8; 16],
    key_opening: G::ScalarField,
) -> ProofResult<&'a [u8]> {
    let witness = AesKeySchWitness::<G::ScalarField, 11, 4>::new(&key, &key_opening);
    aes_prove::<G, SigmaProof<G>, 11>(merlin, ck, &witness)
}

#[inline]
pub fn aes128_verify<G: CurveGroup>(
    arthur: &mut Arthur,
    ck: &CommitmentKey<G>,
    message_commitment: &G,
    round_keys_commitment: &G,
    ctx: [u8; 16],
) -> ProofResult<()> {
    let instance =
        AesCipherInstance::<G, 11, 4>::new(message_commitment, round_keys_commitment, ctx);
    aes_verify::<G, SigmaProof<G>, 11>(arthur, ck, &instance)
}

#[inline]
pub fn aes128ks_verify<G: CurveGroup>(
    arthur: &mut Arthur,
    ck: &CommitmentKey<G>,
    round_keys_com: G,
) -> ProofResult<()> {
    let instance = AeskeySchInstance::<G, 11, 4>::new(&round_keys_com);
    aes_verify::<G, SigmaProof<G>, 11>(arthur, ck, &instance)
}

#[inline]
pub fn aes256_prove<'a, G: CurveGroup>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    message_opening: G::ScalarField,
    key: &[u8; 32],
    key_opening: G::ScalarField,
) -> ProofResult<&'a [u8]> {
    let witness =
        AesCipherWitness::<G::ScalarField, 15, 8>::new(message, key, message_opening, key_opening);
    aes_prove::<G, SigmaProof<G>, 15>(merlin, ck, &witness)
}

#[inline]
pub fn aes256ks_prove<'a, G: CurveGroup>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    key: [u8; 32],
    key_opening: G::ScalarField,
) -> ProofResult<&'a [u8]> {
    let witness = AesKeySchWitness::<G::ScalarField, 15, 8>::new(&key, &key_opening);
    aes_prove::<G, SigmaProof<G>, 15>(merlin, ck, &witness)
}

pub fn aes256_verify<G>(
    arthur: &mut Arthur,
    ck: &CommitmentKey<G>,
    m_com: &G,
    rk_com: &G,
    ctx: [u8; 16],
) -> ProofResult<()>
where
    G: CurveGroup,
{
    let instance = AesCipherInstance::<G, 15, 8>::new(m_com, rk_com, ctx);
    aes_verify::<G, sigma::SigmaProof<G>, 15>(arthur, ck, &instance)
}

pub fn commit_message<G: CurveGroup, const R: usize>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    let m_offset = registry::aes_offsets::<R>().message;
    let m = m.iter().flat_map(|x| [x & 0xf, x >> 4]).collect::<Vec<_>>();
    let message_opening = G::ScalarField::rand(csrng);
    let message_commitment =
        crate::umsm::u8msm::<G>(&ck.vec_G[m_offset * 2..], &m) + ck.H * message_opening;

    (message_commitment, message_opening)
}

pub fn commit_aes128_message<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    commit_message::<G, 11>(csrng, ck, m)
}

pub fn commit_aes256_message<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    commit_message::<G, 15>(csrng, ck, m)
}

pub fn commit_aes128_key<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    key: &[u8; 16],
) -> (G, G::ScalarField) {
    commit_round_keys(csrng, ck, &crate::witness::aes128_keyschedule(key))
}

pub fn commit_aes256_keys<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    key: &[u8; 32],
) -> (G, G::ScalarField) {
    commit_round_keys(csrng, ck, &crate::witness::aes256_keyschedule(key))
}

fn commit_round_keys<G: CurveGroup, const R: usize>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    round_keys: &[[u8; 16]; R],
) -> (G, G::ScalarField) {
    let kk = round_keys
        .iter()
        .flatten()
        .flat_map(|x| [x & 0xf, x >> 4])
        .collect::<Vec<_>>();

    let key_opening = G::ScalarField::rand(csrng);
    let round_keys_offset = registry::aes_offsets::<R>().round_keys * 2;
    let round_keys_commitment =
        umsm::u8msm::<G>(&ck.vec_G[round_keys_offset..], &kk) + ck.H * key_opening;

    (round_keys_commitment, key_opening)
}
