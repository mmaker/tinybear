#![allow(non_snake_case)]
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::CryptoRng;
use rand::RngCore;
use std::ops::Mul;
use transcript::IOPTranscript;

use crate::linalg;
use crate::pedersen::commit_hiding;
use crate::pedersen::CommitmentKey;

#[derive(Default, CanonicalSerialize)]
pub struct SigmaProof<G: CurveGroup> {
    pub K_1: G::Affine,
    pub K_2: G::Affine,
    pub vec_z: Vec<G::ScalarField>,
    pub zeta_1: G::ScalarField,
    pub zeta_2: G::ScalarField,
}

/// Prove that <x, a> = y, where x and y are private
/// phi is blinder of vec_x
/// psi is blinder of y
pub fn lineval_prover<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,

    vec_x: &Vec<G::ScalarField>, // private
    phi: G::ScalarField,
    psi: G::ScalarField,

    vec_a: &Vec<G::ScalarField>, // public
) -> SigmaProof<G> {
    // Create the prover's blinders
    let vec_k = (0..vec_x.len())
        .map(|_| G::ScalarField::rand(csrng))
        .collect::<Vec<_>>();

    // Commit to the blinders and send the commitments to the verifier
    let (K_1, kappa_1) = commit_hiding(csrng, &ck, &vec_k);

    let (K_2, kappa_2) = commit_hiding(csrng, &ck, &[linalg::inner_product(&vec_k, &vec_a)]);

    transcript
        .append_serializable_element(b"k_gg", &[K_1, K_2])
        .unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    // Compute prover's response
    let vec_z = linalg::linear_combination(&[&vec_k, &vec_x], &[c]);
    let zeta_1 = kappa_1 + c * phi;
    let zeta_2 = kappa_2 + c * psi;

    transcript
        .append_serializable_element(b"response", &[vec_z.clone()])
        .unwrap();
    transcript
        .append_serializable_element(b"response2", &[zeta_1, zeta_2])
        .unwrap();

    SigmaProof {
        K_1: K_1.into(),
        K_2: K_2.into(),
        vec_z,
        zeta_1,
        zeta_2,
    }
}

/// Verify a proof that given commitment X, its opening x has: <x, a> = y
pub fn lineval_verifier<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,

    vec_a: &Vec<G::ScalarField>,
    X: &G,
    Y: &G,

    proof: &SigmaProof<G>,
) -> bool {
    transcript
        .append_serializable_element(b"k_gg", &[proof.K_1, proof.K_2])
        .unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    // Check (1)
    let z_i_G_i = G::msm_unchecked(&ck.vec_G, &proof.vec_z);
    assert_eq!(
        z_i_G_i + ck.H.mul(proof.zeta_1) - proof.K_1 - X.mul(c),
        G::zero()
    );

    // Check (2)
    let z_i_a_i_G_i = ck.vec_G[0].mul(&linalg::inner_product(&proof.vec_z, &vec_a));
    assert_eq!(
        z_i_a_i_G_i + ck.H.mul(proof.zeta_2) - proof.K_2 - Y.mul(c),
        G::zero()
    );

    transcript
        .append_serializable_element(b"response", &[proof.vec_z.clone()])
        .unwrap();
    transcript
        .append_serializable_element(b"response2", &[proof.zeta_1, proof.zeta_2])
        .unwrap();

    // XXX
    true
}

/// Check proof that <vec_x, vec_a> = y
#[test]
fn test_sigma_end_to_end() {
    use crate::pedersen;

    type G = ark_curve25519::EdwardsProjective;

    // Basic setup
    let rng = &mut rand::rngs::OsRng;

    let mut transcript_p = IOPTranscript::<ark_curve25519::Fr>::new(b"sumcheck");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<ark_curve25519::Fr>::new(b"sumcheck");
    transcript_v.append_message(b"init", b"init").unwrap();

    let ck = pedersen::setup::<G>(rng, 2084);

    // Linear evaluation setup
    let len = 16;
    let rho = (0..len)
        .map(|_| ark_curve25519::Fr::rand(rng))
        .collect::<Vec<_>>();
    let vec_a = linalg::tensor(&rho);

    let vec_x = (0..len)
        .map(|_| ark_curve25519::Fr::rand(rng))
        .collect::<Vec<_>>();
    let (X, phi) = commit_hiding(rng, &ck, &vec_x);

    let y = linalg::inner_product(&vec_x, &vec_a);
    let (Y, psi) = commit_hiding(rng, &ck, &[y]);

    // Let's prove!
    let sigma_proof =
        lineval_prover(rng, &mut transcript_p, &ck, &vec_x, phi, psi, &vec_a);

    lineval_verifier(&mut transcript_v, &ck, &vec_a, &X, &Y, &sigma_proof);
}
