#![allow(non_snake_case)]
use std::vec;

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::CryptoRng;
use rand::RngCore;
use transcript::IOPTranscript;

use crate::linalg;
use crate::pedersen::commit_hiding;
use crate::pedersen::CommitmentKey;

#[derive(Default, CanonicalSerialize)]
pub struct SigmaProof<G: CurveGroup> {
    pub commitment: Vec<G>,
    pub response: Vec<G::ScalarField>,
}

pub fn mul_prove<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    a: G::ScalarField,
    B: G,
    rho_a: G::ScalarField,
    rho_b: G::ScalarField,
    rho_c: G::ScalarField,
) -> SigmaProof<G> {
    let vec_k = (0..3)
        .map(|_| G::ScalarField::rand(csrng))
        .collect::<Vec<_>>();
    let K = vec![
        G::msm_unchecked(&[ck.G, ck.H], &vec_k[..2]),
        G::msm_unchecked(&[B.into(), ck.H], &[vec_k[0], vec_k[2]]),
    ];
    transcript.append_serializable_element(b"k_gg", &K).unwrap();
    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    // Compute prover's response
    let vec_z = vec![
        vec_k[0] + c * a,
        vec_k[1] + c * rho_a,
        vec_k[2] + c * (rho_c - a * rho_b),
    ];
    SigmaProof {
        commitment: K,
        response: vec_z,
    }
}

pub fn mul_verify<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    A: G,
    B: G,
    C: G,
    proof: &SigmaProof<G>,
) -> Result<(), ()> {
    transcript
        .append_serializable_element(b"k_gg", &proof.commitment)
        .unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();
    if proof.commitment[0]
        == G::msm_unchecked(
            &[(-A).into(), ck.G, ck.H],
            &[c, proof.response[0], proof.response[1]],
        )
        && proof.commitment[1]
            == G::msm_unchecked(
                &[(-C).into(), B.into(), ck.H],
                &[c, proof.response[0], proof.response[2]],
            )
    {
        Ok(())
    } else {
        Err(())
    }
}

#[test]
fn test_mul() {
    type F = ark_curve25519::Fr;
    let rng = &mut rand::thread_rng();
    let ck = crate::pedersen::setup::<ark_curve25519::EdwardsProjective>(rng, 3);
    let a = ark_curve25519::Fr::rand(rng);
    let b = ark_curve25519::Fr::rand(rng);
    let c = a * b;
    let rho_a = F::rand(rng);
    let rho_b = F::rand(rng);
    let rho_c = F::rand(rng);
    let A = ck.G * a + ck.H * rho_a;
    let B = ck.G * b + ck.H * rho_b;
    let C = ck.G * c + ck.H * rho_c;
    let mut transcript_p = IOPTranscript::<ark_curve25519::Fr>::new(b"test");
    let proof = mul_prove(rng, &mut transcript_p, &ck, a, B, rho_a, rho_b, rho_c);
    let mut transcript_v = IOPTranscript::<ark_curve25519::Fr>::new(b"test");
    let result = mul_verify(&mut transcript_v, &ck, A, B, C, &proof);
    assert!(result.is_ok());
}

/// Prove that <x, a> = y, where x and y are private
/// phi is blinder of vec_x
/// psi is blinder of y
pub fn lin_prove<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,

    x_vec: &Vec<G::ScalarField>, // private
    X_opening: G::ScalarField,   // blinding factor of vec_x
    Y_opening: G::ScalarField,   // blinding factor of y

    a_vec: &[G::ScalarField], // public
) -> SigmaProof<G> {
    // Create the prover's blinders
    let mut vec_k = (0..x_vec.len())
        .map(|_| G::ScalarField::rand(csrng))
        .collect::<Vec<_>>();

    // Commit to the blinders and send the commitments to the verifier
    let (K_1, kappa_1) = commit_hiding(csrng, ck, &vec_k);
    let (K_2, kappa_2) = commit_hiding(csrng, ck, &[linalg::inner_product(&vec_k, a_vec)]);
    vec_k.extend_from_slice(&[kappa_1, kappa_2]);
    let K = vec![K_1, K_2];

    transcript.append_serializable_element(b"k_gg", &K).unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();
    // Compute prover's response
    let witness = x_vec
        .iter()
        .chain(core::iter::once(&X_opening))
        .chain(core::iter::once(&Y_opening));
    for (z_i, w_i) in vec_k.iter_mut().zip(witness) {
        *z_i += c * w_i;
    }
    let vec_z = vec_k;

    transcript
        .append_serializable_element(b"response", &[vec_z.clone()])
        .unwrap();

    SigmaProof {
        commitment: K,
        response: vec_z,
    }
}

/// Verify a proof that given commitment X, its opening x has: <x, a> = y
pub fn lin_verify<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,

    vec_a: &[G::ScalarField],
    X: &G,
    Y: &G,

    proof: &SigmaProof<G>,
) -> Result<(), ()> {
    let n = proof.response.len() - 2;
    // debug_assert!(n < vec_a.len());

    // XXX. missing statement
    transcript
        .append_serializable_element(b"k_gg", &proof.commitment)
        .unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    let z_response =
        G::msm_unchecked(&ck.vec_G[..n], &proof.response[..n]) + ck.H * proof.response[n];
    let za_response = ck.G * linalg::inner_product(&proof.response[..n], &vec_a[..n])
        + ck.H * proof.response[n + 1];

    transcript
        .append_serializable_element(b"response", &[proof.response.clone()])
        .unwrap();
    if z_response == proof.commitment[0] + X.mul(c) && za_response == proof.commitment[1] + Y.mul(c)
    {
        Ok(())
    } else {
        Err(())
    }
}

/// Check proof that <vec_x, vec_a> = y
#[test]
fn test_lineval_correctness() {
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
    let len = 8;
    let rho = (0..len)
        .map(|_| ark_curve25519::Fr::rand(rng))
        .collect::<Vec<_>>();
    let vec_a = linalg::tensor(&rho);

    let vec_x = (0..vec_a.len())
        .map(|_| ark_curve25519::Fr::rand(rng))
        .collect::<Vec<_>>();
    let (X, X_opening) = commit_hiding(rng, &ck, &vec_x);

    let y = linalg::inner_product(&vec_x, &vec_a);
    let (Y, Y_opening) = commit_hiding(rng, &ck, &[y]);

    // Let's prove!
    let sigma_proof = lin_prove(
        rng,
        &mut transcript_p,
        &ck,
        &vec_x,
        X_opening,
        Y_opening,
        &vec_a,
    );

    assert!(lin_verify(&mut transcript_v, &ck, &vec_a, &X, &Y, &sigma_proof).is_ok());
}
