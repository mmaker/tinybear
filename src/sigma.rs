use ark_std::UniformRand;
use ark_std::Zero;
use ark_ff::{Field, PrimeField};
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use rand::RngCore;
use rand::CryptoRng;
use transcript::IOPTranscript;

use crate::pedersen;
use crate::linalg;

/// Prove that <x, a> = y, where x is private
pub fn sigma_linear_evaluation_prover<G: CurveGroup>(
    csrng: &mut (impl RngCore + CryptoRng),
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &[G::Affine],

    vec_x: &Vec<G::ScalarField>, // private
    vec_a: &Vec<G::ScalarField>, // public
) -> (G, Vec<G::ScalarField>) {
        // Create the prover's blinders
    let k_len = vec_x.len();
    let mut vec_k = (0..k_len)
        .map(|_| G::ScalarField::rand(csrng))
        .collect::<Vec<_>>();
    // set k to be the kernel of a
    // k_0 = a_0^{-1} * (k_1*a_1 + ... k_n * a_n)
    vec_k[0] = vec_a[0].inverse().unwrap() * (-linalg::inner_product(&vec_k[1..], &vec_a[1..]));
    // check that the vec_k is the kernel of vec_a
    assert_eq!(linalg::inner_product(&vec_k, &vec_a), G::ScalarField::zero());

    // Commit to the blinders and send the commitment to the verifier
    let k_gg = G::msm_unchecked(&ck, &vec_k);
    transcript.append_serializable_element(b"k_gg", &[k_gg]).unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    // Compute prover's response
    let vec_s = linalg::linear_combination(&[&vec_k, &vec_x], &[c]);

    (k_gg, vec_s)
}

/// Verify a proof that given commitment X, its opening x has: <x, a> = y
pub fn sigma_linear_evaluation_verifier<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &[G::Affine],

    x_gg: &G,
    vec_a: &Vec<G::ScalarField>,
    y: &G::ScalarField,

    // transcript
    k_gg: G,
    vec_s: &Vec<G::ScalarField>,
) -> bool {
    transcript.append_serializable_element(b"k_gg", &[k_gg]).unwrap();

    // Get challenges from verifier
    let c = transcript.get_and_append_challenge(b"c").unwrap();

    // Check schnorr
    let s_i_g_i = G::msm_unchecked(&ck, &vec_s);
    assert_eq!(s_i_g_i - k_gg - x_gg.mul(c), G::zero());

    // Check linear relation
    assert_eq!(linalg::inner_product(vec_s, vec_a), c*y);

    // XXX
    true
}

/// Check proof that <vec_x, vec_a> = y
#[test]
fn test_sigma_end_to_end() {
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
    let x_gg = G::msm_unchecked(&ck, &vec_x);

    let y = linalg::inner_product(&vec_x, &vec_a);

    // Let's prove!
    let (k_gg, vec_s) = sigma_linear_evaluation_prover(rng, &mut transcript_p, &ck, &vec_x, &vec_a);

    sigma_linear_evaluation_verifier(&mut transcript_v, &ck, &x_gg, &vec_a, &y, k_gg, &vec_s);
}
