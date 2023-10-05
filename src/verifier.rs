use ark_ec::CurveGroup;
use ark_ff::{One, Zero};

use transcript::IOPTranscript;

use crate::linalg;
use crate::linalg::{tensor};

use crate::pedersen::CommitmentKey;
use crate::{lookup, pedersen};
use crate::sigma::sigma_linear_evaluation_verifier;
use crate::prover::{prove, Proof};

use super::{sumcheck};

pub struct InvalidProof;
type ProofResult = Result<(), InvalidProof>;

#[allow(unused)] // XXX during dev
pub fn verify<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    k: [u8; 16],
    proof: &Proof<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    // Step 2: Lookup verifier challenges
    transcript.append_serializable_element(b"witness_com", &[proof.witness_com]).unwrap();

    let r_mcolpre = transcript.get_and_append_challenge(b"r_mcolpre").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    transcript.append_serializable_element(b"m", &[proof.freqs_com,]).unwrap();

    let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();

    transcript.append_serializable_element(b"g", &[proof.inverse_needles_com]).unwrap();
    transcript.append_serializable_element(b"gamma", &[proof.gamma]).unwrap();

    // Compute h and t
    let (haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_mcolpre, alpha);

    // Step 5: Sumcheck
    let (sumcheck_challenges, tensorcheck_claim) =
        sumcheck::reduce(transcript, &proof.sumcheck_messages, proof.sumcheck_claim_f_g);

    // Verify sumcheck claim
    assert_eq!(proof.sumcheck_claim_f_g , G::ScalarField::from(proof.needles_len as i32) - alpha * proof.gamma);

    // Verify sumcheck tensorcheck claim (random evaluation)
    // using yet unverified y_1 and y_2
    assert_eq!(tensorcheck_claim, proof.sigmas.y_1 * proof.sigmas.y_2);

    // Step 6: Linear evaluations
    // time to verify that g, m and gamma are correctly provided by the prover

    // Verify first sigma: <m, h> = gamma
    sigma_linear_evaluation_verifier(transcript, &ck, &proof.freqs_com, &inverse_haystack, &proof.gamma,
                                     proof.sigmas.sigma_proof_m_h.0, &proof.sigmas.sigma_proof_m_h.1);

    // Verify merged scalar product: <g, tensor + c> = y_1 + c * gamma
    let c = transcript.get_and_append_challenge(b"c").unwrap();
    let tensor_evaluation_point = linalg::tensor(&sumcheck_challenges);
    let vec_tensor_c: Vec<G::ScalarField> = tensor_evaluation_point.iter().map(|t| *t + c).collect();
    let y_1_c_gamma = proof.sigmas.y_1 + c * proof.gamma;
    sigma_linear_evaluation_verifier(transcript, &ck, &proof.inverse_needles_com, &vec_tensor_c, &y_1_c_gamma,
                                     proof.sigmas.sigma_proof_g_1_tensor.0, &proof.sigmas.sigma_proof_g_1_tensor.1);

    // Verify fourth sigma: <h, tensor> = gamma
    // XXX
    // let morphism = tensor(&sumcheck_challenges);
    // let morphism_witness = challenge_for_witness(&morphism, r_sbox, r_mcolpre, r_xor, r2_xor);

    Err(InvalidProof)
}


#[test]
fn test_end_to_end() {
    type G = ark_curve25519::EdwardsProjective;

    let mut transcript_p = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript_v.append_message(b"init", b"init").unwrap();


    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2084);

    let proof = prove::<G>(&mut transcript_p, &ck, message, &key);

    let _ = verify::<G>(&mut transcript_v, &ck, key, &proof);
}

