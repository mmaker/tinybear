#![allow(non_snake_case)]
use ark_ec::CurveGroup;

use transcript::IOPTranscript;

use crate::linalg;

use crate::lookup;
use crate::pedersen::CommitmentKey;
use crate::prover::TinybearProof;
use crate::sigma::lineval_verifier;

use super::sumcheck;

pub struct InvalidProof;
type ProofResult = Result<(), InvalidProof>;

#[allow(unused)] // XXX during dev
pub fn verify<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    k: [u8; 16],
    proof: &TinybearProof<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    // Step 2: Lookup verifier challenges
    transcript
        .append_serializable_element(b"witness_com", &[proof.witness_com])
        .unwrap();

    let r_mul = transcript.get_and_append_challenge(b"r_mul").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    transcript
        .append_serializable_element(b"m", &[proof.freqs_com])
        .unwrap();

    let c = transcript.get_and_append_challenge(b"c").unwrap();

    transcript
        .append_serializable_element(b"Q", &[proof.inverse_needles_com])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Compute h and t
    let (haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_mul, c);

    // Step 5: Sumcheck
    let (sumcheck_challenges, tensorcheck_claim) =
        sumcheck::reduce(transcript, &proof.sumcheck_messages, proof.sumcheck_claim_s);

    // Verify sumcheck claim
    // XXX !!! XXX fix after blinders
    // assert_eq!(proof.sumcheck_claim_s , G::ScalarField::from(proof.needles_len as i32) - c * proof.y);

    // Verify sumcheck tensorcheck claim (random evaluation)
    // using yet unverified y_1 and y_2
    // XXX !!! XXX fix after blinders
    //assert_eq!(tensorcheck_claim, proof.sigmas.y_1 * proof.sigmas.y_2);

    // Step 6: Linear evaluations
    // time to verify that g, m and y are correctly provided by the prover

    // // Verify first sigma: <m, h> = y
    lineval_verifier(
        transcript,
        &ck,
        &inverse_haystack,
        &proof.freqs_com,
        &proof.Y,
        &proof.sigmas.proof_m_h,
    );

    // Verify merged scalar product: <g, tensor + z> = y_1 + z * y

    let tensor_evaluation_point = linalg::tensor(&sumcheck_challenges);

    let z = transcript.get_and_append_challenge(b"bc").unwrap();
    let vec_tensor_z: Vec<G::ScalarField> =
        tensor_evaluation_point.iter().map(|t| *t + z).collect();
    let Y_1_z_Y = proof.sigmas.Y_1 + proof.Y.mul(z);
    lineval_verifier(
        transcript,
        &ck,
        &vec_tensor_z,
        &proof.inverse_needles_com,
        &Y_1_z_Y,
        &proof.sigmas.proof_q_1_tensor,
    );

    // Verify fourth sigma: <h, tensor> = y
    // XXX
    // let morphism = tensor(&sumcheck_challenges);
    // let morphism_witness = challenge_for_witness(&morphism, r_sbox, r_mul, r_xor, r2_xor);

    Err(InvalidProof)
}

#[test]
fn test_end_to_end() {
    use crate::pedersen;
    use crate::prover::prove;

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
