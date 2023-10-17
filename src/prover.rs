#![allow(non_snake_case)]

/// See Figure 8 in the paper to learn how this protocol works
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

use transcript::IOPTranscript;

use super::{aes, helper, linalg, lookup, pedersen, sigma, sumcheck};
use crate::sigma::SigmaProof;
use crate::{pedersen::CommitmentKey};





// A summary of the evaluations and proofs required in the protocol.
#[derive(Default, CanonicalSerialize)]
pub struct LinearEvaluationProofs<G: CurveGroup> {
    // Proof for <m, h> = y
    pub proof_m_h: SigmaProof<G>,

    // Proof and partial result for merged scalar product: <g, tensor + c> = y_1 + c * y
    pub proof_q_1_tensor: SigmaProof<G>,
    // com(y_1)
    pub Y_1: G,

    // Proof and result for <f, tensor> = y_2
    pub sigma_proof_f_tensor: SigmaProof<G>,
    // com(y_2)
    pub Y_2: G,
}

#[derive(Default, CanonicalSerialize)]
pub struct TinybearProof<G: CurveGroup> {
    pub witness_com: G,

    // we actually know the len of the items below, it's LOOKUP_CHUNKS
    pub freqs_com: G, // com(m)

    pub inverse_needles_com: G, // com(g)
    pub needles_len: usize,     // |f|
    pub Y: G,                   // com(y)

    // we actually know the len of this thing,
    // it's going to be 12 for aes128 with 4-bit xor
    // it's going to be 17 for 8-bit table xor
    // XXX
    pub sumcheck_messages: Vec<[G::ScalarField; 2]>,
    // <q,f> = s = |f| - c * y
    pub sumcheck_claim_s: G::ScalarField,

    // Proofs and results for the linear evaluation proofs
    pub sigmas: LinearEvaluationProofs<G>,
}

fn get_r2j_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let xs = witness.s_box.iter().copied();
    let ys = witness.m_col_xor[0].iter().copied();
    xs.zip(ys).collect()
}

// sbox needles to lookup in table x -> SBOX[x]
fn get_s_box_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let s_box = witness._s_row.iter().zip(&witness.s_box);
    // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
    s_box.map(|(&x, &y)| (x, y)).collect()
}

// xor needles to lookup in table (x, y, z = x ^ y)
fn get_xor_witness(witness: &aes::Witness) -> Vec<(u8, u8, u8)> {
    let mut witness_xor = Vec::new();
    // m_col_xor
    for i in 0..4 {
        let xs = witness.m_col_xor[i].iter().copied();
        let ys = witness._aux_m_col_xor[i].iter().copied();
        let zs = witness.m_col_xor[i + 1].iter().copied();
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }
    // addroundkey_xor
    {
        let xs = witness.m_col_xor[4].iter().copied();
        let zs = witness.start.iter().copied();
        // ys are the round keys
        let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
        witness_xor.extend(new_witness)
    }
    // k_sch_xor
    // for i in 0..witness.k_sch[0].len() {
    //     let (x, z) = (witness.k_sch_s_box[i], witness.k_sch[0][i]);
    //     let y = x ^ z; // this is the round constant
    //     witness_xor.push((x, y, z))
    // }
    // for x in 0..4 {
    //     for i in 4..witness.k_sch[x + 1].len() {
    //         let (x, y, z) = (
    //             witness.k_sch[x][i],
    //             witness.k_sch[x + 1][i - 4],
    //             witness.k_sch[x + 1][i],
    //         );
    //         assert_eq!(z, x ^ y);
    //         witness_xor.push((x, y, z))
    //     }
    // }
    // final_round_xor
    // {
    //     let xs = witness.s_box.iter().copied();
    //     let zs = witness.output.iter().copied();
    //     let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
    //     witness_xor.extend(new_witness)
    // }
    witness_xor
}


/// Compute needles and frequencies
/// Return (needles, frequencies, frequencies_u8)
pub fn compute_needles_and_frequencies<F: Field>(
    witness: &aes::Witness,
    r_xor: F,
    r2_xor: F,
    r_sbox: F,
    r_mul: F,
) -> (Vec<F>, Vec<F>, Vec<u8>) {
    // Generate the witness.
    // witness_s_box = [(a, sbox(a)), (b, sbox(b)), ...]
    let witness_s_box = get_s_box_witness(witness);

    let witness_r2j = get_r2j_witness(witness);

    // witness_xor = [(a, b, xor(a, b)), (c, d, xor(c, d)), ...]
    let witness_xor = get_xor_witness(witness);

    // Needles: these are the elements that want to be found in the haystack.
    // Note: sbox+mixcol is a single table x -> MXCOLHELP[SBOX[x]]

    // s_box_needles = [x_1 + r * sbox[x_1], x_2 + r * sbox[x_2], ...]
    let s_box_needles = lookup::compute_u8_needles(&witness_s_box, r_sbox);
    let r2j_needles = lookup::compute_u8_needles(&witness_r2j, r_mul);

    // ASN xor_needles = ??? 4 bit stuff
    let xor_needles = lookup::compute_u16_needles(&witness_xor, [r_xor, r2_xor]);

    let needles = [s_box_needles, r2j_needles, xor_needles].concat();

    // Frequencies: these count how many times each element will appear in the haystack.
    // To do so, we build the frequency vectors.
    // Frequencies are organized in this way
    // | 4-bit xor | sbox | r2j |
    // |  256      | 256  | 256       |
    // First, group witness by lookup table.
    let mut frequencies_u8 = vec![0u8; 256 * 3];
    lookup::count_u16_frequencies(&mut frequencies_u8[0..256], &witness_xor);
    lookup::count_u8_frequencies(&mut frequencies_u8[256..512], &witness_s_box);
    lookup::count_u8_frequencies(&mut frequencies_u8[512..768], &witness_r2j);

    let frequencies = frequencies_u8
        .iter()
        .map(|x| F::from(*x))
        .collect::<Vec<_>>();

    (needles, frequencies, frequencies_u8)
}

pub fn prove<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    key: &[u8; 16],
) -> TinybearProof<G>
where
    G: CurveGroup,
{
    let rng = &mut rand::rngs::OsRng;

    let mut proof = TinybearProof::<G>::default();
    // witness generation
    // TIME: 7e-3ms
    let witness = aes::aes128_trace(message, *key);

    // commit to trace of the program.
    // TIME: ~3-4ms [outdated]
    let witness_vector = helper::vectorize_witness(&witness);
    let (witness_com, omega) = pedersen::commit_hiding_u8(rng, &ck, &witness_vector);

    // Send W
    proof.witness_com = witness_com;
    transcript
        .append_serializable_element(b"witness_com", &[proof.witness_com])
        .unwrap();

    //////////////////////////// Lookup protocol //////////////////////////////

    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    let r_mul = transcript.get_and_append_challenge(b"r_mul").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    let (needles, frequencies, frequencies_u8) =
        compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_mul);

    // Commit to m (using mu as the blinder) and send it over
    let (freqs_com, mu) = pedersen::commit_hiding_u8(rng, ck, &frequencies_u8);

    // Send M
    proof.freqs_com = freqs_com;
    transcript
        .append_serializable_element(b"m", &[proof.freqs_com])
        .unwrap();

    // Get the lookup challenge c and compute q and y
    let c = transcript.get_and_append_challenge(b"c").unwrap();
    // Compute vector of inverse_needles[i] = 1 / (needles[i] + a) = q
    let mut inverse_needles = needles.iter().map(|k| c + k).collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_needles);

    // Q = Com(q)
    let (inverse_needles_com, theta) = pedersen::commit_hiding(rng, &ck, &inverse_needles);
    // y = <g,1>
    let y = inverse_needles.iter().sum();
    let (Y, psi) = pedersen::commit_hiding(rng, &ck, &[y]);

    // Send (Q,Y)
    proof.inverse_needles_com = inverse_needles_com;
    proof.Y = Y;
    proof.needles_len = needles.len();
    transcript
        .append_serializable_element(b"Q", &[proof.inverse_needles_com])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Finally compute h and t
    let (haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_mul, c);

    ////////////////////////////// Sumcheck  //////////////////////////////

    // Reduce scalar product <f,g> to a tensor product
    let (sumcheck_challenges, sumcheck_messages) =
        sumcheck::sumcheck(transcript, &needles, &inverse_needles);

    // pour sumcheck messages into the proof
    proof.sumcheck_messages = sumcheck_messages;
    // add inner product result to the proof: <f, q> = s = |f| - c * y
    proof.sumcheck_claim_s = G::ScalarField::from(needles.len() as i32) - c * y;

    //////////////////////////////// Sanity checks ////////////////////////////////////////

    // Sanity check: check that the witness is indeed valid
    // sum_i q_i  = sum_i f_i
    assert_eq!(inverse_haystack.len(), frequencies_u8.len());
    for x in &needles {
        assert!(haystack.contains(x))
    }
    assert_eq!(
        inverse_haystack
            .iter()
            .zip(&frequencies_u8)
            .map(|(&a, &b)| a * G::ScalarField::from(b))
            .sum::<G::ScalarField>(),
        inverse_needles.iter().sum::<G::ScalarField>()
    );

    // check that: <q, f> = |f| - c * y
    assert_eq!(
        proof.sumcheck_claim_s,
        G::ScalarField::from(needles.len() as i32) - c * y
    );

    // check other linear evaluation scalar products
    // <m, h> == y
    assert_eq!(linalg::inner_product(&frequencies, &inverse_haystack), y);
    // <g, 1> == y
    assert_eq!(inverse_needles.iter().sum::<G::ScalarField>(), y);

    ////////////////////////////// Sigma protocols //////////////////////////////

    ////////////////////// First sigma: <m, h> = y ////////////////////
    proof.sigmas.proof_m_h = sigma::lineval_prover(
        rng,
        transcript,
        ck,
        &frequencies,
        mu,
        psi,
        &inverse_haystack,
    );

    ////////////////////// Second (merged) sigma: <g, tensor + z> = y_1 + z * y ////////////////////

    // Merge two sigmas <g, tensor> = y_1 and <g, 1> = y
    // multiply the latter with random z and merge by linearity
    // into <g, tensor + z> = y_1 + z * y

    // Public part (evaluation challenge) of tensor relation: ⦻(1, rho_j)
    let tensor_evaluation_point = linalg::tensor(&sumcheck_challenges);

    let z = transcript.get_and_append_challenge(b"bc").unwrap();
    let vec_tensor_z: Vec<G::ScalarField> =
        tensor_evaluation_point.iter().map(|t| *t + z).collect();

    // Compute partial result and commit to it
    let y_1 = linalg::inner_product(&inverse_needles, &tensor_evaluation_point);
    let (Y_1, epsilon) = pedersen::commit_hiding(rng, &ck, &[y_1]);

    // The blinder of the commitment `Y_1 + z * Y` for use in the sigma below
    let Y_1_z_Y_blinder = epsilon + z * psi;

    // Finally compute the sigma proof
    proof.sigmas.proof_q_1_tensor = sigma::lineval_prover(
        rng,
        transcript,
        ck,
        &inverse_needles,
        theta,
        Y_1_z_Y_blinder,
        &vec_tensor_z,
    );
    proof.sigmas.Y_1 = Y_1;

    ////////////////////// Final sigma: <f, tensor> = y_2 ////////////////////

    let y_2 = linalg::inner_product(&needles, &tensor_evaluation_point);
    let (Y_2, _iota) = pedersen::commit_hiding(rng, &ck, &[y_2]);
    // XXX need to figure out what blinder to put for needles below instead of theta
    proof.sigmas.sigma_proof_f_tensor = sigma::lineval_prover(
        rng,
        transcript,
        ck,
        &needles,
        theta,
        epsilon,
        &tensor_evaluation_point,
    );
    proof.sigmas.Y_2 = Y_2;

    proof
}


#[test]
fn test_prove() {
    type G = ark_curve25519::EdwardsProjective;

    let mut transcript = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript.append_message(b"init", b"init").unwrap();

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2084);

    let proof = prove::<G>(&mut transcript, &ck, message, &key);
    println!("size: {}", proof.compressed_size());
    println!("size: {}", proof.sigmas.compressed_size());
}
