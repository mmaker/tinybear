/// See Figure 8 in the paper to learn how this protocol works
use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand, Zero, One};
use ark_serialize::CanonicalSerialize;

use transcript::IOPTranscript;

use crate::sigma::sigma_linear_evaluation_prover;
use super::{aes, linalg, lookup, pedersen, sumcheck};

// XXX?
// const WITNESS_LEN: usize = 1760;

#[derive(Default)]
struct AesWitnessRegions {
    start: usize,
    s_box: usize,
    // final_s_box: usize,
    m_col_xor: [usize; 5],
}

// The witness is structured as follows:
// .start is the state at each intermediate round, so
//   pos = 0
//   len = 16 * 9 = 144
// .s_box is the state after the sbox, so
//   pos = 16 * 9 = 144
//   len = 16 * 9 = 144
// .m_col_xor[i] is the state after the m_col_xor[i], so
//   pos = .start.len +
const OFFSETS: AesWitnessRegions = {
    let start = 0;
    let s_box = start + 2 * (16 * 9 + 16);
    // let final_s_box = s_box + 2 * 16;
    // thank Rust for const for loops
    let m_col_offset = s_box + 2 * (16 * 9);
    let m_col_len = 2 * (16 * 9);
    let m_col_xor = [
        m_col_offset + m_col_len * 0,
        m_col_offset + m_col_len * 1,
        m_col_offset + m_col_len * 2,
        m_col_offset + m_col_len * 3,
        m_col_offset + m_col_len * 4,
    ];

    AesWitnessRegions {
        start,
        s_box,
        // final_s_box,
        m_col_xor,
    }
};

// A summary of the evaluations and proofs required in the protocol.
#[derive(Default, CanonicalSerialize)]
pub struct LinearEvaluationProofs<G: CurveGroup> {
    // Proof for <m, h> = gamma
    pub sigma_proof_m_h: (G, Vec<G::ScalarField>),

    // Proof for <g, 1> = gamma
    pub sigma_proof_g_1: (G, Vec<G::ScalarField>),

    // Proof and result for <g, tensor> = y_1
    pub sigma_proof_g_tensor: (G, Vec<G::ScalarField>),
    pub y_1: G::ScalarField,

    // Proof and result for <f, tensor> = y_2
    pub sigma_proof_f_tensor: (G, Vec<G::ScalarField>),
    pub y_2: G::ScalarField,
}

#[derive(Default, CanonicalSerialize)]
pub struct Proof<G: CurveGroup> {
    pub witness_com: G,

    // we actually know the len of the items below, it's LOOKUP_CHUNKS
    pub freqs_com: G, // com(m)

    pub inverse_needles_com: G, // com(g)
    pub needles_len: usize, // |f|

    pub gamma: G::ScalarField, // gamma = <g,1>

    // we actually know the len of this thing,
    // it's going to be 12 for aes128 with 4-bit xor
    // it's going to be 17 for 8-bit table xor
    // XXX
    pub sumcheck_messages: Vec<[G::ScalarField; 2]>,
    // <f,g> = |f| - alpha * gamma
    pub sumcheck_claim_f_g: G::ScalarField,

    // Proofs and results for the linear evaluation proofs
    pub sigmas: LinearEvaluationProofs<G>,
}

/// Transforms an AES witness into a flattened vector representation.
///
/// This function takes an AES witness, which captures the execution trace of AES encryption, and turns it into a
/// continuous vector of 4-bit chunks.  Each 8-bit byte from the witness is split into two 4-bit parts to simplify
/// the lookup operations.
fn vectorize_witness(witness: &aes::Witness) -> Vec<u8> {
    let mut w = Vec::new();

    assert_eq!(OFFSETS.start, w.len());
    w.extend(witness.start.iter().map(|x| [x & 0xf, x >> 4]).flatten());

    assert_eq!(OFFSETS.s_box, w.len());
    w.extend(witness.s_box.iter().map(|x| [x & 0xf, x >> 4]).flatten());

    // assert_eq!(OFFSETS.final_s_box, w.len());
    // w.extend(
    //     witness
    //         .final_s_box
    //         .iter()
    //         .map(|x| [x & 0xf, x >> 4])
    //         .flatten(),
    // );

    for i in 0..5 {
        assert_eq!(OFFSETS.m_col_xor[i], w.len());
        w.extend(
            witness.m_col_xor[i]
                .iter()
                .map(|x| [x & 0xf, x >> 4])
                .flatten(),
        );
    }

    // w.extend(
    //     witness
    //         .final_s_box
    //         .iter()
    //         .map(|x| [x & 0xf, x >> 4])
    //         .flatten(),
    // );

    w
}

fn get_m_col_pre_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let xs = witness.s_box.iter().copied();
    let ys = witness.m_col_xor[0].iter().copied();
    xs.zip(ys).collect()
}

// sbox needles to lookup in table x -> SBOX[x]
fn get_s_box_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let s_box = witness._s_row.iter().zip(&witness.s_box);
    // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
    // let final_s_box = witness._final_s_row.iter().zip(&witness.final_s_box);
    // s_box.chain(final_s_box).map(|(&x, &y)| (x, y)).collect()
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
    {
        let xs = witness.final_s_box.iter().copied();
        let zs = witness.output.iter().copied();
        let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
        witness_xor.extend(new_witness)
    }
    witness_xor
}

/// DOCDOC
/// Used by sigma protocol verifier in order to construct the right evaluation given the shiftrow permutation
fn challenge_for_witness<F: Field>(vector: &[F], r_sbox: F, r: F, r_xor: F, r2_xor: F) -> Vec<F> {
    // the final matrix that maps witness -> needles
    // has dimensions: needles.len() x witness.len()
    // where
    // needles.len() = 1472
    //   s_box_needles.len() (9 * 16) +
    //   m_col_pre.len() (9 * 16) +
    //   xor_needles.len() (16 * 9 * 5 * 2)
    // witness.len() =
    //   start.len() (9 * 16 * 2)
    //   s_box.len() (9 * 16 * 2)
    //   m_col_pre.len() (9 * 16 * 5 * 2)
    const WITNESS_LEN: usize = 2016 + 144;

    let mut current_row = vec![F::zero(); WITNESS_LEN];
    let identity = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let s_row = aes::shiftrows(identity);
    let mut aux_m_col = [identity; 4];
    aes::rotate_right_inplace(&mut aux_m_col[0], 1);
    aes::rotate_right_inplace(&mut aux_m_col[1], 2);
    aes::rotate_right_inplace(&mut aux_m_col[2], 3);
    aes::rotate_right_inplace(&mut aux_m_col[3], 3);

    let mut offset = 0;
    // sbox
    for round in 0..9 {
        for i in 0..16 {
            let s_row_pos = 16 * round + s_row[i] as usize;
            let s_box_pos = 16 * round + i;
            //
            let c_lo = vector[round * 16 + i];
            let c_hi = c_lo.double().double().double().double();
            current_row[s_row_pos * 2] += c_lo;
            current_row[s_row_pos * 2 + 1] += c_hi;
            current_row[OFFSETS.s_box + s_box_pos * 2] += r_sbox * c_lo;
            current_row[OFFSETS.s_box + s_box_pos * 2 + 1] += r_sbox * c_hi;
        }
    }

    offset += 16 * 9;
    // add mxcolpre
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            //
            let c_lo = vector[offset + pos];
            let c_hi = c_lo.double().double().double().double();
            current_row[OFFSETS.s_box + pos * 2] += c_lo;
            current_row[OFFSETS.s_box + pos * 2 + 1] += c_hi;
            current_row[OFFSETS.m_col_xor[0] + pos * 2] += r * c_lo;
            current_row[OFFSETS.m_col_xor[0] + pos * 2 + 1] += r * c_hi;
        }
    }

    offset += 16 * 9;
    for k in 0..4 {
        for round in 0..9 {
            for i in 0..16 {
                let pos = 16 * round + i;
                let ys_pos = 16 * round + aux_m_col[k][i];
                let ys_offset = if k < 3 {
                    OFFSETS.s_box
                } else {
                    OFFSETS.m_col_xor[0]
                };
                let c_even = vector[offset + 16 * 9 * 2 * k + pos * 2];
                let c_odd = vector[offset + 16 * 9 * 2 * k + pos * 2 + 1];
                current_row[OFFSETS.m_col_xor[k] + pos * 2] += c_even;
                current_row[ys_offset + ys_pos * 2] += r_xor * c_even;
                current_row[OFFSETS.m_col_xor[k + 1] + pos * 2] += r2_xor * c_even;

                current_row[OFFSETS.m_col_xor[k] + pos * 2 + 1] += c_odd;
                current_row[ys_offset + ys_pos * 2 + 1] += r_xor * c_odd;
                current_row[OFFSETS.m_col_xor[k + 1] + pos * 2 + 1] += r2_xor * c_odd;
            }
        }
    }

    offset += 16 * 9 * 4 * 2;
    // add mxcolpre
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let c_even = vector[offset + pos * 2];
            let c_odd = vector[offset + pos * 2 + 1];
            current_row[OFFSETS.m_col_xor[4] + pos * 2] += c_even;
            // current_row[ys_offset + ys_pos * 2] += r_xor * c_even;
            current_row[OFFSETS.start + pos * 2] += r2_xor * c_even;

            current_row[OFFSETS.m_col_xor[4] + pos * 2 + 1] += c_odd;
            // current_row[ys_offset + ys_pos * 2 + 1] += r_xor * c_odd;
            current_row[OFFSETS.start + pos * 2 + 1] += r2_xor * c_odd;
        }
    }
    current_row
}

pub fn prove<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &[G::Affine],
    message: [u8; 16],
    key: &[u8; 16],
) -> Proof<G>
where
    G: CurveGroup,
{
    let rng = &mut rand::rngs::OsRng;

    let mut proof = Proof::<G>::default();
    // witness generation
    // TIME: 7e-3ms
    let witness = aes::aes128_trace(message, *key);

    // commit to trace of the program.
    // TIME: ~3-4ms [outdated]
    let witness_vector = vectorize_witness(&witness);
    proof.witness_com = pedersen::commit_u8(&ck, &witness_vector);
    transcript.append_serializable_element(b"witness_com", &[proof.witness_com]).unwrap();

    //////////////////////////// Lookup protocol //////////////////////////////

    // Generate the witness.
    // witness_s_box = [(a, sbox(a)), (b, sbox(b)), ...]
    let witness_s_box = get_s_box_witness(&witness);

    let witness_m_col_pre = get_m_col_pre_witness(&witness);

    // witness_xor = [(a, b, xor(a, b)), (c, d, xor(c, d)), ...]
    let witness_xor = get_xor_witness(&witness);

    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    let r_mcolpre = transcript.get_and_append_challenge(b"r_mcolpre").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    // Needles: these are the elements that want to be found in the haystack.
    // Note: sbox+mixcol is a single table x -> MXCOLHELP[SBOX[x]]

    // s_box_needles = [x_1 + r * sbox[x_1], x_2 + r * sbox[x_2], ...]
    let s_box_needles = lookup::compute_u8_needles(&witness_s_box, r_sbox);
    let m_col_pre_needles = lookup::compute_u8_needles(&witness_m_col_pre, r_mcolpre);

    // ASN xor_needles = ??? 4 bit stuff
    let xor_needles = lookup::compute_u16_needles(&witness_xor, [r_xor, r2_xor]);

    let needles = [s_box_needles, m_col_pre_needles, xor_needles].concat();

    // Frequencies: these count how many times each element will appear in the haystack.
    // To do so, we build the frequency vectors.
    // Frequencies are organized in this way
    // | 4-bit xor | sbox | m_col_pre |
    // |  256      | 256  | 256       |
    // First, group witness by lookup table.
    let mut frequencies_u8 = vec![0u8; 256 * 3];
    lookup::count_u16_frequencies(&mut frequencies_u8[0..256], &witness_xor);
    lookup::count_u8_frequencies(&mut frequencies_u8[256..512], &witness_s_box);
    lookup::count_u8_frequencies(&mut frequencies_u8[512..768], &witness_m_col_pre);

    let frequencies = frequencies_u8
        .iter()
        .map(|x| G::ScalarField::from(*x))
        .collect::<Vec<_>>();

    // Commit to m and send it over
    proof.freqs_com = pedersen::commit_u8(ck, &frequencies_u8);
    transcript.append_serializable_element(b"m", &[proof.freqs_com,]).unwrap();


    // Get the lookup challenge alpha and compute g and gamma
    let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();
    // Compute vector of inverse_needles[i] = 1 / (needles[i] + a) = g
    let mut inverse_needles = needles
        .iter()
        .map(|k| alpha + k)
        .collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_needles);

    proof.inverse_needles_com = pedersen::commit(&ck, &inverse_needles);
    // gamma = <g,1>
    proof.gamma = inverse_needles.iter().sum();
    proof.needles_len = needles.len();

    transcript.append_serializable_element(b"g", &[proof.inverse_needles_com]).unwrap();
    transcript.append_serializable_element(b"gamma", &[proof.gamma]).unwrap();

    // Finally compute h and t
    let (haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_mcolpre, alpha);

    ////////////////////////////// Sumcheck  //////////////////////////////

   // Reduce scalar product <f,g> to a tensor product
   let (sumcheck_challenges, sumcheck_messages) = sumcheck::sumcheck(transcript, &needles, &inverse_needles);
    // pour sumcheck messages into the proof
    proof.sumcheck_messages = sumcheck_messages;
    // add inner product result to the proof: <f, g> = |f| - alpha * gamma
    proof.sumcheck_claim_f_g = linalg::inner_product(&needles, &inverse_needles);

    //////////////////////////////// Sanity checks ////////////////////////////////////////

    // Sanity check: check that the witness is indeed valid
    // sum_i g_i  = sum_i f_i
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

    // check that: <f, g> = |f| - alpha * gamma
    assert_eq!(proof.sumcheck_claim_f_g, G::ScalarField::from(needles.len() as i32) - alpha * proof.gamma);

    // check other linear evaluation scalar products
    // <m, h> == gamma
    assert_eq!(linalg::inner_product(&frequencies, &inverse_haystack), proof.gamma);
    // <g, 1> == gamma
    let vec_ones = vec![G::ScalarField::one(); inverse_needles.len()];
    assert_eq!(linalg::inner_product(&inverse_needles, &vec_ones), proof.gamma);

    ////////////////////////////// Sigma protocol //////////////////////////////

    // First sigma: <m, h> = gamma
    proof.sigmas.sigma_proof_m_h = sigma_linear_evaluation_prover(rng, transcript, ck, &frequencies, &inverse_haystack);

    // Second sigma: <g, 1> = gamma
    proof.sigmas.sigma_proof_g_1 = sigma_linear_evaluation_prover(rng, transcript, ck, &inverse_needles, &vec_ones);

    // Public part (evaluation challenge) of tensor relation: ⦻(1, rho_j)
    let tensor_evaluation_point = linalg::tensor(&sumcheck_challenges);

    // Third sigma: <g, tensor> = y_1
    proof.sigmas.sigma_proof_g_tensor = sigma_linear_evaluation_prover(rng, transcript, ck, &inverse_needles, &tensor_evaluation_point);
    proof.sigmas.y_1 =
        linalg::inner_product(&inverse_needles, &tensor_evaluation_point);

    // Fourth sigma: <f, tensor> = y_2
    proof.sigmas.sigma_proof_f_tensor = sigma_linear_evaluation_prover(rng, transcript, ck, &needles, &tensor_evaluation_point);
    proof.sigmas.y_2 =
        linalg::inner_product(&needles, &tensor_evaluation_point);

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
