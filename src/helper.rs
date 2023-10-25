use crate::aes;
use ark_ff::Field;

#[derive(Default)]
pub(super) struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col: [usize; 5],
    pub message: usize,
    pub round_keys: usize,
    pub len: usize,
}

pub const NEEDLES_LEN: usize =
    16 * 10 + // s_box
    16 * 9 + // rj2
    16 * 9 * 5 * 2 + // m_col xor's
    16 * 2 * 2 // addroundkey first and last
;

/// The witness is structured as follows:
///
/// ```text
/// +--------------+
/// |  .start      |
/// +--------------+
/// |  .sbox       |
/// ---------------+
/// |  .m_col      |
/// +--------------+
/// |  .message    |  <-- from outside
/// +--------------+
/// |  .round_keys |  <-- from outside
/// +--------------+
/// ```
///
/// where:
/// - `.start`
///   denotes the state at the end of each round, except the final one.
///   In other words, it is the round state excluding message and ciphertext.
///   Therefore, it has length 10 * 16 = 160.
/// - `.s_box`
///   denotes the state at the end of each sbox operation.
///   Therefore, it has length 10 * 16 = 160.
/// - `.m_col`
///   denotes the intermediate states of each mixcolumn operation.
///   `m_col[0]` denotes the state after multiplication by Rj(2).
///   `m_col[1]` up to `m_col[4]` denotes the state at the end of each xor operation.
///    Therefore, it has length 16 * 9 * 5 = 720.
///    (Note: the final AddRoundKey operation is not included involves `.start` and `.m_col[4]`)
/// - `.message` and `.round_keys`
///  denote message and round keys, respectively. They are given as part of the statement.
pub(super) const OFFSETS: AesWitnessRegions = {
    let start = 0;
    let s_box = start + 16 * 10;
    // thank Rust for const for loops
    let m_col_offset = s_box + 16 * 10;
    let m_col_len = 16 * 9;
    let m_col = [
        m_col_offset + m_col_len * 0,
        m_col_offset + m_col_len * 1,
        m_col_offset + m_col_len * 2,
        m_col_offset + m_col_len * 3,
        m_col_offset + m_col_len * 4,
    ];
    // let addroundkey_len = 16 * 11;
    let message = m_col[4] + m_col_len;
    let round_keys = message + 16;

    AesWitnessRegions {
        start,
        s_box,
        m_col,
        message,
        round_keys,
        len: round_keys + 16 * 11,
    }
};

/// Transforms an AES witness into a flattened vector representation.
///
/// This function takes an AES witness, which captures the execution trace of AES encryption, and
/// turns it into a continuous vector.
/// Each 8-bit byte from the witness is split into two 4-bit parts to simplify
/// the lookup operations.
pub(crate) fn vectorize_witness(witness: &aes::Witness) -> Vec<u8> {
    let mut w = Vec::<u8>::new();

    assert_eq!(OFFSETS.start, w.len());
    w.extend(&witness.start);
    assert_eq!(OFFSETS.s_box, w.len());
    w.extend(&witness.s_box);
    for i in 0..5 {
        assert_eq!(OFFSETS.m_col[i], w.len());
        w.extend(&witness.m_col[i]);
    }
    // split the witness and low and high 4-bits.
    w.iter().map(|x| [x & 0xf, x >> 4]).flatten().collect()
}

fn lin_sbox_map<F: Field>(dst: &mut [F], v: &[F], r: F) {
    let identity = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let s_row = aes::shiftrows(identity);

    for round in 0..10 {
        for i in 0..16 {
            let s_row_pos = 16 * round + s_row[i] as usize;
            let s_box_pos = 16 * round + i;
            let c_lo = v[round * 16 + i];
            let c_hi = c_lo.double().double().double().double();
            dst[(OFFSETS.start + s_row_pos) * 2] += c_lo;
            dst[(OFFSETS.start + s_row_pos) * 2 + 1] += c_hi;
            dst[(OFFSETS.s_box + s_box_pos) * 2] += r * c_lo;
            dst[(OFFSETS.s_box + s_box_pos) * 2 + 1] += r * c_hi;
        }
    }
}

fn lin_rj2_map<F: Field>(dst: &mut [F], v: &[F], r: F) {
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let c_lo = v[pos];
            let c_hi = c_lo.double().double().double().double();
            dst[(OFFSETS.s_box + pos) * 2] += c_lo;
            dst[(OFFSETS.s_box + pos) * 2 + 1] += c_hi;
            dst[(OFFSETS.m_col[0] + pos) * 2] += r * c_lo;
            dst[(OFFSETS.m_col[0] + pos) * 2 + 1] += r * c_hi;
        }
    }
}

fn lin_xor_m_col_map<F: Field>(dst: &mut [F], v: &[F], r: F, r2: F) {
    let identity = (0..16).collect::<Vec<_>>();
    let mut aux_m_col = vec![identity; 4];
    aes::rotate_right_inplace(&mut aux_m_col[0], 1);
    aes::rotate_right_inplace(&mut aux_m_col[1], 2);
    aes::rotate_right_inplace(&mut aux_m_col[2], 3);
    aes::rotate_right_inplace(&mut aux_m_col[3], 3);

    for k in 0..4 {
        for round in 0..9 {
            for i in 0..16 {
                let pos = 16 * round + i;
                let ys_pos = 16 * round + aux_m_col[k][i];
                let ys_offset = if k < 3 {
                    OFFSETS.s_box
                } else {
                    OFFSETS.m_col[0]
                };
                let v_even = v[(16 * 9 * k + pos) * 2];
                let v_odd = v[(16 * 9 * k + pos) * 2 + 1];
                dst[(OFFSETS.m_col[k] + pos) * 2] += v_even;
                dst[(ys_offset + ys_pos) * 2] += r * v_even;
                dst[(OFFSETS.m_col[k + 1] + pos) * 2] += r2 * v_even;

                dst[(OFFSETS.m_col[k] + pos) * 2 + 1] += v_odd;
                dst[(ys_offset + ys_pos) * 2 + 1] += r * v_odd;
                dst[(OFFSETS.m_col[k + 1] + pos) * 2 + 1] += r2 * v_odd;
            }
        }
    }
}

fn lin_xor_addroundkey<F: Field>(output: &[u8; 16], dst: &mut [F], v: &[F], r: F, r2: F) -> F {
    let mut constant_term = F::from(0);

    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let v_even = v[pos * 2];
            let v_odd = v[pos * 2 + 1];
            dst[(OFFSETS.m_col[4] + pos) * 2] += v_even;
            dst[(OFFSETS.start + pos + 16) * 2] += r2 * v_even;
            dst[(OFFSETS.round_keys + pos + 16) * 2] += r * v_even;

            dst[(OFFSETS.m_col[4] + pos) * 2 + 1] += v_odd;
            dst[(OFFSETS.start + pos + 16) * 2 + 1] += r2 * v_odd;
            dst[(OFFSETS.round_keys + pos + 16) * 2 + 1] += r * v_odd;
        }
    }
    // final round
    for i in 0..16 {
        let pos = 16 * 9 + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        dst[(OFFSETS.s_box + pos) * 2] += v_even;
        dst[(OFFSETS.s_box + pos) * 2 + 1] += v_odd;
        dst[(OFFSETS.round_keys + pos + 16) * 2] += r * v_even;
        dst[(OFFSETS.round_keys + pos + 16) * 2 + 1] += r * v_odd;
        // in AES-EM mode, we would have to add the message instead.
        // dst[(OFFSETS.message + i) * 2] += r * v_even;
        // dst[(OFFSETS.message + i) * 2 + 1] += r * v_odd;
        constant_term += r2 * v_even * F::from(output[i] & 0xf);
        constant_term += r2 * v_odd * F::from(output[i] >> 4);
    }

    // initial round
    for i in 0..16 {
        let pos = 16 * 10 + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        // message
        dst[(OFFSETS.message + i) * 2] += v_even;
        dst[(OFFSETS.message + i) * 2 + 1] += v_odd;
        // initial round key
        dst[(OFFSETS.round_keys + i) * 2] += r * v_even;
        dst[(OFFSETS.round_keys + i) * 2 + 1] += r * v_odd;
        // .start
        dst[(OFFSETS.start + i) * 2] += r2 * v_even;
        dst[(OFFSETS.start + i) * 2 + 1] += r2 * v_odd;
    }
    constant_term
}

/// Compute the linear map that maps the AES witness to the needles vector.
pub(crate) fn trace_to_needles_map<F: Field>(
    output: &[u8; 16],
    src: &[F],
    r_sbox: F,
    r_rj2: F,
    r_xor: F,
    r2_xor: F,
) -> (Vec<F>, F) {
    let mut dst = vec![F::zero(); OFFSETS.len * 2];
    let mut offset = 0;
    lin_sbox_map(&mut dst, src, r_sbox);
    offset += 16 * 10;
    lin_rj2_map(&mut dst, &src[offset..], r_rj2);
    offset += 16 * 9;
    lin_xor_m_col_map(&mut dst, &src[offset..], r_xor, r2_xor);
    offset += 16 * 9 * 4 * 2;
    let constant_term = lin_xor_addroundkey(output, &mut dst, &src[offset..], r_xor, r2_xor);

    (dst, constant_term)
}

#[test]
fn test_trace_to_needles_map() {
    use crate::{linalg, prover};
    type F = ark_curve25519::Fr;
    use ark_std::UniformRand;

    let rng = &mut rand::thread_rng();

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let witness = aes::aes128_trace(message, key);
    // actual length needed is: ceil(log(OFFSETS.cipher_len * 2))
    let challenges = (0..11).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let vector = linalg::tensor(&challenges);

    let r_xor = F::rand(rng);
    let r2_xor = F::rand(rng);
    let r_sbox = F::rand(rng);
    let r_rj2 = F::rand(rng);

    let (needles, _, _) =
        prover::compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_rj2);
    let got = linalg::inner_product(&needles, &vector);

    let cipher_trace = vectorize_witness(&witness);
    let round_keys = aes::keyschedule(&key);

    // these elements will be commited to a separate vector.
    let message = witness.message.iter().map(|x| [x & 0xf, x >> 4]).flatten();
    let keys = round_keys
        .iter()
        .flatten()
        .map(|x| [x & 0xf, x >> 4])
        .flatten();

    let trace = cipher_trace
        .into_iter()
        .chain(message)
        .chain(keys)
        .map(|x| F::from(x))
        .collect::<Vec<_>>();

    let (needled_vector, constant_term) =
        trace_to_needles_map(&witness.output, &vector, r_sbox, r_rj2, r_xor, r2_xor);
    let expected = linalg::inner_product(&needled_vector, &trace) + constant_term;
    assert_eq!(got, expected);
}
