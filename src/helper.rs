use crate::aes;

use ark_ff::Field;

#[derive(Default)]
pub(super) struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col_xor: [usize; 5],
    pub len: usize,
}

/// The witness is structured as follows:
///
/// ````
/// +--------------+
/// |   .start     |
/// +--------------+
/// |   .sbox      |
/// +--------------+
/// |   .m_col     |
/// +--------------+
/// ```
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
///
/// The final witness length is therefore 160 + 160 + 720 = 1040.
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

    AesWitnessRegions {
        start,
        s_box,
        m_col_xor: m_col,
        len: m_col[4] + m_col_len,
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
        assert_eq!(OFFSETS.m_col_xor[i], w.len());
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
            dst[(OFFSETS.m_col_xor[0] + pos) * 2] += r * c_lo;
            dst[(OFFSETS.m_col_xor[0] + pos) * 2 + 1] += r * c_hi;
        }
    }
}

fn lin_xor_map<F: Field>(dst: &mut [F], v: &[F], r: F, r2: F) {
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
                    OFFSETS.m_col_xor[0]
                };
                let c_even = v[(16 * 9 * k + pos) * 2];
                let c_odd = v[(16 * 9 * k + pos) * 2 + 1];
                dst[(OFFSETS.m_col_xor[k] + pos) * 2] += c_even;
                dst[(ys_offset + ys_pos) * 2] += r * c_even;
                dst[(OFFSETS.m_col_xor[k + 1] + pos) * 2] += r2 * c_even;

                dst[(OFFSETS.m_col_xor[k] + pos) * 2 + 1] += c_odd;
                dst[(ys_offset + ys_pos) * 2 + 1] += r * c_odd;
                dst[(OFFSETS.m_col_xor[k + 1] + pos) * 2 + 1] += r2 * c_odd;
            }
        }
    }
}



/// Compute the linear map that maps the AES witness to the needles vector.
fn trace_to_needles_map<F: Field>(src: &[F], r_sbox: F, r_rj2: F, r_xor: F, r2_xor: F) -> Vec<F> {
    let mut dst = vec![F::zero(); OFFSETS.len*2];
    let mut offset = 0;
    lin_sbox_map(&mut dst, src, r_sbox);
    offset += 16 * 10;
    lin_rj2_map(&mut dst, &src[offset..], r_rj2);
    offset += 16 * 9;
    lin_xor_map(&mut dst, &src[offset..], r_xor, r2_xor);
    dst
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
    let mut vector = vec![F::from(0); 3000];
    for i in 0 .. 10*16 + 9 * 16 + 9*16*4 {
        vector[i] = F::rand(rng);
    }

    let r_xor =  F::from(2);
    let r2_xor = F::from(100);
    let r_sbox =  F::from(42);
    let r_rj2 =  F::from(0x42);

    let (needles, _, _) = prover::compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_rj2);
    let got = linalg::inner_product(&needles, &vector);

    let trace = vectorize_witness(&witness).iter().map(|x| F::from(*x)).collect::<Vec<_>>();
    let needled_vector = trace_to_needles_map(&vector, r_sbox, r_rj2, r_xor, r2_xor);
    let expected = linalg::inner_product(&needled_vector, &trace);
    assert_eq!(got, expected);
}
