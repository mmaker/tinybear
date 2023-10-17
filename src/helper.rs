use crate::aes;

use ark_ff::Field;

#[derive(Default)]
pub(super) struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    // final_s_box: usize,
    pub m_col_xor: [usize; 5],
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
pub(super) const OFFSETS: AesWitnessRegions = {
    let start = 0;
    let s_box = start + 16 * 9 + 16;
    // thank Rust for const for loops
    let m_col_offset = s_box + 16 * 10;
    let m_col_len = 16 * 9;
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


/// Transforms an AES witness into a flattened vector representation.
///
/// This function takes an AES witness, which captures the execution trace of AES encryption, and turns it into a
/// continuous vector of 4-bit chunks.  Each 8-bit byte from the witness is split into two 4-bit parts to simplify
/// the lookup operations.
pub(crate) fn vectorize_witness(witness: &aes::Witness) -> Vec<u8> {
    let mut w = Vec::<u8>::new();

    assert_eq!(OFFSETS.start, w.len());
    w.extend(&witness.start);
    assert_eq!(OFFSETS.s_box, w.len());
    w.extend(&witness.s_box);
    for i in 0..5 {
        assert_eq!(OFFSETS.m_col_xor[i], w.len());
        w.extend(&witness.m_col_xor[i]);
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
            //
            let c_lo = v[round * 16 + i];
            let c_hi = c_lo.double().double().double().double();
            dst[s_row_pos * 2] += c_lo;
            dst[s_row_pos * 2 + 1] += c_hi;
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
    let identity = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut aux_m_col = [identity; 4];
    aes::rotate_right_inplace(&mut aux_m_col[0], 1);
    aes::rotate_right_inplace(&mut aux_m_col[1], 2);
    aes::rotate_right_inplace(&mut aux_m_col[2], 3);
    aes::rotate_right_inplace(&mut aux_m_col[3], 3);

    let mut offset = 0;

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
                let c_even = v[offset + 16 * 9 * 2 * k + pos * 2];
                let c_odd = v[offset + 16 * 9 * 2 * k + pos * 2 + 1];
                dst[OFFSETS.m_col_xor[k] + pos * 2] += c_even;
                dst[ys_offset + ys_pos * 2] += r * c_even;
                dst[OFFSETS.m_col_xor[k + 1] + pos * 2] += r2 * c_even;

                dst[OFFSETS.m_col_xor[k] + pos * 2 + 1] += c_odd;
                dst[ys_offset + ys_pos * 2 + 1] += r * c_odd;
                dst[OFFSETS.m_col_xor[k + 1] + pos * 2 + 1] += r2 * c_odd;
            }
        }
    }

    offset += 16 * 9 * 4 * 2;
    // add mxcolpre
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let c_even = v[offset + pos * 2];
            let c_odd = v[offset + pos * 2 + 1];
            dst[OFFSETS.m_col_xor[4] + pos * 2] += c_even;
            // current_row[ys_offset + ys_pos * 2] += r_xor * c_even;
            dst[OFFSETS.start + pos * 2] += r2 * c_even;

            dst[OFFSETS.m_col_xor[4] + pos * 2 + 1] += c_odd;
            // current_row[ys_offset + ys_pos * 2 + 1] += r_xor * c_odd;
            dst[OFFSETS.start + pos * 2 + 1] += r2 * c_odd;
        }
    }
}



/// DOCDOC
/// Used by sigma protocol verifier in order to construct the right evaluation given the shiftrow permutation
fn trace_to_needles_map<F: Field>(src: &[F], r_sbox: F, r_rj2: F, r_xor: F, r2_xor: F) -> Vec<F> {
    // the final matrix that maps witness -> needles
    // has dimensions: needles.len() x witness.len()
    // where
    // needles.len() = 1472
    //   s_box_needles.len() (9 * 16) +
    //   r2j.len() (9 * 16) +
    //   xor_needles.len() (16 * 9 * 5 * 2)
    // witness.len() =
    //   start.len() (9 * 16 * 2)
    //   s_box.len() (9 * 16 * 2)
    //   r2j.len() (9 * 16 * 5 * 2)
    const WITNESS_LEN: usize = 2016 + 144;

    let mut dst = vec![F::zero(); WITNESS_LEN];
    // sbox
    let mut offset = 0;
    lin_sbox_map(&mut dst, src, r_sbox);
    // rj2
    offset += 16 * 10;
    lin_rj2_map(&mut dst, &src[offset..], r_rj2);
    // xor
    offset += 16 * 9;
    // lin_xor_map(&mut dst, &src[offset..], r_xor, r2_xor);

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
    let mut vector = vec![F::from(0u8); 3000];
    for i in 0 .. 10*16 + 9 * 16{
        vector[i] = F::rand(rng);
    }

    let r_xor =  F::from(0);
    let r2_xor = F::from(0);
    let r_sbox =  F::from(42);
    let r_rj2 =  F::from(1);

    let (needles, _, _) = prover::compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_rj2);
    let got = linalg::inner_product(&needles, &vector);

    let trace = vectorize_witness(&witness).iter().map(|x| F::from(*x)).collect::<Vec<_>>();
    let needled_vector = trace_to_needles_map(&vector, r_sbox, r_rj2, r_xor, r2_xor);
    let expected = linalg::inner_product(&needled_vector, &trace);
    assert_eq!(got, expected);
}

