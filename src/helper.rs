use crate::aes::{self, Witness};

use ark_ff::Field;

#[derive(Default)]
pub(super) struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col: [usize; 5],
    pub cipher_len: usize,
}

/// The witness is structured as follows:
///
/// ```text
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
    let addroundkey_len = 16  * 11;
    let cipher_len = m_col[4] + m_col_len + addroundkey_len;

    AesWitnessRegions {
        start,
        s_box,
        m_col,
        cipher_len,
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
    // now constrain the first round
}

struct AesEMStatement {
    message: [u8; 16],
    round_keys: [[u8; 16]; 11],
    output: [u8; 16],
}

fn lin_xor_addroundkey<F: Field>(stmt: AesEMStatement, dst: &mut [F], v: &[F], r: F, r2: F) -> F {
    let mut constant_term = F::from(0);

    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let v_even = v[pos * 2];
            let v_odd = v[pos * 2 + 1];
            dst[(OFFSETS.m_col[4] + pos) * 2] += v_even;
            dst[(OFFSETS.start + pos + 16) * 2] += r2 * v_even;
            // round key is missing
            constant_term += r * v_even * F::from(stmt.round_keys[round + 1][i] & 0xf);

            dst[(OFFSETS.m_col[4] + pos) * 2 + 1] += v_odd;
            dst[(OFFSETS.start + pos + 16) * 2 + 1] += r2 * v_odd;
            // round key is missing
            constant_term += r * v_odd * F::from(stmt.round_keys[round + 1][i] >> 4);
        }
    }
    // final round
    for i in 0..16 {
        let pos = 16 * 9 + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        dst[(OFFSETS.s_box + pos) * 2] += v_even;
        dst[(OFFSETS.s_box + pos) * 2 + 1] += v_odd;
        // final round key missing
        constant_term += r * v_even * F::from(stmt.round_keys[10][i] & 0xf);
        constant_term += r * v_odd * F::from(stmt.round_keys[10][i] >> 4);
        // output missing
        constant_term += r2 * v_even * F::from(stmt.output[i] & 0xf);
        constant_term += r2 * v_odd * F::from(stmt.output[i] >> 4);
    }

    // initial round is missing
    for i in 0..16 {
        let pos = 16 * 10 + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        dst[(OFFSETS.start + i) * 2] += r2 * v_even;
        dst[(OFFSETS.start + i) * 2 + 1] += r2 * v_odd;

        // initial round key missing
        constant_term += r * v_even * F::from(stmt.round_keys[0][i] & 0xf);
        constant_term += r * v_odd * F::from(stmt.round_keys[0][i] >> 4);
        // message missing
        constant_term += v_even * F::from(stmt.message[i] & 0xf);
        constant_term +=  v_odd * F::from(stmt.message[i] >> 4);
    }
    constant_term
}

/// Compute the linear map that maps the AES witness to the needles vector.
fn trace_to_needles_map<F: Field>(
    stmt: AesEMStatement,
    src: &[F],
    r_sbox: F,
    r_rj2: F,
    r_xor: F,
    r2_xor: F,
) -> (Vec<F>, F) {
    let mut dst = vec![F::zero(); OFFSETS.cipher_len * 2];
    let mut offset = 0;
    lin_sbox_map(&mut dst, src, r_sbox);
    offset += 16 * 10;
    lin_rj2_map(&mut dst, &src[offset..], r_rj2);
    offset += 16 * 9;
    lin_xor_m_col_map(&mut dst, &src[offset..], r_xor, r2_xor);
    offset += 16 * 9 * 4 * 2;
    let constant_term = lin_xor_addroundkey(stmt, &mut dst, &src[offset..], r_xor, r2_xor);

    (dst, constant_term)
}

impl From<&Witness> for AesEMStatement {
    fn from(value: &Witness) -> Self {
        AesEMStatement {
            message: value.message,
            round_keys: value._keys,
            output: value.output,
        }
    }
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
    let mut vector = vec![F::from(0); OFFSETS.cipher_len * 2];

    // let's do some counting of the constraints in this protocol
    let constraints_sbox = 10 * 16;
    let constraints_rj2 = 9 * 16;
    let constraints_m_col = 9 * 16 * 4 * 2;
    let constraints_addroundkey = 16 * 2 * 12 ;
    for i in 0.. vector.len() { // constraints_sbox + constraints_rj2 + constraints_m_col + constraints_addroundkey {
        vector[i] = F::rand(rng);
    }

    let r_xor = F::rand(rng);
    let r2_xor = F::rand(rng);
    let r_sbox = F::rand(rng);
    let r_rj2 = F::rand(rng);

    let (needles, _, _) =
        prover::compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_rj2);
    println!("needles: {:?}", needles.len());
    let got = linalg::inner_product(&needles, &vector);

    let trace = vectorize_witness(&witness)
        .iter()
        .map(|x| F::from(*x))
        .collect::<Vec<_>>();
    let stmt = (&witness).into();
    let (needled_vector, constant_term)  = trace_to_needles_map(stmt, &vector, r_sbox, r_rj2, r_xor, r2_xor);
    let expected = linalg::inner_product(&needled_vector, &trace) + constant_term;
    assert_eq!(got, expected);
}
