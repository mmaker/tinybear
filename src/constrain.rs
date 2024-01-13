use ark_ff::Field;

use crate::{aes, registry};

pub fn aes_trace_to_needles<F: Field, const R: usize>(
    output: &[u8; 16],
    src: &[F],
    [c_xor, c_xor2, c_sbox, c_rj2]: [F; 4],
) -> (Vec<F>, F) {
    let reg = registry::aes_offsets::<R>();

    let mut dst = vec![F::zero(); reg.len * 2];
    let mut offset = 0;
    cipher_sbox::<F, R>(&mut dst, src, c_sbox);
    offset += 16 * (R - 1);
    cipher_rj2::<F, R>(&mut dst, &src[offset..], c_rj2);
    offset += 16 * (R - 2);
    cipher_mcol::<F, R>(&mut dst, &src[offset..], c_xor, c_xor2);
    offset += 16 * (R - 2) * 4 * 2;
    let constant_term = cipher_addroundkey::<F, R>(output, &mut dst, &src[offset..], c_xor, c_xor2);

    (dst, constant_term)
}

pub fn aes_keysch_trace_to_needles<F: Field, const R: usize, const N: usize>(
    src: &[F],
    [c_xor, c_xor2, c_sbox, _c_rj2]: [F; 4],
) -> (Vec<F>, F) {
    let registry = registry::aes_keysch_offsets::<R, N>();
    let mut dst = vec![F::zero(); registry.len * 2];
    let mut offset: usize = 0;
    crate::constrain::ks_lin_sbox_map::<F, R, N>(&mut dst, src, c_sbox);
    offset += 4 * (R - N / 4);
    let constant_term =
        crate::constrain::ks_lin_xor_map::<F, R, N>(&mut dst, &src[offset..], [c_xor, c_xor2]);
    (dst, constant_term)
}

pub fn cipher_sbox<F: Field, const R: usize>(dst: &mut [F], v: &[F], r: F) {
    let identity = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let s_row = aes::shiftrows(identity);
    let reg = registry::aes_offsets::<R>();

    for round in 0..R - 1 {
        for i in 0..16 {
            let s_row_pos = 16 * round + s_row[i] as usize;
            let s_box_pos = 16 * round + i;
            let c_lo = v[round * 16 + i];
            let c_hi = c_lo.double().double().double().double();
            dst[(reg.start + s_row_pos) * 2] += c_lo;
            dst[(reg.start + s_row_pos) * 2 + 1] += c_hi;
            dst[(reg.s_box + s_box_pos) * 2] += r * c_lo;
            dst[(reg.s_box + s_box_pos) * 2 + 1] += r * c_hi;
        }
    }
}

pub fn cipher_rj2<F: Field, const R: usize>(dst: &mut [F], v: &[F], r: F) {
    let reg = registry::aes_offsets::<R>();

    for round in 0..R - 2 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let c_lo = v[pos];
            let c_hi = c_lo.double().double().double().double();
            dst[(reg.s_box + pos) * 2] += c_lo;
            dst[(reg.s_box + pos) * 2 + 1] += c_hi;
            dst[(reg.m_col[0] + pos) * 2] += r * c_lo;
            dst[(reg.m_col[0] + pos) * 2 + 1] += r * c_hi;
        }
    }
}

pub fn cipher_mcol<F: Field, const R: usize>(dst: &mut [F], v: &[F], r: F, r2: F) {
    let identity = (0..16).collect::<Vec<_>>();
    let registry = registry::aes_offsets::<R>();

    let mut aux_m_col = vec![identity; 4];
    aes::rotate_right_inplace(&mut aux_m_col[0], 1);
    aes::rotate_right_inplace(&mut aux_m_col[1], 2);
    aes::rotate_right_inplace(&mut aux_m_col[2], 3);
    aes::rotate_right_inplace(&mut aux_m_col[3], 3);

    for k in 0..4 {
        for round in 0..R - 2 {
            for i in 0..16 {
                let pos = 16 * round + i;
                let ys_pos = 16 * round + aux_m_col[k][i];
                let ys_offset = if k < 3 {
                    registry.s_box
                } else {
                    registry.m_col[0]
                };
                let v_even = v[(16 * (R - 2) * k + pos) * 2];
                let v_odd = v[(16 * (R - 2) * k + pos) * 2 + 1];
                dst[(registry.m_col[k] + pos) * 2] += v_even;
                dst[(ys_offset + ys_pos) * 2] += r * v_even;
                dst[(registry.m_col[k + 1] + pos) * 2] += r2 * v_even;

                dst[(registry.m_col[k] + pos) * 2 + 1] += v_odd;
                dst[(ys_offset + ys_pos) * 2 + 1] += r * v_odd;
                dst[(registry.m_col[k + 1] + pos) * 2 + 1] += r2 * v_odd;
            }
        }
    }
}

pub fn cipher_addroundkey<F: Field, const R: usize>(
    output: &[u8; 16],
    dst: &mut [F],
    v: &[F],
    r: F,
    r2: F,
) -> F {
    let mut constant_term = F::from(0);
    let registry = registry::aes_offsets::<R>();

    for round in 0..R - 2 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let v_even = v[pos * 2];
            let v_odd = v[pos * 2 + 1];
            dst[(registry.m_col[4] + pos) * 2] += v_even;
            dst[(registry.start + pos + 16) * 2] += r2 * v_even;
            dst[(registry.round_keys + pos + 16) * 2] += r * v_even;

            dst[(registry.m_col[4] + pos) * 2 + 1] += v_odd;
            dst[(registry.start + pos + 16) * 2 + 1] += r2 * v_odd;
            dst[(registry.round_keys + pos + 16) * 2 + 1] += r * v_odd;
        }
    }
    // final round
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        let pos = 16 * (R - 2) + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        dst[(registry.s_box + pos) * 2] += v_even;
        dst[(registry.s_box + pos) * 2 + 1] += v_odd;
        dst[(registry.round_keys + pos + 16) * 2] += r * v_even;
        dst[(registry.round_keys + pos + 16) * 2 + 1] += r * v_odd;
        // in AES-EM mode, we would have to add the message instead.
        // dst[(OFFSETS.message + i) * 2] += r * v_even;
        // dst[(OFFSETS.message + i) * 2 + 1] += r * v_odd;
        constant_term += r2 * v_even * F::from(output[i] & 0xf);
        constant_term += r2 * v_odd * F::from(output[i] >> 4);
    }

    // initial round
    for i in 0..16 {
        let pos = 16 * (R - 1) + i;
        let v_even = v[pos * 2];
        let v_odd = v[pos * 2 + 1];
        // message
        dst[(registry.message + i) * 2] += v_even;
        dst[(registry.message + i) * 2 + 1] += v_odd;
        // initial round key
        dst[(registry.round_keys + i) * 2] += r * v_even;
        dst[(registry.round_keys + i) * 2 + 1] += r * v_odd;
        // .start
        dst[(registry.start + i) * 2] += r2 * v_even;
        dst[(registry.start + i) * 2 + 1] += r2 * v_odd;
    }
    constant_term
}

pub fn ks_lin_sbox_map<F: Field, const R: usize, const N: usize>(dst: &mut [F], v: &[F], r: F) {
    let reg = registry::aes_keysch_offsets::<R, N>();
    let n_4 = N / 4;
    let identity = [0, 1, 2, 3];
    let mut rotated_left = identity.clone();
    rotated_left.rotate_left(1);

    for round in n_4..R {
        let idx = if N > 6 && (round * 4) % N == 4 {
            identity
        } else {
            rotated_left
        };
        for (y_j, x_j) in idx.into_iter().enumerate() {
            let x_pos = 16 * (round - n_4) + 3 * 4 + x_j;
            let y_pos = 4 * round + y_j;

            let c_lo = v[(round - n_4) * 4 + y_j];
            let c_hi = c_lo.double().double().double().double();
            dst[(reg.round_keys + x_pos) * 2] += c_lo;
            dst[(reg.round_keys + x_pos) * 2 + 1] += c_hi;
            dst[(reg.s_box + y_pos) * 2] += r * c_lo;
            dst[(reg.s_box + y_pos) * 2 + 1] += r * c_hi;
        }
    }
}

pub fn ks_lin_xor_map<F: Field, const R: usize, const N: usize>(
    dst: &mut [F],
    v: &[F],
    [r, r2]: [F; 2],
) -> F {
    let reg = registry::aes_keysch_offsets::<R, N>();
    // the running index over the source vector
    let mut v_pos = 0;
    let mut constant_term = F::from(0);

    // round_keys[i - n_4][1..4] XOR round_keys[i][0..3] = round_keys[i][1..4]
    let n_4 = N / 4;
    for round in n_4..R {
        for i in 1..4 {
            for j in 0..4 {
                let x_pos = 16 * (round - n_4) + i * 4 + j;
                let y_pos = 16 * round + (i - 1) * 4 + j;
                let z_pos = 16 * round + i * 4 + j;

                let v_even = v[v_pos * 2];
                let v_odd = v[v_pos * 2 + 1];

                dst[(reg.round_keys + x_pos) * 2] += v_even;
                dst[(reg.round_keys + y_pos) * 2] += r * v_even;
                dst[(reg.round_keys + z_pos) * 2] += r2 * v_even;

                dst[(reg.round_keys + x_pos) * 2 + 1] += v_odd;
                dst[(reg.round_keys + y_pos) * 2 + 1] += r * v_odd;
                dst[(reg.round_keys + z_pos) * 2 + 1] += r2 * v_odd;

                v_pos += 1;
            }
        }
    }

    // at this point,
    // v_pos = 3 * (R-1) * 4

    for round in n_4..R {
        for j in 0..4 {
            let x_pos = 16 * (round - n_4) + j;
            let y_pos = 4 * round + j;
            let z_pos = 16 * round + j;

            let v_even = v[v_pos * 2];
            let v_odd = v[v_pos * 2 + 1];

            dst[(reg.round_keys + x_pos) * 2] += v_even;
            dst[(reg.xor + y_pos) * 2] += r * v_even;
            dst[(reg.round_keys + z_pos) * 2] += r2 * v_even;

            dst[(reg.round_keys + x_pos) * 2 + 1] += v_odd;
            dst[(reg.xor + y_pos) * 2 + 1] += r * v_odd;
            dst[(reg.round_keys + z_pos) * 2 + 1] += r2 * v_odd;

            v_pos += 1;
        }
    }

    // at this point,
    // count = 3 * (R-1) * 4 + (R-1) * 4
    constant_term
}
