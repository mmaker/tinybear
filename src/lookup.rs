use ark_ff::Field;

use crate::aes::{self};

/// Counts the occurrences of 16-bit tuples in the given witness.
///
/// This function increases counters in the `dst` array for each occurrence of the 4-bit slices of `x` and `y` found in
/// the witness.
pub fn count_u16_frequencies<'a>(
    dst: &mut [u8],
    witness: impl IntoIterator<Item = &'a (u8, u8, u8)>,
) {
    for &(x, y, _z) in witness {
        let i_lo = (x & 0xf) | ((y & 0xf) << 4);
        let i_hi = (x >> 4) | (y & 0xf0);
        dst[i_lo as usize] += 1;
        dst[i_hi as usize] += 1;
    }
}

/// Counts the occurrences of 8-bit values in the given witness.
///
/// This function increases counters in the `dst` array for each occurrence of `x` found in the witness.
pub fn count_u8_frequencies<'a>(dst: &mut [u8], witness: impl IntoIterator<Item = &'a (u8, u8)>) {
    for &(x, _y) in witness {
        dst[x as usize] += 1;
    }
}

/// For each (x, y) tuple in the witness, compute a needle out of it using a random linear combination.
///
/// Given (x, y), compute `x + r * y`.
pub fn compute_u8_needles<'a, F: Field>(
    witness: impl IntoIterator<Item = &'a (u8, u8)>,
    r: F,
) -> Vec<F> {
    witness
        .into_iter()
        .map(|&(x, y)| F::from(x) + r * F::from(y))
        .collect()
}

/// Computes "needles" for each tuple `(x, y, z)` from the witness by computing random linear combinations for both the
/// low-order and high-order 4-bits of each byte in the tuple.
///
/// # How It Works
/// 1. Each byte in the tuple `(x, y, z)` is split into its low-order and high-order 4-bits.
/// 2. For the low-order 4-bits, the linear combination is:
///     lo_combination = F(lo_x) + r[0] F(lo_y) + r[1] F(lo_z)
/// 3. For the high-order 4-bits, the linear combination is:
///     hi_combination = F(hi_x) + r[0] F(hi_y) + r[1] F(hi_z)
/// 4. Both `lo_combination` and `hi_combination` are returned in sequence for each tuple.
///
/// # Returns
/// A flattened vector containing all the computed linear combinations. For `n` tuples in the witness,
/// the resulting vector will contain `2n` field elements, where every two consecutive elements
/// represent the low and high linear combinations for a single tuple.
pub fn compute_u16_needles<'a, F: Field>(
    witness: impl IntoIterator<Item = &'a (u8, u8, u8)>,
    r: [F; 2],
) -> Vec<F> {
    witness
        .into_iter()
        .map(|&(x, y, z)| {
            let (lo_x, lo_y, lo_z) = (x & 0xf, y & 0xf, z & 0xf);
            let (hi_x, hi_y, hi_z) = (x >> 4, y >> 4, z >> 4);
            [
                F::from(lo_x) + F::from(lo_y) * r[0] + F::from(lo_z) * r[1],
                F::from(hi_x) + F::from(hi_y) * r[0] + F::from(hi_z) * r[1],
            ]
        })
        .flatten()
        .collect()
}

/// Compute the haystack table t
pub fn compute_haystack<F: Field>(
    r_xor: F,
    r2_xor: F,
    r_sbox: F,
    r_mul: F,
    lookup_challenge: F,
) -> (Vec<F>, Vec<F>) {
    // Start computing vector of inverse_haystack
    // First we need to iterate over all the possibilities for each operation
    let haystack_xor = (0u8..=255)
        .map(|i| {
            let x = i & 0xf;
            let y = i >> 4;
            let z = x ^ y;
            F::from(x) + r_xor * F::from(y) + r2_xor * F::from(z)
        })
        .collect::<Vec<_>>();
    let haystack_s_box = (0u8..=255)
        .map(|i| {
            let x = i;
            let y = aes::SBOX[x as usize];
            F::from(x) + r_sbox * F::from(y)
        })
        .collect::<Vec<_>>();
    let haystack_m_col_pre = (0u8..=255)
        .map(|i| {
            let x = i;
            let y = aes::M_COL_HELP[x as usize];
            F::from(x) + r_mul * F::from(y)
        })
        .collect::<Vec<_>>();

    // Compute vector of inverse_haystack[i] = 1 / (haystack[i] + a) = h
    let haystack = [haystack_xor, haystack_s_box, haystack_m_col_pre].concat();
    let mut inverse_haystack = haystack
        .iter()
        .map(|x| lookup_challenge + x)
        .collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_haystack);

    (haystack, inverse_haystack)
}
