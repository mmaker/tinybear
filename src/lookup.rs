use ark_ff::Field;

pub fn count_u16_frequencies<'a>(dst: &mut [u8], witness: impl IntoIterator<Item = &'a (u8, u8, u8)>) {
    for &(x, y, _z) in witness {
        let i_lo = (x & 0xf) | ((y & 0xf) << 4);
        let i_hi = (x >> 4) | (y & 0xf0);
        dst[i_lo as usize] += 1;
        dst[i_hi as usize] += 1;
    }
}

pub fn count_u8_frequencies<'a>(dst: &mut [u8], witness: impl IntoIterator<Item = &'a (u8, u8)>) {
    for &(x, _y) in witness {
        dst[x as usize] += 1;
    }
}

pub fn compute_u8_needles<'a, F: Field>(witness: impl IntoIterator<Item = &'a (u8, u8)>, r: F) -> Vec<F> {
    witness
        .into_iter()
        .map(|&(x, y)| F::from(x) + r * F::from(y))
        .collect()
}

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
