//! See Figure 8 in the paper to learn how this protocol works
#![allow(non_snake_case)]

use crate::traits::Witness;
use crate::witness::registry::aes_keysch_offsets;
use crate::witness::trace::keyschedule::{self, AesKeySchTrace};
use crate::{constrain, lookup};
use ark_ff::Field;

pub struct AesKeySchWitness<F: Field, const R: usize, const N: usize> {
    trace: AesKeySchTrace<R, N>,
    witness_vec: Vec<u8>,
    round_keys_opening: F,
}

impl<F: Field, const R: usize, const N: usize> AesKeySchWitness<F, R, N> {
    pub fn new(key: &[u8], &round_keys_opening: &F) -> Self {
        let trace = AesKeySchTrace::<R, N>::new(key);
        let witness_vec = Self::vectorize_keysch(&trace);
        Self {
            trace,
            witness_vec,
            round_keys_opening,
        }
    }

    fn get_s_box_witness(&self) -> Vec<(u8, u8)> {
        let mut witness_s_box = Vec::new();
        let n_4 = N / 4;

        for i in n_4..R {
            let a = if N > 6 && (i * 4) % N == 4 {
                self.trace.round_keys[i - 1][3]
            } else {
                let mut a = self.trace.round_keys[i - 1][3];
                a.rotate_left(1);
                a
            };
            for (x, y) in a.into_iter().zip(self.trace.s_box[i]) {
                witness_s_box.push((x, y))
            }
        }
        witness_s_box
    }

    fn get_xor_witness(&self) -> Vec<(u8, u8, u8)> {
        let n_4 = N / 4;
        let mut witness_xor = Vec::new();

        for i in n_4..R {
            let xs = self.trace.round_keys[i - n_4][1..4]
                .iter()
                .flatten()
                .copied();
            let ys = self.trace.round_keys[i][0..3].iter().flatten().copied();
            let zs = self.trace.round_keys[i][1..4].iter().flatten().copied();

            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }

        for i in n_4..R {
            let xs = self.trace.round_keys[i - n_4][0].iter().copied();
            let ys = self.trace.xor[i].iter().copied();
            let zs = self.trace.round_keys[i][0].iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }

        witness_xor
    }

    pub fn vectorize_keysch(witness: &keyschedule::AesKeySchTrace<R, N>) -> Vec<u8> {
        let mut w = Vec::<u8>::new();
        let registry = aes_keysch_offsets::<R, N>();

        assert_eq!(registry.s_box, w.len());
        w.extend(witness.s_box.iter().flatten());
        assert_eq!(registry.xor, w.len());
        w.extend(witness.xor.iter().flatten());
        // assert_eq!(registry.round_keys, w.len());
        // w.extend(witness.round_keys.iter().flatten().flatten());
        // split the witness and low and high 4-bits.
        w.iter().flat_map(|x| [x & 0xf, x >> 4]).collect()
    }
}

impl<F: Field, const R: usize, const N: usize> Witness<F> for AesKeySchWitness<F, R, N> {
    fn witness_vec(&self) -> &[u8] {
        self.witness_vec.as_slice()
    }

    fn needles_len(&self) -> usize {
        aes_keysch_offsets::<R, N>().needles_len
    }

    fn compute_needles_and_frequencies(
        &self,
        [c_xor, c_xor2, c_sbox, _c_rj2]: [F; 4],
    ) -> (Vec<F>, Vec<F>, Vec<u64>) {
        let witness_s_box = self.get_s_box_witness();
        //This will need to chang since we'll have an additional xor
        let witness_xor = self.get_xor_witness();
        let s_box_needles = lookup::compute_u8_needles(&witness_s_box, c_sbox);
        let xor_needles = lookup::compute_u16_needles(&witness_xor, [c_xor, c_xor2]);
        let needles = [s_box_needles, xor_needles].concat();

        let mut freq_u64 = vec![0u64; 256 * 3];
        lookup::count_u16_frequencies(&mut freq_u64[0..256], &witness_xor);
        lookup::count_u8_frequencies(&mut freq_u64[256..512], &witness_s_box);

        let freq = freq_u64.iter().map(|x| F::from(*x)).collect::<Vec<_>>();
        (needles, freq, freq_u64)
    }

    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F) {
        constrain::aes_keysch_trace_to_needles::<F, R, N>(src, r)
    }

    fn full_witness(&self) -> Vec<F> {
        let round_keys = self
            .trace
            .round_keys
            .iter()
            .flatten()
            .flatten()
            .flat_map(|x| [x & 0xf, x >> 4]);
        self.witness_vec
            .iter()
            .copied()
            .chain(round_keys)
            .map(|x| F::from(x))
            .collect()
    }

    fn full_witness_opening(&self) -> F {
        self.round_keys_opening
    }
}

#[test]
fn test_linear_ks() {
    use crate::linalg::inner_product;
    use ark_curve25519::Fr as F;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let registry = aes_keysch_offsets::<11, 4>();
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let opening = F::from(1u8);
    let r = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    let ks = AesKeySchWitness::<F, 11, 4>::new(&key, &opening);
    let z = ks.full_witness();
    let v = (0..registry.needles_len)
        .map(|_| F::rand(rng))
        .collect::<Vec<_>>();

    let (Az, _f, _f8) = ks.compute_needles_and_frequencies(r);
    assert_eq!(Az.len(), registry.needles_len);
    // 180 constraints

    let (Av, _constant_term) = ks.trace_to_needles_map(&v, r);
    assert_eq!(inner_product(&Az, &v), inner_product(&Av, &z));
}
