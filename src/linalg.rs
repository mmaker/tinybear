use ark_ff::Field;
use core::{iter, ops};

/// Return the inner product of vectors `xs` and `ys`.
///
/// TODO: check if https://eprint.iacr.org/2022/367 brings improvements.
/// implemented in https://github.com/arkworks-rs/gemini/blob/main/src/misc.rs#L235.
pub fn inner_product<F: Copy + ops::Mul<Output = F> + iter::Sum>(xs: &[F], ys: &[F]) -> F {
    xs.iter().zip(ys).map(|(&x, &y)| x * y).sum()
}

/// Return a vector of length `len` containing the consecutive powers of element.
pub(crate) fn powers<F: Field>(element: F, len: usize) -> Vec<F> {
    let mut powers = vec![F::one(); len];
    for i in 1..len {
        powers[i] = element * powers[i - 1];
    }
    powers
}

pub(crate) fn hadamard<F: ops::Mul<Output = F> + Copy>(lhs: &[F], rhs: &[F]) -> Vec<F> {
    lhs.iter().zip(rhs).map(|(&x, &y)| x * y).collect()
}

pub(crate) fn add_constant<F: ops::Add<Output = F> + Copy>(v: &[F], c: F) -> Vec<F> {
    v.iter().map(|&x| x + c).collect()
}

/// Given as input `elements`, an array of field elements
/// \\(\rho_0, \dots, \rho_{n-1}\\)
/// compute the tensor product
/// \\( \otimes_j (1, \rho_j )\\)
pub fn tensor<F: Field>(elements: &[F]) -> Vec<F> {
    assert!(!elements.is_empty());
    let mut tensor = vec![F::one(); 1 << elements.len()];
    let mut elements_iterator = elements.iter().enumerate();

    tensor[1] = *elements_iterator
        .next()
        .expect("Expecting at lest one element in the tensor product.")
        .1;
    // guaranteed to have at least one element.
    for (i, element) in elements_iterator {
        for j in 0..1 << i {
            tensor[(1 << i) + j] = tensor[j] * element;
        }
    }
    tensor
}

pub fn linear_combination<F: Field>(vectors: &[&[F]], coefficients: &[F]) -> Vec<F> {
    // get longest vector length
    let len = vectors.iter().map(|v| v.len()).max().unwrap();

    let mut result = vectors[0].to_vec();
    result.resize(len, F::zero());
    for (v, c) in vectors[1..].iter().zip(coefficients) {
        for i in 0..v.len() {
            result[i] += v[i] * c;
        }
    }
    result
}
