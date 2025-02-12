use ark_ff::Field;
use core::{iter, ops};
use std::cmp::max;

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

#[derive(Debug)]
pub struct SparseMatrix<F: Field> {
    pub num_rows: usize,
    pub num_cols: usize,
    pub vals: Vec<F>,
    pub rows: Vec<usize>,
    pub cols: Vec<usize>,
}

impl<F: Field> SparseMatrix<F> {
    pub fn empty() -> Self {
        Self {
            num_rows: 0,
            num_cols: 0,
            vals: Vec::new(),
            rows: Vec::new(),
            cols: Vec::new(),
        }
    }

    pub fn new(vals: Vec<F>, rows: Vec<usize>, cols: Vec<usize>) -> Self {
        Self {
            num_rows: rows.iter().max().unwrap() + 1,
            num_cols: cols.iter().max().unwrap() + 1,
            vals: vals,
            rows: rows,
            cols: cols,
        }
    }

    pub fn combine(mut self, other: SparseMatrix<F>) -> Self {
        // println!("{:?}", other);
        self.num_rows = max(self.num_rows, other.num_rows);
        //self.num_rows + other.num_rows;
        self.vals.extend(other.vals);
        self.rows.extend(other.rows);
        self.cols.extend(other.cols);
        self.num_cols = max(self.num_cols, other.num_cols);
        self
    }

    pub fn combine_with_rowshift(self, mut other: SparseMatrix<F>) -> Self {
        other.rows.iter_mut().for_each(|x| *x += self.num_rows);
        other.num_rows = *other.rows.iter().max().unwrap() + 1;
        self.combine(other)
    }
}

impl<F, J> core::ops::Mul<J> for &SparseMatrix<F>
where
    F: Field,
    J: AsRef<[F]>,
{
    type Output = Vec<F>;

    fn mul(self, rhs: J) -> Self::Output {
        let mut result = vec![F::ZERO; self.num_rows];
        for i in 0..self.rows.len() {
            result[self.rows[i]] += self.vals[i] * rhs.as_ref()[self.cols[i]];
        }
        result
    }
}

impl<F: Field> core::ops::Mul<SparseMatrix<F>> for &[F] {
    type Output = Vec<F>;

    fn mul(self, rhs: SparseMatrix<F>) -> Self::Output {
        let mut result = vec![F::ZERO; rhs.num_cols];
        for i in 0..rhs.cols.len() {
            result[rhs.cols[i]] += rhs.vals[i] * self[rhs.rows[i]];
        }
        result
    }
}
