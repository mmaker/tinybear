use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use nimue::plugins::ark::*;
use nimue::{Arthur, DuplexHash, IOPattern, Merlin};
use std::ops

use crate::pedersen::{self, CommitmentKey};
use crate::traits::SumcheckIO;

pub struct Claim<A: AdditiveGroup>(pub Vec<A>, pub Vec<A>);

impl<G: CurveGroup, H: DuplexHash<u8>> SumcheckIO<G> for IOPattern<H>
where
    IOPattern<H>: GroupIOPattern<G> + FieldIOPattern<G::ScalarField>,
{
    fn add_sumcheck(mut self, len: usize) -> Self {
        for _ in 0..ark_std::log2(len) {
            self = self
                .add_points(2, "round-message")
                .challenge_scalars(1, "challenge");
        }
        self
    }
}

/// Helper function for when we are folding a vector of points with a vector of scalars
pub fn group_fold_inplace<G: CurveGroup>(f: &mut Vec<G::Affine>, r: G::ScalarField) {
    let half = (f.len() + 1) / 2;
    for i in 0..half {
        f[i] = (f[i * 2] + f.get(i * 2 + 1).unwrap_or(&G::Affine::ZERO).mul(r)).into();
    }
    f.drain(half..);
}

pub fn fold_inplace<M: AdditiveGroup>(f: &mut Vec<M>, r: M::Scalar) {
    let half = (f.len() + 1) / 2;
    for i in 0..half {
        f[i] = f[i * 2] + *f.get(i * 2 + 1).unwrap_or(&M::ZERO) * r;
    }
    f.drain(half..);
}

/// Helper function for when we are doing a sumcheck between a vector of points and a vector of scalars
pub fn group_round_message<G: CurveGroup>(f: &[G::ScalarField], g: &[G::Affine]) -> [G; 2] {
    let f_zero = G::ScalarField::ZERO;
    let g_zero = G::Affine::ZERO;

    let mut f_even = Vec::<G::ScalarField>::new();
    let mut g_even = Vec::<G::Affine>::new();
    let mut f_odd = Vec::<G::ScalarField>::new();
    let mut g_odd = Vec::<G::Affine>::new();

    for (f_pair, g_pair) in f.chunks(2).zip(g.chunks(2)) {
        // The even part of the polynomial must always be unwrapped.
        f_even.push(f_pair[0]);
        g_even.push(g_pair[0]);
        f_odd.push(*f_pair.get(1).unwrap_or(&f_zero));
        g_odd.push(*g_pair.get(1).unwrap_or(&g_zero));
    }

    let a = G::msm_unchecked(&g_even, &f_even);
    let b = G::msm_unchecked(&g_odd, &f_even) + G::msm_unchecked(&g_even, &f_odd);

    [a, b]
}

pub fn round_message<F, G>(f: &[F], g: &[G]) -> [G; 2]
where
    F: PrimeField,
    G: AdditiveGroup<Scalar = F>,
{
    let mut a = G::zero();
    let mut b = G::zero();
    let f_zero = F::zero();
    let g_zero = G::zero();

    for (f_pair, g_pair) in f.chunks(2).zip(g.chunks(2)) {
        // The even part of the polynomial must always be unwrapped.
        let f_even = f_pair[0];
        let g_even = g_pair[0];
        // For the right part, we might obtain zero if the degree is not a multiple of 2.
        let f_odd = f_pair.get(1).unwrap_or(&f_zero);
        let g_odd = g_pair.get(1).unwrap_or(&g_zero);
        // Add to the partial sum
        a += g_even * f_even;
        b += *g_odd * f_even + g_even * f_odd;
    }
    [a, b]
}

pub fn reduce_with_challenges<G: AdditiveGroup>(
    messages: &[[G; 2]],
    challenges: &[G::Scalar],
    mut claim: G,
) -> G {
    for (&[a, b], x) in messages.iter().zip(challenges) {
        let c = claim - a;
        claim = a + b * x + c * x.square();
    }
    claim
}

pub fn reduce<G>(arthur: &mut Arthur, n: usize, claim: G) -> (Vec<G::Scalar>, G)
where
    G: CurveGroup,
    G::Scalar: PrimeField,
{
    let logn = ark_std::log2(n) as usize;
    let mut challenges = Vec::with_capacity(logn);
    let mut messages = Vec::with_capacity(logn);
    // reduce to a subclaim using the prover's messages.
    for _ in 0..logn {
        let [a, b] = arthur.next_points().unwrap();
        messages.push([a, b]);
        // compute the next challenge from the previous coefficients.
        let [r] = arthur.challenge_scalars().unwrap();
        challenges.push(r);
    }
    let claim = reduce_with_challenges(&messages, &challenges, claim);
    (challenges, claim)
}

impl<F: Field> Claim<F> {
    pub fn new(v: &[F], w: &[F]) -> Self {
        Self(v.to_vec(), w.to_vec())
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }

    #[inline]
    fn fold(&mut self, r: F) {
        fold_inplace(&mut self.0, r);
        fold_inplace(&mut self.1, r);
    }
}

/// Prove the inner product <v, w> using a sumcheck
#[allow(non_snake_case)]
pub fn batch_sumcheck<G: CurveGroup, const N: usize>(
    merlin: &mut Merlin,
    ck: &CommitmentKey<G>,
    claims: &mut [Claim<G::ScalarField>; N],
    challenges: &[G::Scalar],
) -> (Vec<G::ScalarField>, Vec<[G::ScalarField; 2]>) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut openings = Vec::new();

    while claims.iter().any(|claim| claim.len() > 2) {
        let Claim(f, g) = &claims[0];
        let [mut a, mut b] = round_message(f, g);
        for (claim, challenge) in claims[1..].iter_mut().zip(challenges.iter()) {
            let Claim(f, g) = claim;
            let [claim_a, claim_b] = round_message(f, g);
            a += claim_a * challenge;
            b += claim_b * challenge;
        }

        let (A, a_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[a]);
        let (B, b_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[b]);
        merlin.add_points(&[A, B]).unwrap();
        let [c] = merlin.challenge_scalars().unwrap();

        claims.iter_mut().for_each(|claim| claim.fold(c));

        msgs.push([A, B]);
        chals.push(c);
        openings.push([a_opening, b_opening]);
    }
    (chals, openings)
}

/// Prove the inner product <v, w> using a sumcheck
#[allow(non_snake_case)]
pub fn sumcheck<G: CurveGroup>(
    merlin: &mut Merlin,
    ck: &CommitmentKey<G>,
    v: &[G::ScalarField],
    w: &[G::ScalarField],
) -> (
    Vec<G::ScalarField>,
    Vec<[G::ScalarField; 2]>,
    (G::ScalarField, G::ScalarField),
) {
    let mut chals = Vec::new();
    let mut openings = Vec::new();

    let mut v = v.to_vec();
    let mut w = w.to_vec();
    while w.len() + v.len() > 2 {
        let [a, b] = round_message(&v, &w);

        let (A, a_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[a]);
        let (B, b_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[b]);

        merlin.add_points(&[A, B]).unwrap();
        let [c] = merlin.challenge_scalars().unwrap();
        fold_inplace(&mut v, c);
        fold_inplace(&mut w, c);

        chals.push(c);
        openings.push([a_opening, b_opening]);
    }
    (chals, openings, (v[0], w[0]))
}

#[test]
fn test_sumcheck() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;
    use crate::linalg;
    use ark_std::UniformRand;

    let mut rng = rand::rngs::OsRng;
    let ck = pedersen::setup::<G>(&mut rng, 16);
    let v = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let w = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let ip = linalg::inner_product(&v, &w);
    let (ip_com, mut ip_opening) = pedersen::commit_hiding(&mut rng, &ck, &[ip]);

    let iop = IOPattern::new("sumcheck");
    let iop = SumcheckIO::<G>::add_sumcheck(iop, 16);
    let mut merlin = iop.to_merlin();
    // Prover side of sumcheck
    let (expected_chals, openings, final_foldings) = sumcheck(&mut merlin, &ck, &v[..], &w[..]);

    ip_opening = reduce_with_challenges(&openings, &expected_chals[..], ip_opening);
    // Verifier side:

    // Get sumcheck random challenges and tensorcheck claim (random evaluation claim)
    let mut arthur = iop.to_arthur(merlin.transcript());
    let (challenges, tensorcheck_claim) = reduce(&mut arthur, 16, ip_com);
    assert_eq!(challenges, expected_chals);
    assert_eq!(
        ck.G * final_foldings.0 * final_foldings.1 + ck.H * ip_opening,
        tensorcheck_claim
    );
    // Compute evaluation point from challenges
    let challenge_point = linalg::tensor(&challenges);

    // Evaluate "polynomial" v at challenge point
    let folded_v = linalg::inner_product(&v, &challenge_point[..]);
    // Evaluate "polynomial" w at challenge point
    let folded_w = linalg::inner_product(&w, &challenge_point[..]);

    // Check that their product matches the tensorcheck claim
    assert_eq!(folded_v, final_foldings.0);
    assert_eq!(folded_w, final_foldings.1);
}
