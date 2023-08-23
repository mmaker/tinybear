use ark_ec::CurveGroup;
use ark_ff::AdditiveGroup;
use ark_ff::{Field, PrimeField};
use rand::{CryptoRng, RngCore};
use transcript::IOPTranscript;

use crate::pedersen::{self, CommitmentKey};

fn fold_inplace<M: AdditiveGroup>(f: &mut Vec<M>, r: M::Scalar) {
    let half = (f.len() + 1) / 2;
    for i in 0..half {
        f[i] = f[i * 2] + *f.get(i * 2 + 1).unwrap_or(&M::zero()) * r;
    }
    f.drain(half..);
}

fn round_message<F, G>(f: &[F], g: &[G]) -> [G; 2]
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

pub fn reduce<G>(
    transcript: &mut IOPTranscript<G::Scalar>,
    messages: &[[G; 2]],
    claim: G,
) -> (Vec<G::Scalar>, G)
where
    G: AdditiveGroup,
    G::Scalar: PrimeField,
{
    let mut challenges = Vec::with_capacity(messages.len());
    // reduce to a subclaim using the prover's messages.
    for &[a, b] in messages {
        // compute the next challenge from the previous coefficients.
        transcript
            .append_serializable_element(b"ab", &[a, b])
            .unwrap();
        let r = transcript.get_and_append_challenge(b"r").unwrap();
        challenges.push(r);
    }
    let claim = reduce_with_challenges(messages, &challenges, claim);
    (challenges, claim)
}

pub(crate) struct Claim<F: Field>(pub Vec<F>, pub Vec<F>);

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
    transcript: &mut IOPTranscript<G::ScalarField>,
    rng: &mut (impl RngCore + CryptoRng),
    ck: &CommitmentKey<G>,
    claims: &mut [Claim<G::ScalarField>; N],
    challenges: &[G::Scalar],
) -> (Vec<G::ScalarField>, Vec<[G; 2]>, Vec<[G::ScalarField; 2]>) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut openings = Vec::new();

    while claims.iter().any(|claim| claim.len() > 2) {
        let [mut a, mut b] = round_message(&claims[0].0, &claims[0].1);
        for (claim, challenge) in claims[1..].iter_mut().zip(challenges.iter()) {
            let [claim_a, claim_b] = round_message(&claim.0, &claim.1);
            a += claim_a * challenge;
            b += claim_b * challenge;
        }

        let (A, a_opening) = pedersen::commit_hiding(rng, ck, &[a]);
        let (B, b_opening) = pedersen::commit_hiding(rng, ck, &[b]);

        transcript
            .append_serializable_element(b"ab", &[A, B])
            .unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();

        claims.iter_mut().for_each(|claim| claim.fold(c));

        msgs.push([A, B]);
        chals.push(c);
        openings.push([a_opening, b_opening]);
    }
    (chals, msgs, openings)
}



/// Prove the inner product <v, w> using a sumcheck
#[allow(non_snake_case)]
pub fn sumcheck<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    rng: &mut (impl RngCore + CryptoRng),
    ck: &CommitmentKey<G>,
    v: &[G::ScalarField],
    w: &[G::ScalarField],
) -> (
    Vec<G::ScalarField>,
    Vec<[G; 2]>,
    Vec<[G::ScalarField; 2]>,
    (G::ScalarField, G::ScalarField),
) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut openings = Vec::new();

    let mut v = v.to_vec();
    let mut w = w.to_vec();
    while w.len() + v.len() > 2 {
        let [a, b] = round_message(&v, &w);

        let (A, a_opening) = pedersen::commit_hiding(rng, ck, &[a]);
        let (B, b_opening) = pedersen::commit_hiding(rng, ck, &[b]);

        transcript
            .append_serializable_element(b"ab", &[A, B])
            .unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        fold_inplace(&mut v, c);
        fold_inplace(&mut w, c);

        msgs.push([A, B]);
        chals.push(c);
        openings.push([a_opening, b_opening]);
    }
    (chals, msgs, openings, (v[0], w[0]))
}

#[test]
fn test_sumcheck() {
    type F = ark_curve25519::Fr;
    use crate::linalg;
    use ark_std::UniformRand;

    let mut rng = rand::rngs::OsRng;
    let ck = pedersen::setup::<ark_curve25519::EdwardsProjective>(&mut rng, 16);
    let v = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let w = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let ip = linalg::inner_product(&v, &w);
    let (ip_com, mut ip_opening) = pedersen::commit_hiding(&mut rng, &ck, &[ip]);

    let mut transcript_p = IOPTranscript::<F>::new(b"sumcheck");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<F>::new(b"sumcheck");
    transcript_v.append_message(b"init", b"init").unwrap();

    // Prover side of sumcheck
    let (expected_chals, messages, openings, final_foldings) =
        sumcheck(&mut transcript_p, &mut rng, &ck, &v[..], &w[..]);

    ip_opening = reduce_with_challenges(&openings, &expected_chals[..], ip_opening);
    // Verifier side:

    // Get sumcheck random challenges and tensorcheck claim (random evaluation claim)
    let (challenges, tensorcheck_claim) = reduce(&mut transcript_v, &messages, ip_com);
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
