use ark_ec::CurveGroup;
use ark_ff::AdditiveGroup;
use ark_ff::{Field, PrimeField, Zero};
use rand::{CryptoRng, RngCore};
use transcript::IOPTranscript;
use ark_ec::VariableBaseMSM;

use crate::linalg::{self, inner_product};
use crate::pedersen::{self, CommitmentKey};

/// Folds together `(a, b)` using challenges `x` and `y`.
fn fold<F: Field>(a: &[F], b: &[F], x: &F, y: &F) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| a * x + b * y)
        .collect()
}

fn fold_generators<G: CurveGroup>(
    a: &[G::Affine],
    b: &[G::Affine],
    x: &G::ScalarField,
    y: &G::ScalarField,
) -> Vec<G::Affine> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| (a * x + b * y).into_affine())
        .collect()
}

fn round_message<F, G>(f: &[F], g: &[G]) -> [G; 2]
where
    F: PrimeField,
    G: AdditiveGroup<Scalar = F>,
{
    let n = (f.len() + 1) / 2;
    let (f_left, f_right) = f.split_at(n);
    let (g_left, g_right) = g.split_at(n);

    let a = g_right.iter().zip(f_left.iter()).fold(G::zero(), |acc, (&g, &f)| acc + g * f);
    let b = g_left.iter().zip(f_right.iter()).fold(G::zero(), |acc, (&g, &f)| acc + g * f);

    [a, b]
}

fn group_round_message<F, G>(f: &[F], g: &[G::Affine]) -> [G; 2]
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let n = (f.len() + 1) / 2;
    let (f_left, f_right) = f.split_at(n);
    let (g_left, g_right) = g.split_at(n);

    let a = g_right.iter().zip(f_left.iter()).fold(G::zero(), |acc, (&g, &f)| acc + g * f);
    let b = g_left.iter().zip(f_right.iter()).fold(G::zero(), |acc, (&g, &f)| acc + g * f);

    [a, b]
}



// fn group_round_message<G>(f: &mut Vec<G::ScalarField>, g: &mut Vec<G::Affine>) -> [G; 2]
// where
//     G: CurveGroup,
// {
//     let f_even = f.iter().copied().step_by(2).collect::<Vec<_>>();
//     let g_even = g.iter().copied().step_by(2).collect::<Vec<_>>();
//     let f_odd = f.iter().copied().skip(1).step_by(2).collect::<Vec<_>>();
//     let g_odd = g.iter().copied().skip(1).step_by(2).collect::<Vec<_>>();

//     let a = G::msm_unchecked(&g_even, &f_even);
//     let b = G::msm_unchecked(&g_odd, &f_even) + G::msm_unchecked(&g_even, &f_odd);
//     [a, b]
// }

pub fn reduce<G>(
    transcript: &mut IOPTranscript<G::Scalar>,
    messages: &[[G; 2]],
    mut claim: G,
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

        // evaluate (a + bx + cx2) at r
        claim = a + claim * r + b * r.square();
    }
    (challenges, claim)
}

pub(crate) enum Claim<G: CurveGroup> {
    Field(Vec<G::ScalarField>, Vec<G::ScalarField>),
    Group(Vec<G::ScalarField>, Vec<G::Affine>),
}

impl<G: CurveGroup> Claim<G> {
    fn len(&self) -> usize {
        match self {
            Claim::Field(a, b) => a.len() + b.len(),
            Claim::Group(a, b) => a.len() + b.len(),
        }
    }

    fn fold(&mut self, c: G::ScalarField) {
        match self {
            Claim::Field(a, b) => {
                let n = (a.len() + 1) / 2;
                let (a_left, a_right) = a.split_at_mut(n);
                let (b_left, b_right) = b.split_at_mut(n);
                let a = fold(a_left, a_right, &c, &G::ScalarField::zero());
                let b = fold(b_left, b_right, &G::ScalarField::zero(), &c);
            }
            Claim::Group(a, b) => {
                let n = (a.len() + 1) / 2;
                let (a_left, a_right) = a.split_at_mut(n);
                let (b_left, b_right) = b.split_at_mut(n);
                let a = fold(a_left, a_right, &c, &G::ScalarField::zero());
                let b = fold_generators::<G>(b_left, b_right, &G::ScalarField::zero(), &c);
            }
        }
    }
}

pub(crate) fn batch_sumcheck<G: CurveGroup, const N: usize>(
    rng: &mut (impl RngCore + CryptoRng),
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    mut claims: [Claim<G>; N],
    batch_challenges: [G::ScalarField; N],
) -> (
    [Claim<G>; N],
    Vec<G::ScalarField>,
    Vec<[G; 2]>,
    Vec<[G::ScalarField; 2]>,
) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut openings = Vec::new();
    while claims.iter().any(|claim| claim.len() > 2) {
        let mut field_msg = [G::ScalarField::zero(), G::ScalarField::zero()];
        let mut group_msg = [G::zero(), G::zero()];
        for (batch_chal, claim) in batch_challenges.iter().zip(claims.iter_mut()) {
            match claim {
                Claim::Field(v, w) => {
                    let [a, b] = round_message(&v, &w);
                    field_msg[0] += a * batch_chal;
                    field_msg[1] += b * batch_chal;
                }
                Claim::Group(v, w) => {
                    let [a, b]: [G; 2] = group_round_message(&v, &w);
                    group_msg[0] += a * batch_chal;
                    group_msg[1] += b * batch_chal;
                }
            }
        }
        let (com_a, a_opening) = pedersen::commit_hiding(rng, ck, &[field_msg[0]]);
        let (com_b, b_opening) = pedersen::commit_hiding(rng, ck, &[field_msg[1]]);
        // let com_a = ck.G * field_msg[0];
        // let com_b = ck.G * field_msg[1];
        let msg = [com_a + group_msg[0], com_b + group_msg[1]];
        transcript.append_serializable_element(b"ab", &msg).unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        claims.iter_mut().for_each(|claim| claim.fold(c));
        msgs.push(msg);
        openings.push([a_opening, b_opening]);
        chals.push(c);
    }
    (claims, chals, msgs, openings)
}

/// Prove the inner product <v, w> using a sumcheck
pub fn sumcheck<F: PrimeField>(
    transcript: &mut IOPTranscript<F>,
    v: &[F],
    w: &[F],
) -> ((F, F), Vec<F>, Vec<[F; 2]>) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut v = v.to_vec();
    let mut w = w.to_vec();
    while w.len() + v.len() > 2 {
        let n = (v.len() + 1) / 2;

        let (v_left, v_right) = v.split_at(n);
        let (w_left, w_right) = w.split_at(n);

        let a = v_left.iter().zip(w_right.iter()).fold(F::zero(), |acc, (&x, &y)| acc + x * y);
        let b = v_right.iter().zip(w_left.iter()).fold(F::zero(), |acc, (&x, &y)| acc + x * y);
        transcript.append_serializable_element(b"ab", &[a, b]).unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        v = fold(v_left, v_right, &F::one(), &c);
        w = fold(w_left, w_right, &c, &F::one());

        msgs.push([a, b]);
        chals.push(c);
    }
    ((v[0], w[0]), chals, msgs)
}

#[test]
fn test_sumcheck() {
    type F = ark_curve25519::Fr;
    use crate::linalg;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    let mut rng = test_rng();
    let v = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let w = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let a = linalg::inner_product(&v, &w);

    let mut transcript_p = IOPTranscript::<F>::new(b"sumcheck");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<F>::new(b"sumcheck");
    transcript_v.append_message(b"init", b"init").unwrap();

    // Prover side of sumcheck
    let (folded_claims, expected_chals, messages) = sumcheck(&mut transcript_p, &v, &w);

    // Verifier side:

    // Get sumcheck random challenges and tensorcheck claim (random evaluation claim)
    let (mut challenges, tensorcheck_claim) = reduce(&mut transcript_v, &messages, a);
    assert_eq!(challenges, expected_chals);

    assert_eq!(folded_claims.0 * folded_claims.1, tensorcheck_claim);

    challenges.reverse();

    // Compute evaluation point from challenges
    let challenge_point = linalg::tensor(&challenges);
    let mut r_challenge_point = challenge_point.clone();
    r_challenge_point.reverse();

    // Evaluate "polynomial" v at challenge point
    let b = linalg::inner_product(&v, &challenge_point[..]);
    // Evaluate "polynomial" w at challenge point
    let c = linalg::inner_product(&w, &r_challenge_point[..]);

    // Check that their product matches the tensorcheck claim
    assert_eq!(tensorcheck_claim, b * c);
}

#[test]
fn test_batch_sumcheck() {
    type F = ark_curve25519::Fr;
    use ark_curve25519::EdwardsProjective;
    use ark_std::UniformRand;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let v = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let w = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let ck = pedersen::setup::<ark_curve25519::EdwardsProjective>(&mut rng, 16);

    let mut transcript_p = IOPTranscript::<F>::new(b"sumcheck");
    let ipa_claim = [
        Claim::Field(v.clone(), w.clone()),
        Claim::Group(
            v.clone(),
            ck.vec_G.clone(),
        ),
        Claim::Group(
            w.clone(),
            ck.vec_G.clone(),
        ),
    ];
    let batch_challenges = [F::from(1), F::from(2), F::from(3)];
    let (claims, chals, messages, openings) = batch_sumcheck(
        &mut rng,
        &mut transcript_p,
        &ck,
        ipa_claim,
        batch_challenges,
    );
    let verifier_statement = ck.G * batch_challenges[0] * inner_product(&v, &w)
        + EdwardsProjective::msm(&ck.vec_G, &v).unwrap() * batch_challenges[1]
        + EdwardsProjective::msm(&ck.vec_G, &w).unwrap() * batch_challenges[2];

    let mut transcript_v = IOPTranscript::<F>::new(b"sumcheck");
    let (verifier_chals, tensorcheck_claim) =
        reduce(&mut transcript_v, &messages, verifier_statement);
    assert_eq!(verifier_chals, chals);
    let tensor = linalg::tensor(&chals[..]);
    let reduced_v = linalg::inner_product(&v, &tensor);
    let reduced_w = linalg::inner_product(&w, &tensor);
    let reduced_G = EdwardsProjective::msm(&ck.vec_G, &tensor).unwrap();

    let mut blinding_factor = F::zero();
    for (opening, c) in openings.iter().zip(chals) {
        blinding_factor = opening[0] + opening[1] * c + (blinding_factor - opening[0]) * c.square()
    }
    let tensorcheck_claim = tensorcheck_claim - ck.H * blinding_factor;
    let expected_claim = ck.G * batch_challenges[0] * reduced_v * reduced_w
        + reduced_G * batch_challenges[1] * reduced_v
        + reduced_G * batch_challenges[2] * reduced_w;
    assert_eq!(tensorcheck_claim, expected_claim);
}
