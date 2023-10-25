use ark_ff::AdditiveGroup;
use ark_ff::PrimeField;
use transcript::IOPTranscript;

fn fold_inplace<F: PrimeField>(f: &mut Vec<F>, r: F) {
    let half = (f.len() + 1) / 2;
    for i in 0..half {
        f[i] = f[i * 2] + r * f.get(i * 2 + 1).unwrap_or(&F::zero());
    }
    f.drain(half..);
}

fn round_message<F, G>(f: &mut Vec<F>, g: &mut Vec<G>) -> [G; 2]
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

pub fn reduce<F: PrimeField, G: AdditiveGroup<Scalar = F>>(
    transcript: &mut IOPTranscript<F>,
    messages: &[[G; 2]],
    mut claim: G,
) -> (Vec<F>, G) {
    let mut challenges = Vec::with_capacity(messages.len());
    // reduce to a subclaim using the prover's messages.
    for &[a, b] in messages {
        // compute the next challenge from the previous coefficients.
        transcript
            .append_serializable_element(b"ab", &[a, b])
            .unwrap();
        let r = transcript.get_and_append_challenge(b"r").unwrap();

        challenges.push(r);

        let c = claim - a;
        // evaluate (a + bx + cx2) at r
        claim = a + b * r + c * r.square();
    }
    (challenges, claim)
}

/// Prove the inner product <v, w> using a sumcheck
///
pub fn sumcheck<F: PrimeField>(
    transcript: &mut IOPTranscript<F>,
    v: &[F],
    w: &[F],
) -> (Vec<F>, Vec<[F; 2]>) {
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut v = v.to_vec();
    let mut w = w.to_vec();
    while w.len() + v.len() > 2 {
        let msg = round_message(&mut v, &mut w);

        transcript.append_serializable_element(b"ab", &msg).unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        fold_inplace(&mut v, c);
        fold_inplace(&mut w, c);

        msgs.push(msg);
        chals.push(c);
    }
    (chals, msgs)
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
    let (expected_chals, messages) = sumcheck(&mut transcript_p, &v, &w);

    // Verifier side:

    // Get sumcheck random challenges and tensorcheck claim (random evaluation claim)
    let (challenges, tensorcheck_claim) = reduce(&mut transcript_v, &messages, a);
    assert_eq!(challenges, expected_chals);
    // Compute evaluation point from challenges
    let challenge_point = linalg::tensor(&challenges);

    // Evaluate "polynomial" v at challenge point
    let b = linalg::inner_product(&v, &challenge_point[..]);
    // Evaluate "polynomial" w at challenge point
    let c = linalg::inner_product(&w, &challenge_point[..]);

    // Check that their product matches the tensorcheck claim
    assert_eq!(tensorcheck_claim, b * c);
}
