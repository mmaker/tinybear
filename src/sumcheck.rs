
use ark_ff::PrimeField;
use transcript::IOPTranscript;

fn fold_inplace<F: PrimeField>(f: &mut Vec<F>, r: F) {
    let half = (f.len() + 1) / 2;
    for i in 0..half {
        f[i] = f[i * 2] + r * f.get(i * 2 + 1).unwrap_or(&F::zero());
    }
    f.drain(half..);
}

fn round_message<F: PrimeField>(f: &mut Vec<F>, g: &mut Vec<F>) -> [F; 2] {
    let mut a = F::zero();
    let mut b = F::zero();
    let zero = F::zero();

    for (f_pair, g_pair) in f.chunks(2).zip(g.chunks(2)) {
        // The even part of the polynomial must always be unwrapped.
        let f_even = f_pair[0];
        let g_even = g_pair[0];
        // For the right part, we might obtain zero if the degree is not a multiple of 2.
        let f_odd = f_pair.get(1).unwrap_or(&zero);
        let g_odd = g_pair.get(1).unwrap_or(&zero);
        // Add to the partial sum
        a += f_even * g_even;
        b += f_even * g_odd + g_even * f_odd;
    }
    [a, b]
}

pub fn batch_sumcheck<F>(
    transcript: &mut IOPTranscript<F>,
    vs: [&[F]; 2],
    ws: [&[F]; 2],
    batch_chal: F,
) -> (Vec<F>, Vec<[F; 2]>)
where
    F: PrimeField,
{
    let mut msgs = Vec::new();
    let mut chals = Vec::new();
    let mut vs = [vs[0].to_vec(), vs[1].to_vec()];
    let mut ws = [ws[0].to_vec(), ws[1].to_vec()];
    println!(
        "{} {} {} {}",
        ws[0].len(),
        ws[1].len(),
        vs[0].len(),
        vs[1].len()
    );
    while ws[0].len() + vs[0].len() + vs[1].len() + ws[1].len() > 4 {
        let msg0 = round_message(&mut vs[0], &mut ws[0]);
        let msg1 = round_message(&mut vs[1], &mut ws[1]);
        let msg = [
            msg0[0] + batch_chal * msg1[0],
            msg0[1] + batch_chal * msg1[1],
        ];
        transcript.append_serializable_element(b"ab", &msg).unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        // fold the polynomials
        fold_inplace(&mut vs[0], c);
        fold_inplace(&mut ws[0], c);
        fold_inplace(&mut vs[1], c);
        fold_inplace(&mut ws[1], c);

        msgs.push(msg);
        chals.push(c);
    }
    (chals, msgs)
}

pub fn reduce<F: PrimeField>(
    transcript: &mut IOPTranscript<F>,
    messages: &[[F; 2]],
    mut claim: F,
) -> (Vec<F>, F) {
    let mut challenges = Vec::with_capacity(messages.len());
    // reduce to a subclaim using the prover's messages.
    for &[a, b] in messages {
        // compute the next challenge from the previous coefficients.
        transcript.append_serializable_element(b"ab", &[a, b]).unwrap();
        let r = transcript.get_and_append_challenge(b"r").unwrap();

        challenges.push(r);

        let c = claim - a;
        // evaluate (a + bx + cx2) at r
        claim = a + r * b + c * r.square();
    }
    (challenges, claim)
}

/// Prove the inner product <v, w> using a sumcheck
///
#[cfg(test)]
pub fn sumcheck<F: PrimeField>(
    transcript: &mut IOPTranscript<F>,
    v: &[F],
    w: &[F]
) -> Vec<[F; 2]> {
    let mut msgs = Vec::new();
    let mut v = v.to_vec();
    let mut w = w.to_vec();
    while w.len() + v.len() > 2 {
        let msg = round_message(&mut v, &mut w);

        transcript.append_serializable_element(b"ab", &msg).unwrap();
        let c = transcript.get_and_append_challenge(b"r").unwrap();
        fold_inplace(&mut v, c);
        fold_inplace(&mut w, c);
        msgs.push(msg);
    }
    msgs
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
    let messages = sumcheck(&mut transcript_p, &v, &w);

    // Verifier side:

    // Get sumcheck random challenges and tensorcheck claim (random evaluation claim)
    let (challenges, tensorcheck_claim) = reduce(&mut transcript_v, &messages, a);
    // Compute evaluation point from challenges
    let challenge_point = linalg::tensor(&challenges);

    // Evaluate "polynomial" v at challenge point
    let b = linalg::inner_product(&v, &challenge_point[..]);
    // Evaluate "polynomial" w at challenge point
    let c = linalg::inner_product(&w, &challenge_point[..]);

    // Check that their product matches the tensorcheck claim
    assert_eq!(tensorcheck_claim, b * c);
}


#[test]
fn test_batch_sumcheck() {
    type F = ark_curve25519::Fr;
    use crate::linalg;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    let mut transcript_p = IOPTranscript::<F>::new(b"sumcheck");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<F>::new(b"sumcheck");
    transcript_v.append_message(b"init", b"init").unwrap();

    // Use batch sumcheck to batch prove the following inner products:
    // <l_1, r_1> = a
    // <l_2, r_2> = b
    let mut rng = test_rng();
    let l_1 = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let r_1 = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let a: F = linalg::inner_product(&l_1, &r_1);

    let l_2 = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let r_2 = (0..16).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
    let b: F = linalg::inner_product(&l_2, &r_2);

    // Batching challenge
    let c: F = F::rand(&mut rng);

    // Prover side
    let sumcheck_data = batch_sumcheck(&mut transcript_p, [&l_1, &l_2], [&r_1, &r_2], c);
    let sumcheck_messages = sumcheck_data.1;

    // Verifier side
    let result = a + c * b;
    let (sumcheck_challenges, tensorcheck_claim) = reduce(&mut transcript_v, &sumcheck_messages, result);
    let challenge_point = linalg::tensor(&sumcheck_challenges);

    // Verify the batched tensorcheck claim
    let y_1 = linalg::inner_product(&l_1, &challenge_point[..]);
    let y_2 = linalg::inner_product(&r_1, &challenge_point[..]);
    let y_3 = linalg::inner_product(&l_2, &challenge_point[..]);
    let y_4 = linalg::inner_product(&r_2, &challenge_point[..]);
    assert_eq!(tensorcheck_claim, y_1 * y_2 + c * y_3 * y_4);

}
