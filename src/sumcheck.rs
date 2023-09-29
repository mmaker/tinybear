
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
        transcript.append_serializable_element(b"XXX", &msg).unwrap();
        let c = transcript.get_and_append_challenge(b"c").unwrap();
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

#[cfg(test)]
pub fn sumcheck<F: PrimeField>(
    transcript: &mut IOPTranscript<F>,
    v: &[F], w: &[F]) -> Vec<[F; 2]> {
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

    let messages = sumcheck(&mut transcript_p, &v, &w);
    let (challenges, claim) = reduce(&mut transcript_v, &messages, a);
    let challenge_point = linalg::tensor(&challenges);
    let b = linalg::inner_product(&v, &challenge_point[..]);
    let c = linalg::inner_product(&w, &challenge_point[..]);
    assert_eq!(claim, b * c);
}
