use ark_ec::CurveGroup;

/// Simpler pippenger for u8 scalars.
pub fn u8msm<G: CurveGroup>(bases: &[G::Affine], scalars: &[u8]) -> G {
    let mut buckets = [G::zero(); 8];
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        buckets.iter_mut().enumerate().for_each(|(i, bucket)| {
            if scalar & (1u8 << i) != 0 {
                bucket.add_assign(base);
            }
        });
    }

    for b in (1..8).rev() {
        buckets[b].double_in_place();
        buckets[b - 1].add_assign(buckets[b]);
    }
    buckets[0]
}

#[test]
fn test_u8msm() {
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;
    use rand::Rng;
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let mut rng = rand::thread_rng();
    let bases = (0..8)
        .map(|_| G::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let scalars = (0..8).map(|_| rng.gen()).collect::<Vec<u8>>();
    let ff_scalars = scalars.iter().map(|&x| F::from(x)).collect::<Vec<_>>();

    let expected = G::msm(&bases, &ff_scalars).unwrap();
    let actual: G = u8msm(&bases, &scalars);
    assert_eq!(expected, actual)
}
