use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use nimue::IOPattern;
use tinybear::sigma::CompressedSigma;
use tinybear::*;

#[allow(non_snake_case)]
fn bench_compressed_sigma(c: &mut Criterion) {
    c.bench_function("compressed sigma", |b| {
        type G = ark_curve25519::EdwardsProjective;
        type F = ark_curve25519::Fr;
        let rng = &mut nimue::DefaultRng::default();

        // Basic setup
        let len = 1 << 12;
        let iop = IOPattern::new("lineval bench ⏱️");
        let iop = LinProofIO::<G>::add_compressed_lin_proof(iop, len);

        let ck = pedersen::setup::<G>(rng, len);
        // Linear evaluation setup
        let a_vec = (0..len).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let x_vec = (0..len).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let (_X, X_opening) = pedersen::commit_hiding(rng, &ck, &x_vec);
        let y = x_vec
            .iter()
            .zip(a_vec.iter())
            .map(|(a, b)| a * b)
            .sum::<F>();
        let (_Y, Y_opening) = pedersen::commit_hiding(rng, &ck, &[y]);

        b.iter(|| {
            // Let's prove!
            let mut arthur = iop.to_arthur();
            CompressedSigma::new(&mut arthur, &ck, &x_vec, &X_opening, &Y_opening, &a_vec).unwrap();
        });
    });
}

#[allow(non_snake_case)]
fn bench_fold_generators(c: &mut Criterion) {
    c.bench_function("fold generators", |b| {
        type G = ark_curve25519::EdwardsProjective;
        type F = ark_curve25519::Fr;
        let rng = &mut nimue::DefaultRng::default();

        // Basic setup
        let len = 1 << 12;
        let ck = pedersen::setup::<G>(rng, len);
        let mut vec_G = ck.vec_G.into_iter().map(|x| x.into()).collect::<Vec<_>>();
        let rs = (0..ark_std::log2(len))
            .map(|_| F::rand(rng))
            .collect::<Vec<_>>();
        b.iter(|| {
            for &r in &rs {
                tinybear::sumcheck::fold_inplace::<G>(&mut vec_G, r);
            }
        });
    });
}

criterion_group! {
    name=linproof_benches;
    config=Criterion::default();
    targets=
            bench_compressed_sigma, bench_fold_generators
}
criterion_main!(linproof_benches);
