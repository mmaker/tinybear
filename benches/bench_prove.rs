use criterion::{criterion_group, criterion_main, Criterion};
use tinybear::*;

type G = ark_curve25519::EdwardsProjective;

fn bench_prove(c: &mut Criterion) {
    c.bench_function("prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 16];
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        b.iter(|| {
            zkp::prove::<G>(&ck, message, &key);
        });
    });
}

criterion_group! {
    name=prover_benches;
    config=Criterion::default();
    targets=
            bench_prove,
}
criterion_main!(prover_benches);
