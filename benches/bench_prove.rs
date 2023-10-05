use criterion::{criterion_group, criterion_main, Criterion};
use tinybear::*;
use transcript::IOPTranscript;

type G = ark_curve25519::EdwardsProjective;

fn bench_prove(c: &mut Criterion) {
    c.bench_function("prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 16];
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        let mut transcript = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
        transcript.append_message(b"init", b"init").unwrap();

        b.iter(|| {
            prover::prove::<G>(&mut transcript, &ck, message, &key);
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
