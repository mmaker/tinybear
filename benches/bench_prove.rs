use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use nimue::plugins::arkworks::ArkGroupIOPattern;
use tinybear::*;

type G = ark_curve25519::EdwardsProjective;
type F = ark_curve25519::Fr;

fn bench_aes128_prove(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;
    c.bench_function("aes128/prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 16];
        let message_opening = F::rand(rng);
        let key_opening = F::rand(rng);
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        let iopat = ArkGroupIOPattern::new("benchmark-tinybear-aes128").add_aes128_proof();
        b.iter(|| {
            let mut arthur = iopat.to_arthur();

            crate::aes128_prove(
                &mut arthur,
                &ck,
                message,
                message_opening,
                &key,
                key_opening,
            ).unwrap();
        });
    });
}

fn bench_aes256_prove(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;
    c.bench_function("aes256/prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 32];
        let message_opening = F::rand(rng);
        let key_opening = F::rand(rng);
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        let iopat = ArkGroupIOPattern::new("benchmark-tinybear-aes256").add_aes256_proof();
        b.iter(|| {
            let mut arthur = iopat.to_arthur();

            aes256_prove(
                &mut arthur,
                &ck,
                message,
                message_opening,
                &key,
                key_opening,
            ).unwrap();
        });
    });
}

fn bench_aes128_verify(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;

    type G = ark_curve25519::EdwardsProjective;

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 4000);

    let (message_com, message_opening) = commit_aes128_message(rng, &ck, message);
    let (round_keys_com, key_opening) = commit_aes128_key(rng, &ck, &key);
    let ctx = aes::aes128(message, key);

    c.bench_function("aes128/verify", |b| {
        let iopat = ArkGroupIOPattern::new("benchmark-tinybear-aes128").add_aes128_proof();
        let mut arthur = iopat.to_arthur();
        let proof = aes128_prove(
            &mut arthur,
            &ck,
            message,
            message_opening,
            &key,
            key_opening,
        ).unwrap();
        b.iter(|| {
            let mut merlin = iopat.to_merlin(proof);
            assert!(aes128_verify(
                &mut merlin,
                &ck,
                &message_com,
                &round_keys_com,
                ctx,
            )
            .is_ok())
        });
    });
}

fn bench_aes256_verify(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;

    type G = ark_curve25519::EdwardsProjective;

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C, 0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23,
        0x69, 0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 4000);

    let (message_com, message_opening) = commit_aes256_message(rng, &ck, message);
    let (round_keys_com, key_opening) = commit_aes256_keys(rng, &ck, &key);
    let ctx = aes::aes256(message, key);

    c.bench_function("aes256/verify", |b| {
        let iopat = ArkGroupIOPattern::new("benchmark-tinybear-aes256").add_aes128_proof();

        let mut arthur = iopat.to_arthur();
        let proof = aes256_prove(
            &mut arthur,
            &ck,
            message,
            message_opening,
            &key,
            key_opening,
        ).unwrap();

        b.iter(|| {
            let mut merlin = iopat.to_merlin(proof);
            aes256_verify(
                &mut merlin,
                &ck,
                &message_com,
                &round_keys_com,
                ctx,
            )
        });
    });
}

criterion_group! {
    name=prover_benches;
    config=Criterion::default();
    targets=
            bench_aes128_prove, bench_aes256_prove, bench_aes128_verify, bench_aes256_verify
}
criterion_main!(prover_benches);
