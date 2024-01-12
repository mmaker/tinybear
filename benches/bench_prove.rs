use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use tinybear::*;
use transcript::IOPTranscript;

type G = ark_curve25519::EdwardsProjective;
type F = ark_curve25519::Fr;

fn bench_aes128_prove(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;
    c.bench_function("aes128/prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 16];
        let message_blinder = F::rand(rng);
        let key_blinder = F::rand(rng);
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        let mut transcript = IOPTranscript::<F>::new(b"aes");
        transcript.append_message(b"init", b"init").unwrap();

        b.iter(|| {
            crate::aes128_prove(
                &mut transcript,
                &ck,
                message,
                message_blinder,
                &key,
                key_blinder,
            );
        });
    });
}

fn bench_aes256_prove(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;
    c.bench_function("aes256/prove", |b| {
        let message = [0u8; 16];
        let key = [0u8; 32];
        let message_blinder = F::rand(rng);
        let key_blinder = F::rand(rng);
        let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2048);
        let mut transcript = IOPTranscript::<F>::new(b"aes");
        transcript.append_message(b"init", b"init").unwrap();

        b.iter(|| {
            prover::aes256_prove(
                &mut transcript,
                &ck,
                message,
                message_blinder,
                &key,
                key_blinder,
            );
        });
    });
}

fn bench_aes128_verify(c: &mut Criterion) {
    use crate::crate::aes128_prove;

    let rng = &mut rand::rngs::OsRng;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 4000);

    let (message_com, message_blinder) = prover::commit_aes128_message(rng, &ck, message);
    let (round_keys_com, key_blinder) = prover::commit_aes128_keys(rng, &ck, &key);
    let ctx = aes::aes128(message, key);

    c.bench_function("aes128/verify", |b| {
        let mut transcript_p = IOPTranscript::<F>::new(b"aes");
        transcript_p.append_message(b"init", b"init").unwrap();

        let mut transcript_v = IOPTranscript::<F>::new(b"aes");
        transcript_v.append_message(b"init", b"init").unwrap();
        let proof = aes128_prove(
            &mut transcript_p,
            &ck,
            message,
            message_blinder,
            &key,
            key_blinder,
        );
        b.iter(|| {
            assert!(verifier::aes128_verify(
                &mut transcript_v.clone(),
                &ck,
                &message_com,
                &round_keys_com,
                ctx,
                &proof,
            )
            .is_ok())
        });
    });
}

fn bench_aes256_verify(c: &mut Criterion) {
    let rng = &mut rand::rngs::OsRng;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

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

    let (message_com, message_blinder) = prover::commit_aes256_message(rng, &ck, message);
    let (round_keys_com, key_blinder) = prover::commit_aes256_keys(rng, &ck, &key);
    let ctx = aes::aes256(message, key);

    c.bench_function("aes256/verify", |b| {
        let mut transcript_p = IOPTranscript::<F>::new(b"aes");
        transcript_p.append_message(b"init", b"init").unwrap();

        let mut transcript_v = IOPTranscript::<F>::new(b"aes");
        transcript_v.append_message(b"init", b"init").unwrap();
        let proof = prover::aes256_prove(
            &mut transcript_p,
            &ck,
            message,
            message_blinder,
            &key,
            key_blinder,
        );
        b.iter(|| {
            assert!(verifier::aes256_verify(
                &mut transcript_v.clone(),
                &ck,
                &message_com,
                &round_keys_com,
                ctx,
                &proof,
            )
            .is_ok())
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
