use transcript::IOPTranscript;

use crate::{aes, pedersen};

type G = ark_curve25519::EdwardsProjective;
type F = ark_curve25519::Fr;

#[test]
fn test_aes128() {
    let mut transcript_p = IOPTranscript::<F>::new(b"aes");
    transcript_p.append_message(b"init", b"init").unwrap();
    let rng = &mut rand::rngs::OsRng;

    let mut transcript_v = IOPTranscript::<F>::new(b"aes");
    transcript_v.append_message(b"init", b"init").unwrap();

    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), crate::registry::AES128REG.len * 2);

    let message = *b"\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7";
    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";
    let ctx = aes::aes128(message, key);

    let (message_commitment, message_blinder) = crate::commit_aes128_message(rng, &ck, message);
    let (round_keys_commitment, round_keys_blinder) = crate::commit_aes128_key(rng, &ck, &key);
    let proof = crate::aes128_prove(
        &mut transcript_p,
        &ck,
        message,
        message_blinder,
        &key,
        round_keys_blinder,
    );
    let result = crate::aes128_verify(
        &mut transcript_v,
        &ck,
        &message_commitment,
        &round_keys_commitment,
        ctx,
        &proof,
    );
    assert!(result.is_ok());
}

#[test]
fn test_aes128ks() {
    use crate::pedersen;

    let mut transcript_p = IOPTranscript::<F>::new(b"aes");
    transcript_p.append_message(b"init", b"init").unwrap();
    let rng = &mut rand::rngs::OsRng;

    let mut transcript_v = IOPTranscript::<F>::new(b"aes");
    transcript_v.append_message(b"init", b"init").unwrap();

    let ck = pedersen::setup::<G>(rng, crate::registry::AES128REG.len * 2);

    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";

    let (round_keys_com, key_opening) = crate::commit_aes128_key(rng, &ck, &key);
    let proof = crate::aes128ks_prove(&mut transcript_p, &ck, key, key_opening);

    assert!(crate::aes128ks_verify(&mut transcript_v, &ck, round_keys_com, &proof).is_ok());
}

#[test]
fn test_aes256() {
    use crate::{aes, pedersen};

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let mut transcript_p = IOPTranscript::<F>::new(b"aes");
    transcript_p.append_message(b"init", b"init").unwrap();
    let rng = &mut rand::rngs::OsRng;

    let mut transcript_v = IOPTranscript::<F>::new(b"aes");
    transcript_v.append_message(b"init", b"init").unwrap();

    let ck = pedersen::setup::<G>(rng, crate::registry::AES256REG.len * 2);

    let message = *b"\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7";
    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";
    let ctx = aes::aes256(message, key);

    let (message_commitment, message_blinder) = crate::commit_aes256_message(rng, &ck, message);
    let (round_keys_commitment, round_keys_blinder) = crate::commit_aes256_keys(rng, &ck, &key);
    let proof = crate::aes256_prove(
        &mut transcript_p,
        &ck,
        message,
        message_blinder,
        &key,
        round_keys_blinder,
    );
    let result = crate::aes256_verify(
        &mut transcript_v,
        &ck,
        &message_commitment,
        &round_keys_commitment,
        ctx,
        &proof,
    );
    assert!(result.is_ok());
}
