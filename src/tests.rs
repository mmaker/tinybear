use nimue::plugins::arkworks::ArkGroupIOPattern;

use crate::{aes, pedersen, TinybearIO};

type G = ark_curve25519::EdwardsProjective;
// type F = ark_curve25519::Fr;

#[test]
fn test_aes128() {
    let iop = ArkGroupIOPattern::<G>::new("tinybear test aes128").add_aes128_proof();

    let mut arthur = iop.to_arthur();
    let ck = pedersen::setup::<G>(arthur.rng(), crate::registry::AES128REG.witness_len * 2);

    let message = *b"\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7";
    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";
    let ctx = aes::aes128(message, key);

    let (message_commitment, message_opening) =
        crate::commit_aes128_message(arthur.rng(), &ck, message);
    let (round_keys_commitment, round_keys_opening) =
        crate::commit_aes128_key(arthur.rng(), &ck, &key);
    let proof_result = crate::aes128_prove(
        &mut arthur,
        &ck,
        message,
        message_opening,
        &key,
        round_keys_opening,
    );
    assert!(proof_result.is_ok());
    let proof = &proof_result.unwrap().to_vec();
    drop(arthur);
    let mut merlin = iop.to_merlin(proof);
    let result = crate::aes128_verify(
        &mut merlin,
        &ck,
        &message_commitment,
        &round_keys_commitment,
        ctx,
    );
    assert!(result.is_ok());
}

#[ignore = "rearrange keyschedule registry"]
#[test]
fn test_aes128ks() {
    let iop = ArkGroupIOPattern::<G>::new("tinybear test aes128").add_aes128keysch_proof();

    let mut arthur = iop.to_arthur();

    let ck = pedersen::setup::<G>(
        arthur.rng(),
        crate::registry::aes_keysch_offsets::<11, 4>().witness_len * 10,
    );
    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";

    let (round_keys_com, key_opening) = crate::commit_aes128_key(arthur.rng(), &ck, &key);
    let proof_result = crate::aes128ks_prove(&mut arthur, &ck, key, key_opening);
    assert!(proof_result.is_ok());

    // The reason that this test fails that:
    // commitments to the round_keys for AES cipher proofs use a specific index in the committer key
    // which is different to the commitments of the AES keyschedule
    // reorganizing the witness for keyschedule and the registers will fix this.
    // It will not affect the running time.
    let mut merlin = iop.to_merlin(proof_result.unwrap());
    assert!(crate::aes128ks_verify(&mut merlin, &ck, round_keys_com).is_ok());
}

#[test]
fn test_aes256() {
    let iop = ArkGroupIOPattern::<G>::new("tinybear test aes256").add_aes256_proof();
    let mut arthur = iop.to_arthur();

    let ck = pedersen::setup::<G>(arthur.rng(), crate::registry::AES256REG.witness_len * 3);

    let message = *b"\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7";
    let key = *b"\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C\xE7\x4A\x8F\x6D\xE2\x12\x7B\xC9\x34\xA5\x58\x91\xFD\x23\x69\x0C";
    let ctx = aes::aes256(message, key);

    let (message_commitment, message_opening) =
        crate::commit_aes256_message(arthur.rng(), &ck, message);
    let (round_keys_commitment, round_keys_opening) =
        crate::commit_aes256_keys(arthur.rng(), &ck, &key);
    let proof_result = crate::aes256_prove(
        &mut arthur,
        &ck,
        message,
        message_opening,
        &key,
        round_keys_opening,
    );
    assert!(proof_result.is_ok());
    let mut merlin = iop.to_merlin(proof_result.unwrap());
    let result = crate::aes256_verify(
        &mut merlin,
        &ck,
        &message_commitment,
        &round_keys_commitment,
        ctx,
    );
    assert!(result.is_ok(), "Proof veirification fails with {}", result.unwrap_err());
}
