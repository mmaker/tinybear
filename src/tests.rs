use hex_literal::hex;
use nimue::plugins::ark::IOPattern;

use crate::{pedersen, witness::registry, witness::trace::cipher, TinybearIO};

type G = ark_curve25519::EdwardsProjective;
// type F = ark_curve25519::Fr;

#[test]
fn test_aes128() {
    let iop = IOPattern::new("tinybear test aes128");
    let iop = TinybearIO::<G>::add_aes128_proof(iop);

    let mut merlin = iop.to_merlin();
    let ck = pedersen::setup::<G>(merlin.rng(), registry::AES128REG.witness_len * 2);

    let message: [u8; 16] = hex!("4A8F6DE2127BC934A55891FD23690CE7");
    let key: [u8; 16] = hex!("E74A8F6DE2127BC934A55891FD23690C");
    let ctx = cipher::aes128(message, key);

    let (message_commitment, message_opening) =
        crate::commit_aes128_message(merlin.rng(), &ck, message);
    let (round_keys_commitment, round_keys_opening) =
        crate::commit_aes128_key(merlin.rng(), &ck, &key);
    let proof_result = crate::aes128_prove(
        &mut merlin,
        &ck,
        message,
        message_opening,
        &key,
        round_keys_opening,
    );
    assert!(proof_result.is_ok());
    let proof = &proof_result.unwrap().to_vec();
    drop(merlin);
    let mut arthur = iop.to_arthur(proof);
    let result = crate::aes128_verify(
        &mut arthur,
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
    let iop = IOPattern::new("tinybear test aes128");
    let iop = TinybearIO::<G>::add_aes128keysch_proof(iop);

    let mut merlin = iop.to_merlin();

    let ck = pedersen::setup::<G>(
        merlin.rng(),
        registry::aes_keysch_offsets::<11, 4>().witness_len * 10,
    );
    let key = hex!("E74A8F6DE2127BC934A55891FD23690C");

    let (round_keys_com, key_opening) = crate::commit_aes128_key(merlin.rng(), &ck, &key);
    let proof_result = crate::aes128ks_prove(&mut merlin, &ck, key, key_opening);
    assert!(proof_result.is_ok());

    // The reason that this test fails that:
    // commitments to the round_keys for AES cipher proofs use a specific index in the committer key
    // which is different to the commitments of the AES keyschedule
    // reorganizing the witness for keyschedule and the registers will fix this.
    // It will not affect the running time.
    let mut arthur = iop.to_arthur(proof_result.unwrap());
    assert!(crate::aes128ks_verify(&mut arthur, &ck, round_keys_com).is_ok());
}

#[test]
fn test_aes256() {
    use hex_literal::hex;
    let iop = IOPattern::new("tinybear test aes256");
    let iop = TinybearIO::<G>::add_aes256_proof(iop);
    let mut merlin = iop.to_merlin();

    let ck = pedersen::setup::<G>(merlin.rng(), registry::AES256REG.witness_len * 3);

    let message: [u8; 16] = hex!("4A8F6DE2127BC934A55891FD23690CE7");
    let key: [u8; 32] = hex!("E74A8F6DE2127BC934A55891FD23690CE74A8F6DE2127BC934A55891FD23690C");
    let ctx = cipher::aes256(message, key);

    let (message_commitment, message_opening) =
        crate::commit_aes256_message(merlin.rng(), &ck, message);
    let (round_keys_commitment, round_keys_opening) =
        crate::commit_aes256_keys(merlin.rng(), &ck, &key);
    let proof_result = crate::aes256_prove(
        &mut merlin,
        &ck,
        message,
        message_opening,
        &key,
        round_keys_opening,
    );
    assert!(proof_result.is_ok());
    let mut arthur = iop.to_arthur(proof_result.unwrap());
    let result = crate::aes256_verify(
        &mut arthur,
        &ck,
        &message_commitment,
        &round_keys_commitment,
        ctx,
    );
    assert!(
        result.is_ok(),
        "Proof verification fails with {}",
        result.unwrap_err()
    );
}
