#![allow(non_snake_case)]
use std::ops::Mul;
use std::vec;

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use ark_ff::UniformRand;
use nimue::plugins::ark::*;
use nimue::{DuplexHash, ProofError, ProofResult};

use crate::pedersen::commit_hiding;
use crate::pedersen::CommitmentKey;
use crate::sumcheck;
use crate::traits::MulProofIO;
use crate::traits::{LinProof, LinProofIO};
use crate::{linalg, SumcheckIO};

#[derive(Default, CanonicalSerialize)]
pub struct SigmaProof<G: CurveGroup> {
    pub commitment: Vec<G>,
    pub response: Vec<G::ScalarField>,
}

impl<G: CurveGroup, H: DuplexHash<u8>> LinProofIO<G> for IOPattern<H>
where
    IOPattern<H>: GroupIOPattern<G> + FieldIOPattern<G::ScalarField>,
{
    fn add_lin_proof(self, len: usize) -> Self {
        self.add_points(2, "commitment")
            .challenge_scalars(1, "challenge")
            .add_scalars(len + 2, "response")
    }

    fn add_compressed_lin_proof(self, len: usize) -> Self {
        self.add_sumcheck(len + 1)
            .add_points(1, "folded f")
            .add_mul_proof()
    }
}

impl<G: CurveGroup, H: DuplexHash<u8>> MulProofIO<G> for IOPattern<H>
where
    IOPattern<H>: GroupIOPattern<G> + FieldIOPattern<G::ScalarField>,
{
    fn add_mul_proof(self) -> Self {
        self.add_points(2, "commitment")
            .challenge_scalars(1, "challenge")
            .add_scalars(3, "response")
    }
}

pub fn mul_prove<'a, G: CurveGroup>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    a: G::ScalarField,
    B: G,
    rho_a: G::ScalarField,
    rho_b: G::ScalarField,
    rho_c: G::ScalarField,
) -> ProofResult<&'a [u8]> {
    // Produce the commitment
    let vec_k = (0..3)
        .map(|_| G::ScalarField::rand(merlin.rng()))
        .collect::<Vec<_>>();
    let K = vec![
        G::msm_unchecked(&[ck.G, ck.H], &vec_k[..2]),
        G::msm_unchecked(&[B.into(), ck.H], &[vec_k[0], vec_k[2]]),
    ];
    merlin.add_points(&K)?;

    // Get challenges from verifier
    let [c]: [G::ScalarField; 1] = merlin.challenge_scalars()?;
    // Compute prover's response
    let vec_z = vec![
        vec_k[0] + c * a,
        vec_k[1] + c * rho_a,
        vec_k[2] + c * (rho_c - a * rho_b),
    ];

    merlin.add_scalars(&vec_z)?;
    Ok(merlin.transcript())
}

pub fn mul_verify<G: CurveGroup>(
    arthur: &mut Arthur,
    ck: &CommitmentKey<G>,
    A: G,
    B: G,
    C: G,
) -> ProofResult<()> {
    let commitment: [G; 2] = arthur.next_points()?;
    let [c]: [G::ScalarField; 1] = arthur.challenge_scalars()?;
    let response: [G::ScalarField; 3] = arthur.next_scalars()?;

    if commitment[0] == G::msm_unchecked(&[(-A).into(), ck.G, ck.H], &[c, response[0], response[1]])
        && commitment[1]
            == G::msm_unchecked(
                &[(-C).into(), B.into(), ck.H],
                &[c, response[0], response[2]],
            )
    {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }
}

#[derive(Default, CanonicalSerialize)]
pub struct CompressedSigma<G: CurveGroup>(Vec<[G; 2]>, G::ScalarField);

impl<G: CurveGroup> LinProof<G> for CompressedSigma<G> {
    fn new<'a>(
        merlin: &'a mut Merlin,
        ck: &CommitmentKey<G>,
        x_vec: &[G::ScalarField],
        X_opening: &G::ScalarField,
        Y_opening: &G::ScalarField,
        a_vec: &[G::ScalarField],
    ) -> ProofResult<&'a [u8]> {
        let n = usize::min(a_vec.len(), x_vec.len());

        // Adding zero knowledge
        // vec_x_prime = [x_1, ..., x_n, r_x]
        let mut x_vec_prime = x_vec.to_vec();
        x_vec_prime.push(*X_opening);

        // vec_G_prime = [G_1, ..., G_n, H]
        debug_assert!(n <= ck.vec_G.len());
        let mut G_vec_prime = ck.vec_G[..n].to_vec();
        G_vec_prime.push(ck.H);
        assert_eq!(x_vec_prime.len(), G_vec_prime.len());

        // vec_a_prime = [a_1, ..., a_n, 0]
        let mut a_vec_prime = a_vec.to_vec();
        a_vec_prime.push(G::ScalarField::zero());
        assert_eq!(x_vec_prime.len(), a_vec_prime.len());
        let aG_vec_prime = ck.G.into().batch_mul(&a_vec_prime);

        // Compute <a' + G'>
        let vec_aG_tmp = ark_std::cfg_iter!(aG_vec_prime)
            .zip(G_vec_prime.iter())
            .map(|(&aG, G_i)| (aG + G_i))
            .collect::<Vec<G>>();
        let mut vec_aG = G::normalize_batch(&vec_aG_tmp);

        // Show that <x', a' + G'> = Y + X
        let mut openings = Vec::new();
        let mut chals = Vec::new();
        while vec_aG.len() + x_vec_prime.len() > 2 {
            let [A, B]: [G; 2] = sumcheck::group_round_message(&x_vec_prime, &vec_aG);

            let A_opening = G::ScalarField::rand(merlin.rng());
            let B_opening = G::ScalarField::rand(merlin.rng());
            // Blind A and B
            let A = A + ck.H.mul(A_opening);
            let B = B + ck.H.mul(B_opening);
            merlin.add_points(&[A, B])?;

            let [c] = merlin.challenge_scalars().unwrap();

            sumcheck::fold_inplace(&mut x_vec_prime, c);
            sumcheck::group_fold_inplace::<G>(&mut vec_aG, c);

            chals.push(c);
            openings.push([A_opening, B_opening]);
        }

        // Commit to the folded x_vec_prime
        let (X_folded_com, X_folded_com_opening) =
            commit_hiding(merlin.rng(), ck, &[x_vec_prime[0]]);
        merlin.add_points(&[X_folded_com]).unwrap();

        let ipa_sumcheck_opening = sumcheck::reduce_with_challenges(&openings, &chals, *Y_opening);

        // Create a mul proof that v_0 * W_0 = Y'
        // where Y' is the tensorcheck claim
        mul_prove(
            merlin,
            &ck,
            x_vec_prime[0],
            vec_aG[0].into(),
            X_folded_com_opening,
            G::ScalarField::zero(),
            ipa_sumcheck_opening,
        )?;

        Ok(merlin.transcript())
    }

    fn verify(
        arthur: &mut Arthur,
        ck: &CommitmentKey<G>,
        a_vec: &[<G>::ScalarField],
        X: &G,
        Y: &G,
    ) -> ProofResult<()> {
        // vec_G_prime = [G_1, ..., G_n, H]
        debug_assert!(a_vec.len() <= ck.vec_G.len());
        let mut G_vec_prime = ck.vec_G[..a_vec.len()].to_vec();
        G_vec_prime.push(ck.H);

        // vec_a_prime = [a_1, ..., a_n, 0]
        let mut a_vec_prime = a_vec.to_vec();
        a_vec_prime.push(G::ScalarField::zero());

        // Compute <a'G + G'>
        let vec_aG = ark_std::cfg_iter!(a_vec_prime)
            .zip(G_vec_prime)
            .map(|(a, G_i)| (ck.G * a + G_i).into_affine())
            .collect::<Vec<_>>();

        // Do a sumcheck for <x', a'G + G'> = X + Y
        let (challenges, tensorcheck_claim) = sumcheck::reduce(arthur, a_vec_prime.len(), *X + Y);
        let [X_folded_com]: [G; 1] = arthur.next_points().unwrap();

        let challenges_vec = crate::linalg::tensor(&challenges);
        let aG_folded = G::msm_unchecked(&vec_aG, &challenges_vec);

        mul_verify(arthur, ck, X_folded_com, aG_folded, tensorcheck_claim).unwrap();

        Ok(())
    }
}

impl<G: CurveGroup> LinProof<G> for SigmaProof<G> {
    fn new<'a>(
        merlin: &'a mut Merlin,
        ck: &CommitmentKey<G>,
        x_vec: &[G::ScalarField],
        X_opening: &G::ScalarField,
        Y_opening: &G::ScalarField,
        a_vec: &[G::ScalarField],
    ) -> ProofResult<&'a [u8]> {
        assert!(x_vec.len() <= a_vec.len());
        // Create the prover's opening
        let mut vec_k = (0..a_vec.len())
            .map(|_| G::ScalarField::rand(merlin.rng()))
            .collect::<Vec<_>>();

        // Commit to the opening and send the commitments to the verifier
        let y_k = linalg::inner_product(&vec_k, a_vec);
        let (K_1, kappa_1) = commit_hiding(merlin.rng(), ck, &vec_k);
        let (K_2, kappa_2) = commit_hiding(merlin.rng(), ck, &[y_k]);
        vec_k.extend_from_slice(&[kappa_1, kappa_2]);
        merlin.add_points(&[K_1, K_2])?;

        // Get challenges from verifier
        let [c]: [G::ScalarField; 1] = merlin.challenge_scalars()?;
        // Compute prover's response
        let witness = x_vec.iter().chain(Some(X_opening)).chain(Some(Y_opening));

        for (k_i, w_i) in vec_k.into_iter().zip(witness) {
            let z_i = k_i + c * w_i;
            merlin.add_scalars(&[z_i])?;
        }
        Ok(merlin.transcript())
    }

    fn verify(
        arthur: &mut Arthur,
        ck: &CommitmentKey<G>,
        a_vec: &[G::ScalarField],
        X: &G,
        Y: &G,
    ) -> ProofResult<()> {
        let n = a_vec.len();

        let commitment: [G; 2] = arthur.next_points::<2>()?;
        // Get challenges from verifier
        let [c]: [G::ScalarField; 1] = arthur.challenge_scalars()?;

        let mut response = vec![G::ScalarField::zero(); n + 2];
        arthur.fill_next_scalars(&mut response)?;

        let z_response = G::msm_unchecked(&ck.vec_G[..n], &response[..n]) + ck.H * response[n];
        let za_response =
            ck.G * linalg::inner_product(&response[..n], &a_vec[..n]) + ck.H * response[n + 1];

        if z_response == commitment[0] + X.mul(c) && za_response == commitment[1] + Y.mul(c) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

#[test]
fn test_mul() {
    type F = ark_curve25519::Fr;
    type G = ark_curve25519::EdwardsProjective;

    let rng = &mut rand::thread_rng();
    let ck = crate::pedersen::setup::<ark_curve25519::EdwardsProjective>(rng, 3);
    let a = F::rand(rng);
    let b = F::rand(rng);
    let c = a * b;
    let rho_a = F::rand(rng);
    let rho_b = F::rand(rng);
    let rho_c = F::rand(rng);
    let A = ck.G * a + ck.H * rho_a;
    let B = ck.G * b + ck.H * rho_b;
    let C = ck.G * c + ck.H * rho_c;

    let iop = IOPattern::new("test");
    let iop = MulProofIO::<G>::add_mul_proof(iop);
    let mut merlin = iop.to_merlin();
    let proof_result = mul_prove(&mut merlin, &ck, a, B, rho_a, rho_b, rho_c);
    assert!(proof_result.is_ok());
    let proof = proof_result.unwrap();
    let mut arthur = iop.to_arthur(proof);
    let result = mul_verify(&mut arthur, &ck, A, B, C);
    assert!(result.is_ok());
}

/// Check proof that <vec_x, vec_a> = y
#[test]
fn test_lineval_correctness() {
    use crate::pedersen;
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;
    let rng = &mut nimue::DefaultRng::default();

    // Basic setup
    let len = 1 << 8;
    let iop = IOPattern::new("lineval test");
    let iop = LinProofIO::<G>::add_lin_proof(iop, len);

    let mut merlin = iop.to_merlin();

    let ck = pedersen::setup::<G>(rng, 2084);
    // Linear evaluation setup
    let a_vec = (0..len).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let x_vec = (0..len).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let (X, X_opening) = pedersen::commit_hiding(rng, &ck, &x_vec);
    let y = linalg::inner_product(&x_vec, &a_vec);
    let (Y, Y_opening) = pedersen::commit_hiding(rng, &ck, &[y]);

    // Let's prove!
    let proof_result = SigmaProof::new(&mut merlin, &ck, &x_vec, &X_opening, &Y_opening, &a_vec);
    assert!(proof_result.is_ok());
    let proof = proof_result.unwrap();

    let mut transcript_v = iop.to_arthur(proof);
    assert!(SigmaProof::verify(&mut transcript_v, &ck, &a_vec, &X, &Y).is_ok());
}

/// Check proof that <vec_x, vec_a> = y
#[test]
fn test_compressedsigma_correctness() {
    use crate::pedersen;
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;
    let rng = &mut nimue::DefaultRng::default();

    // Basic setup
    let len = 1 << 8;
    let iop = IOPattern::new("lineval test");
    let iop = LinProofIO::<G>::add_compressed_lin_proof(iop, len);

    let mut merlin = iop.to_merlin();

    let ck = pedersen::setup::<G>(rng, len);
    // Linear evaluation setup
    let a_vec = (0..len).map(|_| F::rand(merlin.rng())).collect::<Vec<_>>();
    let x_vec = (0..len).map(|_| F::rand(merlin.rng())).collect::<Vec<_>>();
    let (X, X_opening) = pedersen::commit_hiding(rng, &ck, &x_vec);
    let y = linalg::inner_product(&x_vec, &a_vec);
    let (Y, Y_opening) = pedersen::commit_hiding(rng, &ck, &[y]);

    // Let's prove!
    let proof_result =
        CompressedSigma::new(&mut merlin, &ck, &x_vec, &X_opening, &Y_opening, &a_vec);
    assert!(proof_result.is_ok());
    let proof = proof_result.unwrap();

    let mut arthur = iop.to_arthur(proof);
    assert!(CompressedSigma::verify(&mut arthur, &ck, &a_vec, &X, &Y).is_ok());
}
