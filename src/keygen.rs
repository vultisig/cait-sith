use std::collections::HashSet;

use k256::{AffinePoint, ProjectivePoint, Scalar};
use magikitten::Transcript;
use rand_core::CryptoRngCore;

use crate::crypto::{commit, Commitment};
use crate::math::{GroupPolynomial, Polynomial};
use crate::participants::{ParticipantList, ParticipantMap};
use crate::proofs::dlog;
use crate::protocol::internal::{Communication, Executor};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};
use crate::serde::encode;

#[derive(Debug, Clone)]
pub struct KeygenOutput {
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

async fn do_keygen(
    rng: &mut impl CryptoRngCore,
    comms: Communication,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<KeygenOutput, ProtocolError> {
    let mut transcript = Transcript::new(b"cait-sith v0.1.0 keygen");
    let n = participants.len();

    // Spec 1.2
    transcript.message(b"participants", &encode(&participants));
    // To allow interop between platforms where usize is different!
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );

    // Spec 1.3
    let f = Polynomial::random(rng, threshold);

    // Spec 1.4
    let mut big_f = f.commit();

    // Spec 1.5
    let my_commitment = commit(&big_f);

    // Spec 1.6
    comms.send_many(0, &my_commitment).await;

    // Spec 2.1
    let mut all_commitments = ParticipantMap::new(&participants);
    all_commitments.put(me, my_commitment);
    while !all_commitments.full() {
        let (from, commitment) = comms.recv(0).await?;
        if all_commitments.contains(from) {
            continue;
        }
        all_commitments.put(from, commitment);
    }

    // Spec 2.2
    let my_confirmation = commit(&all_commitments);

    // Spec 2.3
    transcript.message(b"confirmation", my_confirmation.as_ref());

    // Spec 2.4
    comms.send_many(1, &my_confirmation).await;

    // Spec 2.5
    let statement = dlog::Statement {
        public: &big_f.evaluate_zero(),
    };
    let witness = dlog::Witness {
        x: &f.evaluate_zero(),
    };
    let my_phi_proof = dlog::prove(
        rng,
        &mut transcript.forked(b"dlog0", &me.bytes()),
        statement,
        witness,
    );

    // Spec 2.6
    comms.send_many(2, &(&big_f, my_phi_proof)).await;

    // Spec 2.7
    for p in participants.others(me) {
        // Need to add 1, since first evaluation is at 0.
        let x_i_j = f.evaluate(&p.scalar());
        comms.send_private(3, p, &x_i_j).await;
    }
    let mut x_i = f.evaluate(&me.scalar());

    // Spec 3.1 + 3.2
    let mut confirmations_seen = HashSet::with_capacity(n);
    confirmations_seen.insert(me);
    while confirmations_seen.len() < n {
        let (from, confirmation): (_, Commitment) = comms.recv(1).await?;
        if confirmation != my_confirmation {
            return Err(ProtocolError::AssertionFailed(format!(
                "confirmation from {from:?} did not match expectation"
            )));
        }
        confirmations_seen.insert(from);
    }

    // Spec 3.3 + 3.4, and also part of 3.6, for summing up the Fs.
    confirmations_seen.clear();
    let mut big_fs_seen = confirmations_seen;
    big_fs_seen.insert(me);
    while big_fs_seen.len() < n {
        let (from, (their_big_f, their_phi_proof)): (_, (GroupPolynomial, _)) =
            comms.recv(2).await?;
        if big_fs_seen.contains(&from) {
            continue;
        }
        big_fs_seen.insert(from);

        if commit(&their_big_f) != all_commitments[from] {
            return Err(ProtocolError::AssertionFailed(format!(
                "commitment from {from:?} did not match revealed F"
            )));
        }
        let statement = dlog::Statement {
            public: &their_big_f.evaluate_zero(),
        };
        if !dlog::verify(
            &mut transcript.forked(b"phi proof for", &from.bytes()),
            statement,
            &their_phi_proof,
        ) {
            return Err(ProtocolError::AssertionFailed(format!(
                "phi proof from {from:?} failed to verify"
            )));
        }
        big_f += &their_big_f;
    }

    // Spec 3.5 + 3.6
    big_fs_seen.clear();
    let mut x_j_i_seen = big_fs_seen;
    while x_j_i_seen.len() < n {
        let (from, x_j_i): (_, Scalar) = comms.recv(3).await?;
        if x_j_i_seen.contains(&from) {
            continue;
        }
        x_j_i_seen.insert(from);
        x_i += x_j_i;
    }

    // Spec 3.7
    if big_f.evalute(&me.scalar()) != ProjectivePoint::GENERATOR * x_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share".to_string(),
        ));
    }

    // Spec 3.8
    Ok(KeygenOutput {
        private_share: x_i,
        public_key: big_f.evaluate_zero().to_affine(),
    })
}

pub fn keygen<'a>(
    rng: &'a mut impl CryptoRngCore,
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput> + 'a, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    // Spec 1.1
    if threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    }

    let comms = Communication::new(4, participants.len());
    let fut = do_keygen(rng, comms.clone(), participants, me, threshold);
    Ok(Executor::new(comms, fut))
}
