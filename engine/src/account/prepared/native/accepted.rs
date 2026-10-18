//! Sealed accepted-account record: the genesis relation accepted by the operator.
//!
//! Written only by the engine from an `AcceptedGenesisProof` that carries the fully
//! verified response (from state B), never from caller bytes: there is no public
//! constructor for either the accepted candidate or the sealed record's content.
//! It reuses the engine's sealing key with its own magic and AAD, distinct from the
//! key capsule and both pending states, so no ciphertext can authenticate as
//! another kind. Later account transitions are out of scope for this record.
use super::pending::{Reader, Writer, read_context, write_context};
use super::*;
use crate::account::Field;
use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use czkp::ProofScope;

const MAGIC: &[u8] = b"cwlt.account-accepted.v1\0";
const NONCE: usize = 24;
const VERSION: u8 = 1;
/// Original single-value Store limit; the sealed record stays below it.
pub const MAX_ACCEPTED_SEALED: usize = 1024 * 1024;

/// Bounded ciphertext of one accepted account record.
pub struct SealedAcceptedAccount(Vec<u8>);
impl SealedAcceptedAccount {
    /// Check the exact envelope before authenticated restore by the same engine.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= MAGIC.len() + NONCE + 16
            || bytes.len() > MAX_ACCEPTED_SEALED
            || !bytes.starts_with(MAGIC)
        {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Encrypted bytes safe to retain inside the original atomic Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The restored accepted account: genesis state commitment at version zero with its
/// verified issuer certificate and optional ancestry. It exposes no opening.
pub struct AcceptedAccount {
    candidate: PreparedGenesis,
    response: AcceptedResponse,
    extended_acceptance_digest: [u8; 32],
}

impl AcceptedAccount {
    /// Accepted state commitment (public).
    pub fn state(&self) -> [u8; 32] {
        self.candidate.genesis_public().next_state
    }
    /// Accepted version; a genesis account is version zero.
    pub fn version(&self) -> u64 {
        self.candidate.genesis_public().next_version
    }
    /// The community-scoped owner of this account (public; the record leaf's owner).
    pub fn owner(&self) -> [u8; 32] {
        self.candidate.context.enrollment.member
    }
    /// Original operator acceptance time.
    pub fn accepted_at(&self) -> u64 {
        self.response.issuer.accepted_at
    }
    /// The verified issuer response kept for later record and deposit proofs.
    pub fn response(&self) -> &AcceptedResponse {
        &self.response
    }
    /// Digest of the signed acceptance that created this account.
    pub fn extended_acceptance_digest(&self) -> [u8; 32] {
        self.extended_acceptance_digest
    }

    /// The member-side witness of this accepted genesis account: the same committed
    /// opening (the retained blind reproduces the accepted commitment exactly) with the
    /// issuer's P-256 certificate of that state and the given current roster. Every later
    /// update, reservation and wave proof is built from the returned account. It refuses
    /// when the roster does not contain the owner under the same registered secret.
    pub fn witness(
        &self,
        roster: std::sync::Arc<crate::account::witness::Checkpoint>,
    ) -> Result<crate::account::witness::Account, Error> {
        use crate::account::witness::{Account, Certificate, Checkpoint, Genesis};
        let c = &self.candidate;
        let context = &c.context;
        let genesis_roster = std::sync::Arc::new(Checkpoint::from_rows(
            context.enrollment_root,
            vec![context.enrollment.clone()],
        )?);
        let blind = c.opening.blind;
        let built = Account::genesis(
            Genesis {
                community: c.community,
                policy: context.policy,
                extension: context.extension,
                standing: context.standing,
                checkpoint: genesis_roster,
                owner_index: 0,
                owner_secret: &c.secret,
                now: context.checked_at,
                bond: context.bond.clone(),
            },
            &mut || blind,
        )?;
        if built.next.state() != c.commitment {
            return Err(Error::Crypto);
        }
        built
            .next
            .with_certificate(Certificate {
                accepted_at: self.response.issuer.accepted_at,
                signature: self.response.certificate,
            })
            .with_checkpoint(roster)
    }

    /// The record-epoch evidence of this accepted genesis state (see
    /// `Account::record_epoch`). The record relation reads no roster, so the
    /// witness keeps its own one-row genesis roster.
    pub fn record_epoch(
        &self,
        received: &crate::ReceivedRecord,
        presentation_key: [u8; 32],
        now: u64,
    ) -> Result<crate::account::witness::RecordEpochEvidence, Error> {
        self.own_witness()?
            .record_epoch(received, presentation_key, now)
    }

    /// The record-epoch evidence from a leaf the ledger signed for this state.
    pub fn record_epoch_signed(
        &self,
        epoch: &czkp::record::Epoch,
        signed: &czkp::record::SignedLeaf,
        presentation_key: [u8; 32],
        now: u64,
    ) -> Result<crate::account::witness::RecordEpochEvidence, Error> {
        self.own_witness()?
            .record_epoch_signed(epoch, signed, presentation_key, now)
    }

    /// Vouchers this accepted account may still hand out at `now` in the sponsor role
    /// `role` (see `Account::voucher_remaining`).
    pub fn voucher_remaining(&self, role: u8, now: u64) -> Result<u64, Error> {
        self.own_witness()?.voucher_remaining(role, now)
    }

    fn own_witness(&self) -> Result<crate::account::witness::Account, Error> {
        let context = &self.candidate.context;
        let roster = std::sync::Arc::new(crate::account::witness::Checkpoint::from_rows(
            context.enrollment_root,
            vec![context.enrollment.clone()],
        )?);
        self.witness(roster)
    }
}

impl AcceptedGenesisProof {
    /// Digest of the signed acceptance (message then signature).
    pub fn extended_acceptance_digest(&self) -> [u8; 32] {
        self.extended_acceptance_digest
    }

    /// Seal the accepted account record. Refuses unless this candidate carries the
    /// fully verified response, and only the engine that produced it can seal it.
    pub fn seal_account(&self, engine: &Engine) -> Result<SealedAcceptedAccount, Error> {
        let response = self.response.as_ref().ok_or(Error::Invalid)?;
        let candidate = &self.candidate.candidate;
        if !Arc::ptr_eq(&candidate.binding, &engine.sealing)
            || candidate.secret.as_ref() != engine.seed.as_ref()
        {
            return Err(Error::Invalid);
        }
        let mut w = Writer(Zeroizing::new(Vec::with_capacity(MAX_ACCEPTED_SEALED)));
        w.bytes(&[VERSION]);
        w.bytes(engine.seed.as_ref());
        w.bytes(&candidate.opening.blind);
        w.bytes(&candidate.genesis_public().next_state);
        write_context(&mut w, &candidate.context)?;
        w.bytes(&self.candidate.proof.scope.circuit_digest);
        w.bytes(&self.candidate.proof.scope.verifying_key_digest);
        w.bytes(&self.binding.request_id);
        w.bytes(&self.binding.request_digest);
        w.bytes(&self.binding.operator_key);
        w.bytes(&self.extended_acceptance_digest);
        response.write(&mut w)?;
        if w.0.len() + MAGIC.len() + NONCE + 16 > MAX_ACCEPTED_SEALED {
            return Err(Error::Invalid);
        }
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, engine.sealing.context.as_slice()].concat();
        let encrypted = engine
            .sealing
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: w.0.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(SealedAcceptedAccount([MAGIC, &nonce, &encrypted].concat()))
    }
}

impl Engine {
    /// Reopen the accepted account record for this engine. The stored blind must
    /// reproduce the accepted commitment exactly; nothing is reproved or rerooted.
    pub fn restore_accepted_account(
        &self,
        sealed: &SealedAcceptedAccount,
    ) -> Result<AcceptedAccount, Error> {
        let offset = MAGIC.len();
        let nonce: [u8; NONCE] = sealed.0[offset..offset + NONCE]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, self.sealing.context.as_slice()].concat();
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + NONCE..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        let mut r = Reader(&plaintext);
        let version = r.array::<1>()?[0];
        let seed: Field = r.array()?;
        let mut blind: Field = r.array()?;
        let state: Field = r.array()?;
        if version != VERSION || seed != *self.seed {
            return Err(Error::Crypto);
        }
        let context = read_context(&mut r)?;
        let _scope = ProofScope {
            circuit_digest: r.array()?,
            verifying_key_digest: r.array()?,
        };
        let _request_id: Field = r.array()?;
        let _request_digest: Field = r.array()?;
        let _operator_key: Field = r.array()?;
        let digest: Field = r.array()?;
        let response = AcceptedResponse::read(&mut r)?;
        if !r.0.is_empty() || digest == [0; 32] {
            return Err(Error::Crypto);
        }
        let candidate = self.genesis_with_blind(context, blind);
        zeroize::Zeroize::zeroize(&mut blind);
        let candidate = candidate?;
        if candidate.genesis_public().next_state != state {
            return Err(Error::Crypto);
        }
        Ok(AcceptedAccount {
            candidate,
            response,
            extended_acceptance_digest: digest,
        })
    }
}
