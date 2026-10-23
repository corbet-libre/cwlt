//! Durable pending companion and accepted account record.
//!
//! State A (sealed candidate and proof) and the exact signed outbox share one
//! Store commit. State B replaces only the sealed row after the engine verified
//! the actual response; the outbox stays pending. Activation replaces the pending
//! row with the accepted record in one commit and only then acknowledges the
//! outbox, because the Store acknowledges an output in a commit of its own. A
//! crash between the two is repaired by `settle_outbox`, never by a re-send.
use super::*;
use ckmg::wallet_engine::account::{
    AcceptedAccount, AcceptedResponse, OwnerAbsence, PendingGenesisBinding, ResponseTrust,
    SealedAcceptedAccount, SealedPendingGenesis,
};
use cwst::Output;

const PENDING: &[u8] = b"pending-genesis.v1";
const ACCEPTED: &[u8] = b"accepted-account.v1";
const SETTLED: &[u8] = b"accepted-request.v1";
/// Append-only record of discarded state-A requests: request digest then id.
const DISCARDED: &[u8] = b"discarded-genesis.v1";
/// One discarded request: its request digest and request id.
type Discarded = ([u8; 32], [u8; 32]);

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// One owner row, only when the latest committed receipt contains exactly it.
fn committed_row<'s, B: Backend>(
    store: &'s Store<B>,
    key: &[u8],
) -> Result<Option<&'s [u8]>, Error> {
    let Some(row) = store.read(OWNER, key)? else {
        return Ok(None);
    };
    let operation = store.operation()?;
    let receipt = store.receipt(&operation)?;
    if !receipt.is_commit(store, &operation) || !receipt.contains_record(OWNER, key, &digest(row)) {
        return Err(Error::Conflict);
    }
    Ok(Some(row))
}

/// The one pending output of this request, only when the receipt contains it.
fn outbox<B: Backend>(store: &Store<B>, id: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut matching = store
        .load_pending()?
        .iter()
        .filter(|output| &output.id == id);
    let output = matching.next().ok_or(Error::Conflict)?;
    if matching.next().is_some() {
        return Err(Error::Conflict);
    }
    let operation = store.operation()?;
    let receipt = store.receipt(&operation)?;
    if !receipt.is_commit(store, &operation) || !receipt.contains_output(id, &digest(&output.bytes))
    {
        return Err(Error::Conflict);
    }
    Ok(output.bytes.clone())
}

/// A reopened pending companion: its authenticated binding and the exact outbox.
pub struct ReopenedPending {
    /// Opaque upper binding, request identity and (state B) the verified response.
    pub binding: PendingGenesisBinding,
    /// Exact signed request bytes that state A committed; a re-send uses these.
    pub outbox: Vec<u8>,
}
impl ReopenedPending {
    /// True for state B, the only state that can be activated.
    pub fn accepted(&self) -> bool {
        self.binding.extended_acceptance_digest.is_some()
    }
}

/// Verified accepted candidate, waiting for the upper owner's final checks and
/// the accepted commit. It holds sealed bytes and public data only.
pub struct PendingActivation {
    sealed: SealedAcceptedAccount,
    pending: Vec<u8>,
    request_id: [u8; 32],
    state: [u8; 32],
    version: u64,
    accepted_at: u64,
    extended_acceptance_digest: [u8; 32],
}

/// Public result of one committed activation.
#[derive(Debug, PartialEq, Eq)]
pub struct ActivatedAccount {
    /// Accepted private state commitment.
    pub state: [u8; 32],
    /// Accepted version; a genesis account is version zero.
    pub version: u64,
    /// Original operator acceptance time.
    pub accepted_at: u64,
    /// Digest of the signed acceptance that created the account.
    pub extended_acceptance_digest: [u8; 32],
    /// False when the outbox acknowledgement is still owed to `settle_outbox`.
    pub outbox_settled: bool,
}

impl AccountGenesisProof {
    /// Commit state A and the exact signed outbox in one Store commit. A pending
    /// or accepted row is never replaced, so repeating this cannot change state A;
    /// later work reopens from the durable row only. `binding` carries no
    /// acceptance digest or response (state A).
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_pending<B: Backend>(
        &self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &mut Store<B>,
        binding: &PendingGenesisBinding,
        outbox: Vec<u8>,
        operation: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        self.check_current(owner, fresh_engine, store, &self.context, now)?;
        let id = binding.acceptance.request_id;
        if operation == [0; 32]
            || id == [0; 32]
            || outbox.is_empty()
            || binding.extended_acceptance_digest.is_some()
            || binding.response.is_some()
            || store.read(OWNER, PENDING)?.is_some()
            || store.read(OWNER, ACCEPTED)?.is_some()
            || store.load_pending()?.iter().any(|output| output.id == id)
        {
            return Err(Error::Conflict);
        }
        let sealed = self.candidate.seal_pending(&self.engine, binding)?;
        let expected = store.version()?;
        let outputs = [Output { id, bytes: outbox }];
        let receipt = store
            .commit_with_receipt(
                expected,
                operation,
                &[Change::Put {
                    owner: OWNER,
                    key: PENDING,
                    value: sealed.as_bytes(),
                }],
                &outputs,
            )
            .await?;
        if !receipt.is_commit(store, &operation)
            || !receipt.contains_record(OWNER, PENDING, &digest(sealed.as_bytes()))
            || !receipt.contains_output(&id, &digest(&outputs[0].bytes))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

impl DurableAccountOwner {
    /// Reopen the durable pending companion before its horizon: the sealed row,
    /// its row receipt, the owner's account capsule and the pending outbox must
    /// all agree. The candidate is not kept; nothing is reproved.
    pub fn reopen_pending<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &Store<B>,
        now: u64,
    ) -> Result<ReopenedPending, Error> {
        let projection = self.projection(fresh_engine, store)?;
        if store.read(OWNER, ACCEPTED)?.is_some() {
            return Err(Error::Conflict);
        }
        let row = committed_row(store, PENDING)?.ok_or(Error::Conflict)?;
        let sealed = SealedPendingGenesis::from_bytes(row)?;
        let (proof, binding) = fresh_engine.restore_pending_genesis(&sealed, now)?;
        check_row(&self.scope, proof.context(), &projection)?;
        let outbox = outbox(store, &binding.acceptance.request_id)?;
        Ok(ReopenedPending { binding, outbox })
    }

    /// Move state A to state B in one Store commit after the actual response
    /// arrived. The engine verifies the response under the CURRENT trust; the
    /// outbox stays pending. A or B never moves backwards.
    pub async fn advance_pending<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &mut Store<B>,
        response: &AcceptedResponse,
        trust: &ResponseTrust,
        operation: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        let reopened = self.reopen_pending(fresh_engine, store, now)?;
        let row = committed_row(store, PENDING)?.ok_or(Error::Conflict)?;
        let id = reopened.binding.acceptance.request_id;
        if reopened.accepted() || operation == [0; 32] {
            return Err(Error::Conflict);
        }
        let sealed = SealedPendingGenesis::from_bytes(row)?;
        let advanced = fresh_engine.advance_pending(&sealed, response, trust, now)?;
        let expected = store.version()?;
        let receipt = store
            .commit_with_receipt(
                expected,
                operation,
                &[Change::Put {
                    owner: OWNER,
                    key: PENDING,
                    value: advanced.as_bytes(),
                }],
                &[],
            )
            .await?;
        if !receipt.is_commit(store, &operation)
            || !receipt.contains_record(OWNER, PENDING, &digest(advanced.as_bytes()))
            || !receipt.contains_output(&id, &digest(&reopened.outbox))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Reopen state B before its horizon, re-verify the stored response offline
    /// under the CURRENT trust (frontier included) and seal the accepted record.
    /// Nothing is written; the upper owner runs its own checks and then calls
    /// `PendingActivation::commit`.
    pub fn begin_activation<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &Store<B>,
        trust: &ResponseTrust,
        now: u64,
    ) -> Result<PendingActivation, Error> {
        let reopened = self.reopen_pending(fresh_engine, store, now)?;
        if !reopened.accepted() {
            return Err(Error::Conflict);
        }
        let row = committed_row(store, PENDING)?.ok_or(Error::Conflict)?;
        let sealed = SealedPendingGenesis::from_bytes(row)?;
        let accepted = fresh_engine.activate_pending(&sealed, trust, now)?;
        let public = accepted.public_genesis();
        Ok(PendingActivation {
            sealed: accepted.seal_account(fresh_engine)?,
            pending: row.to_vec(),
            request_id: reopened.binding.acceptance.request_id,
            state: public.next_state,
            version: public.next_version,
            accepted_at: accepted.accepted_at(),
            extended_acceptance_digest: accepted.extended_acceptance_digest(),
        })
    }

    /// Acknowledge the outbox of an already accepted account. Safe to repeat;
    /// returns false when no account has been accepted yet.
    pub async fn settle_outbox<B: Backend>(
        &self,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<bool, Error> {
        let Some(row) = committed_row(store, SETTLED)? else {
            return Ok(false);
        };
        let id: [u8; 32] = row.try_into().map_err(|_| Error::Conflict)?;
        if operation == [0; 32] {
            return Err(Error::Conflict);
        }
        if store.load_pending()?.iter().any(|output| output.id == id) {
            let expected = store.version()?;
            store.ack_output(expected, operation, id).await?;
        }
        Ok(true)
    }

    /// Discard the one state-A companion whose request the operator can no longer
    /// accept (`Engine::check_elapsed_pending`: an operator status, signed under
    /// the sealed key, shows no account at least the commit margin after the
    /// request's `expires_at`). ONE Store commit deletes exactly that pending row
    /// and appends its request digest and id to the discarded record; the outbox
    /// is acknowledged afterwards in a commit of its own (`settle_discarded`).
    /// State B, an accepted account or any failed check discards nothing.
    /// Returns the discarded request digest.
    #[allow(clippy::too_many_arguments)]
    pub async fn discard_elapsed_pending<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &mut Store<B>,
        request_expires_at: u64,
        absence: &OwnerAbsence,
        operation: [u8; 32],
        acknowledgement: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        if operation == [0; 32] || acknowledgement == [0; 32] || operation == acknowledgement {
            return Err(Error::Conflict);
        }
        let projection = self.projection(fresh_engine, store)?;
        if store.read(OWNER, ACCEPTED)?.is_some() {
            return Err(Error::Conflict);
        }
        let row = committed_row(store, PENDING)?.ok_or(Error::Conflict)?;
        let sealed = SealedPendingGenesis::from_bytes(row)?;
        let (proof, binding) =
            fresh_engine.check_elapsed_pending(&sealed, request_expires_at, absence)?;
        check_row(&self.scope, proof.context(), &projection)?;
        let id = binding.acceptance.request_id;
        outbox(store, &id)?;
        let mut record = committed_row(store, DISCARDED)?.unwrap_or_default().to_vec();
        record.extend_from_slice(&binding.acceptance.request_digest);
        record.extend_from_slice(&id);
        let expected = store.version()?;
        let receipt = store
            .commit_with_receipt(
                expected,
                operation,
                &[
                    Change::Delete {
                        owner: OWNER,
                        key: PENDING,
                    },
                    Change::Put {
                        owner: OWNER,
                        key: DISCARDED,
                        value: &record,
                    },
                ],
                &[],
            )
            .await?;
        if !receipt.is_commit(store, &operation)
            || !receipt.contains_record(OWNER, DISCARDED, &digest(&record))
            || store.read(OWNER, PENDING)?.is_some()
        {
            return Err(Error::Conflict);
        }
        self.settle_discarded(store, acknowledgement).await?;
        Ok(binding.acceptance.request_digest)
    }

    /// Acknowledge every still pending outbox of a discarded request; such an
    /// output is never sent again. Safe to repeat (a crash after the discard
    /// commit leaves at most these outputs).
    pub async fn settle_discarded<B: Backend>(
        &self,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<(), Error> {
        if operation == [0; 32] {
            return Err(Error::Conflict);
        }
        for (_, id) in self.discarded(store)? {
            if store.load_pending()?.iter().any(|output| output.id == id) {
                let expected = store.version()?;
                store.ack_output(expected, operation, id).await?;
            }
        }
        Ok(())
    }

    /// The request digests of every discarded state-A companion, oldest first.
    /// An operator acceptance of one of them is a broken discard guard: the upper
    /// owner reports it, never adopts or ignores it.
    pub fn discarded_genesis<B: Backend>(&self, store: &Store<B>) -> Result<Vec<[u8; 32]>, Error> {
        Ok(self.discarded(store)?.into_iter().map(|(digest, _)| digest).collect())
    }

    fn discarded<B: Backend>(&self, store: &Store<B>) -> Result<Vec<Discarded>, Error> {
        let Some(row) = committed_row(store, DISCARDED)? else {
            return Ok(Vec::new());
        };
        let (entries, rest) = row.as_chunks::<64>();
        if entries.is_empty() || !rest.is_empty() {
            return Err(Error::Conflict);
        }
        Ok(entries
            .iter()
            .map(|entry| {
                let (digest, id) = entry.split_at(32);
                (
                    digest.try_into().unwrap_or_default(),
                    id.try_into().unwrap_or_default(),
                )
            })
            .collect())
    }

    /// Reopen the accepted account record under a fresh engine and its receipt.
    pub fn restore_accepted<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &Store<B>,
    ) -> Result<AcceptedAccount, Error> {
        self.projection(fresh_engine, store)?;
        let row = committed_row(store, ACCEPTED)?.ok_or(Error::Conflict)?;
        Ok(fresh_engine.restore_accepted_account(&SealedAcceptedAccount::from_bytes(row)?)?)
    }
}

impl PendingActivation {
    /// Accepted private state commitment (public).
    pub fn state(&self) -> [u8; 32] {
        self.state
    }
    /// Original operator acceptance time.
    pub fn accepted_at(&self) -> u64 {
        self.accepted_at
    }
    /// Digest of the signed acceptance that created the account.
    pub fn extended_acceptance_digest(&self) -> [u8; 32] {
        self.extended_acceptance_digest
    }

    /// Replace the unchanged pending row with the accepted record in one commit,
    /// then acknowledge the outbox. The upper owner checks admission, Keys and
    /// binding immediately before and after this call.
    pub async fn commit<B: Backend>(
        self,
        owner: &DurableAccountOwner,
        store: &mut Store<B>,
        operation: [u8; 32],
        acknowledgement: [u8; 32],
    ) -> Result<ActivatedAccount, Error> {
        if operation == [0; 32]
            || acknowledgement == [0; 32]
            || operation == acknowledgement
            || store.read(OWNER, KEY)? != Some(owner.sealed.as_bytes())
            || store.read(OWNER, ACCEPTED)?.is_some()
            || committed_row(store, PENDING)? != Some(self.pending.as_slice())
        {
            return Err(Error::Conflict);
        }
        let expected = store.version()?;
        let receipt = store
            .commit_with_receipt(
                expected,
                operation,
                &[
                    Change::Put {
                        owner: OWNER,
                        key: ACCEPTED,
                        value: self.sealed.as_bytes(),
                    },
                    Change::Put {
                        owner: OWNER,
                        key: SETTLED,
                        value: &self.request_id,
                    },
                    Change::Delete {
                        owner: OWNER,
                        key: PENDING,
                    },
                ],
                &[],
            )
            .await?;
        if !receipt.is_commit(store, &operation)
            || !receipt.contains_record(OWNER, ACCEPTED, &digest(self.sealed.as_bytes()))
            || store.read(OWNER, PENDING)?.is_some()
        {
            return Err(Error::Conflict);
        }
        let outbox_settled = owner.settle_outbox(store, acknowledgement).await.is_ok();
        Ok(ActivatedAccount {
            state: self.state,
            version: self.version,
            accepted_at: self.accepted_at,
            extended_acceptance_digest: self.extended_acceptance_digest,
            outbox_settled,
        })
    }
}
