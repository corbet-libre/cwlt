//! Statements and circuit inputs of the extension circuits that read the accepted state:
//! the peer-release `wave` and `outcome` evidence, the anonymous burn `deposit` and the
//! public `record`. Pure member-side construction: no network, no storage, no proving.
use super::builders::{Acknowledgment, Resolution};
use super::input::{
    AckJson, ExtensionJson, Hx, MapJson, OpeningJson, ResolutionJson, RowJson, SlotJson,
};
use super::statement::ExtensionStatement;
use super::{Account, Delivery, Field, Slot, hashes};
use crate::Error;
use czkp::poseidon::{integer, limbs};
use serde::Serialize;
use zeroize::Zeroize;

/// The conversation context a wave proof binds.
#[derive(Clone)]
pub struct WaveContext {
    /// History digest.
    pub history: Field,
    /// Verifier challenge.
    pub challenge: Field,
}

/// How a reservation ended.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SettledOutcome {
    /// The recipient answered.
    Answer,
    /// The recipient declined.
    Close,
    /// Nobody answered before the lease ended.
    Silence,
}
impl SettledOutcome {
    fn code(self) -> u8 {
        match self {
            Self::Answer => 1,
            Self::Close => 2,
            Self::Silence => 3,
        }
    }
}
/// A settled reservation: its outcome and, for Answer and Close, the signed receipts.
#[derive(Clone)]
pub struct Settled {
    /// How it ended.
    pub outcome: SettledOutcome,
    /// The receipt (Answer and Close).
    pub resolution: Option<Resolution>,
    /// The sender's acknowledgement (Answer).
    pub acknowledgment: Option<Acknowledgment>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextStatement {
    community: Field,
    owner: Field,
    peer: Field,
    role: u8,
    nonce: Field,
    group: Field,
    contact_policy: Field,
    history: Field,
    challenge: Field,
    opened_at: u64,
    expires_at: u64,
    owner_authority: Field,
    peer_authority: Field,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WaveStatement {
    context: ContextStatement,
    state_policy: Field,
    version: u64,
    state: Field,
    accepted_at: u64,
    binding: Field,
    certificate: Vec<u8>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeStatement {
    evidence: WaveStatement,
    outcome: SettledOutcome,
    receipt_digest: Field,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DepositStatement {
    community: Field,
    identity: Field,
    issuer_key: Vec<u8>,
    issuer_valid_from: u64,
    issuer_valid_until: u64,
    recipient: Field,
    release_epoch: u64,
    nullifier: Field,
    authorization_nullifier: Field,
    obligation: Field,
}
/// A record's context: what it is for, the challenge and when it expires.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordContext {
    /// What the record is for.
    pub purpose: RecordPurpose,
    /// Verifier challenge.
    pub challenge: Field,
    /// Exclusive expiry.
    pub expires_at: u64,
}
/// What a public record is for.
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RecordPurpose {
    /// A first-contact eligibility record.
    FirstContact,
    /// A forum listing record.
    ForumListing,
}
#[derive(Serialize)]
struct InboxStatement {
    root: Field,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordStatement {
    context: RecordContext,
    community: Field,
    owner: Field,
    version: u64,
    state: Field,
    inbox: InboxStatement,
    shares: Option<[u16; 3]>,
}

/// The public statement of an extension proof, tagged by circuit.
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum Body {
    Wave {
        policy: ExtensionStatement,
        certificate_key: Vec<u8>,
        wave: WaveStatement,
    },
    Outcome {
        policy: ExtensionStatement,
        certificate_key: Vec<u8>,
        outcome: OutcomeStatement,
    },
    Deposit {
        policy: ExtensionStatement,
        deposit: DepositStatement,
    },
    Record {
        policy: ExtensionStatement,
        record: RecordStatement,
    },
}

/// The Noir input of one extension circuit, kept private.
#[derive(Serialize)]
struct WaveInput {
    extension: ExtensionJson,
    issuer_key: Vec<u8>,
    scope: Field,
    community: Field,
    owner: Field,
    peer: Field,
    role: u8,
    nonce: Field,
    group: Field,
    contact_policy: Field,
    history: Field,
    challenge: Field,
    opened_at: u64,
    expires_at: u64,
    owner_authority: Field,
    peer_authority: Field,
    state_policy: Field,
    version: u64,
    state: Field,
    accepted_at: u64,
    binding: Field,
    secret: Field,
    opening: OpeningJson,
    slot: SlotJson,
    selected: MapJson,
    certificate: Vec<u8>,
    #[serde(flatten)]
    outcome: Option<OutcomeInput>,
}
#[derive(Serialize)]
struct OutcomeInput {
    outcome: u8,
    receipt_digest: Field,
    owner_enrollment: RowJson,
    peer_enrollment: RowJson,
    resolution: ResolutionJson,
    acknowledgment: AckJson,
}
#[derive(Serialize)]
struct DepositInput {
    extension: ExtensionJson,
    issuer_key: Vec<u8>,
    issuer_valid_from: u64,
    issuer_valid_until: u64,
    scope: Field,
    community: Field,
    identity: Field,
    recipient: Field,
    release_epoch: u64,
    nullifier: Field,
    authorization_nullifier: Field,
    obligation: Field,
    reporter: Field,
    secret: Field,
    state_policy: Field,
    version: u64,
    accepted_at: u64,
    state: Field,
    opening: OpeningJson,
    certificate: Vec<u8>,
    slot: SlotJson,
    kind: u8,
}
#[derive(Serialize)]
struct RecordInput {
    extension: ExtensionJson,
    community: Field,
    owner: Field,
    version: u64,
    state: Field,
    inbox: Field,
    purpose: u8,
    challenge: Field,
    expires_at: u64,
    present: bool,
    shares: [u16; 3],
    state_policy: Field,
    registered_secret: Hx,
    opening: OpeningJson,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Input {
    Wave(Box<WaveInput>),
    Deposit(Box<DepositInput>),
    Record(Box<RecordInput>),
}

/// A public statement with the private input that proves it.
pub struct Evidence {
    body: Body,
    input: Input,
    outcome: bool,
}
impl Evidence {
    /// The public statement as JSON.
    pub fn statement_json(&self) -> Result<String, Error> {
        serde_json::to_string(&self.body).map_err(|_| Error::Invalid)
    }
    /// The private circuit input as JSON; the string is wiped when dropped.
    pub fn input_json(&self) -> Result<zeroize::Zeroizing<String>, Error> {
        serde_json::to_string(&self.input)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| Error::Invalid)
    }
    /// True for the `outcome` circuit; false for `wave`, `deposit` and `record`.
    pub fn is_outcome(&self) -> bool {
        self.outcome
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        match &mut self.input {
            Input::Wave(w) => {
                w.secret.zeroize();
                w.opening.blind.zeroize();
            }
            Input::Deposit(d) => {
                d.secret.zeroize();
                d.opening.blind.zeroize();
            }
            Input::Record(r) => r.opening.blind.zeroize(),
        }
    }
}

pub(super) fn ext(a: &Account) -> ExtensionJson {
    let e = &a.cx.extension;
    ExtensionJson {
        revision: e.revision,
        quorum: e.quorum,
        change_cost: e.change_cost,
        delay: e.delay,
        batch: e.batch,
        standing: e.standing,
    }
}
fn slot_in(s: &Slot) -> SlotJson {
    SlotJson {
        role: s.role,
        peer: s.peer,
        nonce: s.nonce,
        group: s.group,
        contact_policy: s.contact_policy,
        amount: s.amount,
        phase: s.phase,
        outcome: s.outcome,
        answered: s.answered,
        self_punished: s.self_punished,
        admitted_at: s.admitted_at,
        expires_at: s.expires_at,
        peer_authority: Hx(s.peer_authority),
        owner_authority: Hx(s.owner_authority),
    }
}

impl Account {
    /// The `wave` evidence of an accepted active reservation (no `settled`), or the `outcome`
    /// evidence of a settled one. Needs the issuer's certificate of the current state.
    pub fn wave_evidence(
        &self,
        event: &Field,
        context: &WaveContext,
        scope: &Field,
        issuer_key: &[u8; 64],
        settled: Option<&Settled>,
    ) -> Result<Evidence, Error> {
        let code = settled.map_or(0, |s| s.outcome.code());
        let slot = self.slot(event).ok_or(Error::Invalid)?;
        let wanted = if code == 3 {
            5
        } else if code != 0 {
            3
        } else {
            2
        };
        let certificate = self.certificate.as_ref().ok_or(Error::Invalid)?;
        if slot.phase != wanted {
            return Err(Error::Invalid);
        }
        let map = if slot.role == 0 {
            &self.outgoing
        } else {
            &self.incoming
        };
        let index = map.find(event).ok_or(Error::Invalid)?;
        let selected = map.witness(index)?;
        let payload = self.obligation(event, slot, slot.phase)?;
        if selected.leaf[1] != payload {
            return Err(Error::Invalid);
        }
        let receipt_digest = if code != 0 && code != 3 {
            settled
                .and_then(|s| s.resolution.as_ref())
                .ok_or(Error::Invalid)?
                .ed25519_receipt_digest
        } else {
            [0; 32]
        };
        let domain: &[u8] = if code != 0 {
            b"cwlt.extension-outcome.v1"
        } else {
            b"cwlt.extension-wave.v1"
        };
        let mut fields = vec![hashes::domain(domain), integer(1)];
        fields.extend(limbs(&self.cx.secret));
        fields.extend([self.commitment, payload]);
        fields.extend(limbs(&context.challenge));
        fields.extend(limbs(&context.history));
        if code != 0 {
            fields.push(integer(u64::from(code)));
            fields.extend(limbs(&receipt_digest));
        }
        let binding = Self::raw(&fields)?;
        let policy = ExtensionStatement::from(&ext(self));
        let wave = WaveStatement {
            context: ContextStatement {
                community: self.cx.community,
                owner: self.owner().member,
                peer: slot.peer,
                role: slot.role,
                nonce: slot.nonce,
                group: slot.group,
                contact_policy: slot.contact_policy,
                history: context.history,
                challenge: context.challenge,
                opened_at: slot.admitted_at,
                expires_at: slot.expires_at,
                owner_authority: slot.owner_authority,
                peer_authority: slot.peer_authority,
            },
            state_policy: self.cx.state_policy,
            version: self.version,
            state: self.commitment,
            accepted_at: certificate.accepted_at,
            binding,
            certificate: certificate.signature.to_vec(),
        };
        let outcome = settled.map(|s| {
            let resolution = s.resolution.clone().map_or_else(
                || ResolutionJson {
                    kind: 0,
                    issued_at: 0,
                    history_digest: [0; 32],
                    ed25519_receipt_digest: [0; 32],
                    signature: vec![0; 64],
                },
                |r| ResolutionJson {
                    kind: r.kind,
                    issued_at: r.issued_at,
                    history_digest: r.history_digest,
                    ed25519_receipt_digest: r.ed25519_receipt_digest,
                    signature: r.signature.to_vec(),
                },
            );
            let ack = s.acknowledgment.clone().map_or_else(
                || AckJson {
                    issued_at: 0,
                    signature: vec![0; 64],
                },
                |a| AckJson {
                    issued_at: a.issued_at,
                    signature: a.signature.to_vec(),
                },
            );
            OutcomeInput {
                outcome: code,
                receipt_digest,
                owner_enrollment: RowJson::from(&slot.owner_enrollment),
                peer_enrollment: RowJson::from(&slot.peer_enrollment),
                resolution,
                acknowledgment: ack,
            }
        });
        let input = WaveInput {
            extension: ext(self),
            issuer_key: issuer_key.to_vec(),
            scope: *scope,
            community: self.cx.community,
            owner: self.owner().member,
            peer: slot.peer,
            role: slot.role,
            nonce: slot.nonce,
            group: slot.group,
            contact_policy: slot.contact_policy,
            history: context.history,
            challenge: context.challenge,
            opened_at: slot.admitted_at,
            expires_at: slot.expires_at,
            owner_authority: slot.owner_authority,
            peer_authority: slot.peer_authority,
            state_policy: self.cx.state_policy,
            version: self.version,
            state: self.commitment,
            accepted_at: certificate.accepted_at,
            binding,
            secret: *self.cx.secret,
            opening: OpeningJson::from(&self.opening),
            slot: slot_in(slot),
            selected: selected.into(),
            certificate: certificate.signature.to_vec(),
            outcome,
        };
        let body = match settled {
            None => Body::Wave {
                policy,
                certificate_key: issuer_key.to_vec(),
                wave,
            },
            Some(s) => Body::Outcome {
                policy,
                certificate_key: issuer_key.to_vec(),
                outcome: OutcomeStatement {
                    evidence: wave,
                    outcome: s.outcome,
                    receipt_digest,
                },
            },
        };
        Ok(Evidence {
            body,
            input: Input::Wave(Box::new(input)),
            outcome: settled.is_some(),
        })
    }

    /// The anonymous deposit of a burned delivery, released in `release_epoch`. `issuer` is
    /// the published ring period whose key signed the account's certificate; the relation
    /// proves the hidden acceptance time lies inside it. `identity` is the community
    /// identity the certificate binds.
    pub fn deposit(
        &self,
        delivery: &Delivery,
        scope: &Field,
        issuer: &czkp::issuer_keys::CertificateKeyPeriod,
        identity: &Field,
        release_epoch: u64,
    ) -> Result<Evidence, Error> {
        let certificate = self.certificate.as_ref().ok_or(Error::Invalid)?;
        let issuer_key = issuer.key().map_err(|_| Error::Invalid)?;
        let (issuer_valid_from, issuer_valid_until) = (issuer.valid_from, issuer.until());
        if issuer_valid_from == 0
            || !(issuer_valid_from..issuer_valid_until).contains(&certificate.accepted_at)
            || *identity == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let slot = &delivery.slot;
        let owner = self.owner().member;
        let event = self.marker(&owner, &slot.peer, &slot.nonce)?;
        let stage = u64::from(delivery.kind == 4);
        let secret = limbs(&self.cx.secret);
        let nullifier = |tag: u64| -> Result<Field, Error> {
            let mut f = vec![event, integer(tag), integer(stage)];
            f.extend(secret);
            Self::raw(&f)
        };
        let nullifier_value = nullifier(41)?;
        let authorization_nullifier = nullifier(40)?;
        let obligation =
            self.delivery(&slot.peer, &owner, &slot.nonce, &slot.group, delivery.kind)?;
        let body = Body::Deposit {
            policy: ExtensionStatement::from(&ext(self)),
            deposit: DepositStatement {
                community: self.cx.community,
                identity: *identity,
                issuer_key: issuer_key.to_vec(),
                issuer_valid_from,
                issuer_valid_until,
                recipient: slot.peer,
                release_epoch,
                nullifier: nullifier_value,
                authorization_nullifier,
                obligation,
            },
        };
        let input = DepositInput {
            extension: ext(self),
            issuer_key: issuer_key.to_vec(),
            issuer_valid_from,
            issuer_valid_until,
            scope: *scope,
            community: self.cx.community,
            identity: *identity,
            recipient: slot.peer,
            release_epoch,
            nullifier: nullifier_value,
            authorization_nullifier,
            obligation,
            reporter: owner,
            secret: *self.cx.secret,
            state_policy: self.cx.state_policy,
            version: self.version,
            accepted_at: certificate.accepted_at,
            state: self.commitment,
            opening: OpeningJson::from(&self.opening),
            certificate: certificate.signature.to_vec(),
            slot: slot_in(slot),
            kind: delivery.kind,
        };
        Ok(Evidence {
            body,
            input: Input::Deposit(Box::new(input)),
            outcome: false,
        })
    }

    /// The public record of the account's accepted/declined/punished shares (hidden below the
    /// extension's quorum).
    pub fn record(&self, context: &RecordContext) -> Result<Evidence, Error> {
        let o = &self.opening;
        let total = o.accepted + o.declined + o.punished;
        let shares = (total >= u64::from(self.cx.extension.quorum)).then(|| {
            let accepted = (o.accepted * 10_000 / total) as u16;
            let declined = (o.declined * 10_000 / total) as u16;
            [accepted, declined, 10_000 - accepted - declined]
        });
        let body = Body::Record {
            policy: ExtensionStatement::from(&ext(self)),
            record: RecordStatement {
                context: context.clone(),
                community: self.cx.community,
                owner: self.owner().member,
                version: self.version,
                state: self.commitment,
                inbox: InboxStatement { root: o.inbox },
                shares,
            },
        };
        let input = RecordInput {
            extension: ext(self),
            community: self.cx.community,
            owner: self.owner().member,
            version: self.version,
            state: self.commitment,
            inbox: o.inbox,
            purpose: u8::from(context.purpose == RecordPurpose::ForumListing),
            challenge: context.challenge,
            expires_at: context.expires_at,
            present: shares.is_some(),
            shares: shares.unwrap_or([0; 3]),
            state_policy: self.cx.state_policy,
            registered_secret: Hx(self.owner().secret_hash),
            opening: OpeningJson::from(o),
        };
        Ok(Evidence {
            body,
            input: Input::Record(Box::new(input)),
            outcome: false,
        })
    }
}
