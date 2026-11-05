//! Holder-side verification of the operator's full ApplyExtended response.
//!
//! The wallet verifies the issuer's state certificate and the epoch ancestry
//! itself, with maintained P-256 and its own LGPL transcript encoders. The issuer
//! crate is deliberately not a dependency: it also owns a database store. All
//! inputs are data; nothing here grants custody or touches the Store.
use super::pending::{Reader, Writer};
use super::*;
use czkp::certificate::{AcceptedState, EpochAncestry};

const MAX_RECORD: usize = 64 * 1024;

/// Published minimum frontier from the current verified material.
#[derive(Clone, PartialEq, Eq)]
pub struct Frontier {
    /// Published epoch number (non-zero).
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Record-epoch issuer Ed25519 key of this epoch, from the authenticated
    /// descriptor (the join leaf's certificate is verified against it).
    pub issuer_key: [u8; 32],
}

/// The published epoch descriptor a join-time ancestry sits under: the one the
/// community's own signed material names when the operator carries that
/// publication on the response. It is not a frozen frontier: a newcomer has no
/// frozen leaf, so only its join-time record leaf is bound here.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinEpoch {
    /// Published epoch number (non-zero).
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Record-epoch issuer Ed25519 key of this epoch, from the authenticated
    /// descriptor (the join leaf's certificate is verified against it).
    pub issuer_key: [u8; 32],
}

/// Current verified issuer material needed to check a response. The upper owner
/// supplies it from the authenticated Balance publication, never from the response.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseTrust {
    /// The published certificate issuer key ring (retired keys stay with their
    /// periods); each certificate is checked with the key of its own time.
    pub certificate_keys: Vec<czkp::issuer_keys::CertificateKeyPeriod>,
    /// The community identity (founding fingerprint) the certificates bind.
    pub community_identity: [u8; 32],
    /// The still-valid frozen minimum frontier, when the material has one. An
    /// ancestry certificate must match it, and without one none may come. A
    /// genesis has no frozen leaf, so under a frontier its response may carry none.
    pub frontier: Option<Frontier>,
    /// The epoch descriptor the community publication carried on the response
    /// names, once the upper owner verified that publication with the community
    /// ring. A first genesis accepted after the record freeze has no frontier,
    /// so this is the only descriptor its join-time ancestry may sit under.
    pub join: Option<JoinEpoch>,
}

/// Private epoch-ancestry certificate returned on the authenticated response.
#[derive(Clone, PartialEq, Eq)]
pub struct AncestryResponse {
    /// Published epoch number.
    pub epoch: u64,
    /// Published epoch root.
    pub root: [u8; 32],
    /// Exact blinded frozen leaf commitment in that root.
    pub frozen_leaf: [u8; 32],
    /// Issuer P-256 low-S signature over the compact ancestry transcript.
    pub signature: [u8; 64],
    /// Opaque private signed-leaf packet, kept unchanged for later record proofs.
    pub record: Vec<u8>,
}

/// The operator's complete ApplyExtended response as the holder must keep it.
#[derive(Clone, PartialEq, Eq)]
pub struct AcceptedResponse {
    /// Original accepted time and operator Ed25519 signature.
    pub issuer: IssuerAcceptance,
    /// Issuer P-256 low-S signature of the accepted-state certificate.
    pub certificate: [u8; 64],
    /// Epoch ancestry of an owner whose state was frozen in the material's
    /// frontier. A fresh genesis has no frozen leaf and carries none.
    pub ancestry: Option<AncestryResponse>,
    /// The descriptor this response was ACCEPTED under when it was not the frozen
    /// frontier (a first genesis after the record freeze). Stored with the
    /// verified response so activation re-checks the same descriptor; it is never
    /// re-read from the response, and it grants nothing at activation that the
    /// ancestry certificate does not already prove.
    pub join: Option<JoinEpoch>,
}

/// The accepted-state body czkp encodes and verifies, for the retained statement.
pub(super) fn accepted_state(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    identity: &[u8; 32],
    at: u64,
) -> AcceptedState {
    AcceptedState {
        community: public.community,
        identity: *identity,
        owner: public.owner,
        state: public.next_state,
        scope: scope.circuit_digest,
        version: public.next_version,
        accepted_at: at,
    }
}

/// The ancestry body czkp encodes and verifies, for the retained statement.
pub(super) fn ancestry_body(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    ancestry: &AncestryResponse,
    issued_at: u64,
) -> EpochAncestry {
    EpochAncestry {
        community: public.community,
        owner: public.owner,
        epoch: ancestry.epoch,
        root: ancestry.root,
        frozen_leaf: ancestry.frozen_leaf,
        state: public.next_state,
        version: public.next_version,
        circuit_digest: scope.circuit_digest,
        verifying_key_digest: scope.verifying_key_digest,
        issued_at,
    }
}

/// A genesis has no frozen leaf, so the only record an issuer can attach to its
/// acceptance is the join-time record leaf: a signed leaf of exactly the accepted
/// genesis state (owner, version, state) whose blinded commitment is the certified
/// `frozen_leaf`. The issuer's Ed25519 signature over it is checked here, against
/// the epoch issuer key, with the existing `czkp::record::verify_certificate`
/// (the same check `Account::record_epoch_signed` runs at presentation).
fn check_join_record(
    public: &GenesisPublic,
    ancestry: &AncestryResponse,
    issuer_key: &[u8; 32],
) -> Result<(), Error> {
    let signed: czkp::record::SignedLeaf =
        serde_json::from_slice(&ancestry.record).map_err(|_| Error::Invalid)?;
    let leaf = &signed.leaf;
    if leaf.owner != public.owner
        || leaf.version != public.next_version
        || leaf.state != public.next_state
        || signed.signature.len() != 64
    {
        return Err(Error::Invalid);
    }
    let commitment = leaf
        .commitment(&public.community, ancestry.epoch)
        .map_err(|_| Error::Invalid)?;
    if commitment != ancestry.frozen_leaf {
        return Err(Error::Invalid);
    }
    czkp::record::verify_certificate(
        issuer_key,
        &public.community,
        ancestry.epoch,
        &commitment,
        &signed.signature,
    )
    .map_err(|_| Error::Crypto)?;
    Ok(())
}

/// Verify the issuer's state certificate and the ancestry rule for one accepted
/// statement under the CURRENT trust. Pure: no clock, no Store, no custody.
pub(super) fn verify_issuer_material(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    response: &AcceptedResponse,
    trust: &ResponseTrust,
) -> Result<(), Error> {
    let at = response.issuer.accepted_at;
    czkp::issuer_keys::verify_accepted(
        &trust.certificate_keys,
        &accepted_state(public, scope, &trust.community_identity, at),
        &response.certificate,
    )
    .map_err(|_| Error::Crypto)?;
    // A genesis has no frozen leaf. The operator attaches either nothing or the
    // join-time record leaf of the accepted genesis (see `check_join_record`), and
    // only when the community published an epoch window that contains the
    // acceptance. This rule is reached ONLY from the genesis path
    // (PreparedGenesisProof::verify_response is the sole caller). A later
    // non-genesis caller must demand the ancestry under a frontier instead.
    let Some(ancestry) = &response.ancestry else {
        return Ok(());
    };
    // A STORED join is the descriptor this acceptance was admitted under: the
    // advance verified the ancestry under it and sealed it with the response (an
    // advance never takes one from its caller). Activation re-checks the stored
    // response under exactly that descriptor for its own epoch, also after the
    // material gained a frontier of a later epoch that this ancestry can never
    // match. A frontier of the SAME epoch must be the same descriptor: a fork of
    // one epoch is refused, never resolved by choosing one side.
    if let Some(join) = response
        .join
        .as_ref()
        .filter(|join| join.epoch == ancestry.epoch)
    {
        if trust.frontier.as_ref().is_some_and(|frontier| {
            frontier.epoch == join.epoch
                && (frontier.root != join.root || frontier.issuer_key != join.issuer_key)
        }) {
            return Err(Error::Invalid);
        }
        return check_ancestry_under(
            public,
            scope,
            response,
            ancestry,
            &trust.certificate_keys,
            &join.epoch,
            &join.root,
            &join.issuer_key,
        );
    }
    match &trust.frontier {
        Some(frontier) => check_ancestry_under(
            public,
            scope,
            response,
            ancestry,
            &trust.certificate_keys,
            &frontier.epoch,
            &frontier.root,
            &frontier.issuer_key,
        ),
        // Without a frozen frontier the ONLY descriptor a join-time ancestry may sit
        // under is the one the community's own signed publication named for this
        // response (filled by the upper owner after it verified that publication).
        // Without it the pair stays Invalid, exactly as before.
        None => match &trust.join {
            Some(join) => check_ancestry_under(
                public,
                scope,
                response,
                ancestry,
                &trust.certificate_keys,
                &join.epoch,
                &join.root,
                &join.issuer_key,
            ),
            None => Err(Error::Invalid),
        },
    }
}

/// One ancestry certificate under one published epoch descriptor: the exact
/// epoch and root, the issuer's signature over the certified commitment, and the
/// join-time record leaf under that epoch's record-issuer key.
fn check_ancestry_under(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    response: &AcceptedResponse,
    ancestry: &AncestryResponse,
    certificate_keys: &[czkp::issuer_keys::CertificateKeyPeriod],
    epoch: &u64,
    root: &[u8; 32],
    issuer_key: &[u8; 32],
) -> Result<(), Error> {
    let at = response.issuer.accepted_at;
    if *epoch == 0
        || ancestry.epoch != *epoch
        || ancestry.root != *root
        || ancestry.record.is_empty()
        || ancestry.record.len() > MAX_RECORD
    {
        return Err(Error::Invalid);
    }
    czkp::issuer_keys::verify_ancestry(
        certificate_keys,
        &ancestry_body(public, scope, ancestry, at),
        &ancestry.signature,
    )
    .map_err(|_| Error::Crypto)?;
    check_join_record(public, ancestry, issuer_key)
}

impl AcceptedResponse {
    pub(super) fn write(&self, w: &mut Writer) -> Result<(), Error> {
        w.u64(self.issuer.accepted_at);
        w.bytes(&self.issuer.signature);
        w.bytes(&self.certificate);
        // Marker 1 keeps the original ancestry-only layout readable by this
        // version; marker 2 appends the join descriptor a first genesis after the
        // record freeze was accepted under.
        match &self.ancestry {
            None => w.bytes(&[0]),
            Some(a) => {
                w.bytes(&[if self.join.is_some() { 2 } else { 1 }]);
                w.u64(a.epoch);
                w.bytes(&a.root);
                w.bytes(&a.frozen_leaf);
                w.bytes(&a.signature);
                w.var(&a.record)?;
                if let Some(join) = &self.join {
                    w.u64(join.epoch);
                    w.bytes(&join.root);
                    w.bytes(&join.issuer_key);
                }
            }
        }
        Ok(())
    }

    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let accepted_at = r.u64()?;
        let signature = r.array()?;
        let certificate = r.array()?;
        let (ancestry, join) = match r.array::<1>()?[0] {
            0 => (None, None),
            marker @ (1 | 2) => {
                let ancestry = AncestryResponse {
                    epoch: r.u64()?,
                    root: r.array()?,
                    frozen_leaf: r.array()?,
                    signature: r.array()?,
                    record: r.var(MAX_RECORD)?.to_vec(),
                };
                let join = if marker == 2 {
                    Some(JoinEpoch {
                        epoch: r.u64()?,
                        root: r.array()?,
                        issuer_key: r.array()?,
                    })
                } else {
                    None
                };
                (Some(ancestry), join)
            }
            _ => return Err(Error::Crypto),
        };
        Ok(Self {
            issuer: IssuerAcceptance {
                accepted_at,
                signature,
            },
            certificate,
            ancestry,
            join,
        })
    }
}
