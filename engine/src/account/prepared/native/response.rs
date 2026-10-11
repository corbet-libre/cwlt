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
}

/// Current verified issuer material needed to check a response. The upper owner
/// supplies it from the authenticated Balance publication, never from the response.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseTrust {
    /// Issuer P-256 certificate key, uncompressed affine coordinates.
    pub certificate_key: [u8; 64],
    /// The still-valid frozen minimum frontier, when the material has one. Its
    /// presence makes an ancestry certificate mandatory; its absence forbids one.
    pub frontier: Option<Frontier>,
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
    /// Epoch ancestry, present exactly when the material has a frontier.
    pub ancestry: Option<AncestryResponse>,
}

/// The accepted-state body czkp encodes and verifies, for the retained statement.
pub(super) fn accepted_state(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    at: u64,
) -> AcceptedState {
    AcceptedState {
        community: public.community,
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

/// Verify the issuer's state certificate and the ancestry rule for one accepted
/// statement under the CURRENT trust. Pure: no clock, no Store, no custody.
pub(super) fn verify_issuer_material(
    public: &GenesisPublic,
    scope: &czkp::ProofScope,
    response: &AcceptedResponse,
    trust: &ResponseTrust,
) -> Result<(), Error> {
    let at = response.issuer.accepted_at;
    accepted_state(public, scope, at)
        .verify(&trust.certificate_key, &response.certificate)
        .map_err(|_| Error::Crypto)?;
    match (&trust.frontier, &response.ancestry) {
        (None, None) => Ok(()),
        (Some(frontier), Some(ancestry)) => {
            if frontier.epoch == 0
                || ancestry.epoch != frontier.epoch
                || ancestry.root != frontier.root
                || ancestry.record.is_empty()
                || ancestry.record.len() > MAX_RECORD
            {
                return Err(Error::Invalid);
            }
            ancestry_body(public, scope, ancestry, at)
                .verify(&trust.certificate_key, &ancestry.signature)
                .map_err(|_| Error::Crypto)
        }
        // A frontier makes ancestry mandatory; without one it must be absent.
        _ => Err(Error::Invalid),
    }
}

impl AcceptedResponse {
    pub(super) fn write(&self, w: &mut Writer) -> Result<(), Error> {
        w.u64(self.issuer.accepted_at);
        w.bytes(&self.issuer.signature);
        w.bytes(&self.certificate);
        match &self.ancestry {
            None => w.bytes(&[0]),
            Some(a) => {
                w.bytes(&[1]);
                w.u64(a.epoch);
                w.bytes(&a.root);
                w.bytes(&a.frozen_leaf);
                w.bytes(&a.signature);
                w.var(&a.record)?;
            }
        }
        Ok(())
    }

    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let accepted_at = r.u64()?;
        let signature = r.array()?;
        let certificate = r.array()?;
        let ancestry = match r.array::<1>()?[0] {
            0 => None,
            1 => Some(AncestryResponse {
                epoch: r.u64()?,
                root: r.array()?,
                frozen_leaf: r.array()?,
                signature: r.array()?,
                record: r.var(MAX_RECORD)?.to_vec(),
            }),
            _ => return Err(Error::Crypto),
        };
        Ok(Self {
            issuer: IssuerAcceptance {
                accepted_at,
                signature,
            },
            certificate,
            ancestry,
        })
    }
}
