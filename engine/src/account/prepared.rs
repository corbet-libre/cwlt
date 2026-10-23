//! Opaque private genesis preparation; current admission remains an upper owner.
use super::{
    Field, hashes,
    maps::IndexedMap,
    opening::{Opening, Standing, Voucher},
    policy::{AccountPolicy, ExtensionPolicy},
};
use crate::{Engine, Error, sealing};
use std::{cell::Cell, sync::Arc};
use zeroize::Zeroizing;

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod native;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use native::{
    AcceptanceBinding, AcceptedAccount, AcceptedGenesisProof, AcceptedResponse, AncestryResponse,
    Frontier, GENESIS_DISCARD_COMMIT_MARGIN_SECONDS, GenesisPublic, IssuerAcceptance,
    MAX_ACCEPTED_SEALED, MAX_PENDING_SEALED, OwnerAbsence, PendingGenesisBinding,
    PreparedGenesisProof, ResponseTrust, SealedAcceptedAccount, SealedPendingGenesis,
};

/// Original published enrollment data; validation alone does not authenticate it.
#[derive(Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// Original community-scoped owner, derived by the admitted account owner.
    pub member: [u8; 32],
    /// Original public account P-256 key, in fixed uncompressed x/y encoding.
    pub key: [u8; 64],
    /// Published commitment to the holder's private registered secret.
    pub secret_hash: [u8; 32],
    /// Inclusive original enrollment start.
    pub starts_at: u64,
    /// Exclusive original enrollment deadline.
    pub expires_at: u64,
    /// Original immutable delegation digest.
    pub delegation_digest: [u8; 32],
    /// Original canonical blinded enrollment leaf.
    pub leaf: [u8; 32],
    /// Original full-width published enrollment index.
    pub index: u32,
    /// Exact32 siblings required by the current original circuit.
    pub path: [[u8; 32]; 32],
}

/// The bond a vouchee holds with its sponsor, derived on both devices from the voucher
/// exchange and kept in vault custody. It never leaves the device.
#[derive(Clone, PartialEq, Eq)]
pub struct VoucherBond {
    /// The sponsor's community-scoped member id.
    pub sponsor: [u8; 32],
    /// The shared bond secret.
    pub secret: [u8; 32],
}

/// Explicit public context data for private computation, never an accepted grant.
/// The caller must separately authenticate current grant, policy and enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct GenesisContext {
    /// Exact originating Keys Binding community ID, never a new caller realm.
    pub community_id: String,
    /// Original admitted account owner to compare with the published enrollment.
    pub owner: [u8; 32],
    /// Current published economic policy data.
    pub policy: AccountPolicy,
    /// Current published extension policy data.
    pub extension: ExtensionPolicy,
    /// The rulebook-signed standing parameters; their digest must equal
    /// `extension.standing`. The tables are derived here by czkp's single owner function.
    pub standing: czkp::standing::Params,
    /// The bond with the sponsor when the account was admitted by a voucher; a founder has none.
    pub bond: Option<VoucherBond>,
    /// Original published enrollment row for this owner.
    pub enrollment: Enrollment,
    /// Independently authenticated common enrollment root.
    pub enrollment_root: [u8; 32],
    /// Trusted actual observation; constructor input alone proves no freshness.
    pub checked_at: u64,
}

/// Private candidate kept in RAM; no field getter, Clone, serialization or proof
/// verdict exists. Preparing it leaves the Engine uninitialized. Installation
/// requires a future actual proof, original issuer acceptance and Store receipt.
pub struct PreparedGenesis {
    context: GenesisContext,
    binding: Arc<sealing::Binding>,
    secret: Zeroizing<Field>,
    community: Field,
    policy_digest: Field,
    state_policy: Field,
    opening: Opening,
    outgoing: IndexedMap,
    incoming: IndexedMap,
    pairs: IndexedMap,
    commitment: Field,
    checked_at: Cell<u64>,
    failed: Cell<bool>,
}

impl Engine {
    /// Compute an opaque original genesis candidate from explicitly public data.
    /// This checks context, registered-secret binding and32-level inclusion;
    /// it does not verify a grant or install accepted state, even on success.
    pub fn prepare_genesis(&self, context: GenesisContext) -> Result<PreparedGenesis, Error> {
        let mut blind = [0; 32];
        getrandom::fill(&mut blind).map_err(|_| Error::Crypto)?;
        let result = self.genesis_with_blind(context, blind);
        zeroize::Zeroize::zeroize(&mut blind);
        result
    }

    /// Deterministic construction from one explicit original blind. Fresh blinds
    /// come only from `prepare_genesis`; pending reopen supplies its stored blind.
    pub(super) fn genesis_with_blind(
        &self,
        context: GenesisContext,
        mut blind: Field,
    ) -> Result<PreparedGenesis, Error> {
        if !self
            .sealing
            .matches_context(context.community_id.as_bytes())
        {
            return Err(Error::Invalid);
        }
        let community = validate_context(&context, &self.seed)?;
        let (policy_digest, state_policy) = context.policy.digests(&community)?;
        let outgoing = IndexedMap::create()?;
        let incoming = IndexedMap::create()?;
        let pairs = IndexedMap::create()?;
        let bonds = IndexedMap::create()?;
        let domain = hashes::domain(b"cfrm.account-state.v2");
        let (sponsor, bond) = match &context.bond {
            Some(b) if b.secret != [0; 32] && b.sponsor != [0; 32] => (
                czkp::voucher::member_tag(&domain, &community, &b.sponsor)
                    .map_err(|_| Error::Crypto)?,
                czkp::voucher::bond_commit(&domain, &b.secret).map_err(|_| Error::Crypto)?,
            ),
            Some(_) => return Err(Error::Invalid),
            None => ([0; 32], [0; 32]),
        };
        let horizon = context.policy.horizon(context.checked_at)?;
        let opening = Opening {
            reserved: 0,
            accepted: 0,
            declined: 0,
            punished: 0,
            inbox: [0; 32],
            authorization: [0; 32],
            outgoing_root: outgoing.root(),
            outgoing_count: outgoing.count(),
            incoming_root: incoming.root(),
            incoming_count: incoming.count(),
            pair_root: pairs.root(),
            pair_count: pairs.count(),
            created_at: horizon,
            standing: Standing {
                g: 0,
                // Starter loan: the newcomer cap above the first slot, in Q16.
                a: (context.standing.c0 - 1) << 16,
                c: 0,
                pr: 0,
                pg: 0,
                lc: 0,
                day: horizon / 86_400,
            },
            voucher: Voucher {
                proven: 0,
                away: 0,
                reserved: 0,
                lost: 0,
                bonus: 0,
                returned: 0,
                answers: 0,
                sponsor,
                bond,
                bond_root: bonds.root(),
                bond_count: bonds.count(),
            },
            blind,
        };
        use zeroize::Zeroize;
        blind.zeroize();
        let commitment = opening.commitment(
            &community,
            &context.owner,
            &state_policy,
            context.enrollment.secret_hash,
            0,
            &context.extension,
        )?;
        let checked_at = Cell::new(context.checked_at);
        Ok(PreparedGenesis {
            context,
            binding: Arc::clone(&self.sealing),
            secret: self.seed.clone(),
            community,
            policy_digest,
            state_policy,
            opening,
            outgoing,
            incoming,
            pairs,
            commitment,
            checked_at,
            failed: Cell::new(false),
        })
    }
}

impl PreparedGenesis {
    /// Recheck this exact candidate against the same engine and public context.
    /// This is a private-data consistency check, never proof/admission authority.
    /// Clock rollback or expiry terminally fences this RAM candidate.
    pub fn check_context(
        &self,
        engine: &Engine,
        context: &GenesisContext,
        now: u64,
    ) -> Result<(), Error> {
        if self.failed.get() {
            return Err(Error::Invalid);
        }
        if now < self.checked_at.get() {
            self.failed.set(true);
            return Err(Error::Invalid);
        }
        self.checked_at.set(now);
        if now >= self.context.policy.horizon(self.context.checked_at)?
            || now >= self.context.enrollment.expires_at
        {
            self.failed.set(true);
            return Err(Error::Invalid);
        }
        if context != &self.context
            || !Arc::ptr_eq(&self.binding, &engine.sealing)
            || self.secret.as_ref() != engine.seed.as_ref()
            || validate_context(context, &self.secret)? != self.community
            || context.policy.digests(&self.community)? != (self.policy_digest, self.state_policy)
            || self.opening.outgoing_root != self.outgoing.root()
            || self.opening.outgoing_count != self.outgoing.count()
            || self.opening.incoming_root != self.incoming.root()
            || self.opening.incoming_count != self.incoming.count()
            || self.opening.pair_root != self.pairs.root()
            || self.opening.pair_count != self.pairs.count()
            || self.opening.commitment(
                &self.community,
                &context.owner,
                &self.state_policy,
                context.enrollment.secret_hash,
                0,
                &context.extension,
            )? != self.commitment
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

fn validate_context(context: &GenesisContext, seed: &Field) -> Result<Field, Error> {
    if context.community_id.is_empty()
        || context.community_id.len() > 256
        || context.community_id.chars().any(char::is_control)
        || context.owner == [0; 32]
        || context.enrollment.member != context.owner
        || context.checked_at > czkp::MAX_INTEGER
    {
        return Err(Error::Invalid);
    }
    let community = hashes::digest(context.community_id.as_bytes())?;
    context.policy.bytes(&community)?;
    context.policy.horizon(context.checked_at)?;
    context.extension.hash()?;
    if ExtensionPolicy::standing_digest(context.standing)? != context.extension.standing {
        return Err(Error::Invalid);
    }
    let row = &context.enrollment;
    if row.starts_at == 0
        || row.starts_at >= row.expires_at
        || row.expires_at > czkp::MAX_INTEGER
        || context.checked_at < row.starts_at
        || context.checked_at >= row.expires_at
        || row.delegation_digest == [0; 32]
        || row.secret_hash != hashes::secret(&community, seed)?
    {
        return Err(Error::Invalid);
    }
    use czkp::poseidon::{integer, limbs};
    let mut fields = Vec::new();
    fields.extend(limbs(&community));
    fields.extend(limbs(&row.member));
    let x: Field = row.key[..32].try_into().map_err(|_| Error::Invalid)?;
    let y: Field = row.key[32..].try_into().map_err(|_| Error::Invalid)?;
    fields.extend(limbs(&x));
    fields.extend(limbs(&y));
    fields.extend([
        row.secret_hash,
        integer(row.starts_at),
        integer(row.expires_at),
    ]);
    fields.extend(limbs(&row.delegation_digest));
    let mut node = hashes::hash(1, &fields)?;
    if node != row.leaf {
        return Err(Error::Invalid);
    }
    let mut index = row.index;
    for sibling in row.path {
        node = if index & 1 == 0 {
            hashes::enrollment_node(node, sibling)?
        } else {
            hashes::enrollment_node(sibling, node)?
        };
        index >>= 1;
    }
    czkp::field(&context.enrollment_root, true).map_err(|_| Error::Invalid)?;
    if node != context.enrollment_root {
        return Err(Error::Invalid);
    }
    Ok(community)
}

#[cfg(test)]
#[path = "prepared/tests.rs"]
mod tests;
