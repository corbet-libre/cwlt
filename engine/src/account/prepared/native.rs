//! Original typed genesis witness; private serialization stays inside this owner.
use super::*;
#[cfg(feature = "prover-core")]
use crate::account::witness::{Account, Checkpoint, Genesis};
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
use crate::native_prover::NativeProver;
use crate::proof::Proof;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
use std::time::Instant;
mod acceptance;
mod accepted;
mod pending;
mod response;
pub use acceptance::{AcceptanceBinding, AcceptedGenesisProof, IssuerAcceptance};
pub use accepted::{AcceptedAccount, MAX_ACCEPTED_SEALED, SealedAcceptedAccount};
pub use pending::{
    GENESIS_DISCARD_COMMIT_MARGIN_SECONDS, MAX_PENDING_SEALED, OwnerAbsence, PendingGenesisBinding,
    SealedPendingGenesis,
};
pub use response::{AcceptedResponse, AncestryResponse, Frontier, ResponseTrust};
#[cfg(all(test, feature = "native-prover", not(target_arch = "wasm32")))]
mod tests;

/// Locally verified proof data. It grants no enrollment, accepted Frontier, Keys
/// authority, Store receipt or operator acceptance; those joins remain separate.
pub struct PreparedGenesisProof {
    candidate: PreparedGenesis,
    proof: Proof,
}

/// Original public genesis statement data, never a grant or accepted account.
/// All values come directly from the candidate used by the native serializer.
pub struct GenesisPublic {
    /// Original protocol for the upper owner's typed statement conversion.
    pub protocol_version: u32,
    /// Original community digest included in the proved public inputs.
    pub community: [u8; 32],
    /// Original community-scoped enrolled account owner.
    pub owner: [u8; 32],
    /// Original economic policy digest.
    pub policy_digest: [u8; 32],
    /// Original authenticated common enrollment root.
    pub enrollment_root: [u8; 32],
    /// Frozen original statement observation, never a renewed proof time.
    pub now: u64,
    /// Original exclusive proof horizon.
    pub valid_until: u64,
    /// True only for this original genesis computation.
    pub genesis: bool,
    /// Original fixed previous account version zero.
    pub previous_version: u64,
    /// Original fixed next genesis version zero.
    pub next_version: u64,
    /// Original fixed empty previous state.
    pub previous_state: [u8; 32],
    /// Commitment to the retained exact private opening.
    pub next_state: [u8; 32],
    /// Original fixed empty settlement marker.
    pub settlement_marker: [u8; 32],
}
impl PreparedGenesisProof {
    /// The explicit public context this candidate was prepared and proven under.
    pub fn context(&self) -> &GenesisContext {
        &self.candidate.context
    }
    /// Project only the original public statement that this candidate proved.
    /// No witness, opening, fresh authority or sending privilege is returned.
    pub fn public_genesis(&self) -> GenesisPublic {
        self.candidate.genesis_public()
    }
}
impl PreparedGenesis {
    fn genesis_public(&self) -> GenesisPublic {
        GenesisPublic {
            protocol_version: 2,
            community: self.community,
            owner: self.context.owner,
            policy_digest: self.policy_digest,
            enrollment_root: self.context.enrollment_root,
            now: self.context.checked_at,
            valid_until: self.opening.created_at,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: self.commitment,
            settlement_marker: [0; 32],
        }
    }
}
impl PreparedGenesisProof {
    /// Recheck the retained exact private candidate without exposing its opening.
    /// This grants no adoption or accepted account; the original candidate remains
    /// owned until a future genuine issuer-acceptance and Store-receipt join.
    pub fn check_context(
        &self,
        engine: &Engine,
        context: &GenesisContext,
        now: u64,
    ) -> Result<(), Error> {
        self.candidate.check_context(engine, context, now)
    }

    /// Exact original configured circuit and verification-key identity.
    pub fn scope(&self) -> &czkp::ProofScope {
        &self.proof.scope
    }
    /// Original ordered public field elements, with no private opening included.
    pub fn public_inputs(&self) -> &[[u8; 32]] {
        &self.proof.public_inputs
    }
    /// Locally verified proof bytes for the original operator's own verification.
    pub fn proof(&self) -> &[u8] {
        &self.proof.proof
    }
}
impl PreparedGenesis {
    /// The one builder of the update input for any prover: genesis is its first transition.
    /// Returns the public part (what the expected public inputs derive from) and the private
    /// input. Runtime has already checked the context; the opening never leaves this owner
    /// except inside the returned input, which the caller hands to exactly one prover.
    #[cfg(feature = "prover-core")]
    pub(crate) fn proof_input(&self) -> Result<(String, zeroize::Zeroizing<String>), Error> {
        let context = &self.context;
        let checkpoint = std::sync::Arc::new(Checkpoint::from_rows(
            context.enrollment_root,
            vec![context.enrollment.clone()],
        )?);
        let blind = self.opening.blind;
        let built = Account::genesis(
            Genesis {
                community: self.community,
                policy: context.policy,
                extension: context.extension,
                standing: context.standing,
                checkpoint,
                owner_index: 0,
                owner_secret: &self.secret,
                now: context.checked_at,
                bond: context.bond.clone(),
            },
            &mut || blind,
        )?;
        if built.next.state() != self.commitment {
            return Err(Error::Invalid);
        }
        Ok((built.input.public_json()?, built.input.to_json()?))
    }

    /// Consume this private candidate into the owned original native prover.
    /// Runtime supplies a real clock and freshly authorized Engine; no client
    /// JSON can select a prover path, policy, witness or timestamp. This still
    /// produces no accepted account or durable owner adoption.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub fn prove(
        self,
        engine: &Engine,
        prover: &NativeProver,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<PreparedGenesisProof, Error> {
        let deadline = Instant::now() + prover.timeout();
        let now = clock()?;
        self.check_context(engine, &self.context, now)?;
        let (public_json, input) = self.proof_input()?;
        let expected = prover.public_inputs(&public_json)?;
        let proof = prover.prove(input, expected, deadline)?;
        self.check_context(engine, &self.context, clock()?)?;
        Ok(PreparedGenesisProof {
            candidate: self,
            proof,
        })
    }

    /// The same proof on the browser prover: the private input goes to the Web Worker behind
    /// the port and only the proof comes back, checked against the public inputs this engine
    /// derived itself. The context is checked before the input is built and again after.
    #[cfg(feature = "browser-prover")]
    pub async fn prove_browser(
        self,
        engine: &Engine,
        prover: &crate::browser_prover::BrowserProver,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<PreparedGenesisProof, Error> {
        let now = clock()?;
        self.check_context(engine, &self.context, now)?;
        let (public_json, input) = self.proof_input()?;
        let expected = prover.public_inputs(&public_json)?;
        let proof = prover.prove(input, expected).await?;
        self.check_context(engine, &self.context, clock()?)?;
        Ok(PreparedGenesisProof {
            candidate: self,
            proof,
        })
    }
}
