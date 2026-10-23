//! A community's accounting activation: the creating device proves one genesis of
//! the extension relation for a throwaway account over a one-entry enrollment, so
//! the hub can verify that its artifacts and policy really run for that community.
//! The account grants no authority: it is not enrolled anywhere and its secrets
//! are discarded with this call.
use super::{AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext, GenesisPublic, hashes};
use crate::{Engine, Error};
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
use crate::native_prover::NativeProver;
use czkp::poseidon::{integer, limbs};

/// What the hub's terms name: the community and the exact policies to prove under.
pub struct ActivationRequest {
    /// The community address, as the hub knows it.
    pub community_id: String,
    /// The ledger's account policy for the day the hub named.
    pub policy: AccountPolicy,
    /// The extension policy, including the published standing digest.
    pub extension: ExtensionPolicy,
    /// The rulebook parameters that digest names; the engine refuses a mismatch.
    pub standing: czkp::standing::Params,
    /// The hub's observation time from its terms; the proof is dated by it.
    pub checked_at: u64,
    /// The one-time owner the proof binds (`czkp::activation_owner` of the address and
    /// this creation's token message), so the proof cannot serve another creation.
    pub owner: [u8; 32],
}

/// The public statement and locally verified proof to upload.
pub struct ActivationProof {
    /// Public projection of the proved genesis statement.
    pub public: GenesisPublic,
    /// The proof bytes.
    pub proof: Vec<u8>,
}

/// Fictional but relation-consistent enrollment of one throwaway owner.
#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    feature = "browser-prover"
))]
fn context(request: ActivationRequest, engine: &Engine) -> Result<GenesisContext, Error> {
    let mut operation = [0u8; 32];
    getrandom::fill(&mut operation).map_err(|_| Error::Crypto)?;
    let member = request.owner;
    let key = engine.prepare_account_key(&request.community_id, operation)?;
    let projection = key.projection(engine)?;
    let community = hashes::digest(request.community_id.as_bytes())?;
    let mut context = GenesisContext {
        community_id: request.community_id,
        owner: member,
        enrollment: Enrollment {
            member,
            key: projection.public_key,
            secret_hash: projection.registered_secret,
            starts_at: request.policy.policy_valid_from,
            expires_at: request.policy.policy_valid_until,
            delegation_digest: [1; 32],
            leaf: [0; 32],
            index: 0,
            path: [[0; 32]; 32],
        },
        policy: request.policy,
        extension: request.extension,
        standing: request.standing,
        bond: None,
        enrollment_root: [0; 32],
        checked_at: request.checked_at,
    };
    let row = &mut context.enrollment;
    let x = row.key[..32].try_into().map_err(|_| Error::Invalid)?;
    let y = row.key[32..].try_into().map_err(|_| Error::Invalid)?;
    let mut fields = [limbs(&community), limbs(&row.member), limbs(&x), limbs(&y)].concat();
    fields.extend([
        row.secret_hash,
        integer(row.starts_at),
        integer(row.expires_at),
    ]);
    fields.extend(limbs(&row.delegation_digest));
    row.leaf = hashes::hash(1, &fields)?;
    let mut root = row.leaf;
    let mut index = row.index;
    for sibling in row.path {
        root = if index & 1 == 0 {
            hashes::enrollment_node(root, sibling)
        } else {
            hashes::enrollment_node(sibling, root)
        }?;
        index >>= 1;
    }
    context.enrollment_root = root;
    Ok(context)
}

/// Prove the activation genesis with the bounded native prover.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub fn prove_activation(
    prover: &NativeProver,
    request: ActivationRequest,
) -> Result<ActivationProof, Error> {
    let mut seed = [0u8; 32];
    let mut sealing = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::Crypto)?;
    getrandom::fill(&mut sealing).map_err(|_| Error::Crypto)?;
    let checked_at = request.checked_at;
    let scope = request.community_id.clone();
    let engine = Engine::from_seed_and_sealing_key(&mut seed, &mut sealing, scope.as_bytes())?;
    let candidate = engine.prepare_genesis(context(request, &engine)?)?;
    let proven = candidate.prove(&engine, prover, || Ok(checked_at))?;
    Ok(ActivationProof {
        public: proven.public_genesis(),
        proof: proven.proof().to_vec(),
    })
}

/// The same activation proof on the browser prover.
#[cfg(feature = "browser-prover")]
pub async fn prove_activation_browser(
    prover: &crate::browser_prover::BrowserProver,
    request: ActivationRequest,
) -> Result<ActivationProof, Error> {
    let mut seed = [0u8; 32];
    let mut sealing = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::Crypto)?;
    getrandom::fill(&mut sealing).map_err(|_| Error::Crypto)?;
    let checked_at = request.checked_at;
    let scope = request.community_id.clone();
    let engine = Engine::from_seed_and_sealing_key(&mut seed, &mut sealing, scope.as_bytes())?;
    let candidate = engine.prepare_genesis(context(request, &engine)?)?;
    let proven = candidate
        .prove_browser(&engine, prover, || Ok(checked_at))
        .await?;
    Ok(ActivationProof {
        public: proven.public_genesis(),
        proof: proven.proof().to_vec(),
    })
}

#[cfg(all(test, feature = "native-prover", not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn request(community: &str) -> ActivationRequest {
        ActivationRequest {
            community_id: community.into(),
            policy: AccountPolicy {
                initial_credit: 20,
                maximum_available: 100,
                outgoing_reservation: 5,
                incoming_reservation: 5,
                policy_revision: 1,
                policy_valid_from: 1,
                policy_valid_until: 10_000,
                newcomer_period: 100,
                rate_window: 100,
                newcomer_admissions: 2,
                maximum_admissions: 10,
                refill_period: 100,
                refill_units: 2,
                abandon_after: 200,
            },
            extension: ExtensionPolicy {
                revision: 1,
                quorum: 2,
                change_cost: 1,
                delay: 100,
                batch: 2,
                standing: ExtensionPolicy::standing_digest(czkp::reference::params()).unwrap(),
            },
            standing: czkp::reference::params(),
            checked_at: 101,
            owner: czkp::activation_owner(community, &[7; 32]),
        }
    }

    #[test]
    fn the_activation_proves_a_throwaway_genesis_for_exactly_the_named_community() {
        let prover = NativeProver::new(crate::native_prover::tests::config()).unwrap();
        let first = prove_activation(&prover, request("firstcommunity")).unwrap();
        let second = prove_activation(&prover, request("secondcommunity")).unwrap();
        assert!(first.public.genesis && second.public.genesis);
        assert!(!first.proof.is_empty() && !second.proof.is_empty());
        assert_eq!(
            first.public.community,
            hashes::digest(b"firstcommunity").unwrap()
        );
        assert_ne!(first.public.community, second.public.community);
        // The proof binds exactly the one-time owner it was asked for.
        assert_eq!(
            first.public.owner,
            czkp::activation_owner("firstcommunity", &[7; 32])
        );
        assert_ne!(first.public.owner, second.public.owner);
        assert_ne!(first.public.next_state, second.public.next_state);
    }

    #[test]
    fn a_standing_digest_that_the_parameters_do_not_name_is_refused() {
        let prover = NativeProver::new(crate::native_prover::tests::config()).unwrap();
        let mut wrong = request("firstcommunity");
        wrong.extension.standing = [9; 32];
        assert!(prove_activation(&prover, wrong).is_err());
    }
}
