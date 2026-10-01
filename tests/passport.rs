#![cfg(feature = "passport")]
//! Real nonexporting holder issuance, restoration and authenticated presentation.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;
use cwlt::PassportHolder as Holder;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_identity_has_no_dependency_on_issuance_randomness() {
    let community = CommunityId::new(b"community-a").unwrap();
    let other = CommunityId::new(b"community-b").unwrap();
    let mut seed = [7; 32];
    let mut first = Holder::from_seed(&mut seed);
    assert_eq!(seed, [0; 32]);
    let mut restored = Holder::from_seed(&mut [7; 32]);
    let mut different = Holder::from_seed(&mut [8; 32]);
    let (pseudonym, tag) = first.with_session(|session| {
        assert_ne!(session.pseudonym(&community), session.pseudonym(&other));
        assert!(session.attributes().is_none());
        (session.pseudonym(&community), session.issuer_tag())
    });
    restored.with_session(|session| {
        assert_eq!(pseudonym, session.pseudonym(&community));
        assert_eq!(tag, session.issuer_tag());
    });
    different.with_session(|session| {
        assert_ne!(pseudonym, session.pseudonym(&community));
    });
    assert_eq!(
        pseudonym.to_hex(),
        "97322b8893bb653c820feb6b9915315da5e5f7716e15ad1ac521b18643b695dcb3a24b42ae422847f63d03efb782af60"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn opaque_issuance_and_refused_renewal_preserve_the_verified_identity() {
    let mut rng = StdRng::seed_from_u64(91);
    let gate = GateId::new("phone").unwrap();
    let issuer =
        IssuerKey::generate(&mut rng, KeyId::new("issuer").unwrap(), vec![gate.clone()]).unwrap();
    let other =
        IssuerKey::generate(&mut rng, KeyId::new("other").unwrap(), vec![gate.clone()]).unwrap();
    let mut holder = Holder::from_seed(&mut [7; 32]);
    let community = CommunityId::new(b"community-a").unwrap();
    let nym = holder.with_session(|session| session.pseudonym(&community));
    holder.with_session(|mut holder| {
        let attributes = PassportAttributes::new(2000, 7).with_gate(gate.clone(), 2000);
        let request =
            PresentationRequest::for_epoch(&mut rng, community.clone(), 7, [gate], 1000, 2000)
                .unwrap();
        let mut signer = csgn::Signer::new(
            "cmty:test",
            csgn::SecretKey::from_seed(&mut [4; 32]),
            0,
            TIME_LIMIT,
        )
        .unwrap();
        let signed = signer
            .sign(
                csgn::Kind::Credential,
                &request.to_bytes(),
                0,
                request.now() + 1,
            )
            .unwrap();
        let expected = AuthenticatedCommunity::from_authenticated_origin(
            community.clone(),
            signer.key_ring().clone(),
        );
        assert!(matches!(
            holder.present(&mut rng, &expected, &signed, 1000),
            Err(Error::PassportUnavailable)
        ));

        let challenge = IssuanceChallenge::generate(&mut rng);
        let issuance = holder
            .begin_issuance(&mut rng, issuer.public_key(), &challenge)
            .unwrap();
        assert!(matches!(
            holder.begin_issuance(&mut rng, issuer.public_key(), &challenge),
            Err(Error::IssuancePending)
        ));
        let issuance = IssuanceRequest::from_bytes(&issuance.to_bytes()).unwrap();
        let blind = issuer
            .issue_blind(&mut rng, &issuance, &challenge, &attributes)
            .unwrap();
        holder.finish_issuance(&blind).unwrap();
        assert_eq!(holder.attributes(), Some(&attributes));
        assert_eq!(
            holder.finish_issuance(&blind),
            Err(Error::NoPendingIssuance)
        );
        let proof = holder.present(&mut rng, &expected, &signed, 1000).unwrap();
        assert_eq!(
            verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
            nym
        );
        assert!(holder.present(&mut rng, &expected, &signed, 1200).is_err());
        let wrong_scope = AuthenticatedCommunity::from_authenticated_origin(
            CommunityId::new(b"other-community").unwrap(),
            signer.key_ring().clone(),
        );
        assert!(
            holder
                .present(&mut rng, &wrong_scope, &signed, 1000)
                .is_err()
        );

        // A response signed for another issuer cannot replace a verified passport.
        let other_request = holder
            .begin_issuance(&mut rng, other.public_key(), &challenge)
            .unwrap();
        let wrong_blind = other
            .issue_blind(&mut rng, &other_request, &challenge, &attributes)
            .unwrap();
        holder.cancel_issuance();
        holder.cancel_issuance();
        holder
            .begin_issuance(&mut rng, issuer.public_key(), &challenge)
            .unwrap();
        assert_eq!(
            holder.finish_issuance(&wrong_blind),
            Err(Error::KeyMismatch)
        );
        assert_eq!(holder.attributes(), Some(&attributes));
        assert_eq!(holder.pseudonym(&community), nym);
        let proof = holder.present(&mut rng, &expected, &signed, 1000).unwrap();
        assert_eq!(
            verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
            nym
        );
        for error in [
            Error::IssuancePending,
            Error::NoPendingIssuance,
            Error::PassportUnavailable,
        ] {
            assert!(!error.to_string().is_empty());
        }
    });
}
