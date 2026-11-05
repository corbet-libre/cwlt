//! Authenticated engine sealing and restoration scenarios.

use cwlt_engine::{Engine, Sealed};

fn engine(seed: u8, key: u8, context: &[u8]) -> Engine {
    let mut seed = [seed; 32];
    let mut key = [key; 32];
    let holder = Engine::from_seed_and_sealing_key(&mut seed, &mut key, context).unwrap();
    assert_eq!(seed, [0; 32]);
    assert_eq!(key, [0; 32]);
    holder
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn immutable_sealing_authenticates_original_root_and_context() {
    let holder = engine(7, 9, b"community.a/balance");
    let first = holder.seal().unwrap();
    let second = holder.seal().unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert!(
        engine(7, 9, b"community.a/balance")
            .restored(&first)
            .is_ok()
    );
    assert!(
        engine(8, 9, b"community.a/balance")
            .restored(&first)
            .is_err()
    );
    assert!(
        engine(7, 8, b"community.a/balance")
            .restored(&first)
            .is_err()
    );
    assert!(
        engine(7, 9, b"community.b/balance")
            .restored(&first)
            .is_err()
    );
    for offset in 0..first.as_bytes().len() {
        let mut changed = first.as_bytes().to_vec();
        changed[offset] ^= 1;
        if let Ok(changed) = Sealed::from_bytes(&changed) {
            assert!(holder.restored(&changed).is_err());
        }
    }
    for end in 0..first.as_bytes().len() {
        assert!(Sealed::from_bytes(&first.as_bytes()[..end]).is_err());
    }
    let mut appended = first.as_bytes().to_vec();
    appended.push(0);
    assert!(Sealed::from_bytes(&appended).is_err());
    assert!(holder.restored(&first).unwrap().seal().is_ok());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn constructor_wipes_on_refusal() {
    for context in [&[][..], &vec![0; 4097][..]] {
        let mut seed = [7; 32];
        let mut key = [9; 32];
        assert!(Engine::from_seed_and_sealing_key(&mut seed, &mut key, context).is_err());
        assert_eq!(seed, [0; 32]);
        assert_eq!(key, [0; 32]);
    }
}

fn rotated(state: u8, opening: &[u8], account: u8) -> Engine {
    let mut opening: Vec<[u8; 32]> = opening.iter().map(|byte| [*byte; 32]).collect();
    Engine::from_seed_and_sealing_keys(
        &mut [7; 32],
        &mut [state; 32],
        &mut opening,
        &mut [account; 32],
        b"community.a/balance",
    )
    .unwrap()
}

// K1 S4 (X3 H3): Keys derives the state key from the member's epoch root, so it rotates
// with every device removal; the predecessors only open. The account-key capsule guards a
// stable scalar and keeps its own key.
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_predecessor_state_key_only_opens_and_the_reopened_state_reseals_under_the_current_key() {
    let epoch1 = rotated(1, &[], 9);
    let before = epoch1.seal().unwrap();
    let epoch3 = rotated(3, &[2, 1], 9);
    let resealed = epoch3.restored(&before).unwrap().seal().unwrap();
    assert!(rotated(3, &[], 9).restored(&resealed).is_ok());
    for stale in [&epoch1, &rotated(2, &[1], 9)] {
        assert!(stale.restored(&resealed).is_err());
        assert!(stale.restored(&epoch3.seal().unwrap()).is_err());
    }
    assert!(rotated(3, &[], 9).restored(&before).is_err());
    assert!(rotated(3, &[4], 9).restored(&before).is_err());
    let capsule = epoch1
        .prepare_account_key("community.a/balance", [5; 32])
        .unwrap()
        .seal()
        .unwrap();
    let account = epoch3
        .restore_account_key(&capsule, "community.a/balance")
        .unwrap();
    assert_eq!(
        account.projection(&epoch3).unwrap(),
        epoch1
            .restore_account_key(&capsule, "community.a/balance")
            .unwrap()
            .projection(&epoch1)
            .unwrap()
    );
    assert!(
        rotated(9, &[9], 1)
            .restore_account_key(&capsule, "community.a/balance")
            .is_err()
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_rotating_constructor_wipes_every_buffer_on_every_return() {
    for context in [&b"community.a/balance"[..], &[][..], &vec![0; 4097][..]] {
        let (mut seed, mut state, mut account) = ([7; 32], [2; 32], [9; 32]);
        let mut opening = [[1; 32], [3; 32]];
        let built = Engine::from_seed_and_sealing_keys(
            &mut seed,
            &mut state,
            &mut opening,
            &mut account,
            context,
        );
        assert_eq!(built.is_ok(), context == b"community.a/balance");
        assert_eq!(
            (seed, state, account, opening),
            ([0; 32], [0; 32], [0; 32], [[0; 32]; 2])
        );
    }
}
