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
