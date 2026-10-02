//! Compare the private Rust map port with actual original Wallet/BB vectors.
//! CI generates the external file with engine/tests/maps.mjs before compilation.
#![forbid(unsafe_code)]

use cwlt_engine::Error;
use serde::Deserialize;
type Field = [u8; 32];
#[path = "../src/hash.rs"]
mod hash;
#[path = "../src/maps.rs"]
mod maps;
#[path = "../src/poseidon.rs"]
mod poseidon;
use hash::{Hash, integer};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    inputs: Vec<String>,
    output: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    root: String,
    count: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Witness {
    leaf: [String; 4],
    index: u64,
    path: [String; 32],
    append_path: [String; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    operation: String,
    key: String,
    payload: String,
    witness: Witness,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema: u32,
    source: String,
    calls: Vec<Call>,
    states: Vec<State>,
    steps: Vec<Step>,
    gap: Witness,
}

fn field(text: &str) -> Field {
    assert_eq!(text.len(), 64);
    assert_eq!(text, text.to_ascii_lowercase());
    hex::decode(text).unwrap().try_into().unwrap()
}
fn witness(actual: maps::Witness, expected: &Witness) {
    assert_eq!(actual.leaf, expected.leaf.each_ref().map(|s| field(s)));
    assert_eq!(actual.index, expected.index);
    assert_eq!(actual.path, expected.path.each_ref().map(|s| field(s)));
    assert_eq!(
        actual.append_path,
        expected.append_path.each_ref().map(|s| field(s))
    );
}

// This executes the maintained Rust primitive on EVERY call, independently of
// the BB-generated expected output. It is not a canned hash implementation.
struct CheckedHash<'a> {
    actual: poseidon::Poseidon,
    expected: std::slice::Iter<'a, Call>,
}
impl Hash for CheckedHash<'_> {
    async fn poseidon2(&mut self, fields: &[Field]) -> Result<Field, Error> {
        let expected = self.expected.next().expect("unexpected hash call");
        assert_eq!(
            fields,
            expected.inputs.iter().map(|s| field(s)).collect::<Vec<_>>()
        );
        let result = self.actual.poseidon2(fields).await?;
        assert_eq!(result, field(&expected.output));
        Ok(result)
    }
}

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_maps_and_hashes() {
    let vectors: Vectors = serde_json::from_str(include_str!(env!("CWLT_MAP_VECTORS"))).unwrap();
    assert_eq!(vectors.schema, 1);
    assert_eq!(vectors.source, "original-runtime/hashes.mjs");
    assert_eq!(vectors.states.len(), vectors.steps.len() + 1);
    futures::executor::block_on(async {
        let mut hash = CheckedHash {
            actual: poseidon::Poseidon::new(),
            expected: vectors.calls.iter(),
        };
        let mut map = maps::IndexedMap::create(&mut hash).await.unwrap();
        assert_eq!(map.root(), field(&vectors.states[0].root));
        assert_eq!(map.count(), vectors.states[0].count);
        for (step, expected) in vectors.steps.iter().zip(vectors.states.iter().skip(1)) {
            let before = (map.root(), map.count());
            let (actual, next) = match step.operation.as_str() {
                "insert" => {
                    map.insert(&mut hash, field(&step.key), field(&step.payload))
                        .await
                }
                "update" => {
                    map.update(&mut hash, field(&step.key), field(&step.payload))
                        .await
                }
                _ => panic!("unknown original operation"),
            }
            .unwrap();
            witness(actual, &step.witness);
            assert_eq!((map.root(), map.count()), before, "accepted map changed");
            assert_eq!(next.root(), field(&expected.root));
            assert_eq!(next.count(), expected.count);
            map = next;
        }
        witness(map.absence(&integer(5)).unwrap(), &vectors.gap);
        assert!(
            hash.expected.next().is_none(),
            "unconsumed original hash calls"
        );
        // These invalid transitions must stop before the exhausted hash transcript.
        let before = (map.root(), map.count());
        assert!(matches!(
            map.insert(&mut hash, integer(3), integer(1)).await,
            Err(Error::Map)
        ));
        assert!(matches!(
            map.update(&mut hash, integer(5), integer(1)).await,
            Err(Error::Map)
        ));
        assert!(matches!(
            map.insert(&mut hash, [0xff; 32], integer(1)).await,
            Err(Error::Map)
        ));
        assert!(matches!(
            map.update(&mut hash, integer(3), [0xff; 32]).await,
            Err(Error::Map)
        ));
        assert!(matches!(map.witness(1 << 32), Err(Error::Map)));
        assert_eq!((map.root(), map.count()), before);
        assert!(matches!(
            poseidon::Poseidon::new().poseidon2(&[[0xff; 32]]).await,
            Err(Error::Crypto)
        ));
    });
}
