//! Original indexed-map constraints using maintained Poseidon2, no fake hashes.
use super::*;

fn root(mut leaf: Field, mut index: u64, path: &[Field; DEPTH]) -> Field {
    for sibling in path {
        leaf = if index & 1 == 0 {
            hashes::hash(13, &[leaf, *sibling])
        } else {
            hashes::hash(13, &[*sibling, leaf])
        }
        .unwrap();
        index >>= 1;
    }
    leaf
}

#[test]
fn original_predecessor_then_append_paths_verify_without_mutating_prior_map() {
    let mut map = IndexedMap::create().unwrap();
    for (key, payload) in [(7, 70), (3, 30), (11, 110)] {
        let before = map.root();
        let count = map.count();
        let (witness, next) = map.insert(integer(key), integer(payload)).unwrap();
        assert_eq!(
            root(
                hashes::hash(12, &witness.leaf).unwrap(),
                witness.index,
                &witness.path
            ),
            before
        );
        let low = [
            witness.leaf[0],
            witness.leaf[1],
            integer(count),
            integer(key),
        ];
        let intermediate = root(
            hashes::hash(12, &low).unwrap(),
            witness.index,
            &witness.path,
        );
        assert_eq!(root([0; 32], count, &witness.append_path), intermediate);
        let appended = [
            integer(key),
            integer(payload),
            witness.leaf[2],
            witness.leaf[3],
        ];
        assert_eq!(
            root(
                hashes::hash(12, &appended).unwrap(),
                count,
                &witness.append_path
            ),
            next.root()
        );
        assert_eq!(map.root(), before);
        assert_eq!(next.count(), count + 1);
        map = next;
    }
    let before = map.root();
    let (witness, updated) = map.update(integer(3), integer(33)).unwrap();
    let changed = [
        witness.leaf[0],
        integer(33),
        witness.leaf[2],
        witness.leaf[3],
    ];
    assert_eq!(
        root(
            hashes::hash(12, &changed).unwrap(),
            witness.index,
            &witness.path
        ),
        updated.root()
    );
    assert_eq!(map.root(), before);
    let gap = map.absence(&integer(5)).unwrap();
    assert!(gap.leaf[0] < integer(5));
    assert!(gap.leaf[3] == ZERO || integer(5) < gap.leaf[3]);
    assert!(map.insert(integer(3), integer(1)).is_err());
    assert!(map.update(integer(5), integer(1)).is_err());
    assert!(map.insert([0xff; 32], integer(1)).is_err());
    assert!(map.update(integer(3), [0xff; 32]).is_err());
    assert_eq!(map.root(), before);
}

#[test]
fn full_width_current_circuit_indices_preserve_sparse_root_and_refuse_overflow() {
    let mut tree = SparseTree::create().unwrap();
    tree.set(LIMIT - 1, integer(21)).unwrap();
    assert_eq!(
        root(integer(21), LIMIT - 1, &tree.path(LIMIT - 1).unwrap()),
        tree.root()
    );
    assert_eq!(root([0; 32], 0, &tree.path(0).unwrap()), tree.root());
    assert!(tree.path(LIMIT).is_err());
    assert!(tree.set(LIMIT, integer(1)).is_err());
    let before = tree.root();
    let mut copy = tree.clone();
    copy.set(0, integer(22)).unwrap();
    assert_eq!(tree.root(), before);
    assert_ne!(copy.root(), before);
    // The actual current circuit uses32 siblings. No20-level map is migrated.
    assert_eq!(tree.path(0).unwrap().len(), 32);
}
