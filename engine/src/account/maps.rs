//! Original runtime/hashes.mjs sparse/indexed-map semantics in Rust.
//! Depth32 follows the actual current original circuit; no legacy map is restored.
//! No permutation lives here: CZKP supplies maintained Poseidon2.
use super::Field;
use super::hashes;
use crate::Error;
use czkp::poseidon::integer;
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub(super) const DEPTH: usize = 32;
const LIMIT: u64 = 1 << DEPTH;
const ZERO: Field = [0; 32];

/// Hash of two siblings in one of the two sparse trees (account maps or enrollment roster).
pub(super) type NodeHash = fn(Field, Field) -> Result<Field, Error>;

fn map_node(left: Field, right: Field) -> Result<Field, Error> {
    hashes::hash(13, &[left, right])
}

#[derive(Clone)]
pub(super) struct SparseTree {
    node: NodeHash,
    empty: [Field; DEPTH + 1],
    nodes: BTreeMap<(usize, u64), Field>,
}

impl SparseTree {
    pub(super) fn create(node: NodeHash) -> Result<Self, Error> {
        let mut empty = [ZERO; DEPTH + 1];
        for level in 0..DEPTH {
            empty[level + 1] = node(empty[level], empty[level])?;
        }
        Ok(Self {
            node,
            empty,
            nodes: BTreeMap::new(),
        })
    }

    fn at(&self, level: usize, index: u64) -> Field {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.empty[level])
    }

    pub(super) fn root(&self) -> Field {
        self.at(DEPTH, 0)
    }

    pub(super) fn path(&self, mut position: u64) -> Result<[Field; DEPTH], Error> {
        if position >= LIMIT {
            return Err(Error::Map);
        }
        let mut path = [ZERO; DEPTH];
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = self.at(level, position ^ 1);
            position >>= 1;
        }
        Ok(path)
    }

    pub(super) fn set(&mut self, mut position: u64, value: Field) -> Result<(), Error> {
        if position >= LIMIT {
            return Err(Error::Map);
        }
        czkp::field(&value, false).map_err(|_| Error::Map)?;
        self.nodes.insert((0, position), value);
        for level in 0..DEPTH {
            let left = position & !1;
            let parent = (self.node)(self.at(level, left), self.at(level, left + 1))?;
            position >>= 1;
            self.nodes.insert((level + 1, position), parent);
        }
        Ok(())
    }
}

// These are private witnesses. No Debug, public serializer or opening accessor.
#[derive(Clone)]
pub(super) struct Witness {
    pub(super) leaf: [Field; 4],
    pub(super) index: u64,
    pub(super) path: [Field; DEPTH],
    pub(super) append_path: [Field; DEPTH],
}

#[derive(Clone)]
pub(super) struct IndexedMap {
    tree: SparseTree,
    leaves: BTreeMap<u64, [Field; 4]>,
    count: u64,
}

impl IndexedMap {
    pub(super) fn create() -> Result<Self, Error> {
        let mut tree = SparseTree::create(map_node)?;
        let leaf = [ZERO; 4];
        let value = hashes::hash(12, &leaf)?;
        tree.set(0, value)?;
        Ok(Self {
            tree,
            leaves: BTreeMap::from([(0, leaf)]),
            count: 1,
        })
    }

    pub(super) fn root(&self) -> Field {
        self.tree.root()
    }
    pub(super) fn count(&self) -> u64 {
        self.count
    }

    /// Every leaf in position order (the tree is rebuilt from these on restore).
    pub(super) fn leaves(&self) -> impl Iterator<Item = &[Field; 4]> {
        self.leaves.values()
    }

    /// Rebuild a map from its leaves in position order; the positions must be 0..n.
    pub(super) fn from_leaves(leaves: Vec<[Field; 4]>) -> Result<Self, Error> {
        if leaves.is_empty()
            || leaves.len() as u64 > LIMIT
            || leaves[0][0] != ZERO
            || leaves[0][1] != ZERO
        {
            return Err(Error::Map);
        }
        let mut tree = SparseTree::create(map_node)?;
        let mut map = BTreeMap::new();
        for (index, leaf) in leaves.iter().enumerate() {
            tree.set(index as u64, hashes::hash(12, leaf)?)?;
            map.insert(index as u64, *leaf);
        }
        Ok(Self {
            tree,
            count: map.len() as u64,
            leaves: map,
        })
    }

    pub(super) fn find(&self, key: &Field) -> Option<u64> {
        self.leaves
            .iter()
            .find_map(|(index, leaf)| (&leaf[0] == key).then_some(*index))
    }

    pub(super) fn witness(&self, index: u64) -> Result<Witness, Error> {
        Ok(Witness {
            leaf: *self.leaves.get(&index).ok_or(Error::Map)?,
            index,
            path: self.tree.path(index)?,
            append_path: [ZERO; DEPTH],
        })
    }

    pub(super) fn absence(&self, key: &Field) -> Result<Witness, Error> {
        czkp::field(key, true).map_err(|_| Error::Map)?;
        if self.find(key).is_some() {
            return Err(Error::Map);
        }
        let index = self
            .leaves
            .iter()
            .find_map(|(index, leaf)| {
                (leaf[0] < *key && (leaf[3] == ZERO || *key < leaf[3])).then_some(*index)
            })
            .ok_or(Error::Map)?;
        self.witness(index)
    }

    // The accepted map is never mutated, including on a failed hash operation.
    pub(super) fn insert(&self, key: Field, payload: Field) -> Result<(Witness, Self), Error> {
        if self.count >= LIMIT {
            return Err(Error::Map);
        }
        czkp::field(&payload, false).map_err(|_| Error::Map)?;
        let mut witness = self.absence(&key)?;
        let mut next = self.clone();
        let low = witness.leaf;
        let updated = [low[0], low[1], integer(self.count), key];
        next.leaves.insert(witness.index, updated);
        let value = hashes::hash(12, &updated)?;
        next.tree.set(witness.index, value)?;
        // Exactly the original circuit ordering: append path AFTER predecessor.
        witness.append_path = next.tree.path(self.count)?;
        let added = [key, payload, low[2], low[3]];
        next.leaves.insert(self.count, added);
        let value = hashes::hash(12, &added)?;
        next.tree.set(self.count, value)?;
        next.count += 1;
        Ok((witness, next))
    }

    pub(super) fn update(&self, key: Field, payload: Field) -> Result<(Witness, Self), Error> {
        czkp::field(&key, true).map_err(|_| Error::Map)?;
        czkp::field(&payload, false).map_err(|_| Error::Map)?;
        let index = self.find(&key).ok_or(Error::Map)?;
        let witness = self.witness(index)?;
        let mut next = self.clone();
        let updated = [key, payload, witness.leaf[2], witness.leaf[3]];
        next.leaves.insert(index, updated);
        let value = hashes::hash(12, &updated)?;
        next.tree.set(index, value)?;
        Ok((witness, next))
    }
}

impl Drop for SparseTree {
    fn drop(&mut self) {
        self.empty.zeroize();
        for value in self.nodes.values_mut() {
            value.zeroize();
        }
    }
}
impl Drop for IndexedMap {
    fn drop(&mut self) {
        for leaf in self.leaves.values_mut() {
            leaf.zeroize();
        }
    }
}

#[cfg(test)]
#[path = "maps/tests.rs"]
mod tests;
impl Drop for Witness {
    fn drop(&mut self) {
        self.leaf.zeroize();
        self.path.zeroize();
        self.append_path.zeroize();
    }
}
