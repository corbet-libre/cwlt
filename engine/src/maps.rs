//! Original runtime/hashes.mjs sparse/indexed-map semantics in Rust.
//! No permutation lives here: the private engine supplies maintained BB Poseidon2.
use super::hash::{Hash, integer};
use super::{Error, Field};
use std::collections::BTreeMap;

pub(super) const DEPTH: usize = 20;
const LIMIT: u64 = 1 << DEPTH;
const ZERO: Field = [0; 32];

#[derive(Clone)]
struct SparseTree {
    empty: [Field; DEPTH + 1],
    nodes: BTreeMap<(usize, u64), Field>,
}

impl SparseTree {
    async fn create(hash: &mut impl Hash) -> Result<Self, Error> {
        let mut empty = [ZERO; DEPTH + 1];
        for level in 0..DEPTH {
            empty[level + 1] = hash.tagged(13, &[empty[level], empty[level]]).await?;
        }
        Ok(Self {
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

    fn root(&self) -> Field {
        self.at(DEPTH, 0)
    }

    fn path(&self, mut position: u64) -> Result<[Field; DEPTH], Error> {
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

    async fn set(
        &mut self,
        hash: &mut impl Hash,
        mut position: u64,
        value: Field,
    ) -> Result<(), Error> {
        if position >= LIMIT {
            return Err(Error::Map);
        }
        czkp::field(&value, false).map_err(|_| Error::Map)?;
        self.nodes.insert((0, position), value);
        for level in 0..DEPTH {
            let left = position & !1;
            let parent = hash
                .tagged(13, &[self.at(level, left), self.at(level, left + 1)])
                .await?;
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
    pub(super) async fn create(hash: &mut impl Hash) -> Result<Self, Error> {
        let mut tree = SparseTree::create(hash).await?;
        let leaf = [ZERO; 4];
        let value = hash.tagged(12, &leaf).await?;
        tree.set(hash, 0, value).await?;
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
    pub(super) async fn insert(
        &self,
        hash: &mut impl Hash,
        key: Field,
        payload: Field,
    ) -> Result<(Witness, Self), Error> {
        if self.count >= LIMIT {
            return Err(Error::Map);
        }
        czkp::field(&payload, false).map_err(|_| Error::Map)?;
        let mut witness = self.absence(&key)?;
        let mut next = self.clone();
        let low = witness.leaf;
        let updated = [low[0], low[1], integer(self.count), key];
        next.leaves.insert(witness.index, updated);
        let value = hash.tagged(12, &updated).await?;
        next.tree.set(hash, witness.index, value).await?;
        // Exactly the original circuit ordering: append path AFTER predecessor.
        witness.append_path = next.tree.path(self.count)?;
        let added = [key, payload, low[2], low[3]];
        next.leaves.insert(self.count, added);
        let value = hash.tagged(12, &added).await?;
        next.tree.set(hash, self.count, value).await?;
        next.count += 1;
        Ok((witness, next))
    }

    pub(super) async fn update(
        &self,
        hash: &mut impl Hash,
        key: Field,
        payload: Field,
    ) -> Result<(Witness, Self), Error> {
        czkp::field(&key, true).map_err(|_| Error::Map)?;
        czkp::field(&payload, false).map_err(|_| Error::Map)?;
        let index = self.find(&key).ok_or(Error::Map)?;
        let witness = self.witness(index)?;
        let mut next = self.clone();
        let updated = [key, payload, witness.leaf[2], witness.leaf[3]];
        next.leaves.insert(index, updated);
        let value = hash.tagged(12, &updated).await?;
        next.tree.set(hash, index, value).await?;
        Ok((witness, next))
    }
}
