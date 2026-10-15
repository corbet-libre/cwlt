//! The independently verified enrollment roster and its membership checks. The roster is
//! data the caller authenticated elsewhere; this module only rebuilds its tree and paths.
use super::{Enrollment, Field, hashes};
use crate::{Error, account::maps::SparseTree};
use czkp::poseidon::{integer, limbs};
use std::collections::BTreeSet;

/// One verified roster row, in published order.
#[derive(Clone, PartialEq, Eq)]
pub struct RosterRow {
    /// Community-scoped member identifier.
    pub member: [u8; 32],
    /// Public account P-256 key (x then y).
    pub key: [u8; 64],
    /// Published commitment to the member's registered secret.
    pub secret_hash: Field,
    /// Inclusive enrollment start.
    pub issued_at: u64,
    /// Exclusive enrollment deadline.
    pub expires_at: u64,
    /// Immutable delegation digest.
    pub delegation_digest: Field,
}

/// The roster with every member's leaf and Merkle path under one root.
#[derive(Clone, PartialEq, Eq)]
pub struct Checkpoint {
    root: Field,
    entries: Vec<Enrollment>,
}

pub(super) const MAX_ROSTER: usize = 65_536;
const SAFE: u64 = czkp::MAX_INTEGER;

/// Leaf of one enrollment: the community, member, key, secret hash, window and delegation.
pub(super) fn leaf(community: &Field, e: &Enrollment) -> Result<Field, Error> {
    let x: Field = e.key[..32].try_into().map_err(|_| Error::Invalid)?;
    let y: Field = e.key[32..].try_into().map_err(|_| Error::Invalid)?;
    let mut fields = Vec::new();
    fields.extend(limbs(community));
    fields.extend(limbs(&e.member));
    fields.extend(limbs(&x));
    fields.extend(limbs(&y));
    fields.extend([e.secret_hash, integer(e.starts_at), integer(e.expires_at)]);
    fields.extend(limbs(&e.delegation_digest));
    hashes::hash(1, &fields)
}

impl Checkpoint {
    /// Build the roster tree. Rows must be unique, well-formed and at most 65,536.
    pub fn from_verified(community: &Field, rows: &[RosterRow]) -> Result<Self, Error> {
        if rows.is_empty() || rows.len() > MAX_ROSTER {
            return Err(Error::Invalid);
        }
        let mut seen = BTreeSet::new();
        let mut tree = SparseTree::create(hashes::enrollment_node)?;
        let mut entries = Vec::with_capacity(rows.len());
        for (index, row) in rows.iter().enumerate() {
            if !seen.insert(row.member)
                || row.issued_at == 0
                || row.expires_at <= row.issued_at
                || row.issued_at > SAFE
                || row.expires_at > SAFE
                || row.delegation_digest == [0; 32]
                || czkp::field(&row.secret_hash, false).is_err()
            {
                return Err(Error::Invalid);
            }
            let mut entry = Enrollment {
                member: row.member,
                key: row.key,
                secret_hash: row.secret_hash,
                starts_at: row.issued_at,
                expires_at: row.expires_at,
                delegation_digest: row.delegation_digest,
                leaf: [0; 32],
                index: u32::try_from(index).map_err(|_| Error::Invalid)?,
                path: [[0; 32]; 32],
            };
            entry.leaf = leaf(community, &entry)?;
            tree.set(index as u64, entry.leaf)?;
            entries.push(entry);
        }
        for entry in &mut entries {
            entry.path = tree.path(u64::from(entry.index))?;
        }
        Ok(Self {
            root: tree.root(),
            entries,
        })
    }
    /// A roster known only by some of its rows (each with its own path), all under `root`.
    /// Every row is checked against the root; the row's `index` is its roster position.
    pub fn from_rows(root: Field, rows: Vec<Enrollment>) -> Result<Self, Error> {
        czkp::field(&root, true).map_err(|_| Error::Invalid)?;
        if rows.is_empty() || rows.len() > MAX_ROSTER {
            return Err(Error::Invalid);
        }
        let mut seen = BTreeSet::new();
        for row in &rows {
            if !seen.insert(row.member) {
                return Err(Error::Invalid);
            }
        }
        Ok(Self {
            root,
            entries: rows,
        })
    }
    /// The authenticated common enrollment root.
    pub fn root(&self) -> Field {
        self.root
    }
    /// Every row with its leaf and path, in published order.
    pub fn entries(&self) -> &[Enrollment] {
        &self.entries
    }
}

fn shape(e: &Enrollment) -> Result<(), Error> {
    if e.member == [0; 32]
        || e.delegation_digest == [0; 32]
        || e.starts_at == 0
        || e.expires_at <= e.starts_at
        || e.expires_at > SAFE
        || czkp::field(&e.secret_hash, false).is_err()
        || czkp::field(&e.leaf, false).is_err()
        || e.path.iter().any(|p| czkp::field(p, false).is_err())
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// The entry is the exact leaf of `member` in `community`, equal to `expected`.
pub(super) fn verify_leaf(
    e: &Enrollment,
    community: &Field,
    member: &Field,
    expected: &Field,
) -> Result<(), Error> {
    shape(e)?;
    if &e.member != member || &e.leaf != expected || leaf(community, e)? != *expected {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// The entry is a member of the roster with `root`.
pub(super) fn verify_path(e: &Enrollment, community: &Field, root: &Field) -> Result<(), Error> {
    verify_leaf(e, community, &e.member, &e.leaf)?;
    let mut node = e.leaf;
    let mut position = e.index;
    for sibling in e.path {
        node = if position & 1 == 1 {
            hashes::enrollment_node(sibling, node)?
        } else {
            hashes::enrollment_node(node, sibling)?
        };
        position >>= 1;
    }
    if &node != root {
        return Err(Error::Invalid);
    }
    Ok(())
}
