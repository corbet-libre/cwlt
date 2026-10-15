//! Durable, engine-sealed form of the account witness state.
//!
//! The record holds exactly what the next builder needs and nothing a caller could use to
//! forge state: the opening, the leaves of the four private maps, the private obligations, the
//! sponsor's bond book and the policies. The owner secret is the engine's own seed and is never
//! written. Restoring rebuilds every tree, then requires the roots, counts and the state
//! commitment to equal the sealed ones, so a record that does not reproduce its commitment is
//! refused. The roster is supplied at restore time from the caller's verified source.
use super::{Account, BondEntry, Certificate, Checkpoint, Context, Slot};
use crate::{
    Engine, Error,
    account::{
        Field,
        codec::{Reader, Writer},
        maps::IndexedMap,
        opening::{Opening, Standing, Voucher},
        policy::{AccountPolicy, ExtensionPolicy},
        prepared::Enrollment,
    },
    plan,
};
use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"cwlt.account-witness.v1\0";
const NONCE: usize = 24;
/// Version 2 adds the voucher `reserved` count; version 1 records open with none reserved.
const VERSION: u8 = 2;
/// Bound of one sealed account record.
pub const MAX_ACCOUNT_SEALED: usize = 4 * 1024 * 1024;
const MAX_LEAVES: usize = 16_384;
const MAX_SLOTS: usize = 4_096;

/// Bounded ciphertext of one account witness record.
pub struct SealedAccount(Vec<u8>);
impl SealedAccount {
    /// Check the exact envelope before authenticated restore by the same engine.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= MAGIC.len() + NONCE + 16
            || bytes.len() > MAX_ACCOUNT_SEALED
            || !bytes.starts_with(MAGIC)
        {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Encrypted bytes safe to retain inside the atomic Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn write_enrollment(w: &mut Writer, e: &Enrollment) {
    w.bytes(&e.member);
    w.bytes(&e.key);
    w.bytes(&e.secret_hash);
    w.u64(e.starts_at);
    w.u64(e.expires_at);
    w.bytes(&e.delegation_digest);
    w.bytes(&e.leaf);
    w.u32(e.index);
    for p in &e.path {
        w.bytes(p);
    }
}
fn read_enrollment(r: &mut Reader<'_>) -> Result<Enrollment, Error> {
    let member = r.array()?;
    let key = r.array()?;
    let secret_hash = r.array()?;
    let starts_at = r.u64()?;
    let expires_at = r.u64()?;
    let delegation_digest = r.array()?;
    let leaf = r.array()?;
    let index = r.u32()?;
    let mut path = [[0; 32]; 32];
    for p in &mut path {
        *p = r.array()?;
    }
    Ok(Enrollment {
        member,
        key,
        secret_hash,
        starts_at,
        expires_at,
        delegation_digest,
        leaf,
        index,
        path,
    })
}
fn write_slot(w: &mut Writer, event: &Field, s: &Slot) {
    w.bytes(event);
    w.bytes(&[
        s.role,
        s.phase,
        s.outcome,
        u8::from(s.answered),
        u8::from(s.self_punished),
    ]);
    for f in [
        &s.peer,
        &s.nonce,
        &s.group,
        &s.contact_policy,
        &s.peer_authority,
        &s.owner_authority,
    ] {
        w.bytes(f);
    }
    w.u32(s.amount);
    w.u64(s.admitted_at);
    w.u64(s.expires_at);
    write_enrollment(w, &s.peer_enrollment);
    write_enrollment(w, &s.owner_enrollment);
}
fn read_slot(r: &mut Reader<'_>) -> Result<(Field, Slot), Error> {
    let event = r.array()?;
    let [role, phase, outcome, answered, self_punished] = r.array::<5>()?;
    if answered > 1 || self_punished > 1 {
        return Err(Error::Crypto);
    }
    let peer = r.array()?;
    let nonce = r.array()?;
    let group = r.array()?;
    let contact_policy = r.array()?;
    let peer_authority = r.array()?;
    let owner_authority = r.array()?;
    let amount = r.u32()?;
    let admitted_at = r.u64()?;
    let expires_at = r.u64()?;
    let peer_enrollment = read_enrollment(r)?;
    let owner_enrollment = read_enrollment(r)?;
    Ok((
        event,
        Slot {
            role,
            peer,
            nonce,
            group,
            contact_policy,
            amount,
            phase,
            outcome,
            answered: answered == 1,
            self_punished: self_punished == 1,
            admitted_at,
            expires_at,
            peer_authority,
            owner_authority,
            peer_enrollment,
            owner_enrollment,
        },
    ))
}
fn write_map(w: &mut Writer, map: &IndexedMap) {
    w.u32(map.count() as u32);
    for leaf in map.leaves() {
        for f in leaf {
            w.bytes(f);
        }
    }
}
fn read_map(r: &mut Reader<'_>) -> Result<IndexedMap, Error> {
    let n = r.u32()? as usize;
    if n == 0 || n > MAX_LEAVES {
        return Err(Error::Crypto);
    }
    let mut leaves = Vec::with_capacity(n);
    for _ in 0..n {
        let mut leaf = [[0; 32]; 4];
        for f in &mut leaf {
            *f = r.array()?;
        }
        leaves.push(leaf);
    }
    IndexedMap::from_leaves(leaves).map_err(|_| Error::Crypto)
}
fn write_params(w: &mut Writer, p: &czkp::standing::Params) {
    for v in [
        p.c0,
        p.h_a,
        p.h_g,
        p.n_half,
        p.n_c,
        p.e_q,
        p.r_max,
        p.r_age,
        p.c_max_q,
        p.c_vet,
        p.age_vet,
        p.boost_q,
        p.boost_days,
        p.slope_q,
        p.mid_q,
        p.kappa_q,
        p.loan_use_q,
    ] {
        w.u64(v);
    }
    let v = &p.voucher;
    for n in v.slope_q.iter().chain(&v.min).chain(&v.max) {
        w.u64(*n);
    }
    for n in [v.days, v.k, v.max_punished, v.brake_cap, v.reward_cap] {
        w.u64(n);
    }
}
fn read_params(r: &mut Reader<'_>) -> Result<czkp::standing::Params, Error> {
    let mut next = || r.u64();
    let c0 = next()?;
    let h_a = next()?;
    let h_g = next()?;
    let n_half = next()?;
    let n_c = next()?;
    let e_q = next()?;
    let r_max = next()?;
    let r_age = next()?;
    let c_max_q = next()?;
    let c_vet = next()?;
    let age_vet = next()?;
    let boost_q = next()?;
    let boost_days = next()?;
    let slope_q = next()?;
    let mid_q = next()?;
    let kappa_q = next()?;
    let loan_use_q = next()?;
    let mut three = || -> Result<[u64; 3], Error> { Ok([next()?, next()?, next()?]) };
    let (vs, vmin, vmax) = (three()?, three()?, three()?);
    let voucher = czkp::standing::VoucherParams {
        slope_q: vs,
        min: vmin,
        max: vmax,
        days: next()?,
        k: next()?,
        max_punished: next()?,
        brake_cap: next()?,
        reward_cap: next()?,
    };
    Ok(czkp::standing::Params {
        c0,
        h_a,
        h_g,
        n_half,
        n_c,
        e_q,
        r_max,
        r_age,
        c_max_q,
        c_vet,
        age_vet,
        boost_q,
        boost_days,
        slope_q,
        mid_q,
        kappa_q,
        loan_use_q,
        voucher,
    })
}

impl Account {
    /// Seal this state for the Store. Only the engine whose seed owns the account can seal it.
    pub fn seal(&self, engine: &Engine) -> Result<SealedAccount, Error> {
        if self.cx.secret.as_ref() != engine.seed.as_ref() {
            return Err(Error::Invalid);
        }
        let c = &self.cx;
        let mut w = Writer(Zeroizing::new(Vec::with_capacity(64 * 1024)));
        w.bytes(&[VERSION]);
        w.bytes(&c.community);
        w.bytes(&self.owner().member);
        let p = &c.policy;
        for v in [
            p.initial_credit,
            p.maximum_available,
            p.outgoing_reservation,
            p.incoming_reservation,
        ] {
            w.u32(v);
        }
        for v in [
            p.policy_revision,
            p.policy_valid_from,
            p.policy_valid_until,
            p.newcomer_period,
            p.rate_window,
        ] {
            w.u64(v);
        }
        w.u32(p.newcomer_admissions);
        w.u32(p.maximum_admissions);
        w.u64(p.refill_period);
        w.u32(p.refill_units);
        w.u64(p.abandon_after);
        let e = &c.extension;
        w.u64(e.revision);
        w.u32(e.quorum);
        w.u32(e.change_cost);
        w.u64(e.delay);
        w.bytes(&[e.batch]);
        w.bytes(&e.standing);
        write_params(&mut w, &c.standing);
        let o = &self.opening;
        w.bytes(&o.reserved.to_be_bytes());
        for v in [o.accepted, o.declined, o.punished] {
            w.u64(v);
        }
        w.bytes(&o.inbox);
        w.bytes(&o.authorization);
        w.u64(o.created_at);
        let s = &o.standing;
        for v in [s.g, s.a, s.c, s.pr, s.pg, s.lc, s.day] {
            w.u64(v);
        }
        let v = &o.voucher;
        for n in [
            v.proven, v.away, v.reserved, v.lost, v.bonus, v.returned, v.answers,
        ] {
            w.u64(n);
        }
        w.bytes(&v.sponsor);
        w.bytes(&v.bond);
        w.bytes(&o.blind);
        w.u64(self.version);
        w.u64(self.now);
        w.bytes(&self.commitment);
        match &self.certificate {
            Some(cert) => {
                w.bytes(&[1]);
                w.u64(cert.accepted_at);
                w.bytes(&cert.signature);
            }
            None => w.bytes(&[0]),
        }
        for map in [&self.outgoing, &self.incoming, &self.pairs, &self.bonds] {
            write_map(&mut w, map);
        }
        w.u32(self.slots.len() as u32);
        for (event, slot) in &self.slots {
            write_slot(&mut w, event, slot);
        }
        w.u32(self.bond_book.len() as u32);
        for (key, (secret, entry)) in &self.bond_book {
            w.bytes(key);
            w.bytes(secret);
            w.u64(entry.limit);
            w.bytes(&[u8::from(entry.done), u8::from(entry.overshoot)]);
            w.u64(entry.punished_seen);
            w.u64(entry.rewards_seen);
        }
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, engine.sealing.context.as_slice()].concat();
        let encrypted = engine
            .sealing
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: w.0.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        if MAGIC.len() + NONCE + encrypted.len() > MAX_ACCOUNT_SEALED {
            return Err(Error::Invalid);
        }
        Ok(SealedAccount([MAGIC, &nonce, &encrypted].concat()))
    }
}

impl Engine {
    /// Reopen an account witness. `checkpoint` is the caller's verified roster; it must contain
    /// the owner and every sealed counterpart row under its root. The restored state must
    /// reproduce the sealed state commitment exactly.
    pub fn restore_account(
        &self,
        sealed: &SealedAccount,
        checkpoint: Arc<Checkpoint>,
    ) -> Result<Account, Error> {
        let offset = MAGIC.len();
        let nonce: [u8; NONCE] = sealed.0[offset..offset + NONCE]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, self.sealing.context.as_slice()].concat();
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + NONCE..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        let mut r = Reader(&plaintext);
        let version = r.array::<1>()?[0];
        if version != VERSION && version != 1 {
            return Err(Error::Crypto);
        }
        let community: Field = r.array()?;
        let member: Field = r.array()?;
        let policy = AccountPolicy {
            initial_credit: r.u32()?,
            maximum_available: r.u32()?,
            outgoing_reservation: r.u32()?,
            incoming_reservation: r.u32()?,
            policy_revision: r.u64()?,
            policy_valid_from: r.u64()?,
            policy_valid_until: r.u64()?,
            newcomer_period: r.u64()?,
            rate_window: r.u64()?,
            newcomer_admissions: r.u32()?,
            maximum_admissions: r.u32()?,
            refill_period: r.u64()?,
            refill_units: r.u32()?,
            abandon_after: r.u64()?,
        };
        let extension = ExtensionPolicy {
            revision: r.u64()?,
            quorum: r.u32()?,
            change_cost: r.u32()?,
            delay: r.u64()?,
            batch: r.array::<1>()?[0],
            standing: r.array()?,
        };
        let standing = read_params(&mut r)?;
        let reserved = u128::from_be_bytes(r.array()?);
        let accepted = r.u64()?;
        let declined = r.u64()?;
        let punished = r.u64()?;
        let inbox = r.array()?;
        let authorization = r.array()?;
        let created_at = r.u64()?;
        let st = Standing {
            g: r.u64()?,
            a: r.u64()?,
            c: r.u64()?,
            pr: r.u64()?,
            pg: r.u64()?,
            lc: r.u64()?,
            day: r.u64()?,
        };
        let proven = r.u64()?;
        let away = r.u64()?;
        let voucher_reserved = if version == 1 { 0 } else { r.u64()? };
        let lost = r.u64()?;
        let bonus = r.u64()?;
        let returned = r.u64()?;
        let answers = r.u64()?;
        let sponsor = r.array()?;
        let bond = r.array()?;
        let blind = r.array()?;
        let version = r.u64()?;
        let now = r.u64()?;
        let commitment: Field = r.array()?;
        let certificate = match r.array::<1>()?[0] {
            0 => None,
            1 => Some(Certificate {
                accepted_at: r.u64()?,
                signature: r.array()?,
            }),
            _ => return Err(Error::Crypto),
        };
        let outgoing = read_map(&mut r)?;
        let incoming = read_map(&mut r)?;
        let pairs = read_map(&mut r)?;
        let bonds = read_map(&mut r)?;
        let n = r.u32()? as usize;
        if n > MAX_SLOTS {
            return Err(Error::Crypto);
        }
        let mut slots = Vec::with_capacity(n);
        for _ in 0..n {
            slots.push(read_slot(&mut r)?);
        }
        let n = r.u32()? as usize;
        if n > MAX_SLOTS {
            return Err(Error::Crypto);
        }
        let mut bond_book = std::collections::BTreeMap::new();
        for _ in 0..n {
            let key: Field = r.array()?;
            let secret: Field = r.array()?;
            let limit = r.u64()?;
            let [done, overshoot] = r.array::<2>()?;
            let entry = BondEntry {
                limit,
                done: done == 1,
                overshoot: overshoot == 1,
                punished_seen: r.u64()?,
                rewards_seen: r.u64()?,
            };
            bond_book.insert(key, (secret, entry));
        }
        if !r.0.is_empty() {
            return Err(Error::Crypto);
        }
        let owner_index = checkpoint
            .entries()
            .iter()
            .position(|e| e.member == member)
            .ok_or(Error::Invalid)?;
        let owner = &checkpoint.entries()[owner_index];
        let (policy_digest, state_policy) = policy.digests(&community)?;
        if crate::account::hashes::secret(&community, &self.seed)? != owner.secret_hash {
            return Err(Error::Crypto);
        }
        let tables = plan::policy_out(
            &czkp::standing::Policy::derive(standing).map_err(|_| Error::Invalid)?,
        );
        let opening = Opening {
            reserved,
            accepted,
            declined,
            punished,
            inbox,
            authorization,
            outgoing_root: outgoing.root(),
            outgoing_count: outgoing.count(),
            incoming_root: incoming.root(),
            incoming_count: incoming.count(),
            pair_root: pairs.root(),
            pair_count: pairs.count(),
            created_at,
            standing: st,
            voucher: Voucher {
                proven,
                away,
                reserved: voucher_reserved,
                lost,
                bonus,
                returned,
                answers,
                sponsor,
                bond,
                bond_root: bonds.root(),
                bond_count: bonds.count(),
            },
            blind,
        };
        let account = Account {
            cx: Arc::new(Context {
                community,
                secret: Zeroizing::new(*self.seed),
                policy,
                extension,
                standing,
                policy_digest,
                state_policy,
                tables,
            }),
            checkpoint,
            owner_index,
            opening,
            outgoing,
            incoming,
            pairs,
            bonds,
            slots,
            bond_book,
            version,
            now,
            commitment,
            certificate,
        };
        if account.commit(&account.opening, version)? != commitment {
            return Err(Error::Crypto);
        }
        Ok(account)
    }
}
