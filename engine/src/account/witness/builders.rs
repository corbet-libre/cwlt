//! The update builders: each prepares exactly one transition of the account and returns the
//! circuit input, the public statement and the next witness state.
use super::input::{
    AckJson, AuxJson, EntryJson, ExtensionJson, Hx, MapJson, OpeningJson, PolicyWire,
    ResolutionJson, RowJson, SlotJson, UpdateInput,
};
use super::{
    Account, BondEntry, Candidate, Context, Delivery, Entropy, Field, Slot, hashes, horizon,
    roster, statement,
};
use crate::{Error, account::maps::Witness, plan};
use czkp::poseidon::{integer, limbs};

const SAFE: u64 = czkp::MAX_INTEGER;

/// A reservation request.
pub struct Reserve {
    /// The peer's position in the roster.
    pub peer_index: usize,
    /// 0 outgoing (the sender), 1 incoming (the recipient).
    pub role: u8,
    /// Conversation nonce.
    pub nonce: Field,
    /// Group identifier.
    pub group: Field,
    /// Contact-policy digest.
    pub contact_policy: Field,
    /// The common lease start; required for an incoming reservation.
    pub opened_at: Option<u64>,
    /// The common lease end; required for an incoming reservation.
    pub expires_at: Option<u64>,
}

/// The authenticated receipt that settles a conversation.
#[derive(Clone)]
pub struct Resolution {
    /// 1 Answer, 2 Close.
    pub kind: u8,
    /// Receipt time.
    pub issued_at: u64,
    /// History digest.
    pub history_digest: Field,
    /// Digest of the Ed25519 receipt.
    pub ed25519_receipt_digest: Field,
    /// Receipt signature.
    pub signature: [u8; 64],
}
/// The sender's acknowledgement of an Answer.
#[derive(Clone)]
pub struct Acknowledgment {
    /// Acknowledgement time.
    pub issued_at: u64,
    /// Signature.
    pub signature: [u8; 64],
}
/// One entry of the forced inbox: its frontier and the delivery commitment.
#[derive(Clone)]
pub struct Delivered {
    /// The inbox root the entry extends.
    pub previous_root: Field,
    /// The delivery commitment.
    pub commitment: Field,
}

pub(super) struct Counted {
    peer: Field,
    enrollment: crate::account::Enrollment,
}

impl From<Witness> for MapJson {
    fn from(w: Witness) -> Self {
        MapJson {
            leaf: w.leaf.map(Hx),
            index: w.index,
            path: w.path.iter().map(|p| Hx(*p)).collect(),
            append_path: w.append_path.iter().map(|p| Hx(*p)).collect(),
        }
    }
}

fn slot_json(s: &Slot) -> SlotJson {
    SlotJson {
        role: s.role,
        peer: s.peer,
        nonce: s.nonce,
        group: s.group,
        contact_policy: s.contact_policy,
        amount: s.amount,
        phase: s.phase,
        outcome: s.outcome,
        answered: s.answered,
        self_punished: s.self_punished,
        admitted_at: s.admitted_at,
        expires_at: s.expires_at,
        peer_authority: Hx(s.peer_authority),
        owner_authority: Hx(s.owner_authority),
    }
}
fn resolution_json(r: &super::builders::Resolution) -> ResolutionJson {
    ResolutionJson {
        kind: r.kind,
        issued_at: r.issued_at,
        history_digest: r.history_digest,
        ed25519_receipt_digest: r.ed25519_receipt_digest,
        signature: r.signature.to_vec(),
    }
}
fn entry_json(e: &BondEntry) -> EntryJson {
    EntryJson {
        limit: e.limit,
        done: e.done,
        overshoot: e.overshoot,
        punished_seen: e.punished_seen,
        rewards_seen: e.rewards_seen,
    }
}
fn entry_plan(e: &plan::BondEntryIo) -> BondEntry {
    BondEntry {
        limit: e.limit,
        done: e.done,
        overshoot: e.overshoot,
        punished_seen: e.punished_seen,
        rewards_seen: e.rewards_seen,
    }
}
fn wire(p: &super::AccountPolicy) -> PolicyWire {
    PolicyWire {
        initial_credit: p.initial_credit,
        maximum_available: p.maximum_available,
        outgoing_reservation: p.outgoing_reservation,
        incoming_reservation: p.incoming_reservation,
        policy_revision: p.policy_revision,
        policy_valid_from: p.policy_valid_from,
        policy_valid_until: p.policy_valid_until,
        newcomer_period: p.newcomer_period,
        rate_window: p.rate_window,
        newcomer_admissions: p.newcomer_admissions,
        maximum_admissions: p.maximum_admissions,
        refill_period: p.refill_period,
        refill_units: p.refill_units,
        abandon_after: p.abandon_after,
    }
}

impl Context {
    pub(super) fn domain() -> Field {
        hashes::domain(b"cfrm.account-state.v2")
    }
}

impl Account {
    // ---- hashes -------------------------------------------------------------------------
    pub(super) fn marker(
        &self,
        owner: &Field,
        peer: &Field,
        nonce: &Field,
    ) -> Result<Field, Error> {
        let fields = [
            limbs(&self.cx.community),
            limbs(&self.cx.secret),
            limbs(owner),
            limbs(peer),
            limbs(nonce),
        ]
        .concat();
        hashes::legacy(5, &fields)
    }
    fn pair_key(&self, peer: &Field) -> Result<Field, Error> {
        let fields = [
            limbs(&self.cx.community),
            limbs(&self.cx.secret),
            limbs(&self.owner().member),
            limbs(peer),
        ]
        .concat();
        hashes::hash(5, &fields)
    }
    pub(super) fn obligation(&self, event: &Field, s: &Slot, phase: u8) -> Result<Field, Error> {
        let mut fields = vec![*event, integer(u64::from(s.role))];
        for v in [&s.peer, &s.nonce, &s.group, &s.contact_policy] {
            fields.extend(limbs(v));
        }
        fields.extend([
            integer(u64::from(s.amount)),
            integer(u64::from(phase)),
            integer(u64::from(s.outcome)),
            integer(u64::from(s.answered)),
            integer(u64::from(s.self_punished)),
            integer(s.admitted_at),
            integer(s.expires_at),
            s.peer_authority,
            s.owner_authority,
        ]);
        hashes::hash(4, &fields)
    }
    pub(super) fn delivery(
        &self,
        recipient: &Field,
        reporter: &Field,
        nonce: &Field,
        group: &Field,
        kind: u8,
    ) -> Result<Field, Error> {
        let mut fields = [
            limbs(&self.cx.community),
            limbs(recipient),
            limbs(reporter),
            limbs(nonce),
            limbs(group),
        ]
        .concat();
        fields.push(integer(u64::from(kind)));
        hashes::hash(32, &fields)
    }
    fn authorization(
        &self,
        peer: &Field,
        nonce: &Field,
        group: &Field,
        kind: u8,
    ) -> Result<Field, Error> {
        let marker = self.marker(&self.owner().member, peer, nonce)?;
        let delivery = self.delivery(peer, &self.owner().member, nonce, group, kind)?;
        hashes::hash(33, &[marker, delivery, integer(u64::from(kind))])
    }
    pub(super) fn raw(values: &[Field]) -> Result<Field, Error> {
        czkp::poseidon::hash(values).map_err(|_| Error::Crypto)
    }

    fn blank_slot(&self, now: u64) -> Slot {
        let owner = self.owner().clone();
        Slot {
            role: 0,
            peer: [0; 32],
            nonce: [0; 32],
            group: [0; 32],
            contact_policy: [0; 32],
            amount: 0,
            phase: 1,
            outcome: 0,
            answered: false,
            self_punished: false,
            admitted_at: now,
            expires_at: now,
            peer_authority: [0; 32],
            owner_authority: [0; 32],
            peer_enrollment: owner.clone(),
            owner_enrollment: owner,
        }
    }

    // ---- shared input / plan / finish ----------------------------------------------------
    pub(super) fn input(&self, blind: Field, now: u64) -> Result<UpdateInput, Error> {
        let owner = self.owner();
        let p = &self.cx.policy;
        let e = &self.cx.extension;
        let blank = self.blank_slot(now);
        Ok(UpdateInput {
            extension: ExtensionJson {
                revision: e.revision,
                quorum: e.quorum,
                change_cost: e.change_cost,
                delay: e.delay,
                batch: e.batch,
                standing: e.standing,
            },
            previous_inbox: self.opening.inbox,
            inbox: self.opening.inbox,
            consume_only: false,
            change_binding: [0; 32],
            community: self.cx.community,
            owner: owner.member,
            policy_digest: self.cx.policy_digest,
            enrollment_root: self.checkpoint.root(),
            now,
            valid_until: horizon(p, now),
            genesis: false,
            previous_version: self.version,
            next_version: self.version + 1,
            previous_state: self.commitment,
            next_state: [0; 32],
            settlement_marker: [0; 32],
            policy: wire(p),
            role: 0,
            obligation: [0; 32],
            owner_secret: *self.cx.secret,
            owner_enrollment: RowJson::from(owner),
            peer_enrollment: RowJson::from(owner),
            receipt_owner_enrollment: RowJson::from(owner),
            delivery_kind: 0,
            contact_signature: vec![0; 64],
            old: OpeningJson::from(&self.opening),
            new_blind: blind,
            action: 1,
            slot: slot_json(&blank),
            own_map: MapJson::empty(),
            opposite_map: MapJson::empty(),
            pair_map: MapJson::empty(),
            pair_exists: false,
            resolution: ResolutionJson {
                kind: 2,
                issued_at: now,
                history_digest: [0; 32],
                ed25519_receipt_digest: [0; 32],
                signature: vec![0; 64],
            },
            acknowledgment: AckJson {
                issued_at: now,
                signature: vec![0; 64],
            },
            standing_policy: self.cx.tables.clone(),
            aux: AuxJson::empty(),
        })
    }

    fn at(&self, now: u64) -> Result<u64, Error> {
        let p = &self.cx.policy;
        if now > SAFE
            || self.opening.created_at == 0
            || now < p.policy_valid_from
            || now >= p.policy_valid_until
        {
            return Err(Error::Invalid);
        }
        Ok(now)
    }

    fn plan(&self, input: &UpdateInput) -> Result<plan::Plan, Error> {
        let o = &self.opening;
        let s = &input.slot;
        let request = plan::Request {
            old: plan::Balances {
                reserved: u64::try_from(o.reserved).map_err(|_| Error::Invalid)?,
                accepted: o.accepted,
                declined: o.declined,
                punished: o.punished,
            },
            standing: plan::Standing {
                g: o.standing.g,
                a: o.standing.a,
                c: o.standing.c,
                pr: o.standing.pr,
                pg: o.standing.pg,
                lc: o.standing.lc,
                day: o.standing.day,
            },
            params: plan::StandingParams::from(&self.cx.standing),
            created_at: o.created_at,
            now: input.now,
            action: input.action,
            amount: s.amount,
            role: s.role,
            phase: s.phase,
            outcome: s.outcome,
            kind: if input.action == 10 {
                input.delivery_kind
            } else {
                input.resolution.kind
            },
            answered: s.answered,
            self_punished: s.self_punished,
            change_cost: self.cx.extension.change_cost,
            voucher: plan::VoucherAccount {
                proven: o.voucher.proven,
                away: o.voucher.away,
                reserved: o.voucher.reserved,
                lost: o.voucher.lost,
                bonus: o.voucher.bonus,
                returned: o.voucher.returned,
                answers: o.voucher.answers,
            },
            voucher_role: input.role,
            count: input.aux.count,
            obligation_kind: input.aux.kind,
            obligation_n: input.aux.n,
            units: input.aux.units,
            entry: plan::BondEntryIo {
                limit: input.aux.entry.limit,
                done: input.aux.entry.done,
                overshoot: input.aux.entry.overshoot,
                punished_seen: input.aux.entry.punished_seen,
                rewards_seen: input.aux.entry.rewards_seen,
            },
        };
        request.prepare().map_err(|_| Error::Invalid)
    }

    fn set_slot(&mut self, event: Field, slot: Slot) {
        match self.slots.iter_mut().find(|(e, _)| *e == event) {
            Some(existing) => existing.1 = slot,
            None => self.slots.push((event, slot)),
        }
    }

    fn finish(
        &self,
        mut next: Account,
        mut input: UpdateInput,
        counted: Option<&Counted>,
    ) -> Result<Candidate, Error> {
        if counted.is_some() {
            input.aux.count = true;
        }
        let plan = self.plan(&input)?;
        next.opening.reserved = u128::from(plan.balances.reserved);
        next.opening.accepted = plan.balances.accepted;
        next.opening.declined = plan.balances.declined;
        next.opening.punished = plan.balances.punished;
        next.opening.standing.g = plan.standing.g;
        next.opening.standing.a = plan.standing.a;
        next.opening.standing.c = plan.standing.c;
        next.opening.standing.pr = plan.standing.pr;
        next.opening.standing.pg = plan.standing.pg;
        next.opening.standing.lc = plan.standing.lc;
        next.opening.standing.day = plan.standing.day;
        next.opening.voucher.proven = plan.voucher.proven;
        next.opening.voucher.away = plan.voucher.away;
        next.opening.voucher.reserved = plan.voucher.reserved;
        next.opening.voucher.lost = plan.voucher.lost;
        next.opening.voucher.bonus = plan.voucher.bonus;
        next.opening.voucher.returned = plan.voucher.returned;
        next.opening.voucher.answers = plan.voucher.answers;
        input.standing_policy = plan.policy;
        next.opening.inbox = input.inbox;
        next.opening.authorization = if plan.authorization != 0 {
            self.authorization(
                &input.slot.peer,
                &input.slot.nonce,
                &input.slot.group,
                plan.authorization,
            )?
        } else {
            [0; 32]
        };
        if let Some(c) = counted {
            // The pair flips from 1 to 5: a distinct peer now counts toward the success proof.
            let pair = self.pair_key(&c.peer)?;
            let (witness, pairs) = self.pairs.update(pair, integer(5))?;
            input.pair_map = witness.into();
            next.pairs = pairs;
            // The counted peer must prove its enrollment began before this account joined.
            input.peer_enrollment = RowJson::from(&c.enrollment);
        }
        next.opening.voucher.bond_root = next.bonds.root();
        next.opening.voucher.bond_count = next.bonds.count();
        next.now = input.now;
        next.version = self.version + 1;
        next.opening.outgoing_root = next.outgoing.root();
        next.opening.outgoing_count = next.outgoing.count();
        next.opening.incoming_root = next.incoming.root();
        next.opening.incoming_count = next.incoming.count();
        next.opening.pair_root = next.pairs.root();
        next.opening.pair_count = next.pairs.count();
        next.opening.blind = input.new_blind;
        next.commitment = next.commit(&next.opening, next.version)?;
        input.next_state = next.commitment;
        if input.consume_only {
            next.version = self.version;
            next.commitment = next.commit(&next.opening, next.version)?;
            input.next_version = self.version;
            input.next_state = next.commitment;
        }
        Ok(Candidate {
            statement: super::AccountStatement::from_input(&input),
            update: statement::effect(&input),
            input,
            next,
            event: None,
            delivery: None,
            entry: None,
            tag: None,
        })
    }

    // ---- reservations and settlement ------------------------------------------------------
    /// Reserve the sender's introduction (`role` 0) or the recipient's slot (`role` 1).
    pub fn reserve(
        &self,
        r: Reserve,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        if r.role > 1 {
            return Err(Error::Invalid);
        }
        let at = self.at(now)?;
        if r.role == 1 && (r.opened_at.is_none() || r.expires_at.is_none()) {
            return Err(Error::Invalid);
        }
        let p = &self.cx.policy;
        let opened = r.opened_at.unwrap_or(at);
        let expiry = r.expires_at.unwrap_or(at + p.abandon_after);
        if opened == 0
            || opened > at
            || expiry <= at
            || expiry >= p.policy_valid_until
            || horizon(p, now) > expiry
            || (r.role == 0 && (opened != at || expiry != at + p.abandon_after))
        {
            return Err(Error::Invalid);
        }
        if r.peer_index == self.owner_index {
            return Err(Error::Invalid);
        }
        let peer = self
            .checkpoint
            .entries()
            .get(r.peer_index)
            .ok_or(Error::Invalid)?
            .clone();
        roster::verify_path(&peer, &self.cx.community, &self.checkpoint.root())?;
        let owner = self.owner().clone();
        let event = self.marker(&owner.member, &peer.member, &r.nonce)?;
        let pair = self.pair_key(&peer.member)?;
        let amount = if r.role == 0 {
            p.outgoing_reservation
        } else {
            p.incoming_reservation
        };
        let slot = Slot {
            role: r.role,
            peer: peer.member,
            nonce: r.nonce,
            group: r.group,
            contact_policy: r.contact_policy,
            amount,
            phase: 1,
            outcome: 0,
            answered: false,
            self_punished: false,
            admitted_at: opened,
            expires_at: expiry,
            peer_authority: peer.leaf,
            owner_authority: owner.leaf,
            peer_enrollment: peer.clone(),
            owner_enrollment: owner,
        };
        let (own, opposite) = if r.role == 0 {
            (&self.outgoing, &self.incoming)
        } else {
            (&self.incoming, &self.outgoing)
        };
        let (own_witness, own_next) = own.insert(event, self.obligation(&event, &slot, 1)?)?;
        let mut input = self.input(rng.blind()?, now)?;
        let mut next = self.clone();
        input.action = 1;
        input.slot = slot_json(&slot);
        input.peer_enrollment = RowJson::from(&peer);
        input.own_map = own_witness.into();
        input.opposite_map = opposite.absence(&event)?.into();
        match self.pairs.find(&pair) {
            Some(index) => {
                input.pair_exists = true;
                input.pair_map = self.pairs.witness(index)?.into();
            }
            None => {
                let (witness, pairs) = self.pairs.insert(pair, integer(1))?;
                input.pair_map = witness.into();
                next.pairs = pairs;
            }
        }
        if r.role == 0 {
            next.outgoing = own_next;
        } else {
            next.incoming = own_next;
        }
        next.opening.reserved += u128::from(amount);
        next.set_slot(event, slot);
        let mut result = self.finish(next, input, None)?;
        result.event = Some(event);
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn change(
        &self,
        event: &Field,
        action: u8,
        resolution: Option<&Resolution>,
        acknowledgment: Option<&Acknowledgment>,
        now: u64,
        peer_enrollment: Option<&crate::account::Enrollment>,
        receipt_owner: Option<&crate::account::Enrollment>,
        counted: Option<&Counted>,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let at = self.at(now)?;
        let old = self.slot(event).ok_or(Error::Invalid)?;
        let wanted = if matches!(action, 2 | 4) { 1 } else { 2 };
        if !(2..=5).contains(&action)
            || (if action == 5 {
                !matches!(old.phase, 2 | 8)
            } else {
                old.phase != wanted
            })
        {
            return Err(Error::Invalid);
        }
        if at < old.admitted_at {
            return Err(Error::Invalid);
        }
        let expired = at >= old.expires_at;
        let within = horizon(&self.cx.policy, now) <= old.expires_at;
        let kind = resolution.map(|r| r.kind);
        if (action == 2 && (expired || !within))
            || (action == 5 && (old.role != 0 || !expired))
            || (action == 3 && old.role == 0 && kind != Some(1))
            || (action == 3 && kind == Some(1) && (expired || !within))
        {
            return Err(Error::Invalid);
        }
        let mut slot = old.clone();
        let mut next = self.clone();
        let mut input = self.input(rng.blind()?, now)?;
        let peer = peer_enrollment.unwrap_or(&slot.peer_enrollment).clone();
        let receipt = receipt_owner.unwrap_or(&slot.owner_enrollment).clone();
        if action == 3 {
            if slot.role == 0 || kind == Some(1) {
                self.verify_receipt(&peer, &slot.peer, &slot.peer_authority, false)?;
            }
            if slot.role == 1 {
                self.verify_receipt(&receipt, &self.owner().member, &slot.owner_authority, true)?;
            }
        }
        input.action = action;
        input.slot = slot_json(&slot);
        input.peer_enrollment = RowJson::from(&peer);
        input.receipt_owner_enrollment = RowJson::from(&receipt);
        let phase = match action {
            2 => 2,
            4 => 4,
            5 => 5,
            _ => 3,
        };
        if action == 3 {
            let kind = kind.ok_or(Error::Invalid)?;
            slot.outcome = kind;
            if kind == 1 {
                slot.answered = true;
            }
        }
        let own = if slot.role == 0 {
            &self.outgoing
        } else {
            &self.incoming
        };
        let (witness, changed) = own.update(*event, self.obligation(event, &slot, phase)?)?;
        input.own_map = witness.into();
        if slot.role == 0 {
            next.outgoing = changed;
        } else {
            next.incoming = changed;
        }
        slot.phase = phase;
        let amount = u128::from(slot.amount);
        next.set_slot(*event, slot);
        if action == 3 {
            let res = resolution.ok_or(Error::Invalid)?;
            input.resolution = resolution_json(res);
            if let Some(ack) = acknowledgment {
                input.acknowledgment = AckJson {
                    issued_at: ack.issued_at,
                    signature: ack.signature.to_vec(),
                };
            }
            next.opening.reserved = next.opening.reserved.saturating_sub(amount);
            input.settlement_marker = *event;
        } else if action == 4 || action == 5 {
            next.opening.reserved = next.opening.reserved.saturating_sub(amount);
            input.settlement_marker = *event;
        }
        self.finish(next, input, counted)
    }

    fn verify_receipt(
        &self,
        entry: &crate::account::Enrollment,
        member: &Field,
        original_leaf: &Field,
        owner: bool,
    ) -> Result<(), Error> {
        roster::verify_leaf(entry, &self.cx.community, member, &entry.leaf)?;
        if &entry.leaf == original_leaf {
            return Ok(());
        }
        if owner && entry.leaf != self.owner().leaf {
            return Err(Error::Invalid);
        }
        roster::verify_path(entry, &self.cx.community, &self.checkpoint.root())
    }

    /// Activate a reserved obligation under the counterpart's signed contact.
    pub fn activate(
        &self,
        event: &Field,
        now: u64,
        contact_signature: [u8; 64],
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut result = self.change(event, 2, None, None, now, None, None, None, rng)?;
        result.input.contact_signature = contact_signature.to_vec();
        Ok(result)
    }
    /// Settle as Answer (kind 1) or Close (kind 2) under the authenticated receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        &self,
        event: &Field,
        resolution: &Resolution,
        acknowledgment: Option<&Acknowledgment>,
        now: u64,
        peer_enrollment: Option<&crate::account::Enrollment>,
        receipt_owner: Option<&crate::account::Enrollment>,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        self.change(
            event,
            3,
            Some(resolution),
            acknowledgment,
            now,
            peer_enrollment,
            receipt_owner,
            None,
            rng,
        )
    }
    /// Cancel a reservation that was never activated.
    pub fn cancel(
        &self,
        event: &Field,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        self.change(event, 4, None, None, now, None, None, None, rng)
    }
    /// Retire an expired outgoing obligation (the sender's refund after silence).
    pub fn expire(
        &self,
        event: &Field,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        self.change(event, 5, None, None, now, None, None, None, rng)
    }

    /// Punish the peer: burns on both sides and blocks the pair in the same update.
    pub fn punish(
        &self,
        event: &Field,
        now: u64,
        contact_signature: [u8; 64],
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let s = self.slot(event).ok_or(Error::Invalid)?.clone();
        let mut input = self.input(rng.blind()?, now)?;
        input.action = if s.answered { 8 } else { 7 };
        input.slot = slot_json(&s);
        input.peer_enrollment = RowJson::from(&s.peer_enrollment);
        input.contact_signature = contact_signature.to_vec();
        let plan = self.plan(&input)?;
        let mut next = self.clone();
        let updated = Slot {
            phase: plan.phase,
            outcome: plan.outcome,
            answered: plan.answered,
            self_punished: plan.self_punished,
            ..s.clone()
        };
        let own = if s.role == 0 {
            &self.outgoing
        } else {
            &self.incoming
        };
        let (witness, changed) =
            own.update(*event, self.obligation(event, &updated, updated.phase)?)?;
        input.own_map = witness.into();
        if s.role == 0 {
            next.outgoing = changed;
        } else {
            next.incoming = changed;
        }
        let pair = self.pair_key(&s.peer)?;
        let (blocked, pairs) = self.pairs.update(pair, integer(2))?;
        input.pair_map = blocked.into();
        next.pairs = pairs;
        next.set_slot(*event, updated);
        input.settlement_marker = Self::raw(&[*event, integer(u64::from(plan.authorization))])?;
        let mut result = self.finish(next, input, None)?;
        result.delivery = Some(Delivery {
            slot: s,
            kind: plan.authorization,
        });
        Ok(result)
    }

    /// Spend a change token bound to `binding`.
    pub fn change_token(
        &self,
        binding: &Field,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        let next = self.clone();
        input.action = 9;
        input.change_binding = *binding;
        let owner = self.owner().member;
        let event = self.marker(&owner, &owner, binding)?;
        let mut fields = vec![event, integer(self.version)];
        fields.extend(limbs(binding));
        input.settlement_marker = Self::raw(&fields)?;
        self.finish(next, input, None)
    }

    /// Re-randomise the commitment without changing the account (also rolls forward the inbox).
    pub fn reblind(&self, now: u64, rng: &mut impl Entropy) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        input.action = 11;
        self.finish(self.clone(), input, None)
    }

    fn consume_inner(
        &self,
        entry: &Delivered,
        now: u64,
        counted: Option<Counted>,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        if entry.previous_root != self.opening.inbox {
            return Err(Error::Invalid);
        }
        let mut selected: Option<(Field, Slot, u8)> = None;
        for (event, s) in &self.slots {
            for kind in 1..=4u8 {
                if self.delivery(&self.owner().member, &s.peer, &s.nonce, &s.group, kind)?
                    == entry.commitment
                {
                    selected = Some((*event, s.clone(), kind));
                }
            }
        }
        let (event, s, kind) = selected.ok_or(Error::Invalid)?;
        let mut input = self.input(rng.blind()?, now)?;
        let mut next = self.clone();
        input.action = 10;
        input.consume_only = true;
        input.delivery_kind = kind;
        input.slot = slot_json(&s);
        let mut bytes = b"cblc.obligation-inbox.v2\0".to_vec();
        bytes.extend_from_slice(&self.cx.community);
        bytes.extend_from_slice(&self.owner().member);
        bytes.extend_from_slice(&self.opening.inbox);
        bytes.extend_from_slice(&entry.commitment);
        input.inbox = hashes::digest(&bytes)?;
        let plan = self.plan(&input)?;
        let updated = Slot {
            phase: plan.phase,
            outcome: plan.outcome,
            answered: plan.answered,
            self_punished: plan.self_punished,
            ..s.clone()
        };
        let own = if s.role == 0 {
            &self.outgoing
        } else {
            &self.incoming
        };
        let (witness, changed) =
            own.update(event, self.obligation(&event, &updated, updated.phase)?)?;
        input.own_map = witness.into();
        if s.role == 0 {
            next.outgoing = changed;
        } else {
            next.incoming = changed;
        }
        next.set_slot(event, updated);
        self.finish(next, input, counted.as_ref())
    }

    /// Absorb one forced-inbox entry: the burned or answered delivery of a known contact.
    pub fn consume(
        &self,
        entry: &Delivered,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        self.consume_inner(entry, now, None, rng)
    }

    // ---- voucher accounting ----------------------------------------------------------------
    /// Settle an answered conversation and count its peer toward the success proof.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_counted(
        &self,
        event: &Field,
        resolution: &Resolution,
        acknowledgment: Option<&Acknowledgment>,
        now: u64,
        peer_enrollment: Option<&crate::account::Enrollment>,
        receipt_owner: Option<&crate::account::Enrollment>,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let slot = self.slot(event).ok_or(Error::Invalid)?;
        let counted = Counted {
            peer: slot.peer,
            enrollment: slot.peer_enrollment.clone(),
        };
        self.change(
            event,
            3,
            Some(resolution),
            acknowledgment,
            now,
            peer_enrollment,
            receipt_owner,
            Some(&counted),
            rng,
        )
    }
    /// Consume a delivered Answer and count its sender toward the success proof.
    pub fn consume_counted(
        &self,
        entry: &Delivered,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        for (_, s) in &self.slots {
            if self.delivery(&self.owner().member, &s.peer, &s.nonce, &s.group, 1)?
                == entry.commitment
            {
                let counted = Counted {
                    peer: s.peer,
                    enrollment: s.peer_enrollment.clone(),
                };
                return self.consume_inner(entry, now, Some(counted), rng);
            }
        }
        Err(Error::Invalid)
    }

    /// The sponsor spends one voucher on an actual admission and remembers the bond.
    pub fn admit(
        &self,
        bond_secret: &Field,
        role: u8,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        let mut next = self.clone();
        input.action = 12;
        input.role = role;
        input.aux = AuxJson {
            bond_secret: *bond_secret,
            ..AuxJson::empty()
        };
        let entry = entry_plan(&self.plan(&input)?.entry);
        let domain = Context::domain();
        let key = czkp::voucher::bond_key(&domain, bond_secret).map_err(|_| Error::Crypto)?;
        let payload = entry.digest(&domain).map_err(|_| Error::Crypto)?;
        let (witness, bonds) = self.bonds.insert(key, payload)?;
        input.aux.bond_map = witness.into();
        next.bonds = bonds;
        next.bond_book.insert(key, (*bond_secret, entry));
        let mut result = self.finish(next, input, None)?;
        result.entry = Some(entry);
        Ok(result)
    }

    /// Consume one obligation posted through the bond; the tag is all a server ever saw.
    pub fn consume_obligation(
        &self,
        bond_secret: &Field,
        kind: u8,
        n: u64,
        entry: BondEntry,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        let mut next = self.clone();
        let domain = Context::domain();
        let tag = czkp::voucher::obligation_tag(&domain, bond_secret, kind, n)
            .map_err(|_| Error::Crypto)?;
        input.action = 13;
        input.obligation = tag;
        input.aux = AuxJson {
            bond_secret: *bond_secret,
            kind,
            n,
            entry: entry_json(&entry),
            ..AuxJson::empty()
        };
        let after = entry_plan(&self.plan(&input)?.entry);
        let key = czkp::voucher::bond_key(&domain, bond_secret).map_err(|_| Error::Crypto)?;
        let payload = after.digest(&domain).map_err(|_| Error::Crypto)?;
        let (witness, bonds) = self.bonds.update(key, payload)?;
        input.aux.bond_map = witness.into();
        next.bonds = bonds;
        next.bond_book.insert(key, (*bond_secret, after));
        let mut result = self.finish(next, input, None)?;
        result.entry = Some(after);
        result.tag = Some(tag);
        Ok(result)
    }

    /// The account's own success proof; every threshold is a public policy value.
    pub fn prove_success(&self, now: u64, rng: &mut impl Entropy) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        input.action = 14;
        self.finish(self.clone(), input, None)
    }

    /// Reserve `units` voucher uses for a new link (action 15): the per-unit issue
    /// nullifiers of the presentation made at link creation count against these.
    pub fn reserve_uses(
        &self,
        units: u64,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        input.action = 15;
        input.aux = AuxJson {
            units,
            ..AuxJson::empty()
        };
        self.finish(self.clone(), input, None)
    }

    /// Release `units` reserved uses of an ended, revoked or declined link (action 16).
    pub fn release_uses(
        &self,
        units: u64,
        now: u64,
        rng: &mut impl Entropy,
    ) -> Result<Candidate, Error> {
        let mut input = self.input(rng.blind()?, now)?;
        input.action = 16;
        input.aux = AuxJson {
            units,
            ..AuxJson::empty()
        };
        self.finish(self.clone(), input, None)
    }
}
