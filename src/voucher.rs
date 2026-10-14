//! Device-side voucher accounting: the exact port the voucher host codes against.
//!
//! The four operations mirror `cvch::link::Allowance` (`can_issue`, `remaining`,
//! `spend_on_admission`, `bond_established`) without naming a member: the account
//! belongs to this device, and the server only ever sees an unlinkable allowance proof
//! and bond-addressed tags. This is the planner state machine; proofs are made from the
//! same plan by the prover that owns the account.
#![allow(missing_docs)]
use czkp::standing::{Policy, State};
use czkp::voucher::{self, Account, Entry};
use std::collections::BTreeMap;

/// Which side of a bond this device holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondSide {
    /// The member who issued the link.
    Sponsor,
    /// The member who was admitted.
    Vouchee,
}

/// The bond secret, kept in vault custody and never sent anywhere.
#[derive(Clone, PartialEq, Eq)]
pub struct Bond(pub [u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub struct Refused;

/// One account's voucher side on this device.
pub struct DeviceAllowance {
    policy: Policy,
    role: u8,
    standing: State,
    account: Account,
    /// Sponsor side: what is remembered per bond, keyed by the bond key.
    entries: BTreeMap<[u8; 32], Entry>,
    /// Vouchee side: the one bond with the sponsor.
    own_bond: Option<Bond>,
    domain: [u8; 32],
}

impl DeviceAllowance {
    pub fn new(policy: Policy, role: u8, standing: State, account: Account) -> Self {
        let mut domain = [0; 32];
        let tag = b"cfrm.account-state.v2";
        domain[32 - tag.len()..].copy_from_slice(tag);
        DeviceAllowance {
            policy,
            role,
            standing,
            account,
            entries: BTreeMap::new(),
            own_bond: None,
            domain,
        }
    }

    /// Replace the standing view (after a day passes or a transition is accepted).
    pub fn set_standing(&mut self, standing: State, role: u8) {
        self.standing = standing;
        self.role = role;
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Vouchers still available, checked against the current pool cap.
    pub fn remaining(&self) -> u32 {
        let cap = self.standing.cap(&self.policy);
        let left = voucher::remaining(&self.policy, self.role, &self.account, cap).unwrap_or(0);
        u32::try_from(left).unwrap_or(u32::MAX)
    }

    /// Whether this account may issue a link right now. The host proves this without
    /// naming the member; a braked member loses it at once because the cap is current.
    pub fn can_issue(&self) -> bool {
        self.remaining() > 0
    }

    /// An actual admission: take one voucher and remember the bond. A bounded overshoot
    /// from concurrent uses is accounted as permanently lost.
    pub fn spend_on_admission(&mut self, bond: &Bond) -> Result<Entry, Refused> {
        let cap = self.standing.cap(&self.policy);
        let key = voucher::bond_key(&self.domain, &bond.0).map_err(|_| Refused)?;
        if self.entries.contains_key(&key) {
            return Err(Refused);
        }
        let entry = self
            .account
            .admit(&self.policy, self.role, cap)
            .map_err(|_| Refused)?;
        self.entries.insert(key, entry);
        Ok(entry)
    }

    /// Called once the bond secret exists on this device.
    pub fn bond_established(&mut self, side: BondSide, bond: Bond) {
        if side == BondSide::Vouchee {
            self.own_bond = Some(bond);
        }
    }

    /// Vouchee side: the tag that posts the success obligation, once success is proven.
    pub fn success_tag(&self) -> Option<[u8; 32]> {
        if self.account.proven == 0 {
            return None;
        }
        let bond = self.own_bond.as_ref()?;
        voucher::obligation_tag(&self.domain, &bond.0, voucher::SUCCESS, 0).ok()
    }

    /// Sponsor side: consume a waiting obligation tag. The tag is recomputed from the
    /// bond, so only the bond holder can name it.
    pub fn consume(&mut self, bond: &Bond, kind: u8, n: u64) -> Result<(), Refused> {
        let key = voucher::bond_key(&self.domain, &bond.0).map_err(|_| Refused)?;
        let entry = self.entries.get_mut(&key).ok_or(Refused)?;
        match kind {
            voucher::SUCCESS if n == 0 => self.account.consume_success(entry).map_err(|_| Refused),
            voucher::PUNISHED if n == entry.punished_seen + 1 => self
                .account
                .consume_punished(entry, &mut self.standing)
                .map_err(|_| Refused),
            voucher::REWARD if n == entry.rewards_seen + 1 => {
                self.account.consume_reward(&self.policy, entry);
                Ok(())
            }
            _ => Err(Refused),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use czkp::standing::Q;

    fn device(role: u8, proven: u64) -> DeviceAllowance {
        let policy = Policy::derive(czkp::reference::params()).unwrap();
        let mut standing = State::new(100, 2 * Q);
        standing.g = 40 * Q;
        let account = Account {
            proven,
            ..Account::default()
        };
        DeviceAllowance::new(policy, role, standing, account)
    }

    #[test]
    fn a_newcomer_cannot_issue_until_proven() {
        assert!(!device(0, 0).can_issue());
        assert!(device(0, 1).can_issue());
        assert!(device(1, 0).can_issue());
    }

    #[test]
    fn admissions_spend_and_success_returns() {
        let mut d = device(0, 1);
        let before = d.remaining();
        let bond = Bond([5; 32]);
        d.spend_on_admission(&bond).unwrap();
        assert_eq!(d.remaining(), before - 1);
        assert!(d.spend_on_admission(&bond).is_err(), "one entry per bond");
        d.consume(&bond, voucher::SUCCESS, 0).unwrap();
        assert_eq!(d.remaining(), before);
        assert!(d.consume(&bond, voucher::SUCCESS, 0).is_err());
    }

    #[test]
    fn a_braked_member_loses_the_right_at_once() {
        let mut d = device(0, 1);
        assert!(d.can_issue());
        let mut braked = State::new(100, 0);
        for _ in 0..50 {
            braked.punished(false);
        }
        d.set_standing(braked, 0);
        // The cap falls to one, so the member allowance clamps to its minimum of one;
        // spending it leaves nothing.
        d.spend_on_admission(&Bond([1; 32])).unwrap();
        assert!(!d.can_issue());
    }

    #[test]
    fn punishment_obligations_arrive_in_order_and_weigh_the_sponsor() {
        let mut d = device(0, 1);
        let bond = Bond([6; 32]);
        d.spend_on_admission(&bond).unwrap();
        assert!(d.consume(&bond, voucher::PUNISHED, 2).is_err());
        let before = d.standing.pr;
        d.consume(&bond, voucher::PUNISHED, 1).unwrap();
        assert!(d.standing.pr > before);
        d.consume(&bond, voucher::REWARD, 1).unwrap();
        assert_eq!(d.account().bonus, 1);
    }

    #[test]
    fn only_a_proven_vouchee_can_name_its_success_tag() {
        let mut d = device(0, 0);
        d.bond_established(BondSide::Vouchee, Bond([7; 32]));
        assert!(d.success_tag().is_none());
        d.account.proven = 3;
        assert!(d.success_tag().is_some());
    }
}
