//! Checked integer planning shared by native and wasm holders. The Noir relation
//! independently constrains the plan, map updates, signatures and commitments.
#![allow(missing_docs)]
use serde::{Deserialize, Serialize};
const SAFE: u64 = 9_007_199_254_740_991;

// No Debug implementation: these values are private wallet openings.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Balances {
    pub available: u32,
    pub reserved: u64,
    pub debt: u64,
    pub accepted: u64,
    pub declined: u64,
    pub punished: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub old: Balances,
    pub action: u8,
    pub capacity: u32,
    pub amount: u32,
    pub role: u8,
    pub phase: u8,
    pub outcome: u8,
    pub kind: u8,
    pub answered: bool,
    pub self_punished: bool,
    pub change_cost: u32,
    pub refill_units: u32,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub balances: Balances,
    pub phase: u8,
    pub outcome: u8,
    pub authorization: u8,
    pub answered: bool,
    pub self_punished: bool,
}
pub struct Invalid;
fn sub(value: u64, amount: u64) -> Result<u64, Invalid> {
    value.checked_sub(amount).ok_or(Invalid)
}
fn add(value: u64, amount: u64) -> Result<u64, Invalid> {
    value
        .checked_add(amount)
        .filter(|n| *n <= SAFE)
        .ok_or(Invalid)
}
impl Request {
    pub fn prepare(&self) -> Result<Plan, Invalid> {
        let mut b = self.old;
        if b.available as u128 + b.reserved as u128 > self.capacity as u128
            || self.role > 1
            || [b.debt, b.accepted, b.declined, b.punished]
                .iter()
                .any(|n| *n > SAFE)
            || (b.debt > 0 && b.available > 0)
        {
            return Err(Invalid);
        }
        let mut phase = self.phase;
        let mut outcome = self.outcome;
        let mut authorization = 0;
        let mut answered = self.answered;
        let mut self_punished = self.self_punished;
        match self.action {
            1 => {
                if b.debt > 0 || self.amount == 0 || phase != 1 || outcome != 0 {
                    return Err(Invalid);
                }
                b.available = b.available.checked_sub(self.amount).ok_or(Invalid)?;
                b.reserved = add(b.reserved, self.amount as u64)?;
            }
            2 => {
                if phase != 1 {
                    return Err(Invalid);
                }
                phase = 2;
            }
            3..=5 => {
                let expected = if self.action == 4 { 1 } else { 2 };
                if phase != expected {
                    return Err(Invalid);
                }
                if self.action == 3 {
                    if outcome != 0
                        || !(1..=2).contains(&self.kind)
                        || (self.role == 0 && self.kind != 1)
                    {
                        return Err(Invalid);
                    }
                    outcome = self.kind;
                    if self.kind == 1 {
                        answered = true;
                    }
                    if self.role == 0 {
                        b.accepted = add(b.accepted, 1)?;
                    } else {
                        authorization = self.kind;
                    }
                }
                phase = self.action;
                b.available = b.available.checked_add(self.amount).ok_or(Invalid)?;
                b.reserved = sub(b.reserved, self.amount as u64)?;
            }
            6 => {
                let paid = b.debt.min(self.refill_units as u64);
                b.debt -= paid;
                let headroom = self.capacity as u64 - b.available as u64 - b.reserved;
                let issued = headroom.min(self.refill_units as u64 - paid);
                b.available = b.available.checked_add(issued as u32).ok_or(Invalid)?;
            }
            7 | 8 | 10 => {
                let own = self.action != 10;
                let kind = if self.action == 7 {
                    3
                } else if self.action == 8 {
                    4
                } else {
                    self.kind
                };
                if !(1..=4).contains(&kind) {
                    return Err(Invalid);
                }
                if own {
                    if self.action == 7
                        && (self.role != 1 || ![1, 2].contains(&phase) || outcome != 0)
                    {
                        return Err(Invalid);
                    }
                    if self.action == 8 && (!answered || self_punished) {
                        return Err(Invalid);
                    }
                    authorization = kind;
                    self_punished = true;
                } else {
                    if (kind != 4 && self.role != 0)
                        || (kind >= 3 && outcome == 3)
                        || (kind < 3 && outcome != 0 && outcome != kind && outcome != 3)
                    {
                        return Err(Invalid);
                    }
                    if kind == 1 && outcome == 0 {
                        b.accepted = add(b.accepted, 1)?;
                    }
                    if kind == 2 && outcome == 0 {
                        b.declined = add(b.declined, 1)?;
                    }
                    if kind >= 3 {
                        if outcome == 1 && self.role == 0 {
                            b.accepted = sub(b.accepted, 1)?;
                        }
                        if outcome == 2 && self.role == 0 {
                            b.declined = sub(b.declined, 1)?;
                        }
                        b.punished = add(b.punished, 1)?;
                    }
                }
                if kind >= 3 {
                    if [1, 2].contains(&phase) {
                        b.reserved = sub(b.reserved, self.amount as u64)?;
                        if kind == 4 {
                            b.available = b.available.checked_add(self.amount).ok_or(Invalid)?;
                        }
                    }
                    if kind == 4 || ![1, 2].contains(&phase) {
                        let cost = if kind == 4 { 1 } else { self.amount as u64 };
                        let paid = cost.min(b.available as u64);
                        b.available -= paid as u32;
                        b.debt = add(b.debt, cost - paid)?;
                    }
                    phase = 7;
                    if kind == 4 {
                        answered = true;
                    }
                    if !own {
                        outcome = 3;
                    }
                } else if outcome != 3 {
                    if kind == 1 && outcome == 0 {
                        if [1, 2].contains(&phase) {
                            b.available = b.available.checked_add(self.amount).ok_or(Invalid)?;
                            b.reserved = sub(b.reserved, self.amount as u64)?;
                        } else if ![4, 5].contains(&phase) {
                            return Err(Invalid);
                        }
                        phase = 3;
                        answered = true;
                    }
                    if kind == 2 && phase == 1 {
                        phase = 2;
                    }
                    outcome = kind;
                }
            }
            9 => {
                if b.debt > 0 || self.change_cost == 0 {
                    return Err(Invalid);
                }
                b.available = b.available.checked_sub(self.change_cost).ok_or(Invalid)?;
            }
            11 => {}
            _ => return Err(Invalid),
        }
        let paid = b.debt.min(b.available as u64);
        b.available -= paid as u32;
        b.debt -= paid;
        // Every accepted action either transfers the same amount between available
        // and reserved, reduces their sum, or refills only the checked headroom.
        // Debt repayment above can only reduce that sum. The entry capacity bound
        // therefore also holds here; the independent Noir relation checks it too.
        Ok(Plan {
            balances: b,
            phase,
            outcome,
            authorization,
            answered,
            self_punished,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(action: u8) -> Request {
        Request {
            old: Balances {
                available: 0,
                reserved: 0,
                debt: 0,
                accepted: 1,
                declined: 0,
                punished: 0,
            },
            action,
            capacity: 3,
            amount: 1,
            role: 0,
            phase: 3,
            outcome: 1,
            kind: 4,
            answered: true,
            self_punished: false,
            change_cost: 1,
            refill_units: 1,
        }
    }
    #[test]
    fn punishment_at_zero_becomes_debt_and_first_refill_pays_it() {
        let burn = request(8).prepare().ok().unwrap();
        assert_eq!(burn.balances.debt, 1);
        let mut refill = request(6);
        refill.old = burn.balances;
        let paid = refill.prepare().ok().unwrap();
        assert_eq!(paid.balances.debt, 0);
        assert_eq!(paid.balances.available, 0);
        refill.old = paid.balances;
        assert_eq!(refill.prepare().ok().unwrap().balances.available, 1);
    }
    #[test]
    fn target_cannot_recover_a_punished_reservation() {
        let mut r = request(10);
        r.old.reserved = 1;
        r.phase = 2;
        r.outcome = 0;
        r.kind = 3;
        let punished = r.prepare().ok().unwrap();
        assert_eq!(punished.balances.reserved, 0);
        assert_eq!(punished.balances.punished, 1);
        r.old = punished.balances;
        r.phase = punished.phase;
        r.outcome = punished.outcome;
        r.action = 5;
        assert!(r.prepare().is_err());
    }
    #[test]
    fn established_punishment_reclassifies_a_sent_outcome() {
        let mut r = request(10);
        r.old.available = 1;
        let p = r.prepare().ok().unwrap();
        assert_eq!(p.balances.accepted, 0);
        assert_eq!(p.balances.punished, 1);
        assert_eq!(p.balances.available, 0);
        r.old = p.balances;
        r.phase = p.phase;
        r.outcome = p.outcome;
        assert!(r.prepare().is_err());
    }
    #[test]
    fn established_delivery_order_cannot_change_the_burn_or_record() {
        let mut r = request(10);
        r.old.available = 1;
        r.old.reserved = 2;
        r.old.accepted = 0;
        r.amount = 2;
        r.phase = 1;
        r.outcome = 0;
        r.answered = false;
        let punished = r.prepare().ok().unwrap();
        assert_eq!(punished.balances.available, 2);
        assert_eq!(punished.balances.reserved, 0);
        assert_eq!(punished.balances.punished, 1);
        let mut late = request(10);
        late.old = punished.balances;
        late.phase = punished.phase;
        late.outcome = punished.outcome;
        late.answered = punished.answered;
        late.kind = 1;
        let terminal = late.prepare().ok().unwrap();
        assert!(terminal.balances == punished.balances);
        assert_eq!(terminal.phase, 7);
        r.kind = 1;
        let answer = r.prepare().ok().unwrap();
        r.old = answer.balances;
        r.phase = answer.phase;
        r.outcome = answer.outcome;
        r.answered = answer.answered;
        r.kind = 4;
        assert!(r.prepare().ok().unwrap().balances == terminal.balances);
    }
}
