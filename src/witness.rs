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
#[path = "../tests/internal/witness.rs"]
mod tests;
