//! Checked integer planning shared by native and wasm holders. The Noir relation
//! independently constrains the plan, map updates, signatures and commitments.
//!
//! Standing v5: the shared pool replaces the token balance. A reservation needs
//! `reserved + amount <= cap`; the standing fields follow czkp's owner module.
#![allow(missing_docs)]
use czkp::standing::{self, Policy, State};
use czkp::voucher;
use serde::{Deserialize, Serialize};
const SAFE: u64 = 9_007_199_254_740_991;
const DAY: u64 = 86_400;

// No Debug implementation: these values are private wallet openings.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Balances {
    pub reserved: u64,
    pub accepted: u64,
    pub declined: u64,
    pub punished: u64,
}
/// The committed standing fields, in the order of the account state.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Standing {
    pub g: u64,
    pub a: u64,
    pub c: u64,
    pub pr: u64,
    pub pg: u64,
    pub lc: u64,
    pub day: u64,
}
/// The rulebook-signed parameters; the tables are derived by czkp, never supplied.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StandingParams {
    pub c0: u64,
    pub h_a: u64,
    pub h_g: u64,
    pub n_half: u64,
    pub n_c: u64,
    pub e_q: u64,
    pub r_max: u64,
    pub r_age: u64,
    pub c_max_q: u64,
    pub c_vet: u64,
    pub age_vet: u64,
    pub boost_q: u64,
    pub boost_days: u64,
    pub slope_q: u64,
    pub mid_q: u64,
    pub kappa_q: u64,
    pub loan_use_q: u64,
    /// Voucher parameters; the defaults apply when a caller predates them.
    #[serde(default)]
    pub voucher: VoucherParamsIn,
}
/// The rulebook-signed voucher parameters (czkp `VoucherParams`).
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VoucherParamsIn {
    pub slope_q: [u64; 3],
    pub min: [u64; 3],
    pub max: [u64; 3],
    pub days: u64,
    pub k: u64,
    pub max_punished: u64,
    pub brake_cap: u64,
    pub reward_cap: u64,
}
impl Default for VoucherParamsIn {
    fn default() -> Self {
        let d = standing::VoucherParams::default();
        VoucherParamsIn {
            slope_q: d.slope_q,
            min: d.min,
            max: d.max,
            days: d.days,
            k: d.k,
            max_punished: d.max_punished,
            brake_cap: d.brake_cap,
            reward_cap: d.reward_cap,
        }
    }
}
impl StandingParams {
    fn policy(&self) -> Result<Policy, Invalid> {
        Policy::derive(standing::Params {
            c0: self.c0,
            h_a: self.h_a,
            h_g: self.h_g,
            n_half: self.n_half,
            n_c: self.n_c,
            e_q: self.e_q,
            r_max: self.r_max,
            r_age: self.r_age,
            c_max_q: self.c_max_q,
            c_vet: self.c_vet,
            age_vet: self.age_vet,
            boost_q: self.boost_q,
            boost_days: self.boost_days,
            slope_q: self.slope_q,
            mid_q: self.mid_q,
            kappa_q: self.kappa_q,
            loan_use_q: self.loan_use_q,
            voucher: standing::VoucherParams {
                slope_q: self.voucher.slope_q,
                min: self.voucher.min,
                max: self.voucher.max,
                days: self.voucher.days,
                k: self.voucher.k,
                max_punished: self.voucher.max_punished,
                brake_cap: self.voucher.brake_cap,
                reward_cap: self.voucher.reward_cap,
            },
        })
        .map_err(|_| Invalid)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub old: Balances,
    pub standing: Standing,
    pub params: StandingParams,
    /// Account creation time in seconds (Opening.created_at).
    pub created_at: u64,
    /// The proof time in seconds (`now`).
    pub now: u64,
    pub action: u8,
    pub amount: u32,
    pub role: u8,
    pub phase: u8,
    pub outcome: u8,
    pub kind: u8,
    pub answered: bool,
    pub self_punished: bool,
    pub change_cost: u32,
    /// The voucher part of the account (zero for an account that has none yet).
    #[serde(default)]
    pub voucher: VoucherAccount,
    /// The sponsor's role class (member, admin, root) for admission accounting.
    #[serde(default)]
    pub voucher_role: u8,
    /// Count this answered conversation toward the account's own success proof.
    #[serde(default)]
    pub count: bool,
    /// Obligation kind and sequence number (action 13).
    #[serde(default)]
    pub obligation_kind: u8,
    #[serde(default)]
    pub obligation_n: u64,
    /// The sponsor's remembered entry for the bond (action 13).
    #[serde(default)]
    pub entry: BondEntryIo,
}
/// The voucher fields of the committed account (czkp `voucher::Account`).
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VoucherAccount {
    pub proven: u64,
    pub away: u64,
    pub lost: u64,
    pub bonus: u64,
    pub returned: u64,
    pub answers: u64,
}
/// What the sponsor remembers about one bond (czkp `voucher::Entry`).
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BondEntryIo {
    pub limit: u64,
    pub done: bool,
    pub overshoot: bool,
    pub punished_seen: u64,
    pub rewards_seen: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub balances: Balances,
    pub standing: Standing,
    /// The pool size the reservation check used (never below one).
    pub cap: u64,
    /// The derived policy tables in the circuit's private input shape.
    pub policy: PolicyOut,
    pub phase: u8,
    pub outcome: u8,
    pub authorization: u8,
    pub answered: bool,
    pub self_punished: bool,
    pub voucher: VoucherAccount,
    /// The bond entry after the action (admission creates it, consumption updates it).
    pub entry: BondEntryIo,
}
/// The circuit's `StandingPolicy` input; its digest is bound by the rulebook signature.
#[derive(Serialize)]
pub struct PolicyOut {
    pub c0: u64,
    pub h_a: u64,
    pub h_g: u64,
    pub n_half: u64,
    pub n_c: u64,
    pub e_q: u64,
    pub r_max: u64,
    pub r_age: u64,
    pub c_max_q: u64,
    pub c_vet: u64,
    pub age_vet: u64,
    pub boost_q: u64,
    pub boost_days: u64,
    pub slope_q: u64,
    pub mid_q: u64,
    pub kappa_q: u64,
    pub loan_use_q: u64,
    pub factor: u64,
    pub v_slope: [u64; 3],
    pub v_min: [u64; 3],
    pub v_max: [u64; 3],
    pub v_days: u64,
    pub v_k: u64,
    pub v_max_punished: u64,
    pub v_brake_cap: u64,
    pub v_reward_cap: u64,
    pub trust: Vec<u64>,
    pub g_table: Vec<u64>,
    pub a_table: Vec<u64>,
}
fn policy_out(p: &Policy) -> PolicyOut {
    let q = &p.params;
    PolicyOut {
        c0: q.c0,
        h_a: q.h_a,
        h_g: q.h_g,
        n_half: q.n_half,
        n_c: q.n_c,
        e_q: q.e_q,
        r_max: q.r_max,
        r_age: q.r_age,
        c_max_q: q.c_max_q,
        c_vet: q.c_vet,
        age_vet: q.age_vet,
        boost_q: q.boost_q,
        boost_days: q.boost_days,
        slope_q: q.slope_q,
        mid_q: q.mid_q,
        kappa_q: q.kappa_q,
        loan_use_q: q.loan_use_q,
        factor: p.factor,
        v_slope: q.voucher.slope_q,
        v_min: q.voucher.min,
        v_max: q.voucher.max,
        v_days: q.voucher.days,
        v_k: q.voucher.k,
        v_max_punished: q.voucher.max_punished,
        v_brake_cap: q.voucher.brake_cap,
        v_reward_cap: q.voucher.reward_cap,
        trust: p.trust.to_vec(),
        g_table: p.g_table.to_vec(),
        a_table: p.a_table.to_vec(),
    }
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
fn state(s: &Standing) -> State {
    State {
        g: s.g,
        a: s.a,
        c: s.c,
        pr: s.pr,
        pg: s.pg,
        lc: s.lc,
        day: s.day,
        joined: 0,
    }
}
impl Request {
    pub fn prepare(&self) -> Result<Plan, Invalid> {
        let mut b = self.old;
        let s = &self.standing;
        let joined = self.created_at / DAY;
        if self.role > 1
            || self.voucher_role > 2
            || [b.reserved, b.accepted, b.declined, b.punished]
                .iter()
                .any(|n| *n > SAFE)
            || [s.g, s.a, s.c, s.pr, s.pg, s.lc, s.day]
                .iter()
                .any(|n| *n > SAFE)
            || self.created_at == 0
            || self.now > SAFE
            || s.day < joined
        {
            return Err(Invalid);
        }
        let policy = self.params.policy()?;
        // Calendar decay to the proof day, then the pool for this transition.
        let mut st = state(s);
        st.joined = joined;
        st.advance(self.now / DAY, &policy);
        let cap = st.cap(&policy);
        let mut phase = self.phase;
        let mut outcome = self.outcome;
        let mut authorization = 0;
        let mut answered = self.answered;
        let mut self_punished = self.self_punished;
        let mut account = voucher::Account {
            proven: self.voucher.proven,
            away: self.voucher.away,
            lost: self.voucher.lost,
            bonus: self.voucher.bonus,
            returned: self.voucher.returned,
            answers: self.voucher.answers,
        };
        let mut entry = voucher::Entry {
            limit: self.entry.limit,
            done: self.entry.done,
            overshoot: self.entry.overshoot,
            punished_seen: self.entry.punished_seen,
            rewards_seen: self.entry.rewards_seen,
        };
        // An answered conversation with a qualifying peer counts toward the success proof.
        let counted = |a: &mut voucher::Account| -> Result<(), Invalid> {
            if self.count {
                a.answers = add(a.answers, 1)?;
            }
            Ok(())
        };
        match self.action {
            1 => {
                if self.amount == 0 || phase != 1 || outcome != 0 {
                    return Err(Invalid);
                }
                // Pool check, both roles: pending first contacts stay within the cap.
                if b.reserved.saturating_add(self.amount as u64) > cap {
                    return Err(Invalid);
                }
                b.reserved = add(b.reserved, self.amount as u64)?;
            }
            2 => {
                if phase != 1 {
                    return Err(Invalid);
                }
                phase = 2;
            }
            3..=5 => {
                let phase_ok = match self.action {
                    4 => phase == 1,
                    5 => phase == 2 || phase == 8,
                    _ => phase == 2,
                };
                if !phase_ok {
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
                        // An Answer is a clean conversation in either role.
                        if self.role == 0 {
                            st.answer_received(&policy);
                        } else {
                            st.answer_given(&policy);
                        }
                        counted(&mut account)?;
                    }
                    if self.role == 0 {
                        b.accepted = add(b.accepted, 1)?;
                    } else {
                        authorization = self.kind;
                    }
                }
                if self.action == 5 {
                    // The waiting period ended without an Answer: the loan pays the miss.
                    st.unanswered(&policy);
                }
                phase = self.action;
                b.reserved = sub(b.reserved, self.amount as u64)?;
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
                    // Punishing costs the punisher the same as the target.
                    st.punish_given();
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
                        // The obligation is consumed: the punishment counts fully.
                        st.punished(kind == 4 || self.answered);
                    }
                }
                if kind >= 3 {
                    // My own wave punished by its target holds its slot until the
                    // waiting period ends (phase 8); every other punishment frees it.
                    let live = [1, 2].contains(&phase);
                    let hold = !own && kind == 3 && self.role == 0 && live;
                    if live && !hold {
                        b.reserved = sub(b.reserved, self.amount as u64)?;
                    }
                    phase = if hold { 8 } else { 7 };
                    if kind == 4 {
                        answered = true;
                    }
                    if !own {
                        outcome = 3;
                    }
                } else if outcome != 3 {
                    if kind == 1 && outcome == 0 {
                        if [1, 2].contains(&phase) {
                            b.reserved = sub(b.reserved, self.amount as u64)?;
                        } else if ![4, 5].contains(&phase) {
                            return Err(Invalid);
                        }
                        phase = 3;
                        answered = true;
                        st.answer_received(&policy);
                        counted(&mut account)?;
                    }
                    if kind == 2 && phase == 1 {
                        phase = 2;
                    }
                    outcome = kind;
                }
            }
            9 => {
                // A binding change needs pool headroom and holds nothing.
                if self.change_cost == 0 || b.reserved.saturating_add(self.change_cost as u64) > cap
                {
                    return Err(Invalid);
                }
            }
            11 => {}
            12 => {
                // The sponsor spends one voucher on an actual admission.
                entry = account
                    .admit(&policy, self.voucher_role, cap)
                    .map_err(|_| Invalid)?;
            }
            13 => match self.obligation_kind {
                1 => {
                    if self.obligation_n != 0 {
                        return Err(Invalid);
                    }
                    account.consume_success(&mut entry).map_err(|_| Invalid)?;
                }
                2 => {
                    if self.obligation_n != entry.punished_seen + 1 {
                        return Err(Invalid);
                    }
                    account
                        .consume_punished(&mut entry, &mut st)
                        .map_err(|_| Invalid)?;
                }
                3 => {
                    if self.obligation_n != entry.rewards_seen + 1 {
                        return Err(Invalid);
                    }
                    account.consume_reward(&policy, &mut entry);
                }
                _ => return Err(Invalid),
            },
            14 => {
                // The account's own success proof; the circuit repeats every threshold.
                st.joined = joined;
                if self.now / DAY == 0
                    || self.now / DAY < joined + policy.params.voucher.days
                    || !voucher::success_ready(&policy, &st, &account, self.old.punished)
                {
                    return Err(Invalid);
                }
                account.proven = self.now / DAY;
            }
            // 6 (refill) is retired: slots return on settlement.
            _ => return Err(Invalid),
        }
        let standing = Standing {
            g: st.g,
            a: st.a,
            c: st.c,
            pr: st.pr,
            pg: st.pg,
            lc: st.lc,
            day: st.day,
        };
        if [st.g, st.a, st.c, st.pr, st.pg, st.lc]
            .iter()
            .any(|n| *n > SAFE)
        {
            return Err(Invalid);
        }
        Ok(Plan {
            balances: b,
            standing,
            cap,
            policy: policy_out(&policy),
            phase,
            outcome,
            authorization,
            answered,
            self_punished,
            voucher: VoucherAccount {
                proven: account.proven,
                away: account.away,
                lost: account.lost,
                bonus: account.bonus,
                returned: account.returned,
                answers: account.answers,
            },
            entry: BondEntryIo {
                limit: entry.limit,
                done: entry.done,
                overshoot: entry.overshoot,
                punished_seen: entry.punished_seen,
                rewards_seen: entry.rewards_seen,
            },
        })
    }
}

#[cfg(test)]
#[path = "../tests/internal/witness.rs"]
mod tests;
