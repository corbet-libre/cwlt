//! Real planner state partitions, also executed as wasm.
use cwlt::witness::{
    Balances, BondEntryIo, Request, Standing, StandingParams, VoucherAccount, VoucherParamsIn,
};

fn params() -> StandingParams {
    StandingParams {
        c0: 3,
        h_a: 14,
        h_g: 14,
        n_half: 25,
        n_c: 60,
        e_q: 16_384,
        r_max: 40,
        r_age: 2,
        c_max_q: 52_428,
        c_vet: 30,
        age_vet: 60,
        boost_q: 65_536,
        boost_days: 30,
        slope_q: 262_144,
        mid_q: 49_152,
        kappa_q: 131_072,
        loan_use_q: 16_384,
        voucher: VoucherParamsIn::default(),
    }
}

fn request(action: u8) -> Request {
    Request {
        old: Balances {
            reserved: 1,
            accepted: 1,
            declined: 1,
            punished: 0,
        },
        standing: Standing {
            g: 0,
            a: 2 << 16,
            c: 0,
            pr: 0,
            pg: 0,
            lc: 0,
            day: 0,
        },
        params: params(),
        created_at: 100,
        now: 200,
        action,
        amount: 1,
        role: 0,
        phase: 1,
        outcome: 0,
        kind: 1,
        answered: false,
        self_punished: false,
        change_cost: 1,
        voucher: VoucherAccount::default(),
        voucher_role: 0,
        count: false,
        obligation_kind: 0,
        obligation_n: 0,
        entry: BondEntryIo::default(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_transition_keeps_the_pool_and_counter_bounds() {
    let safe = 9_007_199_254_740_991;
    let mut accepted = [0; 12];
    let mut rejected = [0; 12];
    for action in 1..=11 {
        for role in 0..=2 {
            for phase in 0..=8 {
                for outcome in 0..=3 {
                    for kind in 0..=4 {
                        for flags in 0..4 {
                            for partition in 0..11 {
                                let mut r = request(action);
                                r.role = role;
                                r.phase = phase;
                                r.outcome = outcome;
                                r.kind = kind;
                                r.answered = flags & 1 != 0;
                                r.self_punished = flags & 2 != 0;
                                match partition {
                                    0 => {}
                                    1 => r.old.reserved = 0,
                                    2 => r.old.reserved = 9,
                                    3 => r.old.accepted = 0,
                                    4 => r.old.declined = 0,
                                    5 => r.old.punished = safe,
                                    6 => r.old.accepted = safe,
                                    7 => r.old.declined = safe,
                                    8 => r.amount = 0,
                                    9 => r.amount = u32::MAX,
                                    _ => r.change_cost = 0,
                                }
                                match r.prepare() {
                                    Ok(p) => {
                                        accepted[action as usize] += 1;
                                        let b = p.balances;
                                        assert!(p.cap >= 1);
                                        assert!(
                                            [b.reserved, b.accepted, b.declined, b.punished]
                                                .iter()
                                                .all(|v| *v <= safe)
                                        );
                                        // Only a reservation may grow the pool, and only within the cap.
                                        if action == 1 {
                                            assert!(b.reserved <= p.cap);
                                        } else {
                                            assert!(b.reserved <= r.old.reserved);
                                        }
                                        if action == 8 {
                                            assert!(p.self_punished);
                                            assert_eq!(p.standing.pg, r.standing.pg + (1 << 16));
                                        }
                                        if action == 11 {
                                            assert!(b == r.old);
                                        }
                                    }
                                    Err(_) => rejected[action as usize] += 1,
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Action 6 (refill) is retired and always refused.
    assert_eq!(accepted[6], 0);
    for action in (1..=11).filter(|a| *a != 6) {
        assert!(accepted[action] > 0, "action {action} never accepted");
        assert!(rejected[action] > 0, "action {action} never refused");
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_state_and_wire_input_fail_closed() {
    for action in [0, 6, 15, 255] {
        assert!(request(action).prepare().is_err());
    }
    let mut r = request(11);
    r.old.punished = 9_007_199_254_740_992;
    assert!(r.prepare().is_err());
    let mut r = request(11);
    r.created_at = 0;
    assert!(r.prepare().is_err());
    let mut r = request(11);
    r.standing.day = 0;
    r.created_at = 3 * 86_400;
    assert!(r.prepare().is_err());
    let mut r = request(11);
    r.params.n_half = 4;
    assert!(r.prepare().is_err());
    for text in ["", "{}", "null", "[]", &"x".repeat(8193)] {
        assert!(cwlt::prepare(text).is_err());
    }
    let text = r#"{"old":{"reserved":0,"accepted":0,"declined":0,"punished":0},"standing":{"g":0,"a":131072,"c":0,"pr":0,"pg":0,"lc":0,"day":0},"params":{"c0":3,"hA":14,"hG":14,"nHalf":25,"nC":60,"eQ":16384,"rMax":40,"rAge":2,"cMaxQ":52428,"cVet":30,"ageVet":60,"boostQ":65536,"boostDays":30,"slopeQ":262144,"midQ":49152,"kappaQ":131072,"loanUseQ":16384},"createdAt":100,"now":200,"action":11,"amount":1,"role":0,"phase":1,"outcome":0,"kind":0,"answered":false,"selfPunished":false,"changeCost":1}"#;
    let result: serde_json::Value = serde_json::from_str(&cwlt::prepare(text).unwrap()).unwrap();
    assert_eq!(result["cap"], 3);
    assert_eq!(result["policy"]["trust"].as_array().unwrap().len(), 65);
    assert_eq!(result["policy"]["g_table"].as_array().unwrap().len(), 64);
    assert!(cwlt::prepare(&text.replace("\"action\":11", "\"action\":0")).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn voucher_actions_follow_the_accounting_rules() {
    // Admission: a proven member spends one voucher; an unproven one overshoots and loses it.
    let mut r = request(12);
    r.voucher.proven = 1;
    let plan = r.prepare().ok().unwrap();
    assert_eq!((plan.voucher.away, plan.voucher.lost), (1, 0));
    assert!(plan.entry.limit >= 1 && !plan.entry.overshoot);
    let plan = request(12).prepare().ok().unwrap();
    assert_eq!((plan.voucher.away, plan.voucher.lost), (0, 1));
    assert!(plan.entry.overshoot);
    // Success returns the voucher once.
    let mut r = request(13);
    r.voucher = VoucherAccount {
        proven: 1,
        away: 1,
        ..VoucherAccount::default()
    };
    r.entry = BondEntryIo {
        limit: 2,
        ..BondEntryIo::default()
    };
    r.obligation_kind = 1;
    let plan = r.prepare().ok().unwrap();
    assert_eq!(
        (plan.voucher.away, plan.voucher.returned, plan.entry.done),
        (0, 1, true)
    );
    r.entry.done = true;
    assert!(r.prepare().is_err());
    // A vouchee punishment weighs one over the limit at issuance, in order.
    let mut r = request(13);
    r.entry = BondEntryIo {
        limit: 4,
        ..BondEntryIo::default()
    };
    r.obligation_kind = 2;
    r.obligation_n = 2;
    assert!(r.prepare().is_err());
    r.obligation_n = 1;
    let plan = r.prepare().ok().unwrap();
    assert_eq!(plan.standing.pr, 65_536 / 4);
    // Reward is capped at two.
    let mut r = request(13);
    r.obligation_kind = 3;
    r.obligation_n = 1;
    r.voucher.bonus = 2;
    assert_eq!(r.prepare().ok().unwrap().voucher.bonus, 2);
    // Success proof: every threshold must hold.
    let mut r = request(14);
    r.created_at = 86_400;
    r.now = 40 * 86_400;
    r.standing.day = 40;
    r.voucher.answers = 3;
    assert_eq!(r.prepare().ok().unwrap().voucher.proven, 40);
    r.voucher.answers = 2;
    assert!(r.prepare().is_err());
    r.voucher.answers = 3;
    r.now = 20 * 86_400;
    assert!(r.prepare().is_err());
}

/// The vouchee journey of the proof scenario: three counted Answers in the first days,
/// then the success proof once the minimum membership has passed.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_vouchee_with_three_counted_answers_proves_success_after_the_waiting_days() {
    let mut r = request(10);
    r.old = Balances {
        reserved: 3,
        accepted: 0,
        declined: 0,
        punished: 0,
    };
    r.created_at = 120;
    r.count = true;
    r.phase = 1;
    r.role = 0;
    r.kind = 1;
    for step in 0..3_u64 {
        r.now = 200 + step * 10;
        let plan = r.prepare().ok().unwrap();
        r.old = plan.balances;
        r.standing = plan.standing;
        r.voucher = plan.voucher;
    }
    assert_eq!(r.voucher.answers, 3);
    let mut prove = r;
    prove.action = 14;
    prove.now = 31 * 86_400 + 10;
    let plan = prove.prepare().ok().unwrap();
    assert_eq!(plan.voucher.proven, 31);
    // One day short of the waiting period must fail.
    prove.now = 29 * 86_400 + 10;
    assert!(prove.prepare().is_err());
}
