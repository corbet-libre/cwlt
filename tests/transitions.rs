//! Real planner state partitions, also executed as wasm.
use cwlt::witness::{Balances, Request};

fn request(action: u8) -> Request {
    Request {
        old: Balances {
            available: 2,
            reserved: 1,
            debt: 0,
            accepted: 1,
            declined: 1,
            punished: 0,
        },
        action,
        capacity: 3,
        amount: 1,
        role: 0,
        phase: 1,
        outcome: 0,
        kind: 1,
        answered: false,
        self_punished: false,
        change_cost: 1,
        refill_units: 1,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_transition_preserves_budget_debt_and_counter_bounds() {
    let safe = 9_007_199_254_740_991;
    let mut accepted = [0; 12];
    let mut rejected = [0; 12];
    for action in 1..=11 {
        for role in 0..=2 {
            for phase in 0..=8 {
                for outcome in 0..=4 {
                    for kind in 0..=5 {
                        for flags in 0..4 {
                            for partition in 0..14 {
                                let mut r = request(action);
                                r.role = role;
                                r.phase = phase;
                                r.outcome = outcome;
                                r.kind = kind;
                                r.answered = flags & 1 != 0;
                                r.self_punished = flags & 2 != 0;
                                match partition {
                                    0 => {}
                                    1 => r.old.available = 0,
                                    2 => r.old.reserved = 0,
                                    3 => r.old.accepted = 0,
                                    4 => r.old.declined = 0,
                                    5 => r.old.punished = safe,
                                    6 => r.old.accepted = safe,
                                    7 => r.old.declined = safe,
                                    8 => {
                                        r.old.available = 0;
                                        r.old.debt = 2;
                                    }
                                    9 => r.old.debt = 1,
                                    10 => r.amount = 0,
                                    11 => r.amount = u32::MAX,
                                    12 => r.change_cost = 0,
                                    _ => r.refill_units = u32::MAX,
                                }
                                match r.prepare() {
                                    Ok(p) => {
                                        accepted[action as usize] += 1;
                                        let b = p.balances;
                                        assert!(
                                            u64::from(b.available) + b.reserved
                                                <= u64::from(r.capacity)
                                        );
                                        assert!(b.debt == 0 || b.available == 0);
                                        assert!(
                                            [b.debt, b.accepted, b.declined, b.punished]
                                                .iter()
                                                .all(|v| *v <= safe)
                                        );
                                        if action == 6 {
                                            assert!(b.debt <= r.old.debt);
                                        }
                                        if action == 8 {
                                            assert!(p.self_punished);
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
    for action in 1..=11 {
        assert!(accepted[action] > 0, "action {action} never accepted");
        assert!(rejected[action] > 0, "action {action} never refused");
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_state_and_wire_input_fail_closed() {
    for action in [0, 12, 255] {
        assert!(request(action).prepare().is_err());
    }
    let mut r = request(11);
    r.capacity = 1;
    assert!(r.prepare().is_err());
    r.capacity = 3;
    r.old.debt = 9_007_199_254_740_992;
    assert!(r.prepare().is_err());
    for text in ["", "{}", "null", "[]", &"x".repeat(8193)] {
        assert!(cwlt::prepare(text).is_err());
    }
    let text = r#"{"old":{"available":0,"reserved":0,"debt":1,"accepted":0,"declined":0,"punished":0},"action":6,"capacity":3,"amount":1,"role":0,"phase":0,"outcome":0,"kind":0,"answered":false,"selfPunished":false,"changeCost":1,"refillUnits":1}"#;
    let result: serde_json::Value = serde_json::from_str(&cwlt::prepare(text).unwrap()).unwrap();
    assert_eq!(result["balances"]["debt"], 0);
    assert_eq!(result["balances"]["available"], 0);
    assert!(cwlt::prepare(&text.replace("\"action\":6", "\"action\":0")).is_err());
}
