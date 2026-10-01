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
