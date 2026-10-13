use super::*;
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
        voucher: VoucherParamsIn::from(&czkp::reference::params().voucher),
    }
}
fn request(action: u8) -> Request {
    Request {
        old: Balances {
            reserved: 0,
            accepted: 1,
            declined: 0,
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
        phase: 3,
        outcome: 1,
        kind: 4,
        answered: true,
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
#[test]
fn punishing_costs_the_punisher_one_given_punishment() {
    let p = request(8).prepare().ok().unwrap();
    assert_eq!(p.standing.pg, 1 << 16);
    assert_eq!(p.standing.lc, 1);
    assert_eq!(p.standing.pr, 0);
}
#[test]
fn a_punished_wave_holds_its_slot_until_the_waiting_period_ends() {
    let mut r = request(10);
    r.old.reserved = 1;
    r.phase = 2;
    r.outcome = 0;
    r.kind = 3;
    let punished = r.prepare().ok().unwrap();
    // Held: the slot stays occupied (phase 8) and the punishment counts at once.
    assert_eq!(punished.balances.reserved, 1);
    assert_eq!(punished.balances.punished, 1);
    assert_eq!(punished.phase, 8);
    assert_eq!(punished.standing.pr, 1 << 16);
    // Expiry settles it as a miss: the slot returns and the loan pays.
    r.old = punished.balances;
    r.standing = punished.standing;
    r.phase = punished.phase;
    r.outcome = punished.outcome;
    r.action = 5;
    r.now = 200 + 86_400;
    let settled = r.prepare().ok().unwrap();
    assert_eq!(settled.balances.reserved, 0);
    assert!(settled.standing.a < r.standing.a);
}
#[test]
fn established_punishment_reclassifies_a_sent_outcome() {
    let mut r = request(10);
    let p = r.prepare().ok().unwrap();
    assert_eq!(p.balances.accepted, 0);
    assert_eq!(p.balances.punished, 1);
    assert_eq!(p.standing.pr, 1 << 16);
    r.old = p.balances;
    r.phase = p.phase;
    r.outcome = p.outcome;
    assert!(r.prepare().is_err());
}
#[test]
fn an_answer_is_a_clean_conversation_and_earns_goodwill() {
    let mut r = request(10);
    r.phase = 2;
    r.outcome = 0;
    r.answered = false;
    r.kind = 1;
    r.old.reserved = 1;
    r.old.accepted = 0;
    r.standing.pr = 2 << 16;
    let a = r.prepare().ok().unwrap();
    assert_eq!(a.balances.reserved, 0);
    assert!(a.standing.g >= 1 << 16);
    assert!(a.standing.pr < 2 << 16);
    assert_eq!(a.standing.c, 1 << 16);
}
#[test]
fn a_reservation_needs_pool_headroom() {
    let mut r = request(1);
    r.phase = 1;
    r.outcome = 0;
    r.answered = false;
    r.old.reserved = 0;
    // The newcomer cap is three: three reservations fit, the fourth does not.
    for held in 0..3 {
        r.old.reserved = held;
        assert!(r.prepare().is_ok());
    }
    r.old.reserved = 3;
    assert!(r.prepare().is_err());
}
