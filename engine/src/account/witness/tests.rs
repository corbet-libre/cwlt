//! Parity with the former TypeScript builders: the golden vectors record every builder input and
//! output of one scenario (generated once from cwlt c5259f4 `runtime/*.mts` and cblc
//! `runtime/extensions/waves.mts` with deterministic blinds); the Rust builders must reproduce
//! them exactly, refusals included.
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/vectors/witness/golden.json"
);

/// Decimal text of a big number to 32 big-endian bytes.
fn decimal(text: &str) -> Field {
    let mut out = [0u8; 32];
    for digit in text.bytes() {
        let mut carry = u32::from(digit - b'0');
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 255) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "number exceeds 32 bytes");
    }
    out
}
fn hex_to_decimal(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    // Repeated division by 10 of the big-endian byte string.
    let mut digits = Vec::new();
    let mut number = bytes;
    while number.iter().any(|b| *b != 0) {
        let mut rest = 0u32;
        for byte in &mut number {
            let v = rest * 256 + u32::from(*byte);
            *byte = (v / 10) as u8;
            rest = v % 10;
        }
        digits.push(char::from(b'0' + rest as u8));
    }
    if digits.is_empty() {
        digits.push('0');
    }
    digits.iter().rev().collect()
}
/// One spelling for every number: decimal strings (TS bigint), hex fields and JSON numbers.
fn canon(v: &Value) -> Value {
    match v {
        Value::Number(n) => Value::String(n.to_string()),
        Value::String(s) if s.starts_with("0x") => Value::String(hex_to_decimal(&s[2..])),
        Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), canon(v))).collect()),
        other => other.clone(),
    }
}
fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    let items: Vec<u8> = v
        .as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    items.try_into().expect("length")
}
fn num(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}
fn event(v: &Value) -> Field {
    decimal(v.as_str().unwrap())
}
fn resolution(v: &Value) -> Resolution {
    Resolution {
        kind: num(&v["kind"]) as u8,
        issued_at: num(&v["issuedAt"]),
        history_digest: bytes(&v["historyDigest"]),
        ed25519_receipt_digest: bytes(&v["ed25519ReceiptDigest"]),
        signature: bytes(&v["signature"]),
    }
}
fn acknowledgment(v: &Value) -> Option<Acknowledgment> {
    (!v.is_null()).then(|| Acknowledgment {
        issued_at: num(&v["issuedAt"]),
        signature: bytes(&v["signature"]),
    })
}
fn entry_of(v: &Value) -> BondEntry {
    BondEntry {
        limit: num(&v["limit"]),
        done: v["done"].as_bool().unwrap(),
        overshoot: v["overshoot"].as_bool().unwrap(),
        punished_seen: num(v.get("punished_seen").unwrap_or(&v["punishedSeen"])),
        rewards_seen: num(v.get("rewards_seen").unwrap_or(&v["rewardsSeen"])),
    }
}
fn settled_of(v: &Value) -> Option<Settled> {
    (!v.is_null()).then(|| Settled {
        outcome: match v["outcome"].as_str().unwrap() {
            "answer" => SettledOutcome::Answer,
            "close" => SettledOutcome::Close,
            _ => SettledOutcome::Silence,
        },
        resolution: v.get("resolution").filter(|r| !r.is_null()).map(resolution),
        acknowledgment: v.get("acknowledgment").and_then(acknowledgment),
    })
}

struct Deterministic(u64);
impl Entropy for Deterministic {
    fn blind(&mut self) -> Result<Field, Error> {
        let digest = Sha256::digest(format!("witness-blind-{}", self.0).as_bytes());
        self.0 += 1;
        Ok(digest.into())
    }
}

fn same(label: &str, got: &impl serde::Serialize, want: &Value) {
    let got = canon(&serde_json::to_value(got).unwrap());
    let want = canon(want);
    if got != want {
        let (g, w) = (
            serde_json::to_string_pretty(&got).unwrap(),
            serde_json::to_string_pretty(&want).unwrap(),
        );
        let first = g
            .lines()
            .zip(w.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b);
        panic!("{label} differs from the TypeScript builder at {first:?}");
    }
}

#[test]
fn rust_builders_reproduce_the_typescript_builders_byte_for_byte() {
    let doc: Value = serde_json::from_slice(&std::fs::read(GOLDEN).unwrap()).unwrap();
    let community: Field = bytes(&doc["community"]);
    let p = &doc["policy"];
    let policy = AccountPolicy {
        initial_credit: num(&p["initialCredit"]) as u32,
        maximum_available: num(&p["maximumAvailable"]) as u32,
        outgoing_reservation: num(&p["outgoingReservation"]) as u32,
        incoming_reservation: num(&p["incomingReservation"]) as u32,
        policy_revision: num(&p["policyRevision"]),
        policy_valid_from: num(&p["policyValidFrom"]),
        policy_valid_until: num(&p["policyValidUntil"]),
        newcomer_period: num(&p["newcomerPeriod"]),
        rate_window: num(&p["rateWindow"]),
        newcomer_admissions: num(&p["newcomerAdmissions"]) as u32,
        maximum_admissions: num(&p["maximumAdmissions"]) as u32,
        refill_period: num(&p["refillPeriod"]),
        refill_units: num(&p["refillUnits"]) as u32,
        abandon_after: num(&p["abandonAfter"]),
    };
    let x = &doc["extension"];
    let extension = ExtensionPolicy {
        revision: num(&x["revision"]),
        quorum: num(&x["publicRecordQuorum"]) as u32,
        change_cost: num(&x["changeTokenCost"]) as u32,
        delay: num(&x["depositDelaySeconds"]),
        batch: num(&x["minimumDepositBatch"]) as u8,
        standing: bytes(&x["standingPolicyDigest"]),
    };
    let standing = czkp::reference::params();
    let hexs = |v: &Value| -> Vec<u8> {
        let s = v.as_str().unwrap();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    let rows: Vec<RosterRow> = doc["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let id = m["memberId"].as_str().unwrap();
            // base64url member id of 32 bytes
            let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut acc = 0u32;
            let mut bits = 0;
            let mut member = Vec::new();
            for c in id.bytes() {
                acc = (acc << 6) | table.iter().position(|t| *t == c).unwrap() as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    member.push((acc >> bits) as u8);
                    acc &= (1 << bits) - 1;
                }
            }
            RosterRow {
                member: member.try_into().unwrap(),
                key: hexs(&m["accountKey"]).try_into().unwrap(),
                secret_hash: hexs(&m["secretHash"]).try_into().unwrap(),
                issued_at: num(&m["issuedAt"]),
                expires_at: num(&m["expiresAt"]),
                delegation_digest: hexs(&m["delegationDigest"]).try_into().unwrap(),
            }
        })
        .collect();
    let checkpoint = Arc::new(Checkpoint::from_verified(&community, &rows).unwrap());
    assert_eq!(
        canon(&Value::String(format!(
            "0x{}",
            checkpoint
                .root()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))),
        Value::String(doc["root"].as_str().unwrap().to_string()),
        "roster root"
    );
    let secrets: Vec<Field> = doc["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| bytes(&m["secret"]))
        .collect();
    let bond_secret: Field = bytes(&doc["bondSecret"]);
    let vouchee = doc["vouchee"].as_u64().unwrap() as usize;
    let sponsor = doc["sponsor"].as_u64().unwrap() as usize;

    let mut accounts: Vec<Option<Account>> = (0..rows.len()).map(|_| None).collect();
    let mut drawn = 0u64;
    let mut delivery: Option<Delivery> = None;
    let (mut built, mut refused) = (0, 0);
    for (n, step) in doc["steps"].as_array().unwrap().iter().enumerate() {
        let op = step["op"].as_str().unwrap();
        let who = step["who"].as_u64().map(|w| w as usize);
        let args = &step["args"];
        let mut rng = Deterministic(drawn);
        drawn += step["draws"].as_u64().unwrap_or(0);
        let me = || accounts[who.unwrap()].as_ref().unwrap();
        let now = args.get("now").map_or(0, num);
        let result: Result<Candidate, Error> = match op {
            "genesis" => {
                let i = who.unwrap();
                Account::genesis(
                    Genesis {
                        community,
                        policy,
                        extension,
                        standing,
                        checkpoint: Arc::clone(&checkpoint),
                        owner_index: i,
                        owner_secret: &secrets[i],
                        now,
                        bond: (i == vouchee).then(|| VoucherBond {
                            sponsor: checkpoint.entries()[sponsor].member,
                            secret: bond_secret,
                        }),
                    },
                    &mut rng,
                )
            }
            "reserve" => me().reserve(
                Reserve {
                    peer_index: num(&args["peerIndex"]) as usize,
                    role: num(&args["role"]) as u8,
                    nonce: bytes(&args["nonce"]),
                    group: bytes(&args["group"]),
                    contact_policy: bytes(&args["contactPolicy"]),
                    opened_at: args.get("openedAt").map(num),
                    expires_at: args.get("expiresAt").map(num),
                },
                now,
                &mut rng,
            ),
            "activate" => me().activate(&event(&args["event"]), now, bytes(&args["sig"]), &mut rng),
            "settle" => me().settle(
                &event(&args["event"]),
                &resolution(&args["resolution"]),
                acknowledgment(&args["ack"]).as_ref(),
                num(&args["now"]),
                None,
                None,
                &mut rng,
            ),
            "settleCounted" => me().settle_counted(
                &event(&args["event"]),
                &resolution(&args["resolution"]),
                acknowledgment(&args["ack"]).as_ref(),
                num(&args["now"]),
                None,
                None,
                &mut rng,
            ),
            "cancel" => me().cancel(&event(&args["event"]), now, &mut rng),
            "expire" => me().expire(&event(&args["event"]), now, &mut rng),
            "punish" => me().punish(&event(&args["event"]), now, bytes(&args["sig"]), &mut rng),
            "changeToken" => me().change_token(&bytes(&args["binding"]), now, &mut rng),
            "reblind" => me().reblind(now, &mut rng),
            "consume" => me().consume(
                &Delivered {
                    previous_root: bytes(&args["entry"]["previous"]["root"]),
                    commitment: bytes(&args["entry"]["commitment"]),
                },
                now,
                &mut rng,
            ),
            "admit" => me().admit(
                &bytes(&args["bondSecret"]),
                num(&args["role"]) as u8,
                now,
                &mut rng,
            ),
            "consumeObligation" => me().consume_obligation(
                &bytes(&args["bondSecret"]),
                num(&args["kind"]) as u8,
                num(&args["n"]),
                entry_of(&args["entry"]),
                now,
                &mut rng,
            ),
            "proveSuccess" => me().prove_success(now, &mut rng),
            "wave" | "outcome" | "deposit" | "record" => {
                let evidence = match op {
                    "deposit" => me().deposit(
                        delivery
                            .as_ref()
                            .expect("a punishment precedes the deposit"),
                        &bytes(&args["scope"]),
                        &bytes(&args["issuer"]),
                        num(&args["epoch"]),
                    ),
                    "record" => me().record(&RecordContext {
                        purpose: match args["context"]["purpose"].as_str().unwrap() {
                            "firstContact" => RecordPurpose::FirstContact,
                            _ => RecordPurpose::ForumListing,
                        },
                        challenge: bytes(&args["context"]["challenge"]),
                        expires_at: num(&args["context"]["expiresAt"]),
                    }),
                    _ => me().wave_evidence(
                        &event(&args["event"]),
                        &WaveContext {
                            history: bytes(&args["history"]),
                            challenge: bytes(&args["challenge"]),
                        },
                        &bytes(&args["scope"]),
                        &bytes(&args["issuer"]),
                        args.get("settled").and_then(settled_of).as_ref(),
                    ),
                };
                match evidence {
                    Ok(e) => {
                        assert!(
                            step["ok"].as_bool().unwrap(),
                            "step {n} {op}: Rust accepted what TypeScript refused"
                        );
                        built += 1;
                        same(
                            &format!("step {n} {op} statement"),
                            &serde_json::from_str::<Value>(&e.statement_json().unwrap()).unwrap(),
                            &step["statement"],
                        );
                        same(
                            &format!("step {n} {op} input"),
                            &serde_json::from_str::<Value>(&e.input_json().unwrap()).unwrap(),
                            &step["input"],
                        );
                    }
                    Err(_) => {
                        refused += 1;
                        assert!(
                            !step["ok"].as_bool().unwrap(),
                            "step {n} {op}: Rust refused what TypeScript built"
                        );
                    }
                }
                continue;
            }
            other => panic!("unknown op {other}"),
        };
        match result {
            Err(_) => {
                refused += 1;
                assert!(
                    !step["ok"].as_bool().unwrap(),
                    "step {n} {op}: Rust refused what TypeScript built"
                );
            }
            Ok(c) => {
                built += 1;
                assert!(
                    step["ok"].as_bool().unwrap(),
                    "step {n} {op}: Rust accepted what TypeScript refused"
                );
                let input: Value = serde_json::from_str(&c.input.to_json().unwrap()).unwrap();
                same(&format!("step {n} {op} input"), &input, &step["input"]);
                same(
                    &format!("step {n} {op} statement"),
                    &c.statement,
                    &step["statement"],
                );
                // The TypeScript genesis never produced the issuer-side effect description.
                if !step["update"].is_null() {
                    same(&format!("step {n} {op} update"), &c.update, &step["update"]);
                }
                if let Some(e) = step.get("event").filter(|e| !e.is_null()) {
                    assert_eq!(c.event, Some(event(e)), "step {n} event");
                }
                assert_eq!(
                    canon(&Value::String(format!(
                        "0x{}",
                        c.next
                            .commitment
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    ))),
                    canon(&Value::String(
                        step["next"]["commitment"]
                            .as_str()
                            .map(|h| format!("0x{h}"))
                            .unwrap()
                    )),
                    "step {n} next commitment"
                );
                assert_eq!(
                    c.next.version.to_string(),
                    step["next"]["version"].as_str().unwrap()
                );
                assert_eq!(
                    c.next.opening.reserved.to_string(),
                    step["next"]["reserved"].as_str().unwrap()
                );
                if let (Some(d), Some(want)) =
                    (&c.delivery, step.get("delivery").filter(|d| !d.is_null()))
                {
                    assert_eq!(u64::from(d.kind), num(&want["kind"]));
                    delivery = Some(d.clone());
                }
                if let Some(want) = step.get("entry").filter(|e| !e.is_null()) {
                    assert!(c.entry == Some(entry_of(want)), "step {n} bond entry");
                }
                if let Some(want) = step.get("tag").filter(|t| !t.is_null()) {
                    same(&format!("step {n} tag"), &c.tag, want);
                }
                let who = who.unwrap();
                let certificate = if op == "genesis" {
                    let cert = &doc["certificates"][who];
                    Some(Certificate {
                        accepted_at: num(&cert["acceptedAt"]),
                        signature: bytes(&cert["signature"]),
                    })
                } else {
                    accounts[who].as_ref().unwrap().certificate.clone()
                };
                let mut next = c.next;
                next.certificate = certificate;
                accounts[who] = Some(next);
            }
        }
    }
    let steps = doc["steps"].as_array().unwrap();
    assert_eq!(
        built,
        steps.iter().filter(|s| s["ok"].as_bool().unwrap()).count()
    );
    assert_eq!(
        refused,
        steps.iter().filter(|s| !s["ok"].as_bool().unwrap()).count()
    );

    // Every final state survives sealing: the restored account builds the same next step.
    for (i, account) in accounts.iter().enumerate() {
        let account = account.as_ref().unwrap();
        let (mut seed, mut key) = (secrets[i], [9u8; 32]);
        let engine =
            crate::Engine::from_seed_and_sealing_key(&mut seed, &mut key, b"witness-test").unwrap();
        let sealed = account.seal(&engine).unwrap();
        let sealed = SealedAccount::from_bytes(sealed.as_bytes()).unwrap();
        let restored = engine
            .restore_account(&sealed, Arc::clone(&checkpoint))
            .unwrap();
        assert_eq!(restored.state(), account.state());
        let at = account.now() + 1;
        let a = account.reblind(at, &mut Deterministic(900)).unwrap();
        let b = restored.reblind(at, &mut Deterministic(900)).unwrap();
        assert_eq!(
            a.input.to_json().unwrap().as_str(),
            b.input.to_json().unwrap().as_str(),
            "member {i}"
        );
        // A different engine (other seed or key) cannot open it.
        let (mut other, mut key) = ([1u8; 32], [9u8; 32]);
        let stranger =
            crate::Engine::from_seed_and_sealing_key(&mut other, &mut key, b"witness-test")
                .unwrap();
        assert!(
            stranger
                .restore_account(&sealed, Arc::clone(&checkpoint))
                .is_err()
        );
        assert!(account.seal(&stranger).is_err());
    }
}
