//! The witness driver: the one Rust witness, driven by JSON lines over stdio, so the cblc proof
//! jobs build every witness with the code members run (the TypeScript builders are retired).
//!
//! One request per line, one response per line, in order:
//! `{"op": "...", ...}` -> `{"ok": true, "result": ...}` or `{"ok": false, "error": "..."}`.
//! A refusal is an ordinary answer (`ok: false`); the harness asserts it where it expects one.
//! Accounts live in the driver process under numeric handles; a builder returns the handle of
//! its `next` account, and the caller adopts it only once the issuer accepted the update.
//!
//! Encoding: byte strings are JSON arrays of numbers, fields that the TypeScript side carried
//! as bigints (events) are decimal strings, integers are numbers or decimal strings.
//! Test and CI use only: the blinds come from the operating system, never from the caller.
use super::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, Write};

/// A driver failure: a malformed request, an unknown handle or a builder refusal.
#[derive(Debug)]
pub struct Refused(pub String);

type Answer = Result<Value, Refused>;

fn refuse<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(why.into()))
}

fn field(v: &Value, name: &str) -> Result<Field, Refused> {
    bytes::<32>(&v[name]).ok_or_else(|| Refused(format!("{name}: 32 bytes expected")))
}

fn bytes<const N: usize>(v: &Value) -> Option<[u8; N]> {
    v.as_array()?
        .iter()
        .map(|n| n.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<Vec<u8>>>()?
        .try_into()
        .ok()
}

fn num(v: &Value, name: &str) -> Result<u64, Refused> {
    let item = &v[name];
    match item {
        Value::String(s) => s.parse().ok(),
        other => other.as_u64(),
    }
    .ok_or_else(|| Refused(format!("{name}: integer expected")))
}

fn opt_num(v: &Value, name: &str) -> Result<Option<u64>, Refused> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => num(v, name).map(Some),
    }
}

/// Decimal text of a field (a TypeScript bigint) to 32 big-endian bytes.
fn decimal(v: &Value, name: &str) -> Result<Field, Refused> {
    let text = match &v[name] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return refuse(format!("{name}: decimal field expected")),
    };
    let mut out = [0u8; 32];
    for digit in text.bytes() {
        if !digit.is_ascii_digit() {
            return refuse(format!("{name}: decimal field expected"));
        }
        let mut carry = u32::from(digit - b'0');
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 255) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return refuse(format!("{name}: exceeds 32 bytes"));
        }
    }
    Ok(out)
}

/// 32 big-endian bytes to decimal text (the TypeScript bigint spelling).
fn to_decimal(field: &Field) -> String {
    let mut digits = Vec::new();
    let mut number = *field;
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

fn resolution(v: &Value) -> Result<Resolution, Refused> {
    Ok(Resolution {
        kind: u8::try_from(num(v, "kind")?).map_err(|_| Refused("kind".into()))?,
        issued_at: num(v, "issuedAt")?,
        history_digest: field(v, "historyDigest")?,
        ed25519_receipt_digest: field(v, "ed25519ReceiptDigest")?,
        signature: bytes(&v["signature"]).ok_or_else(|| Refused("signature".into()))?,
    })
}

fn acknowledgment(v: &Value) -> Result<Option<Acknowledgment>, Refused> {
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(Acknowledgment {
        issued_at: num(v, "issuedAt")?,
        signature: bytes(&v["signature"]).ok_or_else(|| Refused("ack signature".into()))?,
    }))
}

fn entry(v: &Value) -> Result<BondEntry, Refused> {
    let seen = |snake: &str, camel: &str| {
        if v.get(snake).is_some() {
            num(v, snake)
        } else {
            num(v, camel)
        }
    };
    Ok(BondEntry {
        limit: num(v, "limit")?,
        done: v["done"].as_bool().ok_or_else(|| Refused("done".into()))?,
        overshoot: v["overshoot"]
            .as_bool()
            .ok_or_else(|| Refused("overshoot".into()))?,
        punished_seen: seen("punished_seen", "punishedSeen")?,
        rewards_seen: seen("rewards_seen", "rewardsSeen")?,
    })
}

fn entry_json(e: &BondEntry) -> Value {
    json!({"limit": e.limit, "done": e.done, "overshoot": e.overshoot,
        "punishedSeen": e.punished_seen, "rewardsSeen": e.rewards_seen})
}

fn settled(v: Option<&Value>) -> Result<Option<Settled>, Refused> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    Ok(Some(Settled {
        outcome: match v["outcome"].as_str() {
            Some("answer") => SettledOutcome::Answer,
            Some("close") => SettledOutcome::Close,
            Some("silence") => SettledOutcome::Silence,
            _ => return refuse("settled outcome"),
        },
        resolution: match v.get("resolution").filter(|r| !r.is_null()) {
            Some(r) => Some(resolution(r)?),
            None => None,
        },
        acknowledgment: match v.get("acknowledgment") {
            Some(a) => acknowledgment(a)?,
            None => None,
        },
    }))
}

fn json_text(text: &str) -> Answer {
    serde_json::from_str(text).map_err(|e| Refused(format!("encode: {e}")))
}

fn slot_json(event: &Field, s: &Slot) -> Value {
    json!({
        "event": to_decimal(event), "role": s.role, "peer": s.peer, "nonce": s.nonce,
        "group": s.group, "contactPolicy": s.contact_policy, "amount": s.amount, "phase": s.phase,
        "outcome": s.outcome, "answered": s.answered, "selfPunished": s.self_punished,
        "admittedAt": s.admitted_at, "expiresAt": s.expires_at,
        "peerAuthority": to_decimal(&s.peer_authority),
        "ownerAuthority": to_decimal(&s.owner_authority),
        "peerMember": s.peer_enrollment.member, "ownerMember": s.owner_enrollment.member,
    })
}

/// The driver state: one community setup and the accounts under their handles.
#[derive(Default)]
pub struct Driver {
    setup: Option<Setup>,
    accounts: HashMap<u64, Account>,
    deliveries: HashMap<u64, Delivery>,
    next_handle: u64,
}

struct Setup {
    community: Field,
    policy: AccountPolicy,
    extension: ExtensionPolicy,
    checkpoint: Arc<Checkpoint>,
}

impl Driver {
    fn keep(&mut self, account: Account) -> u64 {
        self.next_handle += 1;
        self.accounts.insert(self.next_handle, account);
        self.next_handle
    }

    fn account(&self, v: &Value) -> Result<&Account, Refused> {
        let handle = num(v, "handle")?;
        self.accounts
            .get(&handle)
            .ok_or_else(|| Refused(format!("unknown account handle {handle}")))
    }

    fn setup(&self) -> Result<&Setup, Refused> {
        self.setup
            .as_ref()
            .ok_or_else(|| Refused("setup first".into()))
    }

    /// Answer one request.
    pub fn handle(&mut self, request: &Value) -> Answer {
        let op = request["op"].as_str().unwrap_or_default();
        let mut rng = OsEntropy;
        let r = request;
        let now = || num(r, "now");
        let built = match op {
            "setup" => return self.open(r),
            "view" => return self.view(r),
            "drop" => {
                self.accounts.remove(&num(r, "handle")?);
                return Ok(Value::Null);
            }
            "certify" => {
                let account = self.account(r)?.clone().with_certificate(Certificate {
                    accepted_at: num(r, "acceptedAt")?,
                    signature: bytes(&r["signature"]).ok_or_else(|| Refused("signature".into()))?,
                });
                return Ok(json!({"handle": self.keep(account)}));
            }
            "wave" | "outcome" | "deposit" | "record" => return self.evidence(op, r),
            "genesis" => {
                let s = self.setup()?;
                let secret = field(r, "ownerSecret")?;
                let bond = match r.get("bond").filter(|b| !b.is_null()) {
                    Some(b) => Some(VoucherBond {
                        sponsor: field(b, "sponsor")?,
                        secret: field(b, "secret")?,
                    }),
                    None => None,
                };
                Account::genesis(
                    Genesis {
                        community: s.community,
                        policy: s.policy,
                        extension: s.extension,
                        standing: czkp::reference::params(),
                        checkpoint: Arc::clone(&s.checkpoint),
                        owner_index: usize::try_from(num(r, "ownerIndex")?)
                            .map_err(|_| Refused("ownerIndex".into()))?,
                        owner_secret: &secret,
                        now: now()?,
                        bond,
                    },
                    &mut rng,
                )
            }
            "reserve" => self.account(r)?.reserve(
                Reserve {
                    peer_index: usize::try_from(num(r, "peerIndex")?)
                        .map_err(|_| Refused("peerIndex".into()))?,
                    role: u8::try_from(num(r, "role")?).map_err(|_| Refused("role".into()))?,
                    nonce: field(r, "nonce")?,
                    group: field(r, "group")?,
                    contact_policy: field(r, "contactPolicy")?,
                    opened_at: opt_num(r, "openedAt")?,
                    expires_at: opt_num(r, "expiresAt")?,
                },
                now()?,
                &mut rng,
            ),
            "activate" | "punish" => {
                let account = self.account(r)?;
                let event = decimal(r, "event")?;
                let sig = bytes(&r["sig"]).ok_or_else(|| Refused("sig: 64 bytes".into()))?;
                if op == "activate" {
                    account.activate(&event, now()?, sig, &mut rng)
                } else {
                    account.punish(&event, now()?, sig, &mut rng)
                }
            }
            "settle" | "settleCounted" => {
                let account = self.account(r)?;
                let event = decimal(r, "event")?;
                let resolution = resolution(&r["resolution"])?;
                let ack = acknowledgment(&r["ack"])?;
                if op == "settle" {
                    account.settle(
                        &event,
                        &resolution,
                        ack.as_ref(),
                        now()?,
                        None,
                        None,
                        &mut rng,
                    )
                } else {
                    account.settle_counted(
                        &event,
                        &resolution,
                        ack.as_ref(),
                        now()?,
                        None,
                        None,
                        &mut rng,
                    )
                }
            }
            "cancel" => self
                .account(r)?
                .cancel(&decimal(r, "event")?, now()?, &mut rng),
            "expire" => self
                .account(r)?
                .expire(&decimal(r, "event")?, now()?, &mut rng),
            "changeToken" => self
                .account(r)?
                .change_token(&field(r, "binding")?, now()?, &mut rng),
            "reblind" => self.account(r)?.reblind(now()?, &mut rng),
            "consume" | "consumeCounted" => {
                let e = &r["entry"];
                let delivered = Delivered {
                    previous_root: field(&e["previous"], "root")?,
                    commitment: field(e, "commitment")?,
                };
                if op == "consume" {
                    self.account(r)?.consume(&delivered, now()?, &mut rng)
                } else {
                    self.account(r)?
                        .consume_counted(&delivered, now()?, &mut rng)
                }
            }
            "admit" => self.account(r)?.admit(
                &field(r, "bondSecret")?,
                u8::try_from(num(r, "role")?).map_err(|_| Refused("role".into()))?,
                now()?,
                &mut rng,
            ),
            "consumeObligation" => self.account(r)?.consume_obligation(
                &field(r, "bondSecret")?,
                u8::try_from(num(r, "kind")?).map_err(|_| Refused("kind".into()))?,
                num(r, "n")?,
                entry(&r["entry"])?,
                now()?,
                &mut rng,
            ),
            "proveSuccess" => self.account(r)?.prove_success(now()?, &mut rng),
            "reserveLink" | "releaseLink" => {
                let account = self.account(r)?;
                let units = num(r, "units")?;
                if op == "reserveLink" {
                    account.reserve_uses(units, now()?, &mut rng)
                } else {
                    account.release_uses(units, now()?, &mut rng)
                }
            }
            other => return refuse(format!("unknown op {other:?}")),
        };
        let c = built.map_err(|e| Refused(format!("{op} refused: {e:?}")))?;
        let input = json_text(&c.input.to_json().map_err(|e| Refused(format!("{e:?}")))?)?;
        let statement = serde_json::to_value(&c.statement).map_err(|e| Refused(e.to_string()))?;
        let update = serde_json::to_value(&c.update).map_err(|e| Refused(e.to_string()))?;
        let delivery = c.delivery.map(|d| {
            let shown = slot_json(&[0; 32], &d.slot);
            self.next_handle += 1;
            let handle = self.next_handle;
            let kind = d.kind;
            self.deliveries.insert(handle, d);
            json!({"handle": handle, "slot": shown, "kind": kind})
        });
        let next = self.keep(c.next);
        Ok(json!({
            "next": next, "input": input, "statement": statement, "update": update,
            "event": c.event.as_ref().map(to_decimal), "delivery": delivery,
            "entry": c.entry.as_ref().map(entry_json), "tag": c.tag,
        }))
    }

    fn open(&mut self, r: &Value) -> Answer {
        let p = &r["policy"];
        let small = |name: &str| -> Result<u32, Refused> {
            u32::try_from(num(p, name)?).map_err(|_| Refused(name.into()))
        };
        let policy = AccountPolicy {
            initial_credit: small("initialCredit")?,
            maximum_available: small("maximumAvailable")?,
            outgoing_reservation: small("outgoingReservation")?,
            incoming_reservation: small("incomingReservation")?,
            policy_revision: num(p, "policyRevision")?,
            policy_valid_from: num(p, "policyValidFrom")?,
            policy_valid_until: num(p, "policyValidUntil")?,
            newcomer_period: num(p, "newcomerPeriod")?,
            rate_window: num(p, "rateWindow")?,
            newcomer_admissions: small("newcomerAdmissions")?,
            maximum_admissions: small("maximumAdmissions")?,
            refill_period: num(p, "refillPeriod")?,
            refill_units: small("refillUnits")?,
            abandon_after: num(p, "abandonAfter")?,
        };
        let x = &r["extension"];
        let extension = ExtensionPolicy {
            revision: num(x, "revision")?,
            quorum: u32::try_from(num(x, "publicRecordQuorum")?)
                .map_err(|_| Refused("publicRecordQuorum".into()))?,
            change_cost: u32::try_from(num(x, "changeTokenCost")?)
                .map_err(|_| Refused("changeTokenCost".into()))?,
            delay: num(x, "depositDelaySeconds")?,
            batch: u8::try_from(num(x, "minimumDepositBatch")?)
                .map_err(|_| Refused("minimumDepositBatch".into()))?,
            standing: field(x, "standingPolicyDigest")?,
        };
        let community = field(r, "community")?;
        let rows = r["members"]
            .as_array()
            .ok_or_else(|| Refused("members".into()))?
            .iter()
            .map(|m| {
                Ok(RosterRow {
                    member: field(m, "member")?,
                    key: bytes(&m["accountKey"]).ok_or_else(|| Refused("accountKey".into()))?,
                    secret_hash: field(m, "secretHash")?,
                    issued_at: num(m, "issuedAt")?,
                    expires_at: num(m, "expiresAt")?,
                    delegation_digest: field(m, "delegationDigest")?,
                })
            })
            .collect::<Result<Vec<_>, Refused>>()?;
        let checkpoint = Checkpoint::from_verified(&community, &rows)
            .map_err(|e| Refused(format!("roster refused: {e:?}")))?;
        let root = checkpoint.root();
        self.setup = Some(Setup {
            community,
            policy,
            extension,
            checkpoint: Arc::new(checkpoint),
        });
        self.accounts.clear();
        self.deliveries.clear();
        Ok(json!({"root": root}))
    }

    fn evidence(&self, op: &str, r: &Value) -> Answer {
        let account = self.account(r)?;
        let evidence = match op {
            "deposit" => {
                let handle = num(r, "delivery")?;
                let delivery = self
                    .deliveries
                    .get(&handle)
                    .ok_or_else(|| Refused(format!("unknown delivery {handle}")))?;
                let i = &r["issuance"];
                let period = czkp::issuer_keys::CertificateKeyPeriod {
                    public_key: bytes::<64>(&i["publicKey"])
                        .ok_or_else(|| Refused("publicKey: 64 bytes".into()))?
                        .to_vec(),
                    valid_from: num(i, "validFrom")?,
                    valid_until: opt_num(i, "validUntil")?,
                };
                account.deposit(
                    delivery,
                    &field(r, "scope")?,
                    &period,
                    &field(i, "identity")?,
                    num(r, "releaseEpoch")?,
                )
            }
            "record" => {
                let c = &r["context"];
                account.record(&RecordContext {
                    purpose: match c["purpose"].as_str() {
                        Some("firstContact") => RecordPurpose::FirstContact,
                        Some("forumListing") => RecordPurpose::ForumListing,
                        _ => return refuse("record purpose"),
                    },
                    challenge: field(c, "challenge")?,
                    expires_at: num(c, "expiresAt")?,
                })
            }
            _ => account.wave_evidence(
                &decimal(r, "event")?,
                &WaveContext {
                    history: field(r, "history")?,
                    challenge: field(r, "challenge")?,
                },
                &field(r, "scope")?,
                &bytes(&r["issuer"]).ok_or_else(|| Refused("issuer: 64 bytes".into()))?,
                settled(r.get("settled"))?.as_ref(),
            ),
        }
        .map_err(|e| Refused(format!("{op} refused: {e:?}")))?;
        let statement = json_text(
            &evidence
                .statement_json()
                .map_err(|e| Refused(format!("{e:?}")))?,
        )?;
        let input = json_text(
            &evidence
                .input_json()
                .map_err(|e| Refused(format!("{e:?}")))?,
        )?;
        Ok(json!({"statement": statement, "input": input, "outcome": evidence.is_outcome()}))
    }

    /// The public parts of an account a harness inspects: never the owner secret.
    fn view(&self, r: &Value) -> Answer {
        let a = self.account(r)?;
        let o = &a.opening;
        let s = &o.standing;
        let v = &o.voucher;
        Ok(json!({
            "version": a.version, "now": a.now, "commitment": a.commitment,
            "state": to_decimal(&a.commitment),
            "owner": a.owner().member, "ownerIndex": a.owner_index,
            "certificate": a.certificate.as_ref().map(|c| json!({"acceptedAt": c.accepted_at, "signature": c.signature.to_vec()})),
            "opening": {
                "reserved": o.reserved.to_string(), "accepted": o.accepted, "declined": o.declined,
                "punished": o.punished, "inbox": o.inbox, "authorization": to_decimal(&o.authorization),
                "outgoingRoot": to_decimal(&o.outgoing_root), "outgoingCount": o.outgoing_count,
                "incomingRoot": to_decimal(&o.incoming_root), "incomingCount": o.incoming_count,
                "pairRoot": to_decimal(&o.pair_root), "pairCount": o.pair_count,
                "createdAt": o.created_at,
                "standing": {"g": s.g, "a": s.a, "c": s.c, "pr": s.pr, "pg": s.pg, "lc": s.lc, "day": s.day},
                "voucher": {"proven": v.proven, "away": v.away, "reserved": v.reserved, "lost": v.lost,
                    "bonus": v.bonus, "returned": v.returned, "answers": v.answers,
                    "sponsor": to_decimal(&v.sponsor), "bond": to_decimal(&v.bond),
                    "bondRoot": to_decimal(&v.bond_root), "bondCount": v.bond_count},
            },
            "slots": a.slots.iter().map(|(e, s)| slot_json(e, s)).collect::<Vec<_>>(),
            // The bond secrets stay in the driver; only the keys and entries are shown.
            "bondBook": a.bond_book.iter().map(|(k, (_, e))| json!({
                "key": to_decimal(k), "entry": entry_json(e)})).collect::<Vec<_>>(),
        }))
    }
}

/// Serve requests from `input` until it ends, one JSON line in, one JSON line out.
pub fn serve(input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
    let mut driver = Driver::default();
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(request) => driver.handle(&request),
            Err(e) => Err(Refused(format!("request is not JSON: {e}"))),
        };
        let reply = match answer {
            Ok(result) => json!({"ok": true, "result": result}),
            Err(Refused(error)) => json!({"ok": false, "error": error}),
        };
        writeln!(output, "{reply}")?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(lines: &str) -> Vec<Value> {
        let mut out = Vec::new();
        serve(lines.as_bytes(), &mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn every_request_gets_one_answer_and_refusals_are_answers() {
        let answers = exchange(
            "not json\n\n{\"op\":\"genesis\",\"ownerIndex\":0,\"now\":1}\n{\"op\":\"view\",\"handle\":7}\n{\"op\":\"nope\"}\n",
        );
        assert_eq!(answers.len(), 4);
        assert!(answers.iter().all(|a| a["ok"] == Value::Bool(false)));
        assert!(
            answers[1]["error"]
                .as_str()
                .unwrap()
                .contains("setup first")
        );
        assert!(
            answers[2]["error"]
                .as_str()
                .unwrap()
                .contains("unknown account handle")
        );
    }

    #[test]
    fn fields_round_trip_through_decimal_text() {
        let mut field = [0u8; 32];
        field[0] = 0x30;
        field[31] = 7;
        let text = to_decimal(&field);
        assert_eq!(decimal(&json!({"e": text}), "e").unwrap(), field);
        assert_eq!(to_decimal(&[0; 32]), "0");
        assert!(decimal(&json!({"e": "12x"}), "e").is_err());
    }
}
