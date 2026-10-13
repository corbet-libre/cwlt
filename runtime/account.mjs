// Generated from account.mts by tools/emit.mts. Do not edit.
import { fieldBytes, fieldValue, limbs32 } from '@corbet-labs/czkp/primitives';
import { cat, be, random, zeros } from '@corbet-labs/czkp/encoding';
import { IndexedMap, policyDigest, statePolicyDigest, integer, SAFE, POLICY_KEYS } from './hashes.mjs';
import { refreshEnrollment, verifyEnrollmentPath, verifyReceiptEnrollment } from './enrollment.mjs';

import { statementFromInput, publicInputValues, statementBytes, validateStatement, validityHorizon, POLICY_WIRE } from './statement.mjs';
export { statementFromInput, publicInputValues, statementBytes, validateStatement, validityHorizon, PUBLIC_INPUT_COUNT } from './statement.mjs';
export const emptyMapWitness = () => ({ leaf: [0n, 0n, 0n, 0n], index: 0n,
  path: Array(32).fill(0n), append_path: Array(32).fill(0n) });
export const enrollmentInput = entry => ({ key: entry.key, secret_hash: entry.secretHash, start: entry.start,
  end: entry.end, delegation_digest: entry.delegationDigest, path: entry.path, index: entry.index });
// Standing v5 account state: the shared pool replaces the token balance.
export const openingInput = s => ({ reserved: s.reserved,
  outgoing_root: s.outgoingRoot, outgoing_count: s.outgoingCount,
  incoming_root: s.incomingRoot, incoming_count: s.incomingCount,
  pair_root: s.pairRoot, pair_count: s.pairCount,
  created_at: s.createdAt, standing: standingInput(s.standing), voucher: voucherInput(s.voucher), blind: s.blind });
// The voucher part of the committed account: allowance counters, sponsor and bond commitments,
// and the sponsor's private bond map (root and count).
export const voucherInput = (v     ) => ({ proven: v.proven, away: v.away, lost: v.lost, bonus: v.bonus,
  returned: v.returned, answers: v.answers, sponsor: v.sponsor, bond: v.bond, bond_root: v.bondRoot, bond_count: v.bondCount });
export const emptyAux = ()      => ({ bond_secret: zeros(), kind: 0, n: 0n,
  entry: { limit: 0n, done: false, overshoot: false, punished_seen: 0n, rewards_seen: 0n },
  bond_map: emptyMapWitness(), sponsor: 0n, count: false });
export const standingInput = t => ({ g: t.g, a: t.a, c: t.c, pr: t.pr, pg: t.pg, lc: t.lc, day: t.day });
export const slotInput = s => ({ role: s.role, peer: s.peer, nonce: s.nonce, group: s.group,
  contact_policy: s.contactPolicy, amount: s.amount, phase: s.phase, outcome: s.outcome??0, answered:s.answered??false, self_punished:s.selfPunished??false,
  admitted_at: s.admittedAt, expires_at: s.expiresAt, peer_authority: s.peerAuthority, owner_authority: s.ownerAuthority });
const resolutionInput = r => ({ kind: r.kind, issued_at: r.issuedAt, history_digest: r.historyDigest,
  ed25519_receipt_digest: r.ed25519ReceiptDigest, signature: r.signature });
const emptyResolution = now => ({ kind: 2, issuedAt: now, historyDigest: zeros(), ed25519ReceiptDigest: zeros(), signature: new Uint8Array(64) });
const policyInput = p => Object.fromEntries(POLICY_WIRE.map(([key, wire]) => [wire, p[key]]));

// Local witness state. It is never accepted by an operator without a real proof
// plus a durable accepted-state comparison. Returned candidates do not mutate it.
export class AccountWitness {
  static async genesis({ hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now, extension, transition, standing, policyTables, bond }     ) {
    const value = new this();
    Object.assign(value, { extension, transition, hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now: BigInt(now), version: 0n });
    value.owner = checkpoint.entries[ownerIndex];
    value.policyHash = await policyDigest(community, policy);
    value.statePolicyHash = await statePolicyDigest(community, policy);
    if (fieldValue(await hashes.secretHash(community, ownerSecret)) !== fieldValue(value.owner.secretHash)) throw new Error('Owner secret differs from verified enrollment');
    const empty = await IndexedMap.create(hashes);
    value.outgoing = empty; value.incoming = empty.clone(); value.pairs = empty.clone(); value.bonds = empty.clone();
    value.slots = new Map();
    if (BigInt(policy.rateWindow) > 86400n) throw new Error('Proof window must not exceed one day');
    const horizon = validityHorizon(now, policy);
    value.opening = { reserved: 0n,
      outgoingRoot: empty.root, outgoingCount: 1n, incomingRoot: empty.root, incomingCount: 1n,
      pairRoot: empty.root, pairCount: 1n, createdAt: horizon,
      standing: { g: 0n, a: (BigInt(standing.c0) - 1n) << 16n, c: 0n, pr: 0n, pg: 0n, lc: 0n, day: horizon / 86400n },
      voucher: { proven: 0n, away: 0n, lost: 0n, bonus: 0n, returned: 0n, answers: 0n, sponsor: 0n, bond: 0n,
        bondRoot: empty.root, bondCount: 1n }, blind: random() };
    // A vouchee holds a bond with its sponsor; a founder holds none (both fields stay zero).
    if (bond) {
      value.opening.voucher.sponsor = await hashes.hash(63, [...limbs32(community), ...limbs32(bond.sponsor)]);
      value.opening.voucher.bond = await hashes.hash(61, limbs32(bond.secret));
    }
    value.standing = standing;
    value.commitment = await value.commit(value.opening, 0n);
    const input = value.input(value.opening.blind, now);
    // The planner derives the tables from the signed parameters (czkp's owner function).
    // Test and artifact builds may pass the derived tables (czkp golden vectors) instead of a planner.
    const first = policyTables ? { policy: policyTables } : transition({ old: { reserved: 0, accepted: 0, declined: 0, punished: 0 },
      standing: Object.fromEntries(Object.entries(value.opening.standing).map(([k, v]) => [k, Number(v)])), params: standing,
      createdAt: Number(value.opening.createdAt), now: Number(now), action: 11, amount: 0, role: 0, phase: 1, outcome: 0,
      answered: false, selfPunished: false, kind: 0, changeCost: 1 });
    input.standing_policy = first.policy;
    if (bond) input.aux = { ...emptyAux(), bond_secret: bond.secret, sponsor: value.opening.voucher.sponsor };
    Object.assign(input, { genesis: true, previous_state: zeros(), next_state: fieldBytes(value.commitment),
      previous_version: 0n, next_version: 0n });
    return { input, statement: statementFromInput(input), next: value };
  }
  /** Hook for voucher bookkeeping that must change maps before the commitment; empty here. */
  async beforeFinish(_next     , _input     ) {}
  async commit(opening, version) {
    return this.hashes.state(this.community, this.owner.member, this.statePolicyHash, this.owner.secretHash, version, opening);
  }
  async withPolicy(policy) {
    const stable = await statePolicyDigest(this.community, policy);
    if (!stable.every((value, index) => value === this.statePolicyHash[index])) throw new Error('Immutable account policy changed');
    const copy = this.clone(); copy.policy = structuredClone(policy);
    copy.policyHash = await policyDigest(this.community, policy);
    // This only prepares a witness. The host independently requires its exact
    // current durable policy; a browser cannot authorize its own tuning.
    return copy;
  }
  /** Current independently admitted roster; preserves the accepted private state. */
  async withEnrollment(options) {
    const current = await refreshEnrollment(this, options), copy = this.clone();
    Object.assign(copy, current);
    return copy;
  }
  clone() {
    const copy = new this.constructor(); Object.assign(copy, this);
    copy.slots = new Map(Array.from(this.slots, ([k, v]) => [k, structuredClone(v)]));
    copy.opening = structuredClone(this.opening); return copy;
  }
  input(newBlind, now) {
    return { community: this.community, owner: this.owner.member, policy_digest: this.policyHash,
      enrollment_root: fieldBytes(this.checkpoint.root), now: BigInt(now), valid_until: validityHorizon(now, this.policy), genesis: false,
      previous_version: this.version, next_version: this.version + 1n,
      previous_state: fieldBytes(this.commitment), next_state: zeros(), settlement_marker: zeros(), ...policyInput(this.policy),
      owner_secret: this.ownerSecret, owner_enrollment: enrollmentInput(this.owner), peer_enrollment: enrollmentInput(this.owner),
      receipt_owner_enrollment: enrollmentInput(this.owner),
      old: openingInput(this.opening), new_blind: newBlind, action: 1,
      slot: slotInput({ role: 0, peer: zeros(), nonce: zeros(), group: zeros(), contactPolicy: zeros(), amount: 0,
        phase: 1, admittedAt: BigInt(now), expiresAt: BigInt(now), peerAuthority: 0n, ownerAuthority: 0n }),
      own_map: emptyMapWitness(), opposite_map: emptyMapWitness(), pair_map: emptyMapWitness(), pair_exists: false,
      resolution: resolutionInput(emptyResolution(now)), acknowledgment: { issued_at: BigInt(now), signature: new Uint8Array(64) },
      role: 0, obligation: zeros(), aux: emptyAux() };
  }
  async finish(next, input) {
    await this.beforeFinish(next, input);
    next.now = BigInt(input.now);
    next.version = this.version + 1n;
    next.opening.outgoingRoot = next.outgoing.root; next.opening.outgoingCount = next.outgoing.count;
    next.opening.incomingRoot = next.incoming.root; next.opening.incomingCount = next.incoming.count;
    next.opening.pairRoot = next.pairs.root; next.opening.pairCount = next.pairs.count;
    next.opening.blind = input.new_blind;
    next.commitment = await next.commit(next.opening, next.version);
    input.next_state = fieldBytes(next.commitment);
    return { input, statement: statementFromInput(input), next };
  }
  at(now) {
    const at = integer(now, 64), p = this.policy, o = this.opening;
    if (at > SAFE || o.createdAt === 0n || at < BigInt(p.policyValidFrom) || at >= BigInt(p.policyValidUntil)) throw new Error('Account time/policy');
    return { now: at };
  }
  async reserve({ peerIndex, role, nonce, group, contactPolicy, openedAt, expiresAt, now = this.now }) {
    if (role !== 0 && role !== 1) throw new Error('Reservation role');
    const at = this.at(now);
    if (role === 1 && (openedAt === undefined || expiresAt === undefined)) throw new Error('Incoming reservation requires the authenticated common lease');
    const opened = integer(openedAt ?? at.now, 64);
    const expiry = integer(expiresAt ?? (at.now + BigInt(this.policy.abandonAfter)), 64);
    if (opened === 0n || opened > at.now || expiry <= at.now || expiry >= BigInt(this.policy.policyValidUntil)
        || validityHorizon(now, this.policy) > expiry
        || (role === 0 && (opened !== at.now || expiry !== at.now + BigInt(this.policy.abandonAfter)))) throw new Error('Reservation lease');
    const peer = this.checkpoint.entries[peerIndex];
    if (!peer || peer === this.owner) throw new Error('Current peer enrollment required');
    await verifyEnrollmentPath(peer, this.community, this.checkpoint.root, this.hashes);
    const event = await this.hashes.marker(this.community, this.ownerSecret, this.owner.member, peer.member, nonce);
    const pair = await this.hashes.pairKey(this.community, this.owner.member, this.ownerSecret, peer.member);
    const amount = BigInt(role === 0 ? this.policy.outgoingReservation : this.policy.incomingReservation);
    const slot = { role, peer: peer.member, nonce, group, contactPolicy, amount, phase: 1, outcome: 0, answered:false,selfPunished:false,
      admittedAt: opened, expiresAt: expiry, peerAuthority: peer.leaf, ownerAuthority: this.owner.leaf,
      peerEnrollment: structuredClone(peer), ownerEnrollment: structuredClone(this.owner) };
    const own = role === 0 ? this.outgoing : this.incoming, opposite = role === 0 ? this.incoming : this.outgoing;
    const inserted = await own.insert(event, await this.hashes.obligation(event, slot, 1));
    const input = this.input(random(), now), next = this.clone();
    Object.assign(input, { action: 1, slot: slotInput(slot), peer_enrollment: enrollmentInput(peer),
      own_map: inserted.witness, opposite_map: opposite.absence(event) });
    const existing = this.pairs.find(pair);
    if (existing) { input.pair_exists = true; input.pair_map = this.pairs.witness(existing[0]); }
    else { const added = await this.pairs.insert(pair, 1n); input.pair_map = added.witness; next.pairs = added.next; }
    if (role === 0) next.outgoing = inserted.next; else next.incoming = inserted.next;
    // The planner (finish) applies the pool check against the standing cap.
    next.opening.reserved += amount;
    next.slots.set(event.toString(), slot);
    const result = await this.finish(next, input); result.event = event; return result;
  }
  async change(event, action, resolution, acknowledgment, now = this.now, peerEnrollment, receiptOwnerEnrollment) {
    const at = this.at(now);
    const oldSlot = this.slots.get(event.toString()); if (!oldSlot) throw new Error('Unknown private obligation');
    if (![2, 3, 4, 5].includes(action) || (action === 5 ? ![2, 8].includes(oldSlot.phase) : oldSlot.phase !== ([2, 4].includes(action) ? 1 : 2))) throw new Error('Invalid obligation phase');
    if (at.now < oldSlot.admittedAt) throw new Error('Future obligation');
    const expired = at.now >= oldSlot.expiresAt;
    const withinHorizon = validityHorizon(now, this.policy) <= oldSlot.expiresAt;
    if (action === 2 && (expired || !withinHorizon)) throw new Error('Activation lease expired');
    if (action === 5 && (oldSlot.role !== 0 || !expired)) throw new Error('Only expired outgoing obligations may retire');
    if (action === 3 && oldSlot.role === 0 && Number(resolution?.kind) !== 1) throw new Error('Outgoing Close cannot alter the fixed refund date');
    if (action === 3 && Number(resolution?.kind) === 1 && (expired || !withinHorizon)) throw new Error('Answer arrived after the common lease');
    const slot = structuredClone(oldSlot), next = this.clone(), input = this.input(random(), now);
    const peer = structuredClone(peerEnrollment ?? slot.peerEnrollment),
      receiptOwner = structuredClone(receiptOwnerEnrollment ?? slot.ownerEnrollment);
    if (action === 3) {
      if (slot.role === 0 || Number(resolution?.kind) === 1) {
        await verifyReceiptEnrollment(peer, this, slot.peer, slot.peerAuthority);
      }
      if (slot.role === 1) await verifyReceiptEnrollment(receiptOwner, this, this.owner.member, slot.ownerAuthority, true);
    }
    Object.assign(input, { action, slot: slotInput(slot),
      peer_enrollment: enrollmentInput(peer) });
    input.receipt_owner_enrollment = enrollmentInput(receiptOwner);
    const phase = action === 2 ? 2 : action === 4 ? 4 : action === 5 ? 5 : 3;
    if(action===3) {slot.outcome=Number(resolution.kind);if(slot.outcome===1)slot.answered=true;}
    const changed = await (slot.role === 0 ? this.outgoing : this.incoming).update(event,
      await this.hashes.obligation(event, slot, phase));
    input.own_map = changed.witness;
    if (slot.role === 0) next.outgoing = changed.next; else next.incoming = changed.next;
    slot.phase = phase; next.slots.set(event.toString(), slot);
    if (action === 3) {
      if (!resolution) throw new Error('Authenticated receipt required');
      input.resolution = resolutionInput(resolution);
      if (acknowledgment) input.acknowledgment = { issued_at: acknowledgment.issuedAt, signature: acknowledgment.signature };
      next.opening.reserved -= slot.amount;
      input.settlement_marker = fieldBytes(event);
    } else if (action === 4 || action === 5) {
      next.opening.reserved -= slot.amount;
      input.settlement_marker = fieldBytes(event);
    }
    return this.finish(next, input);
  }
  activate(event, now) { return this.change(event, 2, undefined, undefined, now); }
  settle(event, resolution, acknowledgment, now, peerEnrollment, receiptOwnerEnrollment) {
    return this.change(event, 3, resolution, acknowledgment, now, peerEnrollment, receiptOwnerEnrollment);
  }
  cancel(event, now) { return this.change(event, 4, undefined, undefined, now); }
  expire(event, now) { return this.change(event, 5, undefined, undefined, now); }
  // Retired: slots return on settlement, not by a refill clock.
  async refill() { throw new Error('Refill is retired: the shared pool replaces the token balance'); }
}
