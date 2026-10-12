// Wave wallet operations over cwlt's existing non-genesis witness builders.
//
// Each function only chooses the builder, checks the call's shape and names the
// operation; the builder (and the update circuit behind it) enforces every rule.
// Nothing here proves, submits or blocks: the caller records the member's action
// first (cwlt wave_wallet job journal) and runs these in a background worker.
type Bytes = Uint8Array;

/** What a builder returns: the circuit input, the public statement and the next witness. */
export interface Candidate {input: any; statement: any; next: any; delivery?: any}
/** The slice of the account/extension witness this module drives. */
export interface Witness {
  reserve(options: ReserveOptions): Promise<Candidate>;
  settle(event: bigint, resolution: any, acknowledgment: any, now: bigint | number, ...enrollments: any[]): Promise<Candidate>;
  expire(event: bigint, now: bigint | number): Promise<Candidate>;
  punish(event: bigint, now: bigint | number, contactSignature: Bytes): Promise<Candidate>;
}
interface ReserveOptions {
  peerIndex: number; role: 0 | 1; nonce: Bytes; group: Bytes; contactPolicy: Bytes;
  openedAt?: bigint | number; expiresAt?: bigint | number; now: bigint | number;
}
export interface Wave {peerIndex: number; nonce: Bytes; group: Bytes; contactPolicy: Bytes; now: bigint | number}
export interface Lease {openedAt: bigint | number; expiresAt: bigint | number}
export type Operation =
  | {kind: 'reserve'; role: 0 | 1}
  | {kind: 'answer'} | {kind: 'close'} | {kind: 'silence'} | {kind: 'punish'};
export interface Planned {operation: Operation; candidate: Candidate}

const ANSWER = 1, CLOSE = 2;

/** Reserve the sender's introduction; the lease is opened now by the builder. */
export async function reserveSender(w: Witness, wave: Wave): Promise<Planned> {
  return {operation: {kind: 'reserve', role: 0}, candidate: await w.reserve({...wave, role: 0})};
}
/** Reserve the recipient's slot under the sender's authenticated lease. */
export async function reserveRecipient(w: Witness, wave: Wave, lease: Lease | undefined): Promise<Planned> {
  if (!lease) throw new Error('The sender\'s lease is required');
  return {operation: {kind: 'reserve', role: 1}, candidate: await w.reserve({...wave, role: 1, ...lease})};
}
/** Settle as Answer with the original receipt and the sender's acknowledgement. */
export async function answer(w: Witness, event: bigint, resolution: {kind: number}, acknowledgment: unknown,
    now: bigint | number): Promise<Planned> {
  if (resolution?.kind !== ANSWER || !acknowledgment) throw new Error('An Answer needs its receipt and acknowledgement');
  return {operation: {kind: 'answer'}, candidate: await w.settle(event, resolution, acknowledgment, now)};
}
/** Settle as Close (the recipient declines); no acknowledgement is involved. */
export async function close(w: Witness, event: bigint, resolution: {kind: number}, now: bigint | number): Promise<Planned> {
  if (resolution?.kind !== CLOSE) throw new Error('A Close needs its signed decline');
  return {operation: {kind: 'close'}, candidate: await w.settle(event, resolution, undefined, now)};
}
/** Expire an unanswered reservation: the sender's refund after the deadline. */
export async function silence(w: Witness, event: bigint, now: bigint | number): Promise<Planned> {
  return {operation: {kind: 'silence'}, candidate: await w.expire(event, now)};
}
/** Punish the peer: burns on both sides and blocks the pair in the same update. */
export async function punish(w: Witness, event: bigint, now: bigint | number, contactSignature: Bytes | undefined): Promise<Planned> {
  if (!contactSignature) throw new Error('The peer\'s contact signature is required');
  return {operation: {kind: 'punish'}, candidate: await w.punish(event, now, contactSignature)};
}
/**
 * The update circuit has no standalone block action: the pair map is blocked by
 * `punish`. A plain block is a Contacts event and needs no proof.
 */
export function selfBlock(): never {
  throw new Error('Plain blocking is a Contacts event; the pair map blocks through punish');
}
