import assert from 'node:assert/strict';
import {reserveSender, reserveRecipient, answer, close, silence, punish, selfBlock, type Witness} from '../runtime/wave-wallet.mts';

const calls: any[] = [];
const candidate = (name: string) => ({input: {name}, statement: {name}, next: {}});
const witness: Witness = {
  reserve: async o => (calls.push(['reserve', o]), candidate('reserve')),
  settle: async (...a) => (calls.push(['settle', ...a]), candidate('settle')),
  expire: async (...a) => (calls.push(['expire', ...a]), candidate('expire')),
  punish: async (...a) => (calls.push(['punish', ...a]), candidate('punish')),
};
const bytes = (n: number) => new Uint8Array(32).fill(n);
const wave = {peerIndex: 2, nonce: bytes(1), group: bytes(2), contactPolicy: bytes(3), now: 100n};

assert.deepEqual((await reserveSender(witness, wave)).operation, {kind: 'reserve', role: 0});
assert.equal(calls.at(-1)[1].role, 0);
await assert.rejects(reserveRecipient(witness, wave, undefined), /lease/);
const r = await reserveRecipient(witness, wave, {openedAt: 90n, expiresAt: 190n});
assert.deepEqual(r.operation, {kind: 'reserve', role: 1});
assert.equal(calls.at(-1)[1].openedAt, 90n);
const ack = {issuedAt: 1n, signature: new Uint8Array(64)};
await assert.rejects(answer(witness, 5n, {kind: 2}, ack, 100n), /Answer needs/);
await assert.rejects(answer(witness, 5n, {kind: 1}, undefined, 100n), /Answer needs/);
assert.deepEqual((await answer(witness, 5n, {kind: 1}, ack, 100n)).operation, {kind: 'answer'});
await assert.rejects(close(witness, 5n, {kind: 1}, 100n), /Close needs/);
assert.deepEqual((await close(witness, 5n, {kind: 2}, 100n)).operation, {kind: 'close'});
assert.equal(calls.at(-1)[3], undefined);
assert.deepEqual((await silence(witness, 5n, 300n)).operation, {kind: 'silence'});
await assert.rejects(punish(witness, 5n, 100n, undefined), /signature/);
assert.deepEqual((await punish(witness, 5n, 100n, new Uint8Array(64))).operation, {kind: 'punish'});
assert.throws(selfBlock, /Contacts event/);
console.log('Wave wallet operation vectors passed');
