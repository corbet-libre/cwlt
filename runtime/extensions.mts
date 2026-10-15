// Member-only witness construction. The supplied Rust planner owns integer
// transitions; the authenticated Noir policy independently constrains every field.
import {AccountWitness,enrollmentInput,openingInput,slotInput} from './account.mts';
import {accountHashes,IndexedMap,receiptBytes,ackBytes,noirInput} from './hashes.mjs';
import {statementFromInput,publicInputValues,validityHorizon} from './statement.mjs';
import {fieldBytes,fieldValue,limbs32} from '@corbet-labs/czkp/primitives';
import {cat,be,sha,hex,zeros,random} from '@corbet-labs/czkp/encoding';
/** Largest circuit integer; an open issuer period ends here. */
const MAX_INTEGER=9007199254740991;
export {accountHashes,IndexedMap,receiptBytes,ackBytes,noirInput};
export {checkpointFromVerified} from './hashes.mjs';
const bytes=v=>Uint8Array.from(v);
const extInput=p=>({revision:p.revision,quorum:p.publicRecordQuorum,change_cost:p.changeTokenCost,delay:p.depositDelaySeconds,batch:p.minimumDepositBatch,standing:Array.from(p.standingPolicyDigest)});
export {extInput};
export const advance=(community,owner,root,commitment)=>sha(cat(new TextEncoder().encode('cblc.obligation-inbox.v2\0'),community,owner,root,commitment));
export function contactBytes(community,owner,slot) {
  return cat(new TextEncoder().encode('cblc.contact.v1\0'),community,
    slot.role===0?owner:slot.peer,slot.role===0?slot.peer:owner,slot.nonce,slot.group,slot.contactPolicy,
    fieldBytes(slot.role===0?slot.ownerAuthority:slot.peerAuthority),fieldBytes(slot.role===0?slot.peerAuthority:slot.ownerAuthority),
    be(slot.admittedAt,8),be(slot.expiresAt,8));
}
export function extensionHashes(api) {
  const h=accountHashes(api);
  h.raw=async v=>fieldValue((await api.poseidon2Hash({inputs:v.map(n=>fieldBytes(BigInt(n)))})).hash);
  h.extension=p=>h.hash(31,[...[p.revision,p.publicRecordQuorum,p.changeTokenCost,p.depositDelaySeconds,p.minimumDepositBatch].map(BigInt),...limbs32(Uint8Array.from(p.standingPolicyDigest))]);
  h.delivery=(community,recipient,reporter,slot,kind)=>h.hash(32,[...limbs32(community),...limbs32(recipient),...limbs32(reporter),...limbs32(slot.nonce),...limbs32(slot.group),BigInt(kind)]);
  h.authorization=async(community,owner,secret,slot,kind)=>h.hash(33,[await h.marker(community,secret,owner,slot.peer,slot.nonce),await h.delivery(community,slot.peer,owner,slot,kind),BigInt(kind)]);
  h.obligation=(event,s,phase)=>h.hash(4,[event,BigInt(s.role),...limbs32(s.peer),...limbs32(s.nonce),...limbs32(s.group),...limbs32(s.contactPolicy),BigInt(s.amount),BigInt(phase),BigInt(s.outcome??0),s.answered?1n:0n,s.selfPunished?1n:0n,BigInt(s.admittedAt),BigInt(s.expiresAt),s.peerAuthority,s.ownerAuthority]);
  return h;
}
const balanceKeys=['reserved','accepted','declined','punished'];
const extendedOpening=s=>({...openingInput(s),...Object.fromEntries(balanceKeys.slice(1).map(k=>[k,s[k]])),inbox:s.inbox,authorization:s.authorization});
const standingKeys=['g','a','c','pr','pg','lc','day'];
const voucherKeys=['proven','away','reserved','lost','bonus','returned','answers'];
export class ExtensionWitness extends AccountWitness {
  async commit(o,version) {
    for(const k of balanceKeys.slice(1))o[k]??=0n;
    o.inbox??=zeros();o.authorization??=0n;
    return this.hashes.hash(30,[...limbs32(this.community),...limbs32(this.owner.member),...limbs32(this.statePolicyHash),fieldValue(this.owner.secretHash),BigInt(version),
      await this.hashes.extension(this.extension),...balanceKeys.map(k=>BigInt(o[k])),...limbs32(o.inbox),o.authorization,
      o.outgoingRoot,o.outgoingCount,o.incomingRoot,o.incomingCount,o.pairRoot,o.pairCount,o.createdAt,...standingKeys.map(k=>BigInt(o.standing[k])),
      ...voucherKeys.map(k=>BigInt(o.voucher[k])),o.voucher.sponsor,o.voucher.bond,o.voucher.bondRoot,o.voucher.bondCount,...limbs32(o.blind)]);
  }
  input(blind,now) {
    return {...super.input(blind,now),old:extendedOpening(this.opening),extension:extInput(this.extension),previous_inbox:this.opening.inbox,inbox:this.opening.inbox,
      consume_only:false,change_binding:zeros(),delivery_kind:0,contact_signature:new Uint8Array(64)};
  }
  plan(input) {
    const s=input.slot,old=Object.fromEntries(balanceKeys.map(k=>[k,Number(this.opening[k])])),
      standing=Object.fromEntries(standingKeys.map(k=>[k,Number(this.opening.standing[k])]));
    return this.transition({old,standing,params:this.standing,createdAt:Number(this.opening.createdAt),now:Number(input.now),action:input.action,amount:Number(s.amount),role:Number(s.role),
      phase:Number(s.phase),outcome:Number(s.outcome),answered:s.answered,selfPunished:s.self_punished,
      kind:input.action===10?Number(input.delivery_kind):Number(input.resolution.kind),changeCost:this.extension.changeTokenCost,
      voucher:Object.fromEntries(voucherKeys.map(k=>[k,Number(this.opening.voucher[k])])),voucherRole:Number(input.role),count:input.aux.count,
      obligationKind:Number(input.aux.kind),obligationN:Number(input.aux.n),units:Number(input.aux.units??0),
      entry:{limit:Number(input.aux.entry.limit),done:input.aux.entry.done,overshoot:input.aux.entry.overshoot,
        punishedSeen:Number(input.aux.entry.punished_seen),rewardsSeen:Number(input.aux.entry.rewards_seen)}});
  }
  async finish(next,input) {
    const plan=this.plan(input);
    for(const k of balanceKeys)next.opening[k]=BigInt(plan.balances[k]);
    next.opening.standing=Object.fromEntries(standingKeys.map(k=>[k,BigInt(plan.standing[k])]));
    for(const k of voucherKeys)next.opening.voucher[k]=BigInt(plan.voucher[k]);
    input.standing_policy=plan.policy;
    next.opening.inbox=bytes(input.inbox);
    next.opening.authorization=plan.authorization?await this.hashes.authorization(this.community,this.owner.member,this.ownerSecret,
      {peer:bytes(input.slot.peer),nonce:bytes(input.slot.nonce),group:bytes(input.slot.group)},plan.authorization):0n;
    const result=await super.finish(next,input);
    if(input.consume_only){next.version=this.version;next.commitment=await next.commit(next.opening,next.version);input.next_version=this.version;input.next_state=fieldBytes(next.commitment);result.statement=statementFromInput(input);}
    result.update={previousInbox:{root:Array.from(input.previous_inbox)},inbox:{root:Array.from(input.inbox)},effect:input.action===9?{kind:'change',binding:Array.from(input.change_binding)}:input.action===12?{kind:'admit',role:Number(input.role)}:input.action===13?{kind:'consume',obligation:Array.from(input.obligation)}:{kind:'update'}};
    return result;
  }
  // A contact signature is supplied by the counterpart over contactBytes. Never
  // derive it from an unauthenticated directory or sign it on the server.
  async activate(event,now,contactSignature) {
    const result=await super.activate(event,now);result.input.contact_signature=contactSignature;return result;
  }
  async punish(event,now,contactSignature) {
    const s=this.slots.get(event.toString());if(!s)throw new Error('Unknown contact');
    const input=this.input(random(),now);input.action=s.answered?8:7;
    input.slot=slotInput(s);input.peer_enrollment=enrollmentInput(s.peerEnrollment);input.contact_signature=contactSignature;
    const plan=this.plan(input),next=this.clone(),updated={...s,phase:plan.phase,outcome:plan.outcome,answered:plan.answered,selfPunished:plan.selfPunished};
    const own=s.role===0?this.outgoing:this.incoming;
    const changed=await own.update(event,await this.hashes.obligation(event,updated,updated.phase));input.own_map=changed.witness;
    if(s.role===0)next.outgoing=changed.next;else next.incoming=changed.next;
    const pair=await this.hashes.pairKey(this.community,this.owner.member,this.ownerSecret,s.peer);
    const blocked=await this.pairs.update(pair,2n);input.pair_map=blocked.witness;next.pairs=blocked.next;
    next.slots.set(event.toString(),updated);input.settlement_marker=fieldBytes(await this.hashes.raw([event,plan.authorization]));
    const result=await this.finish(next,input);result.delivery={slot:structuredClone(s),kind:plan.authorization};return result;
  }
  async changeToken(binding,now) {
    const input=this.input(random(),now),next=this.clone();input.action=9;input.change_binding=bytes(binding);
    const event=await this.hashes.marker(this.community,this.ownerSecret,this.owner.member,this.owner.member,bytes(binding));
    input.settlement_marker=fieldBytes(await this.hashes.raw([event,this.version,...limbs32(bytes(binding))]));
    return this.finish(next,input);
  }
  async reblind(now) {const input=this.input(random(),now);input.action=11;return this.finish(this.clone(),input);}
  async consume(entry,now) {
    if(hex(bytes(entry.previous.root))!==hex(this.opening.inbox))throw new Error('Stale inbox frontier');
    let selected;
    for(const [event,s] of this.slots)for(let kind=1;kind<=4;kind++) {
      if(hex(fieldBytes(await this.hashes.delivery(this.community,this.owner.member,s.peer,s,kind)))===hex(bytes(entry.commitment))) selected={event:BigInt(event),s,kind};
    }
    if(!selected)throw new Error('Obligation opening unavailable from authenticated contacts');
    const {event,s,kind}=selected,input=this.input(random(),now),next=this.clone();
    Object.assign(input,{action:10,consume_only:true,delivery_kind:kind,slot:slotInput(s)});
    input.inbox=await advance(this.community,this.owner.member,this.opening.inbox,bytes(entry.commitment));
    const plan=this.plan(input),updated={...s,phase:plan.phase,outcome:plan.outcome,answered:plan.answered,selfPunished:plan.selfPunished};
    const changed=await(s.role===0?this.outgoing:this.incoming).update(event,await this.hashes.obligation(event,updated,updated.phase));
    input.own_map=changed.witness;if(s.role===0)next.outgoing=changed.next;else next.incoming=changed.next;
    next.slots.set(event.toString(),updated);return this.finish(next,input);
  }
  // `issuance` = {publicKey, validFrom, validUntil?, identity}: the published ring period whose
  // key signed the certificate (open period: validUntil absent) and the community identity.
  async deposit({slot,kind},certificate,scope,issuance,releaseEpoch) {
    const until=issuance.validUntil??MAX_INTEGER,at=Number(certificate.acceptedAt);
    if(!(issuance.validFrom>0&&issuance.validFrom<=at&&at<until)||issuance.publicKey.length!==64||issuance.identity.length!==32)
      throw new Error('the certificate lies outside the named issuer key period');
    const event=await this.hashes.marker(this.community,this.ownerSecret,this.owner.member,slot.peer,slot.nonce),stage=kind===4?1:0;
    const deposit={community:Array.from(this.community),identity:Array.from(issuance.identity),issuerKey:Array.from(issuance.publicKey),
      issuerValidFrom:issuance.validFrom,issuerValidUntil:until,recipient:Array.from(slot.peer),releaseEpoch,
      nullifier:Array.from(fieldBytes(await this.hashes.raw([event,41,stage,...limbs32(this.ownerSecret)]))),authorizationNullifier:Array.from(fieldBytes(await this.hashes.raw([event,40,stage,...limbs32(this.ownerSecret)]))),
      obligation:Array.from(fieldBytes(await this.hashes.delivery(this.community,slot.peer,this.owner.member,slot,kind)))};
    return {statement:{kind:'deposit',policy:this.extension,deposit},input:{extension:extInput(this.extension),issuer_key:Array.from(issuance.publicKey),
      issuer_valid_from:issuance.validFrom,issuer_valid_until:until,scope,community:this.community,identity:Array.from(issuance.identity),recipient:slot.peer,release_epoch:releaseEpoch,nullifier:deposit.nullifier,authorization_nullifier:deposit.authorizationNullifier,obligation:deposit.obligation,
      reporter:this.owner.member,secret:this.ownerSecret,state_policy:this.statePolicyHash,version:this.version,accepted_at:certificate.acceptedAt,state:fieldBytes(this.commitment),opening:extendedOpening(this.opening),certificate:certificate.signature,slot:slotInput(slot),kind}};
  }
  record(context) {
    const total=this.opening.accepted+this.opening.declined+this.opening.punished;
    const shares=total>=BigInt(this.extension.publicRecordQuorum)?[Number(this.opening.accepted*10000n/total),Number(this.opening.declined*10000n/total)]:null;
    if(shares)shares.push(10000-shares[0]-shares[1]);
    const record={context,community:Array.from(this.community),owner:Array.from(this.owner.member),version:Number(this.version),state:Array.from(fieldBytes(this.commitment)),inbox:{root:Array.from(this.opening.inbox)},shares};
    return {statement:{kind:'record',policy:this.extension,record},input:{extension:extInput(this.extension),community:this.community,owner:this.owner.member,version:this.version,state:fieldBytes(this.commitment),inbox:this.opening.inbox,
      purpose:context.purpose==='firstContact'?0:1,challenge:context.challenge,expires_at:context.expiresAt,present:shares!==null,shares:shares??[0,0,0],state_policy:this.statePolicyHash,registered_secret:fieldValue(this.owner.secretHash),opening:extendedOpening(this.opening)}};
  }
}
