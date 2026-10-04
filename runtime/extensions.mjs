// Member-only witness construction. The supplied Rust planner owns integer
// transitions; the authenticated Noir policy independently constrains every field.
import {AccountWitness,enrollmentInput,openingInput,slotInput} from './account.mjs';
import {accountHashes,IndexedMap,receiptBytes,ackBytes,noirInput} from './hashes.mjs';
import {statementFromInput,publicInputValues,validityHorizon} from './statement.mjs';
import {fieldBytes,fieldValue,limbs32} from '@corbet-labs/czkp/primitives';
import {cat,be,sha,hex,zeros,random} from '@corbet-labs/czkp/encoding';
import {recordEpochPublicInputs,recordLeafCommitment,recordBytes} from '@corbet-labs/czkp/record';
export {accountHashes,IndexedMap,receiptBytes,ackBytes,noirInput};
export {checkpointFromVerified} from './hashes.mjs';
const bytes=v=>Uint8Array.from(v);
const extInput=p=>({revision:p.revision,quorum:p.publicRecordQuorum,change_cost:p.changeTokenCost,delay:p.depositDelaySeconds,batch:p.minimumDepositBatch});
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
  h.extension=p=>h.hash(31,[p.revision,p.publicRecordQuorum,p.changeTokenCost,p.depositDelaySeconds,p.minimumDepositBatch].map(BigInt));
  h.delivery=(community,recipient,reporter,slot,kind)=>h.hash(32,[...limbs32(community),...limbs32(recipient),...limbs32(reporter),...limbs32(slot.nonce),...limbs32(slot.group),BigInt(kind)]);
  h.authorization=async(community,owner,secret,slot,kind)=>h.hash(33,[await h.marker(community,secret,owner,slot.peer,slot.nonce),await h.delivery(community,slot.peer,owner,slot,kind),BigInt(kind)]);
  h.obligation=(event,s,phase)=>h.hash(4,[event,BigInt(s.role),...limbs32(s.peer),...limbs32(s.nonce),...limbs32(s.group),...limbs32(s.contactPolicy),BigInt(s.amount),BigInt(phase),BigInt(s.outcome??0),s.answered?1n:0n,s.selfPunished?1n:0n,BigInt(s.admittedAt),BigInt(s.expiresAt),s.peerAuthority,s.ownerAuthority]);
  return h;
}
const balanceKeys=['available','reserved','debt','accepted','declined','punished'];
const extendedOpening=s=>({...openingInput(s),...Object.fromEntries(balanceKeys.slice(2).map(k=>[k,s[k]])),inbox:s.inbox,authorization:s.authorization});
export class ExtensionWitness extends AccountWitness {
  async commit(o,version) {
    for(const k of balanceKeys.slice(2))o[k]??=0n;
    o.inbox??=zeros();o.authorization??=0n;
    return this.hashes.hash(30,[...limbs32(this.community),...limbs32(this.owner.member),...limbs32(this.statePolicyHash),fieldValue(this.owner.secretHash),BigInt(version),
      await this.hashes.extension(this.extension),...balanceKeys.map(k=>BigInt(o[k])),...limbs32(o.inbox),o.authorization,
      o.outgoingRoot,o.outgoingCount,o.incomingRoot,o.incomingCount,o.pairRoot,o.pairCount,o.frontier,o.createdAt,o.admissionEpoch,o.admissions,...limbs32(o.blind)]);
  }
  input(blind,now) {
    return {...super.input(blind,now),old:extendedOpening(this.opening),extension:extInput(this.extension),previous_inbox:this.opening.inbox,inbox:this.opening.inbox,
      consume_only:false,change_binding:zeros(),delivery_kind:0,contact_signature:new Uint8Array(64)};
  }
  plan(input) {
    const s=input.slot,old=Object.fromEntries(balanceKeys.map(k=>[k,Number(this.opening[k])]));
    return this.transition({old,action:input.action,capacity:Number(this.at(input.now).capacity),amount:Number(s.amount),role:Number(s.role),phase:Number(s.phase),outcome:Number(s.outcome),
      answered:s.answered,selfPunished:s.self_punished,kind:input.action===10?Number(input.delivery_kind):Number(input.resolution.kind),changeCost:this.extension.changeTokenCost,refillUnits:this.policy.refillUnits});
  }
  async finish(next,input) {
    const plan=this.plan(input);
    for(const k of balanceKeys)next.opening[k]=BigInt(plan.balances[k]);
    next.opening.inbox=bytes(input.inbox);
    next.opening.authorization=plan.authorization?await this.hashes.authorization(this.community,this.owner.member,this.ownerSecret,
      {peer:bytes(input.slot.peer),nonce:bytes(input.slot.nonce),group:bytes(input.slot.group)},plan.authorization):0n;
    const result=await super.finish(next,input);
    if(input.consume_only){next.version=this.version;next.commitment=await next.commit(next.opening,next.version);input.next_version=this.version;input.next_state=fieldBytes(next.commitment);result.statement=statementFromInput(input);}
    result.update={previousInbox:{root:Array.from(input.previous_inbox)},inbox:{root:Array.from(input.inbox)},effect:input.action===9?{kind:'change',binding:Array.from(input.change_binding)}:{kind:'update'}};
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
  async deposit({slot,kind},certificate,scope,issuerKey,releaseEpoch) {
    const event=await this.hashes.marker(this.community,this.ownerSecret,this.owner.member,slot.peer,slot.nonce),stage=kind===4?1:0;
    const deposit={community:Array.from(this.community),recipient:Array.from(slot.peer),releaseEpoch,
      nullifier:Array.from(fieldBytes(await this.hashes.raw([event,41,stage,...limbs32(this.ownerSecret)]))),authorizationNullifier:Array.from(fieldBytes(await this.hashes.raw([event,40,stage,...limbs32(this.ownerSecret)]))),
      obligation:Array.from(fieldBytes(await this.hashes.delivery(this.community,slot.peer,this.owner.member,slot,kind)))};
    return {statement:{kind:'deposit',policy:this.extension,deposit},input:{extension:extInput(this.extension),issuer_key:issuerKey,scope,
      community:this.community,recipient:slot.peer,release_epoch:releaseEpoch,nullifier:deposit.nullifier,authorization_nullifier:deposit.authorizationNullifier,obligation:deposit.obligation,
      reporter:this.owner.member,secret:this.ownerSecret,state_policy:this.statePolicyHash,version:this.version,accepted_at:certificate.acceptedAt,state:fieldBytes(this.commitment),opening:extendedOpening(this.opening),certificate:certificate.signature,slot:slotInput(slot),kind}};
  }
  wave(event,context,scope,issuerKey) {return this.waveEvidence(event,context,scope,issuerKey);}
  waveOutcome(event,context,scope,issuerKey,outcome,resolution,acknowledgment) {
    if(!['answer','close','silence'].includes(outcome))throw new Error('Unknown settled outcome');
    return this.waveEvidence(event,context,scope,issuerKey,{outcome,resolution,acknowledgment});
  }
  async waveEvidence(event,{history,challenge},scope,issuerKey,settled) {
    // All mutable state is detached before the first asynchronous hash.
    const state=this.clone();state.owner=structuredClone(this.owner);state.ownerSecret=bytes(this.ownerSecret);
    state.community=bytes(this.community);state.statePolicyHash=bytes(this.statePolicyHash);
    state.extension=structuredClone(this.extension);state.certificate=structuredClone(this.certificate);
    state.outgoing=this.outgoing.clone();state.incoming=this.incoming.clone();
    history=bytes(history);challenge=bytes(challenge);scope=bytes(scope);issuerKey=bytes(issuerKey);
    settled=settled?structuredClone(settled):undefined;
    const slot=state.slots.get(event.toString());
    const code=settled?{answer:1,close:2,silence:3}[settled.outcome]:0;
    if(!slot||slot.phase!==(code===3?5:code?3:2)||!state.certificate)throw new Error('Accepted active reservation required');
    const map=slot.role===0?state.outgoing:state.incoming,found=map.find(event);
    if(!found)throw new Error('Missing reservation membership');
    const selected=map.witness(found[0]),payload=await state.hashes.obligation(event,slot,slot.phase);
    if(selected.leaf[1]!==payload)throw new Error('Reservation opening differs');
    const receiptDigest=code&&code!==3?bytes(settled.resolution.ed25519ReceiptDigest):zeros();
    const domain=code?0x63776c742e657874656e73696f6e2d6f7574636f6d652e7631n:0x63776c742e657874656e73696f6e2d776176652e7631n;
    const binding=fieldBytes(await state.hashes.raw([domain,1n,
      ...limbs32(state.ownerSecret),state.commitment,payload,...limbs32(challenge),...limbs32(history),
      ...(code?[BigInt(code),...limbs32(receiptDigest)]:[])]));
    const context={community:Array.from(state.community),owner:Array.from(state.owner.member),peer:Array.from(slot.peer),role:slot.role,
      nonce:Array.from(slot.nonce),group:Array.from(slot.group),contactPolicy:Array.from(slot.contactPolicy),history:Array.from(history),challenge:Array.from(challenge),
      openedAt:Number(slot.admittedAt),expiresAt:Number(slot.expiresAt),ownerAuthority:Array.from(fieldBytes(slot.ownerAuthority)),peerAuthority:Array.from(fieldBytes(slot.peerAuthority))};
    const wave={context,statePolicy:Array.from(state.statePolicyHash),version:Number(state.version),state:Array.from(fieldBytes(state.commitment)),
      acceptedAt:state.certificate.acceptedAt,binding:Array.from(binding)};
    const result={statement:{kind:'wave',policy:state.extension,certificateKey:Array.from(issuerKey),wave},input:{extension:extInput(state.extension),issuer_key:issuerKey,scope,
      community:state.community,owner:state.owner.member,peer:slot.peer,role:slot.role,nonce:slot.nonce,group:slot.group,contact_policy:slot.contactPolicy,
      history,challenge,opened_at:slot.admittedAt,expires_at:slot.expiresAt,owner_authority:fieldBytes(slot.ownerAuthority),peer_authority:fieldBytes(slot.peerAuthority),
      state_policy:state.statePolicyHash,version:state.version,state:fieldBytes(state.commitment),accepted_at:state.certificate.acceptedAt,binding,
      secret:state.ownerSecret,opening:extendedOpening(state.opening),slot:slotInput(slot),selected,certificate:state.certificate.signature}};
    if(code){
      const resolution=settled.resolution??{kind:0,issuedAt:0n,historyDigest:zeros(),ed25519ReceiptDigest:zeros(),signature:new Uint8Array(64)};
      const acknowledgment=settled.acknowledgment??{issuedAt:0n,signature:new Uint8Array(64)};
      result.statement={kind:'outcome',policy:state.extension,certificateKey:Array.from(issuerKey),
        outcome:{evidence:wave,outcome:settled.outcome,receiptDigest:Array.from(receiptDigest)}};
      Object.assign(result.input,{outcome:code,receipt_digest:receiptDigest,owner_enrollment:enrollmentInput(slot.ownerEnrollment),peer_enrollment:enrollmentInput(slot.peerEnrollment),
        resolution:{kind:resolution.kind,issued_at:resolution.issuedAt,history_digest:resolution.historyDigest,ed25519_receipt_digest:resolution.ed25519ReceiptDigest,signature:resolution.signature},
        acknowledgment:{issued_at:acknowledgment.issuedAt,signature:acknowledgment.signature}});
    }
    return result;
  }
  record(context) {
    const total=this.opening.accepted+this.opening.declined+this.opening.punished;
    const shares=total>=BigInt(this.extension.publicRecordQuorum)?[Number(this.opening.accepted*10000n/total),Number(this.opening.declined*10000n/total)]:null;
    if(shares)shares.push(10000-shares[0]-shares[1]);
    const record={context,community:Array.from(this.community),owner:Array.from(this.owner.member),version:Number(this.version),state:Array.from(fieldBytes(this.commitment)),inbox:{root:Array.from(this.opening.inbox)},shares};
    return {statement:{kind:'record',policy:this.extension,record},input:{extension:extInput(this.extension),community:this.community,owner:this.owner.member,version:this.version,state:fieldBytes(this.commitment),inbox:this.opening.inbox,
      purpose:context.purpose==='firstContact'?0:1,challenge:context.challenge,expires_at:context.expiresAt,present:shares!==null,shares:shares??[0,0,0],state_policy:this.statePolicyHash,registered_secret:fieldValue(this.owner.secretHash),opening:extendedOpening(this.opening)}};
  }
  // Member-only proof construction. The caller supplies an already authenticated
  // current descriptor and its privately opened common-download witness. This
  // builder cannot authenticate a descriptor or grant listing/contact authority.
  async recordEpoch(presentationPublicKey,witness,scope,issuerKey) {
    const state=this.clone();state.community=bytes(this.community);state.owner=structuredClone(this.owner);
    state.statePolicyHash=bytes(this.statePolicyHash);state.extension=structuredClone(this.extension);
    presentationPublicKey=recordBytes(presentationPublicKey);witness=structuredClone(witness);scope=structuredClone(scope);issuerKey=recordBytes(issuerKey,64);
    const total=state.opening.accepted+state.opening.declined+state.opening.punished;
    const shares=total>=BigInt(state.extension.publicRecordQuorum)?[Number(state.opening.accepted*10000n/total),Number(state.opening.declined*10000n/total)]:null;
    if(shares)shares.push(10000-shares[0]-shares[1]);
    const record={epoch:witness.epoch,owner:Array.from(state.owner.member),presentationKeyCommitment:Array.from(await sha(Uint8Array.from(presentationPublicKey))),shares};
    const input=recordEpochPublicInputs(record,scope,issuerKey),leaf=witness.leaf;
    const equal=(a,b)=>hex(Uint8Array.from(a))===hex(Uint8Array.from(b));
    if(!equal(state.community,input.community)||!equal(recordBytes(leaf.owner),state.owner.member))throw new Error('Foreign record witness');
    const depth=Math.max(1,Math.ceil(Math.log2(witness.epoch.leafCount)));
    if(!Number.isSafeInteger(witness.index)||witness.index<0||witness.index>=witness.epoch.leafCount
      ||!Array.isArray(witness.path)||witness.path.length!==depth)throw new Error('Record path bounds');
    const path=witness.path.map(p=>recordBytes(p));while(path.length<32)path.push(Array(32).fill(0));
    const frozenLeaf=await recordLeafCommitment(state.community,witness.epoch.epoch,leaf);
    const current=fieldBytes(state.commitment),version=Number(state.version);
    const descended=version!==leaf.version||!equal(current,leaf.state)||!equal(state.opening.inbox,leaf.requiredInbox);
    let issuedAt=0,signature=new Uint8Array(64);
    if(descended){
      const a=witness.ancestry;
      if(!a||!Number.isSafeInteger(a.issuedAt)||a.issuedAt<input.epoch_start||a.issuedAt>=input.epoch_end
        ||a.epoch!==input.epoch||a.version!==version||version<=leaf.version
        ||!equal(recordBytes(a.community),state.community)||!equal(recordBytes(a.owner),state.owner.member)
        ||!equal(recordBytes(a.root),input.epoch_root)||!equal(recordBytes(a.frozenLeaf),frozenLeaf)
        ||!equal(recordBytes(a.state),current)||!equal(recordBytes(a.proofScope?.circuitDigest),scope.circuitDigest)
        ||!equal(recordBytes(a.proofScope?.verifyingKeyDigest),scope.verifyingKeyDigest))throw new Error('Missing or unrelated ancestry certificate');
      issuedAt=a.issuedAt;signature=recordBytes(a.signature,64);
    }
    return {statement:{kind:'recordEpoch',policy:state.extension,record},input:{...input,
      presentation_public_key:presentationPublicKey,extension:extInput(state.extension),version:state.version,state:current,frozen_version:leaf.version,frozen_state:leaf.state,
      required_inbox:leaf.requiredInbox,blinding:leaf.blinding,path,index:witness.index,descended,issued_at:issuedAt,certificate:signature,
      state_policy:state.statePolicyHash,registered_secret:fieldValue(state.owner.secretHash),opening:extendedOpening(state.opening)}};
  }
}
