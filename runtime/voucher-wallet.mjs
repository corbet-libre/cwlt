// Generated from voucher-wallet.mts by tools/emit.mts. Do not edit.
// Voucher accounting on the wallet: the sponsor spends a voucher on an admission, consumes
// bond-addressed obligations, and the account proves its own success. The integer rules live
// in the Rust planner (cwlt::witness) and czkp::voucher; the Noir relation constrains every
// step. This file only builds witnesses for those actions.
import {ExtensionWitness} from './extensions.mjs';
import {emptyAux,enrollmentInput} from './account.mjs';
import {fieldBytes,limbs32} from '@corbet-labs/czkp/primitives';
import {random} from '@corbet-labs/czkp/encoding';

export const SUCCESS=1,PUNISHED=2,REWARD=3;
/** What the sponsor remembers about one bond, as returned by the planner. */
                                                                                                                 

export const entryPayload=(h    ,e          )=>h.hash(64,[e.limit,e.done?1n:0n,e.overshoot?1n:0n,e.punished_seen,e.rewards_seen]);
const fromPlan=(e    )          =>({limit:BigInt(e.limit),done:e.done,overshoot:e.overshoot,punished_seen:BigInt(e.punishedSeen),rewards_seen:BigInt(e.rewardsSeen)});

export class VoucherWitness extends ExtensionWitness {
  /** Set by the counted settle wrappers for exactly one transition. */
  pendingCount                                           ;
  /** The sponsor's private view of every bond it holds, keyed by the decimal bond-map key. */
  bondBook                                                =new Map();
  clone() {const copy=super.clone();copy.bondBook=new Map(this.bondBook);copy.pendingCount=undefined;return copy;}
  /** The planner must see the counted flag, so it is set before the plan is computed. */
  async finish(next    ,input    ) {
    if(this.pendingCount)input.aux.count=true;
    return super.finish(next,input);
  }
  /** Bond map and answer counting must change before the commitment is computed. */
  async beforeFinish(next    ,input    ) {
    if(this.pendingCount) {
      // The pair flips from 1 to 5: a distinct peer now counts toward the success proof.
      const pair=await this.hashes.pairKey(this.community,this.owner.member,this.ownerSecret,this.pendingCount.peer);
      const counted=await this.pairs.update(pair,5n);
      input.pair_map=counted.witness;next.pairs=counted.next;
      // The counted peer must prove its enrollment began before this account joined.
      input.peer_enrollment=enrollmentInput(this.pendingCount.enrollment);
      this.pendingCount=undefined;
    }
    next.opening.voucher.bondRoot=next.bonds.root;next.opening.voucher.bondCount=next.bonds.count;
  }
  /** Settle an answered conversation and count its peer toward the success proof. */
  async settleCounted(event       ,resolution    ,acknowledgment    ,now    ,peerEnrollment    ,receiptOwnerEnrollment    ) {
    const slot=this.slots.get(event.toString());if(!slot)throw new Error('Unknown private obligation');
    this.pendingCount={peer:slot.peer,enrollment:slot.peerEnrollment};
    try {return await this.settle(event,resolution,acknowledgment,now,peerEnrollment,receiptOwnerEnrollment);}
    finally {this.pendingCount=undefined;}
  }
  /** Consume a delivered Answer and count its sender toward the success proof. */
  async consumeCounted(entry    ,now    ) {
    for(const [,s] of this.slots) {
      for(let kind=1;kind<=1;kind++) {
        const commitment=await this.hashes.delivery(this.community,this.owner.member,s.peer,s,kind);
        if(Buffer.from(fieldBytes(commitment)).equals(Buffer.from(entry.commitment))) {
          this.pendingCount={peer:s.peer,enrollment:s.peerEnrollment};
          try {return await this.consume(entry,now);}
          finally {this.pendingCount=undefined;}
        }
      }
    }
    throw new Error('Answer delivery unavailable from authenticated contacts');
  }
  /** The sponsor spends one voucher on an actual admission and remembers the bond. */
  async admit(bondSecret           ,role       ,now    ) {
    const input=this.input(random(),now),next=this.clone();
    Object.assign(input,{action:12,role});
    input.aux={...emptyAux(),bond_secret:bondSecret};
    const entry=fromPlan(this.plan(input).entry);
    const key=await this.hashes.hash(62,limbs32(bondSecret));
    const inserted=await this.bonds.insert(key,await entryPayload(this.hashes,entry));
    input.aux.bond_map=inserted.witness;next.bonds=inserted.next;
    next.bondBook.set(key.toString(),{secret:Uint8Array.from(bondSecret),entry});
    const result=await this.finish(next,input);
    return {...result,entry};
  }
  /** Consume one obligation posted through the bond; the tag is the only thing a server saw. */
  async consumeObligation(bondSecret           ,kind       ,n       ,entry          ,now    ) {
    const input=this.input(random(),now),next=this.clone();
    const tag=await this.hashes.hash(60,[...limbs32(bondSecret),BigInt(kind),n]);
    Object.assign(input,{action:13,obligation:fieldBytes(tag)});
    input.aux={...emptyAux(),bond_secret:bondSecret,kind,n,entry};
    const after=fromPlan(this.plan(input).entry);
    const key=await this.hashes.hash(62,limbs32(bondSecret));
    const changed=await this.bonds.update(key,await entryPayload(this.hashes,after));
    input.aux.bond_map=changed.witness;next.bonds=changed.next;
    next.bondBook.set(key.toString(),{secret:Uint8Array.from(bondSecret),entry:after});
    const result=await this.finish(next,input);
    return {...result,entry:after,tag:fieldBytes(tag)};
  }
  /** A link of `units` uses is created: its issue presentation reserved them (action 15). */
  async reserveLink(units       ,role       ,now    ) {
    const input=this.input(random(),now),next=this.clone();
    Object.assign(input,{action:15,role});
    input.aux={...emptyAux(),units};
    return this.finish(next,input);
  }
  /** Unused uses of an expired, revoked or declined link return (action 16). */
  async releaseLink(units       ,role       ,now    ) {
    const input=this.input(random(),now),next=this.clone();
    Object.assign(input,{action:16,role});
    input.aux={...emptyAux(),units};
    return this.finish(next,input);
  }
  /** The account's own success proof; every threshold is a public policy value. */
  async proveSuccess(now    ) {
    const input=this.input(random(),now),next=this.clone();
    input.action=14;
    return this.finish(next,input);
  }
}
