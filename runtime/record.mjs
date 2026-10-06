// Runs inside the vault frame. The opaque Wallet port below delegates to
// DurableRecord; only public keys, records and proofs cross this adapter.
import {createProver} from '@corbet-labs/czkp/prove';
import {witnessInputs,publicInputs} from '@corbet-labs/czkp/abi';
import {hex} from '@corbet-labs/czkp/encoding';

export class RecordProofTask {
  #wallet; #job; #closed=false;
  constructor(wallet) { this.#wallet=wallet; }

  // Called after the authenticated common download is opened. Callers observe
  // the background promise for availability, never await it on listing/contact.
  afterCommonDownload({holder,witness,artifacts,browserFactory,now,threads}) {
    if(this.#closed)throw new Error('Record task closed');
    const epoch=structuredClone(witness.epoch);
    const identity=JSON.stringify(epoch);
    if(this.#job?.identity===identity)return this.#job.promise;
    const previous=this.#job;
    const snapshot=holder.clone(),packet=structuredClone(witness);
    const job={identity,promise:undefined};
    this.#job=job;
    job.promise=(async()=>{
      // One active prover per vault; epoch replacement never races two provers.
      if(previous)await previous.promise.catch(()=>{});
      await new Promise(resolve=>setTimeout(resolve,0));
      if(this.#closed||this.#job!==job)throw new Error('Record job superseded');
      if(await this.#wallet.recordReady(epoch,now()))return;
      const key=await this.#wallet.beginRecordEpoch(epoch,Array.from(snapshot.owner.member),now());
      const prepared=await snapshot.recordEpoch(key,packet,artifacts.scope,artifacts.manifest.issuerKey);
      const selected=artifacts.artifacts('record_epoch');
      const prover=await createProver({artifacts:selected,browserFactory,threads});
      try {
        const result=await prover.prove(witnessInputs(selected.circuit,prepared.input),publicInputs(selected.circuit,prepared.input));
        if(this.#closed||this.#job!==job||now()>=epoch.expiresAt)throw new Error('Record job superseded');
        const proof=hex(new TextEncoder().encode(JSON.stringify({version:1,proofs:[{proof:hex(result.proof)}]})));
        await this.#wallet.finishRecordEpoch(prepared.statement.record,proof);
        return result.timings;
      } finally {await prover.destroy();}
    })();
    // Failed work remains unavailable; a later download/retry may reuse the
    // already sealed key. Report the original rejection to the caller.
    job.promise.catch(()=>{if(this.#job===job)this.#job=undefined;});
    return job.promise;
  }
  // No call to createProver and no await of the background job on this path.
  present(epoch,context,now) {
    if(this.#closed)throw new Error('Record task closed');
    return this.#wallet.presentRecord(epoch,context,now);
  }
  close() { this.#closed=true; }
}
