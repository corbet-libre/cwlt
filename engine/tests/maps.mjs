// Public conformance vectors from ORIGINAL Wallet map code and maintained BB.
// Execute on CI only. This does not generate or reveal a member opening.
import {writeFile} from 'node:fs/promises';
import {Barretenberg, BackendType} from '@aztec/bb.js';
import {IndexedMap, accountHashes} from '../../runtime/hashes.mjs';
import {fieldBytes} from '@corbet-labs/czkp/primitives';
const output=process.argv[2];
if(!process.env.CI||!output)throw new Error('CI and external vector path required');
const hex=bytes=>Buffer.from(bytes).toString('hex');
const field=n=>hex(fieldBytes(n));
const witness=w=>({leaf:w.leaf.map(field),index:Number(w.index),path:w.path.map(field),appendPath:w.append_path.map(field)});
const api=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true,memory:{initial:2048,maximum:32768}});
try {
  const calls=[];
  const recorder={async poseidon2Hash({inputs}){
    const result=await api.poseidon2Hash({inputs});
    calls.push({inputs:inputs.map(hex),output:hex(result.hash)});return result;
  }};
  const hashes=accountHashes(recorder);
  let map=await IndexedMap.create(hashes);
  const states=[{root:field(map.root),count:Number(map.count)}],steps=[];
  for(const [key,payload] of [[7n,70n],[3n,30n],[11n,110n]]){
    const before=field(map.root),result=await map.insert(key,payload);
    if(field(map.root)!==before)throw new Error('Original accepted map mutated');
    steps.push({operation:'insert',key:field(key),payload:field(payload),witness:witness(result.witness)});
    map=result.next;states.push({root:field(map.root),count:Number(map.count)});
  }
  const changed=await map.update(3n,33n);
  steps.push({operation:'update',key:field(3n),payload:field(33n),witness:witness(changed.witness)});
  map=changed.next;states.push({root:field(map.root),count:Number(map.count)});
  const gap=witness(map.absence(5n));
  await writeFile(output,JSON.stringify({schema:1,source:'original-runtime/hashes.mjs',calls,states,steps,gap})+'\n',{flag:'wx'});
} finally {await api.destroy();}
