import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import init,{prepare} from '../pkg/cwlt.js';
await init({module_or_path:await readFile(new URL('../pkg/cwlt_bg.wasm',import.meta.url))});
const params={c0:3,hA:14,hG:14,nHalf:25,nC:60,eQ:16384,rMax:40,rAge:2,cMaxQ:52428,cVet:30,ageVet:60,boostQ:65536,boostDays:30,slopeQ:262144,midQ:49152,kappaQ:131072,loanUseQ:16384};
const standing={g:0,a:131072,c:0,pr:0,pg:0,lc:0,day:0};
const r:any={old:{reserved:0,accepted:1,declined:0,punished:0},standing,params,createdAt:100,now:200,action:8,amount:1,role:0,phase:3,outcome:1,kind:4,answered:true,selfPunished:false,changeCost:1};
const apply=(value:any)=>JSON.parse(prepare(JSON.stringify(value)));
// Punishing costs the punisher one given punishment; refill is retired.
const burn=apply(r);assert.equal(burn.standing.pg,65536);assert.equal(burn.selfPunished,true);
assert.throws(()=>apply({...r,action:6}));
assert.throws(()=>apply({...r,old:burn.balances,phase:7,selfPunished:true}));
assert.throws(()=>prepare('{"private":"malformed"}'));
// A punished wave holds its slot (phase 8); a late Answer cannot change the terminal record.
const original={...r,old:{reserved:2,accepted:0,declined:0,punished:0},action:10,amount:2,phase:2,outcome:0,answered:false,kind:3};
const early=apply(original);assert.equal(early.balances.reserved,2);assert.equal(early.balances.punished,1);assert.equal(early.phase,8);
assert.equal(early.standing.pr,65536);
// The pool: reservations stop at the standing cap.
const reserve={...r,action:1,phase:1,outcome:0,answered:false,old:{reserved:2,accepted:0,declined:0,punished:0}};
assert.equal(apply(reserve).balances.reserved,3);
assert.throws(()=>apply({...reserve,old:{reserved:3,accepted:0,declined:0,punished:0}}));
console.log('Native-equivalent wasm punishment, pool and replay vectors passed');
