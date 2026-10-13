// Generated from wave-wallet.mts by tools/emit.mts. Do not edit.
// Wave wallet operations over cwlt's existing non-genesis witness builders.
//
// Each function only chooses the builder, checks the call's shape and names the
// operation; the builder (and the update circuit behind it) enforces every rule.
// Nothing here proves, submits or blocks: the caller records the member's action
// first (cwlt wave_wallet job journal) and runs these in a background worker.
                        

/** What a builder returns: the circuit input, the public statement and the next witness. */
                                                                                  
/** The slice of the account/extension witness this module drives. */
                          
                                                       
                                                                                                                               
                                                                  
                                                                                           
 
                          
                                                                                   
                                                                                
 
                                                                                                                 
                                                                              
                       
                                  
                                                                              
                                                                     

const ANSWER = 1, CLOSE = 2;

/** Reserve the sender's introduction; the lease is opened now by the builder. */
export async function reserveSender(w         , wave      )                   {
  return {operation: {kind: 'reserve', role: 0}, candidate: await w.reserve({...wave, role: 0})};
}
/** Reserve the recipient's slot under the sender's authenticated lease. */
export async function reserveRecipient(w         , wave      , lease                   )                   {
  if (!lease) throw new Error('The sender\'s lease is required');
  return {operation: {kind: 'reserve', role: 1}, candidate: await w.reserve({...wave, role: 1, ...lease})};
}
/** Settle as Answer with the original receipt and the sender's acknowledgement. */
export async function answer(w         , event        , resolution                , acknowledgment         ,
    now                 )                   {
  if (resolution?.kind !== ANSWER || !acknowledgment) throw new Error('An Answer needs its receipt and acknowledgement');
  return {operation: {kind: 'answer'}, candidate: await w.settle(event, resolution, acknowledgment, now)};
}
/** Settle as Close (the recipient declines); no acknowledgement is involved. */
export async function close(w         , event        , resolution                , now                 )                   {
  if (resolution?.kind !== CLOSE) throw new Error('A Close needs its signed decline');
  return {operation: {kind: 'close'}, candidate: await w.settle(event, resolution, undefined, now)};
}
/** Expire an unanswered reservation: the sender's refund after the deadline. */
export async function silence(w         , event        , now                 )                   {
  return {operation: {kind: 'silence'}, candidate: await w.expire(event, now)};
}
/** Punish the peer: burns on both sides and blocks the pair in the same update. */
export async function punish(w         , event        , now                 , contactSignature                   )                   {
  if (!contactSignature) throw new Error('The peer\'s contact signature is required');
  return {operation: {kind: 'punish'}, candidate: await w.punish(event, now, contactSignature)};
}
