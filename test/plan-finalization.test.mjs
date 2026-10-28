import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createPlanStore} from '../lib/public-plans.mjs';
import {memoryDatabase} from './helpers/database.mjs';
test('credit finalization handles Firebase omitting empty completed maps and remains idempotent',async()=>{
 for(const coldTransactions of [false,true]){
  const {db,records}=memoryDatabase({coldTransactions}),store=createPlanStore(db),path='nebulaPublicPlans/v1/account';
  assert.equal((await store.reservePlan('account','first',100,'medium','nebula-duo')).allowed,true);
  // Realtime Database does not store an empty object; the first successful credit must recreate it.
  delete records.get(path).completed;
  await store.finishPlan('account','first',200,true,1);
  const used=await store.planUsage('account',200,'medium');assert.equal(used.short.used,1);assert.equal(used.week.used,1);assert.equal(used.pending,0);
  await store.finishPlan('account','first',300,true,1);assert.equal((await store.planUsage('account',300,'medium')).week.used,1);
  assert.equal((await store.reservePlan('account','second',400,'medium','nebula-duo')).allowed,true);
  await store.finishPlan('account','second',500,false);assert.equal((await store.planUsage('account',500,'medium')).week.used,1);
 }
});
