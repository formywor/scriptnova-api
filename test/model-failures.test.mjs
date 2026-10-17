import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp,configFromEnv} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
test('a missing model is logged specifically while public responses contain no private exception details',async()=>{
 for(const code of ['MODEL_RELEASE_MISSING','MODEL_SHARD_MISSING','private-secret-code']){
  const {db}=memoryDatabase(),logs=[];
  const app=createApp({getStore:async()=>createStore(db),config:{origins:[],rateSecret:'s'.repeat(40),modelMode:'embedded',training:false},
   generate:async()=>{throw Object.assign(Error('secret private-model-host/path'),{code});},log:value=>logs.push(value)});
  const result=await app(new Request('https://api.test/api/nebula/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:[{role:'user',content:'Hi'}]})}));
  assert.equal(result.status,503);assert.equal((await result.json()).code,'UNAVAILABLE');
  const failure=logs.find(value=>value.event==='MODEL_UNAVAILABLE');
  assert.deepEqual(failure,{event:'MODEL_UNAVAILABLE',reason:code.startsWith('MODEL_')?code:'MODEL_REQUEST_FAILED',mode:'embedded'});
  assert.ok(!JSON.stringify(logs).includes('secret'));assert.ok(!JSON.stringify(logs).includes('private-model-host'));
 }
});
test('copied environment values tolerate surrounding whitespace',()=>{
 assert.equal(configFromEnv({NEBULA_MODEL_MODE:' embedded \n'}).modelMode,'embedded');
});
