import {test} from 'node:test';
import assert from 'node:assert/strict';
import {learningTopics,topicFor,readLearningTopics} from '../lib/learning.mjs';
import {createStore} from '../lib/firebase.mjs';
import {createResearchHandler} from '../lib/research.mjs';
import {redact,configFromEnv} from '../lib/app.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const now=1792186000000,key='a'.repeat(64);
const sample=()=>({source:{kind:'user',accountKey:key,generation:2},consentVersion:1,createdAt:now,topic:'math'});
const rows=()=>({owner:{samples:{chat:Object.fromEntries(Array.from({length:5},(_,i)=>['turn'+i,sample()]))}}});
test('only currently opted-in, recent, unrevoked account generations contribute anonymous topics',()=>{
 const accounts={[key]:{improve:true,trainingGeneration:2}};
 assert.deepEqual(learningTopics(rows(),accounts,now).counts,{identity:0,math:5,memory:0,language:0});
 assert.equal(learningTopics(rows(),{[key]:{improve:false,trainingGeneration:2}},now).eligible,0);
 assert.equal(learningTopics(rows(),{[key]:{improve:true,trainingGeneration:3}},now).eligible,0);
 assert.equal(learningTopics({owner:{...rows().owner,revoked:true}},accounts,now).eligible,0);
 assert.equal(learningTopics(rows(),accounts,now+8*86400000).eligible,0);
 const text=JSON.stringify(learningTopics(rows(),accounts,now));assert.ok(!text.includes(key));assert.ok(!text.includes('turn'));assert.ok(!text.includes('owner'));
});
test('capturing a consented question writes metadata only; deletion blocks late index writes',async()=>{
 const {db,records}=memoryDatabase(),store=createStore(db);
 const value={...sample(),messages:[{role:'user',content:'My secret name is PRIVATE. Calculate 2 + 2.'},{role:'assistant',content:'Wrong: 44.'}]};
 assert.equal(await store.save('owner','chat','turn',value),true);
 const index=records.get('nebulaLearning/v1/owner');assert.equal(index.samples.chat.turn.topic,'math');
 assert.ok(!JSON.stringify(index).includes('PRIVATE'));assert.ok(!JSON.stringify(index).includes('44'));assert.ok(!JSON.stringify(index).includes('messages'));
 await store.deleteOwner('owner');assert.equal(await store.save('owner','chat','turn2',value),false);
 assert.deepEqual(records.get('nebulaLearning/v1/owner'),{revoked:true});
});
test('topic feed reads bounded metadata and fresh consent, never conversation bodies',async()=>{
 const accesses=[];let limit;
 const db={ref:path=>{accesses.push(path);const ref={orderByKey:()=>ref,startAt:()=>ref,limitToFirst:n=>{assert.ok(n<=100);limit=n;return ref;},get:async()=>({val:()=>path==='nebulaLearning/v1'?rows():{improve:true,trainingGeneration:2}})};return ref;}};
 assert.equal((await readLearningTopics(db,now)).counts.math,5);
 assert.ok(accesses.every(path=>!path.startsWith('nebulaTraining')));assert.ok(accesses.includes('nebulaAccounts/v1/'+key));assert.ok(limit<=100);
});
test('curriculum feed is trainer-only and cannot be fetched from a browser origin',async()=>{
 let calls=0;const env={NEBULA_RESEARCH_ENABLED:'true',NEBULA_TRAINER_TOKEN:'t'.repeat(40),NEBULA_EVALUATOR_TOKEN:'e'.repeat(40)};
 const handler=createResearchHandler({services:async()=>{throw Error('No storage needed');},learning:async()=>{calls++;return learningTopics({},{});},env});
 const request=(token,origin)=>new Request('https://api.test/api/nebula/research/curriculum',{headers:{Authorization:'Bearer '+token,...(origin?{Origin:origin}:{})}});
 assert.equal((await handler(request(env.NEBULA_EVALUATOR_TOKEN))).status,403);
 assert.equal((await handler(request(env.NEBULA_TRAINER_TOKEN,'https://scriptnovaa.com'))).status,403);
 assert.equal((await handler(request('invalid'))).status,401);
 assert.equal((await handler(request(env.NEBULA_TRAINER_TOKEN))).status,200);assert.equal(calls,1);
});
test('public release defaults to owned inference and sharing master switch still overrides consent',()=>{
 assert.equal(configFromEnv({}).modelMode,'embedded');assert.equal(configFromEnv({NEBULA_MODEL_URL:'https://private.test/chat'}).modelMode,'');
 assert.equal(configFromEnv({NEBULA_TRAINING_ENABLED:'false'}).training,false);
 assert.equal(topicFor('Hello there'),'language');assert.equal(topicFor('Call me Alex'),'memory');
 for(const prefix of ['hf_','gsk_','AQ.','AIza','sk-'])assert.ok(!redact(prefix+'a'.repeat(40)).includes('a'.repeat(40)));
});
