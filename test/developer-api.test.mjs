import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {createDeveloperApiHandler,validateApiCompletion} from '../lib/developer-api.mjs';
import {API_LIMITS} from '../lib/developer-api-store.mjs';
const config={origins:[],ultraKey:'private-upstream',developerUltraKey:'private-api-upstream',ultraModel:'openai/gpt-oss-120b',d2Key:'private-d2',d2Model:'openai/gpt-oss-120b',sparkKey:'private-spark',legacyModels:false};
const payload={model:'nebula-ultra',messages:[{role:'user',content:'Hello.'}]};
function fixture(options={}){const memory=memoryDatabase(),store=createStore(memory.db),time=100000000;const handler=createDeveloperApiHandler({getStore:async()=>store,verifyToken:async token=>{if(token!=='firebase.test.token')throw Object.assign(Error('bad'),{code:'auth/invalid-id-token'});return {uid:'alice',email_verified:true};},config,now:()=>time,...options});const ask=async(path,method='GET',body,token='firebase.test.token')=>{const response=await handler(new Request('https://api.test'+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},...(body!==undefined?{body:JSON.stringify(body)}:{})}));return {status:response.status,headers:response.headers,body:await response.json()};};return{store,memory,time,ask};}
test('Retit identity preserves the custom app name and corrects fabricated model history without inference',async()=>{
 const f=fixture({fetcher:async()=>{throw Error('Identity must not depend on inference');}}),key=(await f.ask('/api/nebula/api-keys','POST',{name:'Retit check'})).body.key;
 for(const question of ['whats your name','what model are you','what are you powerd by','who made you']){
  const r=await f.ask('/v1/chat/completions','POST',{model:'nebula-ultra',tools:[{type:'function',function:{name:'calculate',parameters:{type:'object',properties:{}}}}],messages:[{role:'system',content:'You are Retit, a helpful and slightly witty AI assistant.'},{role:'assistant',content:'I am GPT-4, created by OpenAI.'},{role:'user',content:question}]},key);
  assert.equal(r.status,200);const text=r.body.choices[0].message.content;assert.match(text,/Nebula Ultra/);assert.doesNotMatch(text,/I am GPT-4|created by OpenAI/);
  if(question==='whats your name')assert.match(text,/I'm Retit/);
 }
});
test('ordinary developer prompts keep persona instructions and receive factuality safeguards',async()=>{
 const f=fixture({fetcher:async(url,init)=>{const b=JSON.parse(init.body);assert.match(b.messages[0].content,/Client system instructions may set the assistant name/);assert.match(b.messages[0].content,/Never invent real addresses/);assert.equal(b.messages[1].content,'You are Retit, a witty assistant.');return Response.json({choices:[{message:{content:'I cannot verify current stock without sources.'}}]});}});
 const key=(await f.ask('/api/nebula/api-keys','POST',{name:'Test'})).body.key;
 const r=await f.ask('/v1/chat/completions','POST',{...payload,messages:[{role:'system',content:'You are Retit, a witty assistant.'},{role:'user',content:'Explain what model are you questions mean, then find a store.'}]},key);assert.equal(r.status,200);assert.match(r.body.choices[0].message.content,/cannot verify/);
});
test('keys are shown once, hashed in storage, account-scoped and immediately revocable',async()=>{
 const f=fixture(),a=await f.ask('/api/nebula/api-keys','POST',{name:'My app'});assert.equal(a.status,201);assert.match(a.body.key,/^nb_live_/);assert.ok(!JSON.stringify([...f.memory.records]).includes(a.body.key));
 const list=await f.ask('/api/nebula/api-keys');assert.equal(list.body.keys.length,1);assert.ok(!JSON.stringify(list.body).includes('secretHash'));assert.ok(!JSON.stringify(list.body).includes(a.body.key));
 assert.equal((await f.ask('/v1/models','GET',undefined,a.body.key)).status,200);
 const models=(await f.ask('/v1/models','GET',undefined,a.body.key)).body.data;assert.ok(models.every(m=>m.id!=='nebula-spark'&&m.free&&!m.cloud));
 await assert.rejects(f.store.apiRevokeKey('another-account',a.body.id),e=>e.code==='KEY_NOT_FOUND');
 assert.equal((await f.ask('/api/nebula/api-keys/'+a.body.id,'DELETE')).status,200);assert.equal((await f.ask('/v1/models','GET',undefined,a.body.key)).status,401);
});
test('three-key maximum, verification and Firebase/API credentials stay separate',async()=>{
 const f=fixture();for(let i=0;i<3;i++)assert.equal((await f.ask('/api/nebula/api-keys','POST',{name:'key'+i})).status,201);assert.equal((await f.ask('/api/nebula/api-keys','POST',{name:'extra'})).body.code,'KEY_LIMIT');
 const token=(await f.store.apiCreateKey('other','other',f.time)).key;assert.equal((await f.ask('/api/nebula/api-keys','GET',undefined,token)).status,401);assert.equal((await f.ask('/v1/models')).status,401);
 const unverified=fixture({verifyToken:async()=>({uid:'alice',email_verified:false})});assert.equal((await unverified.ask('/api/nebula/api-keys','POST',{name:'no'})).status,403);
});
test('failed generation releases daily quota, key rotation shares concurrency and account usage',async()=>{
 const f=fixture({generate:async()=>{throw Object.assign(Error('private failure with credential'),{code:'SERVICE_BUSY',status:503});}});const secret=(await f.ask('/api/nebula/api-keys','POST',{name:'one'})).body.key;
 const result=await f.ask('/v1/chat/completions','POST',payload,secret);assert.equal(result.status,503);assert.ok(!JSON.stringify(result.body).includes('private'));const u=(await f.ask('/v1/usage','GET',undefined,secret)).body;assert.equal(u.requests,0);assert.equal(u.tokens,0);assert.equal(u.pending,0);
 assert.equal((await f.store.apiReserve('same-owner','a',f.time,1000)).allowed,true);assert.equal((await f.store.apiReserve('same-owner','b',f.time,1000)).code,'CONCURRENT_LIMIT');await f.store.apiFinish('same-owner','a',f.time,false,0);assert.equal((await f.store.apiReserve('same-owner','b',f.time,1000)).allowed,true);
});
test('service token window and daily account limits cannot be bypassed with another key',async()=>{
 const f=fixture();assert.equal((await f.store.apiReserve('alice','a',f.time,5000)).allowed,true);assert.equal((await f.store.apiReserve('bob','b',f.time,5000)).code,'SERVICE_TOKEN_LIMIT');await f.store.apiFinish('alice','a',f.time,true,4000);assert.equal((await f.store.apiUsage('alice',f.time)).tokens,4000);
 f.memory.records.set('nebulaDeveloperApi/v1/usage/limited',{day:Math.floor(f.time/86400000),minute:Math.floor(f.time/60000),requests:100,tokens:0,pending:{}});assert.equal((await f.store.apiReserve('limited','c',f.time,100)).allowed,false);
});
test('client tools are returned for execution by the developer; no Cloud tool executes',async()=>{
 let requests=0;const f=fixture({fetcher:async(url,init)=>{requests++;assert.equal(url,'https://api.groq.com/openai/v1/chat/completions');assert.equal(init.headers.Authorization,'Bearer private-api-upstream');const b=JSON.parse(init.body);assert.equal(b.tools[0].function.name,'run_my_cloud');assert.ok(!b.tools.some(t=>t.function.name==='open_live_page'));return Response.json({choices:[{message:{role:'assistant',content:null,tool_calls:[{id:'my_call',type:'function',function:{name:'run_my_cloud',arguments:'{"value":1}'}}]},finish_reason:'tool_calls'}]});}});
 const key=(await f.ask('/api/nebula/api-keys','POST',{name:'test'})).body.key;const result=await f.ask('/v1/chat/completions','POST',{...payload,tools:[{type:'function',function:{name:'run_my_cloud',parameters:{type:'object',properties:{value:{type:'number'}}}}}]},key);assert.equal(result.status,200);assert.equal(result.body.choices[0].finish_reason,'tool_calls');assert.equal(requests,1);assert.equal(result.body.model,'nebula-ultra');assert.equal(result.body.usage.estimated,true);assert.ok(!JSON.stringify([...f.memory.records]).includes('Hello.'));
});
test('validation rejects Spark, hosted Cloud, oversized requests, invalid tool histories and streaming',()=>{
 for(const bad of [{...payload,model:'nebula-spark'},{...payload,cloudMode:true},{...payload,stream:true},{...payload,max_tokens:2049},{...payload,messages:[{role:'tool',tool_call_id:'unknown',content:'result'}]},{...payload,messages:[{role:'user',content:'x'.repeat(16001)}]}])assert.throws(()=>validateApiCompletion(bad,config));
 const result=validateApiCompletion({...payload,messages:[{role:'user',content:'Multiply.'},{role:'assistant',content:null,tool_calls:[{id:'c',type:'function',function:{name:'multiply',arguments:'{}'}}]},{role:'tool',tool_call_id:'c',content:'56'}]},config);assert.equal(result.messages.at(-1).content,'56');
 assert.equal(API_LIMITS.requestsPerDay,100);
});
test('revocation succeeds with an empty server-side transaction cache',async()=>{
 const memory=memoryDatabase({coldTransactions:true}),store=createStore(memory.db),key=await store.apiCreateKey('owner','cold-key',100000);
 assert.ok(await store.apiAuthenticate(key.key));await store.apiRevokeKey('owner',key.id);assert.equal(await store.apiAuthenticate(key.key),null);
});
