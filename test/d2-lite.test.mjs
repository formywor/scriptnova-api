import {test} from 'node:test';
import assert from 'node:assert/strict';
import {d2LiteReply,d2LiteReady,D2_LITE_ID} from '../lib/d2-lite.mjs';
import {modelCatalog} from '../lib/personalization.mjs';
import {apiModels} from '../lib/developer-api.mjs';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const ready={d2LiteEnabled:true,d2LiteUrl:'https://worker.test/generate',d2LiteToken:'w'.repeat(40)};
test('D2 Lite is a distinct disabled research option until its worker is explicitly connected',()=>{
 const model=modelCatalog({}).models.find(m=>m.id===D2_LITE_ID);assert.equal(model.parentModel,'nebula-d2');assert.equal(model.available,false);assert.match(model.description,/Not connected/);assert.equal(d2LiteReady({...ready,d2LiteEnabled:false}),false);assert.equal(modelCatalog(ready).models.find(m=>m.id===D2_LITE_ID).available,true);assert.ok(!apiModels(ready).some(m=>m.id===D2_LITE_ID));
});
test('D2 Lite invokes only its own worker and verifies checkpoint identity',async()=>{
 const r=await d2LiteReply([{role:'system',content:'Owner rules'},{role:'user',content:'Explain this code.'}],ready,{fetcher:async(url,init)=>{assert.equal(String(url),ready.d2LiteUrl);assert.equal(init.headers.Authorization,'Bearer '+ready.d2LiteToken);const b=JSON.parse(init.body);assert.equal(b.model,'nebula-v-d2');assert.equal(b.messages[0].content,'Owner rules');return Response.json({model:'nebula-v-d2',checkpoint:'sha256:'+'a'.repeat(64),text:'Checkpoint reply'});}});assert.equal(r.text,'Checkpoint reply');assert.equal(r.modelRevision,'a'.repeat(64));assert.deepEqual(r.activity,[]);
 await assert.rejects(d2LiteReply([{role:'user',content:'Hi'}],ready,{fetcher:async()=>Response.json({model:'other',text:'Fake',checkpoint:'sha256:'+'a'.repeat(64)})}),e=>e.code==='VD2_RESPONSE_INVALID');
});
test('D2 Lite never substitutes another model or runs unsupported tools',async()=>{
 const fetcher=()=>{throw Error('No network expected');};
 await assert.rejects(d2LiteReply([{role:'user',content:'Hi'}],{}, {fetcher}),e=>e.code==='D2_LITE_NOT_READY');
 await assert.rejects(d2LiteReply([{role:'user',content:'Hi'}],{...ready,cloudTools:{}},{fetcher}),e=>e.code==='D2_LITE_TEXT_ONLY');
});
test('chat endpoint preserves Lite selection and enforces owner/invite gate before generation',async()=>{
 const store=createStore(memoryDatabase().db);let generated=0;
 const app=createApp({getStore:async()=>store,verifyToken:async token=>({uid:token,email:token==='owner.test.token'?'divedyacoub9@gmail.com':'other@example.test',email_verified:true}),config:{origins:[],publicTiers:false,rateSecret:'r'.repeat(40),legacyModels:false},generate:async()=>{generated++;throw Error('Must not silently use Ultra');},log:()=>{}});
 const call=(path,method,body,token='owner.test.token')=>app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body)}));
 await call('/chats/lite','PUT',{title:'Lite test',revision:0,messages:[{id:'u',role:'user',content:'Hi'}]});
 const r=await call('/chat','POST',{chatId:'lite',turnId:'u',modelId:D2_LITE_ID,messages:[{role:'user',content:'Hi'}]});assert.equal(r.status,503,await r.clone().text());assert.equal((await r.json()).code,'D2_LITE_NOT_READY');assert.equal(generated,0);
 await call('/chats/lite','PUT',{title:'Lite test',revision:0,messages:[{id:'u',role:'user',content:'Hi'}]},'other.test.token');
 const denied=await call('/chat','POST',{chatId:'lite',turnId:'u',modelId:D2_LITE_ID,messages:[{role:'user',content:'Hi'}]},'other.test.token');assert.equal(denied.status,403);assert.equal((await denied.json()).code,'D2_INVITE_REQUIRED');
});
