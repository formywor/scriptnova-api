import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {createApp} from '../lib/app.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {WINDOW} from '../lib/workspace.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const user={uid:'alice',name:'Alice'};
function fixture(overrides={}){
 const{db,records}=memoryDatabase();const store=createStore(db);let time=1700000000000;const calls=[];
 const app=createApp({getStore:async()=>store,verifyToken:async token=>({uid:token==='bob.test.token'?'bob':'alice',name:'Alice'}),config:{ultraKey:'unit-test-only-key',origins:[],rateSecret:'x'.repeat(40),modelUrl:'https://model.invalid',training:true,guestLimit:10,askingFraction:2,heavyFraction:2,...overrides},now:()=>time,generate:async messages=>{calls.push(messages);return 'Answer';},log:()=>{}});
 const request=async(path,method='GET',body,token='alice.test.token')=>{const r=await app(new Request('https://api.scriptnovaa.com/api/nebula'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})}));return{status:r.status,body:await r.json()};};
 return{request,store,records,calls,setTime:t=>time=t,get time(){return time;}};
}
const chat=(text='Hello')=>({title:'My chat',revision:0,messages:[{id:'turn-1',role:'user',content:text,trainingEligible:true}]});
const ask=(id='chat-1',turnId='turn-1')=>({chatId:id,turnId,messages:[{role:'user',content:'not trusted'}],training:{enabled:true,consentVersion:1,token:'a'.repeat(64),chatId:id,turnId}});
test('account chats synchronize through API and remain isolated by verified account',async()=>{
 const f=fixture();assert.equal((await f.request('/chats/chat-1','PUT',chat())).status,200);const list=await f.request('/chats');assert.equal(list.body.chats.length,1);assert.equal('messages'in list.body.chats[0],false);assert.equal((await f.request('/chats/chat-1')).body.chat.messages[0].content,'Hello');assert.equal((await f.request('/chats','GET',undefined,'bob.test.token')).body.chats.length,0);assert.equal((await f.request('/chats/chat-1','GET',undefined,'bob.test.token')).status,404);assert.equal((await f.request('/chats','GET',undefined,null)).status,401);
});
test('stale device writes conflict and deleted chats cannot be resurrected',async()=>{
 const f=fixture();await f.request('/chats/chat-1','PUT',chat());assert.equal((await f.request('/chats/chat-1','PATCH',{revision:1,title:'Changed'})).status,200);assert.equal((await f.request('/chats/chat-1','PATCH',{revision:1,title:'Stale'})).status,409);await f.request('/chats/chat-1','DELETE');assert.equal((await f.request('/chats/chat-1','PUT',chat())).status,409);
});
test('model receives stored account conversation; reply survives opening another device',async()=>{
 const f=fixture();await f.request('/chats/chat-1','PUT',chat('Stored message'));const response=await f.request('/chat','POST',ask());assert.equal(response.status,200);assert.equal(f.calls[0].at(-1).content,'Stored message');const remote=await f.request('/chats/chat-1');assert.equal(remote.body.chat.messages.at(-1).content,'Answer');assert.equal(response.body.usage.questions,1);const again=await f.request('/chat','POST',ask());assert.equal(again.status,200);assert.equal(f.calls.length,1);
});
test('default sharing is on for new accounts; explicit opt-out persists',async()=>{
 const f=fixture();assert.equal((await f.request('/account')).body.account.improve,true);await f.request('/account','PATCH',{improve:false});assert.equal((await f.request('/account')).body.account.improve,false);
});
test('a turn saved with sharing off cannot be contributed by enabling it later',async()=>{
 const f=fixture();const body=chat();body.messages[0].trainingEligible=false;await f.request('/chats/chat-1','PUT',body);const r=await f.request('/chat','POST',ask());assert.equal(r.status,200);assert.equal(r.body.trainingSaved,false);
});
test('name and memory settings synchronize; memories are excluded when disabled',async()=>{
 const f=fixture();await f.request('/account','PATCH',{displayName:'New name',memoryEnabled:true});assert.equal((await f.request('/account')).body.account.displayName,'New name');await f.request('/memory','POST',{text:'I prefer concise answers.'});assert.equal((await f.request('/memory')).body.memories.length,1);assert.equal((await f.request('/memory','GET',undefined,'bob.test.token')).body.memories.length,0);await f.request('/chats/chat-1','PUT',chat());await f.request('/chat','POST',ask());assert.match(f.calls[0].find(m=>m.role==='system'&&m.content.includes('Personal context')).content,/concise answers/);await f.request('/account','PATCH',{memoryEnabled:false});await f.request('/chats/chat-2','PUT',chat());await f.request('/chat','POST',ask('chat-2'));assert.equal(f.calls[1].some(m=>m.role==='system'&&m.content.includes('Personal context')),false);assert.equal(f.calls[1][0].role,'system');await f.request('/memory','DELETE');assert.equal((await f.request('/memory')).body.memories.length,0);
});
test('guest questions are limited to 10 per network for 48 hours, with no saved guest chats',async()=>{
 const f=fixture();for(let i=0;i<10;i++){const r=await f.request('/chat','POST',{messages:[{role:'user',content:'Hi'}]},null);assert.equal(r.status,200);}
 const limited=await f.request('/chat','POST',{messages:[{role:'user',content:'Hi'}]},null);assert.equal(limited.status,429);assert.equal(limited.body.code,'GUEST_LIMIT');assert.equal([...f.records.keys()].some(k=>k.startsWith('nebulaChats')),false);f.setTime(f.time+WINDOW+1);assert.equal((await f.request('/chat','POST',{messages:[{role:'user',content:'Hi'}]},null)).status,200);
});
test('capacity threshold at 15 percent asking or 8 percent heavy blocks guests, not accounts',async()=>{
 const f=fixture({askingFraction:.15,heavyFraction:.08});for(let i=0;i<100;i++)await f.store.presence('u-'+i,f.time,{});
 for(let i=0;i<16;i++)assert.equal((await f.store.reserveCapacity('u-'+i,false,f.time,'req-'+i,{})).allowed,true);
 assert.equal((await f.store.reserveCapacity('guest',true,f.time,'guest-request',{askingFraction:.15,heavyFraction:.08})).allowed,false);assert.equal((await f.store.reserveCapacity('signed',false,f.time,'signed-request',{})).allowed,true);
 const other=fixture();for(let i=0;i<100;i++)await other.store.presence('u-'+i,other.time,{});for(let i=0;i<9;i++)for(let j=0;j<5;j++)await other.store.releaseCapacity('u-'+i,'none',other.time,true);
 assert.equal((await other.store.reserveCapacity('guest',true,other.time,'heavy-guest',{})).allowed,false);
});
test('failed model requests release reservations and do not spend guest quota',async()=>{
 const f=fixture();const actor='guest';await f.store.reserveCapacity(actor,true,f.time,'test',{});await f.store.reserveUsage(actor,'test',f.time,true,10);await f.store.finishUsage(actor,'test',f.time,false,10,0);await f.store.releaseCapacity(actor,'test',f.time,false);assert.equal((await f.store.usage(actor,f.time,true,10)).remaining,10);assert.equal((await f.store.presence(actor,f.time,{})).askingUsers,0);
});
