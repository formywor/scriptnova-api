import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
test('uncached Firebase transaction callbacks still finalize and deduplicate successful usage',async()=>{
 const{db}=memoryDatabase({coldTransactions:true});const store=createStore(db),time=1700000000000;
 assert.equal((await store.reserveUsage('guest','turn',time,true,10)).allowed,true);await store.finishUsage('guest','turn',time+1,true,7,12);await store.finishUsage('guest','turn',time+2,true,7,12);const usage=await store.usage('guest',time+3,true,10);assert.equal(usage.questions,1);assert.equal(usage.remaining,9);assert.equal(usage.outputCharacters,12);
});
test('uncached Firebase transactions persist replies, clear active leases and update archive metadata',async()=>{
 const{db}=memoryDatabase({coldTransactions:true});const store=createStore(db),time=1700000000000;
 await store.putChat('account','chat',{revision:0,title:'Chat',messages:[{id:'turn',role:'user',content:'Hi',trainingEligible:false}]},time);
 const answer=await store.appendReply('account','chat','turn','Answer',time+1);assert.equal(answer.messages.at(-1).content,'Answer');await store.appendReply('account','chat','turn','Duplicate',time+2);assert.equal((await store.getChat('account','chat')).messages.length,2);
 assert.equal((await store.patchChat('account','chat',{revision:2,archived:true},time+3)).archived,true);await assert.rejects(()=>store.patchChat('account','missing',{revision:0,archived:true},time),e=>e.code==='NOT_FOUND');
 await store.reserveCapacity('actor',false,time,'lease',{});await store.releaseCapacity('actor','lease',time+1,true);const capacity=await store.presence('actor',time+2,{});assert.equal(capacity.askingUsers,0);
});
