import {test} from 'node:test';
import assert from 'node:assert/strict';
import {accountContext,contextMessage} from '../lib/ultra-context.mjs';
import {ultraReply} from '../lib/ultra.mjs';
test('memory off never reads other conversations or facts',async()=>{
 const store=new Proxy({},{get(){throw Error('Unexpected account read');}});
 assert.deepEqual(await accountContext(store,'owner',{},'current'),{memoryEnabled:false,savedMemories:[],pastChats:[]});
});
test('account context bounds history and omits private and archived conversations',async()=>{
 const store={memory:async key=>{assert.equal(key,'owner');return [{text:'Likes dogs'}];},listChats:async()=>[{id:'current'},{id:'private'},{id:'old'},{id:'archived',archived:true}],getChat:async(key,id)=>{assert.equal(key,'owner');return {title:id,messages:[{role:'user',content:'hello',...(id==='private'?{contextPrivate:true}:{})}]};}};
 const context=await accountContext(store,'owner',{memoryEnabled:true},'current');assert.equal(context.pastChats.length,1);assert.equal(context.pastChats[0].title,'old');assert.deepEqual(context.savedMemories,['Likes dogs']);assert.match(contextMessage(context),/untrusted user data/);
});
test('Ultra receives trusted product context and executes independent lookups together',async()=>{
 let round=0,active=0,peak=0;
 const cloud={calculate:async expr=>{active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,5));active--;return {result:expr==='1+1'?2:4};}};
 const response=await ultraReply([{role:'user',content:'Calculate 1+1 and 2+2.'}],{ultraKey:'test',contextUsed:{memoryEnabled:false},availableModels:[{id:'nebula-v2-1',available:true}]},{cloud,fetcher:async(_,init)=>{
  const body=JSON.parse(init.body);assert.equal(body.parallel_tool_calls,true);assert.match(body.messages[0].content,/https:\/\/api.scriptnovaa.com/);assert.match(body.messages[0].content,/Groq/);
  if(round++===0)return Response.json({choices:[{message:{tool_calls:['1+1','2+2'].map((expression,i)=>({id:'tool'+i,type:'function',function:{name:'calculate',arguments:JSON.stringify({expression})}}))}}]});
  assert.equal(body.messages.filter(m=>m.role==='tool').length,2);return Response.json({choices:[{message:{content:'The results are 2 and 4.',reasoning:'private trace must not leave the provider'}}]});
 }});
 assert.equal(peak,2);assert.equal(response.activity.length,2);assert.equal(response.text,'The results are 2 and 4.');assert.ok(!JSON.stringify(response).includes('private trace'));
});
