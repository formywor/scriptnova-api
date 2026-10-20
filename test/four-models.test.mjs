import {test} from 'node:test';
import assert from 'node:assert/strict';
import {modelCatalog,preferencePatch,RESPONSE_LENGTHS,responseLengthPrompt} from '../lib/personalization.mjs';
import {loadGraphRelease,graphReply} from '../lib/onnx-model.mjs';
import {reviewPlan,reviewRevision} from '../lib/review-schedule.mjs';
import {ownerRules} from '../lib/rules.mjs';

test('four actual owned checkpoints have distinct selectable identities and account defaults',()=>{
 const catalog=modelCatalog({modelMode:'embedded'});assert.deepEqual(catalog.models.map(x=>x.name),['Nebula Classic','Nebula V1','Nebula V1 Lite','Nebula V2.1']);
 for(const model of catalog.models)assert.equal(preferencePatch({defaultModel:model.id}).defaultModel,model.id);
 assert.throws(()=>preferencePatch({defaultModel:'untrusted-provider'}));
 const lite=loadGraphRelease('nebula-v1-lite').release,large=loadGraphRelease('nebula-v2-1').release;
 assert.equal(lite.parameters,8227328);assert.equal(large.parameters,100219392);assert.notEqual(lite.sourceSha256,large.sourceSha256);
 assert.throws(()=>loadGraphRelease('../release'),e=>e.code==='MODEL_ARTIFACT_INVALID');
});
test('legacy length settings add no instructions and share the same output ceiling',()=>{
 assert.equal(RESPONSE_LENGTHS.quick,RESPONSE_LENGTHS.standard);assert.equal(RESPONSE_LENGTHS.quick,RESPONSE_LENGTHS.expanded);assert.ok(RESPONSE_LENGTHS.quick>192);
 assert.equal(responseLengthPrompt('quick'),'');assert.equal(responseLengthPrompt('expanded'),'');
});
test('reviews accept only current fingerprints for each published family and exclude Classic',()=>{
 const config={modelMode:'embedded'},stamp=reviewRevision(config,'nebula-v2-1'),time=1000000;
 const chat={messages:[{id:'q',role:'user',content:'Hi',reviewEligible:true},{id:'a',replyTo:'q',role:'assistant',content:'Hello.',createdAt:time-400000,modelId:'nebula-v2-1',modelRevision:stamp,reviewGeneration:0}]};
 assert.equal(reviewPlan(chat,id=>reviewRevision(config,id),{},time,0).due,true);
 chat.messages[1].modelRevision='old-checkpoint';assert.equal(reviewPlan(chat,id=>reviewRevision(config,id),{},time,0).eligible,false);
 chat.messages[1].modelId='nebula-classic';chat.messages[1].modelRevision=stamp;assert.equal(reviewPlan(chat,id=>reviewRevision(config,id),{},time,0).eligible,false);
});
test('both newly published models execute actual incremental CPU inference',async()=>{
 for(const modelId of ['nebula-v1-lite','nebula-v2-1']){
  const answer=await graphReply([{role:'system',content:ownerRules().instructions.join('\n')},{role:'user',content:'What is your name?'}],{modelId});
  assert.match(answer,/Nebula/);assert.ok(answer.length>0);
 }
});


test('optional personalization can fit a small model without dropping owner rules or the question',async()=>{
 const {fitPromptContext,packPrompt}=await import('../lib/native-model.mjs');
 const owner={role:'system',content:'You are Nebula. Follow owner rules.'},question={role:'user',content:'Hi'};
 assert.deepEqual(fitPromptContext([owner,{role:'system',optionalContext:true,content:'x'.repeat(300)},question],128),packPrompt([owner,question],128));
 assert.throws(()=>fitPromptContext([{role:'system',content:'x'.repeat(300)},question],128),e=>e.code==='MODEL_CONTEXT_LIMIT');
});
test('the real API serves the selected 100M checkpoint and saves its model fingerprint',async()=>{
 const {createApp}=await import('../lib/app.mjs'),{createStore}=await import('../lib/firebase.mjs'),{memoryDatabase}=await import('./helpers/database.mjs');const {db}=memoryDatabase();const store=createStore(db);
 const app=createApp({getStore:async()=>store,verifyToken:async()=>({uid:'model-test'}),config:{origins:[],rateSecret:'r'.repeat(40),modelMode:'embedded',training:false},log:()=>{}});
 const request=async(path,method,body)=>{const result=await app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer test.user.token','Content-Type':'application/json'},body:JSON.stringify(body)}));return {status:result.status,body:await result.json()};};
 assert.equal((await request('/chats/models','PUT',{revision:0,title:'Model test',messages:[{id:'turn',role:'user',content:'hi',trainingEligible:false}]})).status,200);
 const result=await request('/chat','POST',{chatId:'models',turnId:'turn',messages:[{role:'user',content:'hi'}],modelId:'nebula-v2-1',responseLength:'quick'});
 assert.equal(result.status,200,JSON.stringify(result.body));assert.ok(result.body.reply.length>0);assert.equal(result.body.chat.messages.at(-1).modelId,'nebula-v2-1');assert.equal(result.body.chat.messages.at(-1).modelRevision,loadGraphRelease('nebula-v2-1').release.sha256);assert.equal(result.body.usage.questions,1);
});
