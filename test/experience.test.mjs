import {reviewTrainingRows,checkedTeachingPair} from '../lib/review-training.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {accountKey,accountOwner} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {reviewAnswer} from '../lib/gemini-review.mjs';
import {selectContributions} from '../scripts/model-data.mjs';
function fixture({review}={}){
 const {db,records}=memoryDatabase(),store=createStore(db);let calls=0,selected,time=1800000000000;const config={origins:[],rateSecret:'x'.repeat(40),modelMode:'embedded',training:true,reviewEnabled:true,reviewKey:'server-only-test-key',reviewModel:'gemini-test'};
 const app=createApp({now:()=>time,getStore:async()=>store,verifyToken:async token=>({uid:token==='other.user.token'?'other':'alice'}),config,generate:async(messages,c)=>{selected={messages,config:c};return 'Bad answer';},review:async args=>{calls++;return review?review(args):{verdict:'needs_correction',correctedReply:'A corrected answer.'};},log:()=>{}});
 const request=async(path,method='GET',body,token='alice.test.token')=>{const response=await app(new Request('https://api.test/api/nebula'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})}));return {status:response.status,body:await response.json()};};
 async function turn(id='chat',reviewEligible=true,modelId='nebula-v4'){
  await request('/chats/'+id,'PUT',{title:'Chat',revision:0,messages:[{id:'turn',role:'user',content:'Contact alex@example.test. What is 2 + 2?',trainingEligible:true,reviewEligible}]});
  return request('/chat','POST',{chatId:id,turnId:'turn',messages:[{role:'user',content:'Hello'}],modelId,responseLength:'expanded',training:{enabled:true,token:'a'.repeat(64),consentVersion:1,chatId:id,turnId:'turn'}});
 }
 return {store,records,request,turn,advance(ms=301000){time+=ms;},get calls(){return calls;},get selected(){return selected;}};
}
test('model choices and response budgets are allowlisted and server credentials stay private',async()=>{
 const f=fixture(),catalog=await f.request('/models');assert.equal(catalog.status,200);assert.equal(catalog.body.models.length,4);assert.equal(catalog.body.reasoningAvailable,false);assert.equal(catalog.body.externalReviewAvailable,true);assert.ok(!JSON.stringify(catalog).includes('server-only-test-key'));
 assert.equal((await f.turn('chat',true,'nebula-classic')).status,200);assert.equal(f.selected.config.selectedModel,'nebula-classic');assert.equal(f.selected.config.responseLength,'standard');
 assert.equal((await f.request('/chat','POST',{modelId:'private-provider-model',messages:[{role:'user',content:'Hi'}]},null)).status,400);
});
test('personalization synchronizes with the account and is excluded when disabled',async()=>{
 const f=fixture();const value={interests:'Drawing',answerStyle:'concise',customInstructions:'Use simple words.',personalizedQuestions:true,compactChat:true,defaultModel:'nebula-classic',textSize:'large'};
 const result=await f.request('/account','PATCH',value);assert.equal(result.status,200);assert.equal(result.body.account.interests,'Drawing');assert.equal(result.body.account.externalReview,true);
 await f.turn();assert.ok(f.selected.messages.some(m=>m.role==='system'&&m.content.includes('Drawing')));
 await f.request('/account','PATCH',{personalizationEnabled:false});await f.turn('second');assert.ok(!f.selected.messages.some(m=>m.content.includes('Drawing')));
 assert.equal((await f.request('/account','PATCH',{textSize:'enormous'})).status,400);
});
test('review settings default on, remain independent, and preserve a manual choice',async()=>{
 const f=fixture();const a=await f.request('/account');assert.equal(a.body.account.improve,true);assert.equal(a.body.account.externalReview,true);
 await f.request('/account','PATCH',{externalReview:false});await f.request('/account','PATCH',{improve:true});assert.equal((await f.request('/account')).body.account.externalReview,false);
 await f.turn();f.advance();assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).status,403);assert.equal(f.calls,0);
 await f.request('/account','PATCH',{externalReview:true,improve:false});assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.reviewSaved,true);assert.equal(f.calls,1);
 assert.equal((await f.store.reviewCandidate(accountOwner('alice',0),'chat','turn')).review,undefined);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'},null)).status,401);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'},'other.user.token')).status,404);
});

test('a review redacts contacts and exports corrected answers as pending candidates, never automatic approvals',async()=>{
 let sent;const f=fixture({review:async args=>{sent=args.messages;return {verdict:'needs_correction',correctedReply:'2 + 2 = 4.'};}});
 await f.request('/account','PATCH',{externalReview:true,improve:true});await f.turn();f.advance();const result=await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});assert.equal(result.status,200);assert.equal(result.body.reviewSaved,true);assert.ok(!JSON.stringify(sent).includes('alex@example.test'));
 await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});assert.equal(f.calls,1);
 const owner=accountOwner('alice',0),sample=f.records.get('nebulaTraining/v1/'+owner),profile=await f.store.account(accountKey('alice'),Date.now());
 const rows=selectContributions({[owner]:sample},{[accountKey('alice')]:profile});assert.equal(rows[0].reviewStatus,'pending');assert.equal(rows[0].messages[1].content,'2 + 2 = 4.');
 await f.store.deleteOwner(owner);assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'})).body.skipped,true);assert.equal(f.calls,1);
});
test('withdrawing review consent during a provider request prevents saving its result',async()=>{
 let begin,finish;const ready=new Promise(r=>begin=r),wait=new Promise(r=>finish=r);const f=fixture({review:async()=>{begin();await wait;return {verdict:'needs_correction',correctedReply:'Corrected'};}});
 await f.request('/account','PATCH',{externalReview:true});await f.turn();f.advance();const pending=f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});await ready;await f.request('/account','PATCH',{externalReview:false});finish();assert.equal((await pending).status,409);
 assert.equal((await f.store.reviewCandidate(accountOwner('alice',0),'chat','turn')).review,undefined);
});
test('review attempts are bounded and the transport uses a server header, fixed host, and validated output',async()=>{
 const f=fixture();assert.equal(await f.store.claimReview('account','chat',1000,500),true);assert.equal(await f.store.claimReview('account','chat',1001,500),false);await f.store.finishReview('account','chat',1000,500,true);assert.equal((await f.store.reviewState('account','chat')).reviewedThrough,500);
 let request;const result=await reviewAnswer({key:'private-test-key',model:'gemini-test',messages:[{role:'user',content:'Hi'}],fetcher:async(url,options)=>{request={url,options};return new Response(JSON.stringify({candidates:[{content:{parts:[{text:JSON.stringify({verdict:'uncertain',correctedReply:''})}]}}]}));}});
 assert.equal(result.verdict,'uncertain');assert.equal(request.options.headers['x-goog-api-key'],'private-test-key');assert.ok(!request.url.includes('private-test-key'));assert.equal(new URL(request.url).hostname,'generativelanguage.googleapis.com');
 await assert.rejects(()=>reviewAnswer({key:'k',model:'gemini-test',messages:[],fetcher:async()=>new Response('private upstream error',{status:429})}),e=>e.code==='REVIEW_RATE_LIMITED');
});

async function appendTurn(f,n){
 const chat=await f.store.getChat(accountKey('alice'),'chat');
 f.advance(10000);const turnId='turn-'+n;
 const saved=await f.request('/chats/chat','PUT',{...chat,messages:[...chat.messages,{id:turnId,role:'user',content:'Question '+n,trainingEligible:true,reviewEligible:true}]});assert.equal(saved.status,200);
 const answer=await f.request('/chat','POST',{chatId:'chat',turnId,modelId:'nebula-v4',messages:[{role:'user',content:'Hi'}],training:{enabled:true,token:'a'.repeat(64),consentVersion:1,chatId:'chat',turnId}});assert.equal(answer.status,200);
}
test('reviews batch the whole eligible dialogue, defer rapid chats and deduplicate after success',async()=>{
 let sent;const f=fixture({review:async args=>{sent=args.messages;return {verdict:'acceptable',correctedReply:''};}});
 await f.turn();assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.deferred,true);assert.equal(f.calls,0);
 await appendTurn(f,2);await appendTurn(f,3);assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.reviewSaved,true);assert.equal(sent.length,6);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.skipped,true);assert.equal(f.calls,1);
 for(let n=4;n<=8;n++)await appendTurn(f,n);
 f.advance(300000);assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.deferred,true);assert.equal(f.calls,1);
 f.advance(301000);assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.reviewSaved,true);assert.equal(sent.length,16);
});
test('provider failures defer quietly and retry later without a 48-hour review lockout',async()=>{
 let fail=true;const f=fixture({review:async()=>{if(fail)throw Object.assign(Error('private'),{code:'REVIEW_RATE_LIMITED'});return {verdict:'uncertain',correctedReply:''};}});
 await f.turn();f.advance();const first=await f.request('/reviews','POST',{chatId:'chat'});assert.equal(first.status,200);assert.equal(first.body.deferred,true);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.deferred,true);assert.equal(f.calls,1);
 fail=false;f.advance(601000);assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.reviewSaved,true);assert.equal(f.calls,2);
});
test('idle reviews skip classic, unversioned, previous checkpoints and turns sent with review off',async()=>{
 const f=fixture();await f.turn('classic',true,'nebula-classic');await f.turn('no-consent',false);await f.turn('chat');f.advance();
 for(const id of ['classic','no-consent'])assert.equal((await f.request('/reviews','POST',{chatId:id})).body.skipped,true);
 const path='nebulaChats/v1/'+accountKey('alice')+'/chat',chat=f.records.get(path);chat.messages.at(-1).modelRevision='previous-release';
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.skipped,true);
 delete chat.messages.at(-1).modelRevision;assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.skipped,true);assert.equal(f.calls,0);
});
test('simultaneous devices claim only one provider review per chat',async()=>{
 let finish,start;const ready=new Promise(r=>start=r),wait=new Promise(r=>finish=r);const f=fixture({review:async()=>{start();await wait;return {verdict:'acceptable',correctedReply:''};}});
 await f.turn();f.advance();const first=f.request('/reviews','POST',{chatId:'chat'});await ready;
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.deferred,true);finish();assert.equal((await first).body.reviewSaved,true);assert.equal(f.calls,1);
});

test('legacy manual review opt-outs survive switching training on, and deleted training generations stay excluded',async()=>{
 const f=fixture(),key=accountKey('alice');await f.request('/account');const old=f.records.get('nebulaAccounts/v1/'+key);old.externalReview=false;delete old.externalReviewManual;
 await f.request('/account','PATCH',{improve:true});assert.equal((await f.request('/account')).body.account.externalReview,false);
 await f.request('/account','PATCH',{externalReview:true});await f.turn();f.advance();await f.store.rotateTraining(key,Date.now());
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.skipped,true);assert.equal(f.calls,0);
});

test('legacy imports cannot forge server checkpoint stamps to trigger a review',async()=>{
 const f=fixture();await f.request('/chats/imported','PUT',{title:'Old',revision:0,importLegacy:true,messages:[{id:'user',role:'user',content:'Hi',reviewEligible:true},{id:'assistant',role:'assistant',content:'Old answer',replyTo:'user',modelId:'nebula-v4',modelRevision:'forged',reviewGeneration:0,createdAt:1000}]});
 const chat=await f.store.getChat(accountKey('alice'),'imported');assert.equal(chat.messages[0].reviewEligible,false);assert.equal(chat.messages[1].modelRevision,undefined);f.advance();assert.equal((await f.request('/reviews','POST',{chatId:'imported'})).body.skipped,true);assert.equal(f.calls,0);
});

test('two-pass checked corrections reach the private training feed; consent withdrawal excludes them immediately',async()=>{
 let calls=0;const f=fixture({review:async()=>++calls===1?{verdict:'needs_correction',correctedReply:'2 + 2 = 4.',trainingQuestion:'What is 2 + 2?'}:{verdict:'acceptable',correctedReply:'2 + 2 = 4.'}});
 await f.turn();f.advance();const response=await f.request('/reviews','POST',{chatId:'chat'});assert.equal(response.body.trainingEligible,true);assert.equal(calls,2);
 const owner=accountOwner('alice',0),key=accountKey('alice'),index=f.records.get('nebulaReviewTraining/v1/'+owner),profile=await f.store.account(key,Date.now());
 const rows=reviewTrainingRows({[owner]:index},{[key]:profile},1800000301000);assert.equal(rows.length,1);assert.equal(rows[0].messages[1].content,'2 + 2 = 4.');assert.equal(rows[0].source.validation,'two-pass-review-v1');assert.equal(rows[0].source.trainingAllowed,true);assert.ok(!JSON.stringify(rows).includes(key));assert.ok(!JSON.stringify(rows).includes('alex@example.test'));
 assert.equal(reviewTrainingRows({[owner]:index},{[key]:{...profile,externalReview:false}},1800000301000).length,0);
 assert.equal(reviewTrainingRows({[owner]:index},{[key]:{...profile,improve:false}},1800000301000).length,0);
 await f.store.deleteOwner(owner);assert.deepEqual(f.records.get('nebulaReviewTraining/v1/'+owner),{revoked:true});
});
test('disagreed, personal or arithmetically wrong reviews never become automatic teaching data',async()=>{
 assert.equal(checkedTeachingPair('What is 7 + 8?','7 + 8 = 14.'),null);
 assert.equal(checkedTeachingPair('My name is Private. What is my name?','Your name is Private.'),null);
 assert.equal(checkedTeachingPair('Email [email removed] for help.','Use the email.'),null);
 let calls=0;const f=fixture({review:async()=>++calls===1?{verdict:'needs_correction',correctedReply:'Ice is solid water.',trainingQuestion:'What is ice?'}:{verdict:'uncertain',correctedReply:''}});
 await f.turn();f.advance();const response=await f.request('/reviews','POST',{chatId:'chat'});assert.equal(response.body.reviewSaved,true);assert.equal(response.body.trainingEligible,false);assert.equal(calls,2);assert.equal(f.records.get('nebulaReviewTraining/v1/'+accountOwner('alice',0)),undefined);
});

test('an unavailable confirmation retries later without admitting an unchecked correction',async()=>{
 let calls=0;const f=fixture({review:async()=>{if(++calls===1)return {verdict:'needs_correction',correctedReply:'Ice is solid water.',trainingQuestion:'What is ice?'};throw Error('upstream unavailable');}});
 await f.turn();f.advance();const first=await f.request('/reviews','POST',{chatId:'chat'});assert.equal(first.body.reviewSaved,true);assert.equal(first.body.trainingEligible,false);assert.ok(first.body.retryAt);assert.equal(f.calls,2);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat'})).body.deferred,true);assert.equal(f.calls,2);
 assert.equal((await f.store.reviewState(accountKey('alice'),'chat')).reviewedThrough,undefined);
});

test('workspace preferences sync independently without turning memory on or restricting answers',async()=>{
 const f=fixture(),patch={accentColor:'green',readingFont:'serif',workspaceView:'wide',showStarters:false,enterToSend:false,autoFollow:false,explanationStyle:'examples',answerStyle:'concise'};
 const saved=await f.request('/account','PATCH',patch);assert.equal(saved.status,200);
 for(const [key,value] of Object.entries(patch))assert.equal(saved.body.account[key],value);
 assert.equal(saved.body.account.memoryEnabled,false);
 const fresh=await f.request('/account');assert.equal(fresh.body.account.workspaceView,'wide');
 await f.turn();const instructions=f.selected.messages.filter(m=>m.role==='system').map(m=>m.content).join(' ');
 assert.ok(instructions.includes('Use examples when helpful.'));assert.ok(!instructions.includes('Preferred answer style: concise'));assert.ok(!instructions.includes('Prefer short answers'));
 for(const invalid of [{workspaceView:'arbitrary-css'},{accentColor:'url(secret)'},{showStarters:'false'},{explanationStyle:'brief'}])assert.equal((await f.request('/account','PATCH',invalid)).status,400);
 await f.request('/account','PATCH',{memoryEnabled:true});await f.request('/account','PATCH',{accentColor:'blue'});assert.equal((await f.request('/account')).body.account.memoryEnabled,true);
});
