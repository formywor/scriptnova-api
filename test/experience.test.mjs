import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {accountKey,accountOwner} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {reviewAnswer} from '../lib/gemini-review.mjs';
import {selectContributions} from '../scripts/model-data.mjs';
function fixture({review}={}){
 const {db,records}=memoryDatabase(),store=createStore(db);let calls=0,selected;const config={origins:[],rateSecret:'x'.repeat(40),modelMode:'embedded',training:true,reviewEnabled:true,reviewKey:'server-only-test-key',reviewModel:'gemini-test'};
 const app=createApp({getStore:async()=>store,verifyToken:async token=>({uid:token==='other.user.token'?'other':'alice'}),config,generate:async(messages,c)=>{selected={messages,config:c};return 'Bad answer';},review:async args=>{calls++;return review?review(args):{verdict:'needs_correction',correctedReply:'A corrected answer.'};},log:()=>{}});
 const request=async(path,method='GET',body,token='alice.test.token')=>{const response=await app(new Request('https://api.test/api/nebula'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})}));return {status:response.status,body:await response.json()};};
 async function turn(id='chat',reviewEligible=true){
  await request('/chats/'+id,'PUT',{title:'Chat',revision:0,messages:[{id:'turn',role:'user',content:'Contact alex@example.test. What is 2 + 2?',trainingEligible:true,reviewEligible}]});
  return request('/chat','POST',{chatId:id,turnId:'turn',messages:[{role:'user',content:'Hello'}],modelId:'nebula-classic',responseLength:'expanded',training:{enabled:true,token:'a'.repeat(64),consentVersion:1,chatId:id,turnId:'turn'}});
 }
 return {store,records,request,turn,get calls(){return calls;},get selected(){return selected;}};
}
test('model choices and response budgets are allowlisted and server credentials stay private',async()=>{
 const f=fixture(),catalog=await f.request('/models');assert.equal(catalog.status,200);assert.equal(catalog.body.models.length,2);assert.equal(catalog.body.reasoningAvailable,false);assert.equal(catalog.body.externalReviewAvailable,true);assert.ok(!JSON.stringify(catalog).includes('server-only-test-key'));
 assert.equal((await f.turn()).status,200);assert.equal(f.selected.config.selectedModel,'nebula-classic');assert.equal(f.selected.config.responseLength,'expanded');
 assert.equal((await f.request('/chat','POST',{modelId:'private-provider-model',messages:[{role:'user',content:'Hi'}]},null)).status,400);
});
test('personalization synchronizes with the account and is excluded when disabled',async()=>{
 const f=fixture();const value={interests:'Drawing',answerStyle:'concise',customInstructions:'Use simple words.',personalizedQuestions:true,compactChat:true,defaultModel:'nebula-classic',textSize:'large'};
 const result=await f.request('/account','PATCH',value);assert.equal(result.status,200);assert.equal(result.body.account.interests,'Drawing');assert.equal(result.body.account.externalReview,false);
 await f.turn();assert.ok(f.selected.messages.some(m=>m.role==='system'&&m.content.includes('Drawing')));
 await f.request('/account','PATCH',{personalizationEnabled:false});await f.turn('second');assert.ok(!f.selected.messages.some(m=>m.content.includes('Drawing')));
 assert.equal((await f.request('/account','PATCH',{textSize:'enormous'})).status,400);
});
test('reviews require separate consent, current sharing, eligible new turns, and account ownership',async()=>{
 const f=fixture();await f.turn();assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'})).status,403);assert.equal(f.calls,0);
 await f.request('/account','PATCH',{externalReview:true,improve:false});assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'})).status,403);assert.equal(f.calls,0);
 await f.request('/account','PATCH',{improve:true});await f.turn('old',false);assert.equal((await f.request('/reviews','POST',{chatId:'old',turnId:'turn'})).status,403);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'},null)).status,401);
 const other=await f.request('/account','PATCH',{externalReview:true,improve:true},'other.user.token');assert.equal(other.status,200);
 assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'},'other.user.token')).status,404);
 assert.equal(f.calls,0);
});
test('a review redacts contacts and exports corrected answers as pending candidates, never automatic approvals',async()=>{
 let sent;const f=fixture({review:async args=>{sent=args.messages;return {verdict:'needs_correction',correctedReply:'2 + 2 = 4.'};}});
 await f.request('/account','PATCH',{externalReview:true,improve:true});await f.turn();const result=await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});assert.equal(result.status,200);assert.equal(result.body.reviewSaved,true);assert.ok(!JSON.stringify(sent).includes('alex@example.test'));
 await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});assert.equal(f.calls,1);
 const owner=accountOwner('alice',0),sample=f.records.get('nebulaTraining/v1/'+owner),profile=await f.store.account(accountKey('alice'),Date.now());
 const rows=selectContributions({[owner]:sample},{[accountKey('alice')]:profile});assert.equal(rows[0].reviewStatus,'pending');assert.equal(rows[0].messages[1].content,'2 + 2 = 4.');
 await f.store.deleteOwner(owner);assert.equal((await f.request('/reviews','POST',{chatId:'chat',turnId:'turn'})).status,409);assert.equal(f.calls,1);
});
test('withdrawing review consent during a provider request prevents saving its result',async()=>{
 let begin,finish;const ready=new Promise(r=>begin=r),wait=new Promise(r=>finish=r);const f=fixture({review:async()=>{begin();await wait;return {verdict:'needs_correction',correctedReply:'Corrected'};}});
 await f.request('/account','PATCH',{externalReview:true});await f.turn();const pending=f.request('/reviews','POST',{chatId:'chat',turnId:'turn'});await ready;await f.request('/account','PATCH',{externalReview:false});finish();assert.equal((await pending).status,409);
 assert.equal((await f.store.reviewCandidate(accountOwner('alice',0),'chat','turn')).review,undefined);
});
test('review attempts are bounded and the transport uses a server header, fixed host, and validated output',async()=>{
 const f=fixture();for(let i=0;i<3;i++)assert.equal(await f.store.allowReview('account',1000+i),true);assert.equal(await f.store.allowReview('account',2000),false);assert.equal(await f.store.allowReview('account',1000+48*3600000),true);
 let request;const result=await reviewAnswer({key:'private-test-key',model:'gemini-test',messages:[{role:'user',content:'Hi'}],fetcher:async(url,options)=>{request={url,options};return new Response(JSON.stringify({candidates:[{content:{parts:[{text:JSON.stringify({verdict:'uncertain',correctedReply:''})}]}}]}));}});
 assert.equal(result.verdict,'uncertain');assert.equal(request.options.headers['x-goog-api-key'],'private-test-key');assert.ok(!request.url.includes('private-test-key'));assert.equal(new URL(request.url).hostname,'generativelanguage.googleapis.com');
 await assert.rejects(()=>reviewAnswer({key:'k',model:'gemini-test',messages:[],fetcher:async()=>new Response('private upstream error',{status:429})}),e=>e.code==='REVIEW_RATE_LIMITED');
});
