import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createReviewRouter,reviewProviders} from '../lib/review-router.mjs';
import {reviewGroq} from '../lib/groq-review.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {configFromEnv,createApp} from '../lib/app.mjs';
import {modelCatalog} from '../lib/personalization.mjs';
import {accountKey,accountOwner} from '../lib/accounts.mjs';
const config={reviewEnabled:true,reviewGroqKey:'private-groq',reviewGroqModel:'openai/gpt-oss-20b',reviewKey:'private-gemini',reviewModel:'gemini-test'};
const okay={verdict:'acceptable',correctedReply:'A useful answer.',trainingQuestion:'A simple question?'};
const busy=()=>Object.assign(Error('PRIVATE upstream detail'),{code:'REVIEW_RATE_LIMITED'});
function setup(){const {db,records}=memoryDatabase();return {store:createStore(db),records};}
test('reviews alternate across new router instances; confirmation prefers the other healthy provider',async()=>{
 const {store}=setup();const calls=[];const transports=Object.fromEntries(['groq','gemini'].map(name=>[name,async()=>{calls.push(name);return okay;}]));
 for(let n=0;n<4;n++){
  const router=createReviewRouter({config,store,transports,now:()=>1000});
  const result=await router({messages:[]});assert.equal(result.provider,n%2?'gemini':'groq');
  const other=result.provider==='groq'?'gemini':'groq';assert.equal((await router({messages:[],preferredProvider:other})).provider,other);
 }
 assert.deepEqual(calls,['groq','gemini','gemini','groq','groq','gemini','gemini','groq']);
});
test('a failed provider immediately falls back, stays paused across cold instances and recovers after cooldown',async()=>{
 const {store}=setup();let time=1000,fail=true;const calls=[];
 const transports={groq:async()=>{calls.push('groq');if(fail)throw busy();return okay;},gemini:async()=>{calls.push('gemini');return okay;}};
 let router=createReviewRouter({config,store,transports,now:()=>time});assert.equal((await router({messages:[]})).provider,'gemini');
 router=createReviewRouter({config,store,transports,now:()=>time});for(let n=0;n<3;n++)assert.equal((await router({messages:[]})).provider,'gemini');assert.equal(calls.filter(n=>n==='groq').length,1);
 time+=61000;fail=false;
 // Cursor rotation may choose either first; the recovered provider must rejoin within two jobs.
 const recovered=[];for(let n=0;n<2;n++)recovered.push((await router({messages:[]})).provider);assert.ok(recovered.includes('groq'));
});
test('Gemini failure falls back to Groq; uncertain judgments do not trigger approval shopping',async()=>{
 const {store}=setup();let groq=0,gemini=0;const router=createReviewRouter({config,store,now:()=>1000,transports:{groq:async()=>{groq++;return {...okay,verdict:'uncertain'};},gemini:async()=>{gemini++;throw Error('private');}}});
 assert.equal((await router({messages:[],preferredProvider:'gemini'})).provider,'groq');assert.equal(groq,1);assert.equal(gemini,1);
 assert.equal((await router({messages:[]})).verdict,'uncertain');assert.equal(gemini,1);
});
test('when both fail, errors are sanitized and cooling providers are not repeatedly called',async()=>{
 const {store}=setup();let calls=0;const router=createReviewRouter({config,store,now:()=>1000,transports:{groq:async()=>{calls++;throw busy();},gemini:async()=>{calls++;throw Error('PRIVATE key');}}});
 await assert.rejects(()=>router({messages:[]}),e=>e.code==='REVIEW_UNAVAILABLE'&&!e.message.includes('PRIVATE'));
 await assert.rejects(()=>router({messages:[]}),e=>e.code==='REVIEW_RATE_LIMITED');assert.equal(calls,2);
});
test('one configured provider is sufficient and public availability never reveals keys or providers',()=>{
 const c=configFromEnv({NEBULA_REVIEW_ENABLED:'true',GROQ_API_KEY:'private-key'});assert.equal(c.reviewGroqKey,'private-key');assert.equal(c.reviewGroqModel,'openai/gpt-oss-20b');assert.equal(reviewProviders(c).length,1);const catalog=modelCatalog(c);assert.equal(catalog.externalReviewAvailable,true);assert.ok(!JSON.stringify(catalog).includes('private-key'));assert.ok(!JSON.stringify(catalog).includes('groq'));
});
test('Groq transport uses fixed HTTPS, header auth, bounded JSON and the common review schema',async()=>{
 let sent;const result=await reviewGroq({messages:[{role:'user',content:'Hi'}],key:'private-key',model:'openai/gpt-oss-20b',fetcher:async(url,options)=>{sent={url,options};return new Response(JSON.stringify({choices:[{message:{content:JSON.stringify(okay)}}]}));}});
 assert.equal(result.trainingQuestion,okay.trainingQuestion);assert.equal(sent.url,'https://api.groq.com/openai/v1/chat/completions');assert.equal(sent.options.headers.Authorization,'Bearer private-key');assert.equal(sent.options.redirect,'error');const body=JSON.parse(sent.options.body);assert.equal(body.response_format.type,'json_object');assert.equal(body.reasoning_effort,'low');assert.equal(body.max_completion_tokens,2048);
 await assert.rejects(()=>reviewGroq({messages:[],key:'k',model:'test',fetcher:async()=>new Response('private error',{status:429})}),e=>e.code==='REVIEW_RATE_LIMITED');
 await assert.rejects(()=>reviewGroq({messages:[],key:'k',model:'test',fetcher:async()=>new Response('x'.repeat(25000))}),e=>e.code==='REVIEW_UNAVAILABLE');
 await assert.rejects(()=>reviewGroq({messages:[],key:'k',model:'test',fetcher:async()=>new Response(JSON.stringify({choices:[{message:{content:'not JSON'}}]}))}),e=>e.code==='REVIEW_UNAVAILABLE');
});
test('the real API router can produce checked Groq teaching examples without a Gemini key',async t=>{
 const {store,records}=setup();let time=1800000000000,calls=0;
 t.mock.method(globalThis,'fetch',async(url,options)=>{
  assert.equal(url,'https://api.groq.com/openai/v1/chat/completions');assert.equal(options.headers.Authorization,'Bearer groq-test-only');calls++;
  return new Response(JSON.stringify({choices:[{message:{content:JSON.stringify({verdict:calls===1?'needs_correction':'acceptable',correctedReply:'2 + 2 = 4.',trainingQuestion:'What is 2 + 2?'})}}]}));
 });
 const app=createApp({getStore:async()=>store,verifyToken:async()=>({uid:'alice'}),config:{ultraKey:'unit-test-only-key',origins:[],rateSecret:'x'.repeat(40),modelMode:'embedded',training:true,reviewEnabled:true,reviewGroqKey:'groq-test-only',reviewGroqModel:'openai/gpt-oss-20b'},now:()=>time,generate:async()=> '2 + 2 = 44.',log:()=>{}});
 const request=async(path,body)=>{const response=await app(new Request('https://api.test/api/nebula'+path,{method:path.startsWith('/chats/')?'PUT':'POST',headers:{Authorization:'Bearer alice.test.token','Content-Type':'application/json'},body:JSON.stringify(body)}));assert.equal(response.status,200);return response.json();};
 await request('/chats/chat',{title:'Practice',revision:0,messages:[{id:'turn',role:'user',content:'What is 2 + 2?',trainingEligible:true,reviewEligible:true}]});
 await request('/chat',{chatId:'chat',turnId:'turn',messages:[{role:'user',content:'Hi'}],training:{enabled:true,token:'a'.repeat(64),consentVersion:1,chatId:'chat',turnId:'turn'}});time+=301000;
 const result=await request('/reviews',{chatId:'chat'});assert.equal(result.trainingEligible,true);assert.equal(calls,2);
 const sample=await store.reviewCandidate(accountOwner('alice',0),'chat','turn');assert.equal(sample.review.provider,'groq');assert.equal(sample.review.qualityChecked,true);assert.ok(records.get('nebulaReviewTraining/v1/'+accountOwner('alice',0)));
});
