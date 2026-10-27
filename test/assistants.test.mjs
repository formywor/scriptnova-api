import {test} from 'node:test';
import assert from 'node:assert/strict';
import {sparkReply,duoReply} from '../lib/assistants.mjs';
import {modelCatalog,preferencePatch,preferenceView} from '../lib/personalization.mjs';
import {createCloudHandler} from '../lib/cloud.mjs';
import {createStore} from '../lib/firebase.mjs';
import {cloudConfig,webSearch} from '../lib/cloud-services.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';
test('Spark uses server credential and validated tool results without exposing reasoning',async()=>{
 let step=0;const result=await sparkReply([{role:'user',content:'Calculate 2+3'}],{sparkKey:'private-key',cloudTools:{calculate:async()=>({result:5})}},{fetcher:async(url,init)=>{
 assert.equal(url,'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions');assert.equal(init.headers.Authorization,'Bearer private-key');const b=JSON.parse(init.body);assert.equal(b.model,'gemini-3.5-flash');assert.equal(b.max_completion_tokens,undefined);assert.doesNotMatch(b.messages[0].content,/Groq|Kaggle|Vercel/);
 return Response.json({choices:[{message:step++===0?{tool_calls:[{id:'calc',type:'function',function:{name:'calculate',arguments:'{"expression":"2+3"}'}}]}:{content:'5',reasoning:'hidden'}}]});
 }});assert.equal(result.text,'5');assert.equal(result.activity[0].tool,'calculate');assert.ok(!JSON.stringify(result).includes('private-key'));assert.ok(!JSON.stringify(result).includes('hidden'));
});
test('Duo runs independent drafts and mutual review with tools only available to final composer',async()=>{
 const calls=[];const spark=async(m,c)=>{calls.push(['spark',m,c]);assert.equal(c.cloudTools,undefined);return {text:m.at(-1).content.includes('Compare the two')?'A detail remains uncertain.':'Candidate S',reasoning:'must not leak'};};
 const ultra=async(m,c)=>{calls.push(['ultra',m,c]);return {text:c.assistantName==='Nebula Duo'?'Final answer with uncertainty.':'Candidate U',activity:[]};};
 const r=await duoReply([{role:'user',content:'Compare two approaches for this project.'}],{sparkKey:'s',ultraKey:'u',cloudTools:{calculate:true}},{spark,ultra});
 assert.equal(calls.length,5);assert.equal(r.collaboration.phases.length,3);assert.equal(r.collaboration.status,'reviewed');assert.equal(calls.filter(x=>x[2].cloudTools).length,1);assert.match(r.text,/uncertainty/);assert.ok(!JSON.stringify(r).includes('must not leak'));
});
test('Duo simple greetings skip the long collaboration and failed reviewers cannot invent consensus',async()=>{
 let count=0;const r=await duoReply([{role:'user',content:'Hi!'}],{sparkKey:'s',ultraKey:'u'},{spark:async()=>{count++;return {text:'Hi!'};},ultra:async()=>{throw Error('must not run');}});assert.equal(count,1);assert.equal(r.collaboration.mode,'direct');
 await assert.rejects(duoReply([{role:'user',content:'Explain a complex project.'}],{sparkKey:'s',ultraKey:'u'},{spark:async()=>{throw Error('upstream failed');},ultra:async()=>({text:'ok'})}));
});
test('model availability and saved default support Spark and Duo without public credentials',()=>{
 const c=modelCatalog({sparkKey:'secret',ultraKey:'other'});assert.equal(c.models.find(m=>m.id==='nebula-duo').available,true);assert.equal(modelCatalog({sparkKey:'s'}).models.find(m=>m.id==='nebula-duo').available,false);assert.ok(!JSON.stringify(c).includes('secret'));assert.equal(preferencePatch({defaultModel:'nebula-spark'}).defaultModel,'nebula-spark');assert.equal(preferenceView({defaultModel:'nebula-duo'}).defaultModel,'nebula-duo');
});
test('Run now saves only to authenticated account and needs no scheduling service',async()=>{
 const store=createStore(memoryDatabase().db);const h=createCloudHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice'}),config:cloudConfig({})});
 const ask=token=>h(new Request('https://api.test/api/nebula/cloud/run',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer test.valid.token'}:{})},body:JSON.stringify({kind:'reminder',instructions:'Remember the meeting'})}));
 assert.equal((await ask(false)).status,401);const r=await ask(true);assert.equal(r.status,200);const a=await store.cloudState(accountKey('alice'));assert.equal(Object.values(a.jobs)[0].result.text,'Remember the meeting');assert.equal(Object.values(a.jobs)[0].status,'completed');assert.deepEqual((await store.cloudState(accountKey('bob'))).jobs,{});
});
test('grounded search refuses ungrounded answers and returns only sourced results',async()=>{
 const c={sparkKey:'server-only'};const f=async(url,init)=>{assert.match(String(url),/generateContent$/);assert.equal(init.headers['x-goog-api-key'],'server-only');assert.ok(JSON.parse(init.body).tools[0].google_search);return Response.json({candidates:[{content:{parts:[{text:'A source-backed answer.'}]},groundingMetadata:{groundingChunks:[{web:{uri:'https://example.com/',title:'Source'}},{web:{uri:'javascript:bad',title:'Blocked'}}]}}]});};const r=await webSearch('query',c,f);assert.equal(r.results.length,1);assert.equal(r.results[0].url,'https://example.com/');await assert.rejects(webSearch('query',c,async()=>Response.json({candidates:[{content:{parts:[{text:'No source'}]}}]})),e=>e.code==='NO_SEARCH_RESULTS');
});

test('Duo progress is streamed from real server stages, followed by the normal result',async()=>{
 const {createApp}=await import('../lib/app.mjs');const store=createStore(memoryDatabase().db);const app=createApp({getStore:async()=>store,config:{origins:[],rateSecret:'r'.repeat(40),sparkKey:'s',ultraKey:'u',training:false},generate:async(m,c)=>{c.onProgress('Comparing answers…');return {text:'Reviewed answer',collaboration:{mode:'reviewed',status:'reviewed',phases:[]}};},log:()=>{}});
 const r=await app(new Request('https://api.test/api/nebula/chat',{method:'POST',headers:{'Content-Type':'application/json',Accept:'text/event-stream','x-forwarded-for':'192.0.2.1'},body:JSON.stringify({modelId:'nebula-duo',messages:[{role:'user',content:'Compare these ideas.'}]})}));assert.match(r.headers.get('content-type'),/text\/event-stream/);const events=(await r.text()).trim().split('\n\n').map(x=>JSON.parse(x.slice(6)));assert.equal(events[0].type,'progress');assert.equal(events.at(-1).data.reply,'Reviewed answer');assert.equal(events.at(-1).status,200);
});

test('Node deployment adapter delivers progress before the final response is ready',async()=>{
 const {createServer}=await import('node:http'),{createNodeHandler}=await import('../index.js');let finish;const waiting=new Promise(r=>finish=r);const encoder=new TextEncoder();
 const handler=createNodeHandler(async()=>new Response(new ReadableStream({async start(controller){controller.enqueue(encoder.encode('data: {"type":"progress"}\n\n'));await waiting;controller.enqueue(encoder.encode('data: {"type":"result"}\n\n'));controller.close();}}),{headers:{'Content-Type':'text/event-stream'}}));
 const server=createServer(handler);await new Promise(r=>server.listen(0,'127.0.0.1',r));try{const r=await fetch('http://127.0.0.1:'+server.address().port,{signal:AbortSignal.timeout(2000)}),reader=r.body.getReader();const first=await reader.read();assert.match(new TextDecoder().decode(first.value),/progress/);finish();let rest='';while(true){const b=await reader.read();if(b.done)break;rest+=new TextDecoder().decode(b.value);}assert.match(rest,/result/);}finally{finish();server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('model identity answers use Nebula branding without revealing private configuration',async()=>{
 const r=await sparkReply([{role:'user',content:'Say hello and tell me your Nebula model name.'}],{sparkKey:'s'},{fetcher:async()=>{throw Error('Identity does not require provider metadata');}});assert.match(r.text,/Nebula Spark/);assert.doesNotMatch(r.text,/Gemini|Google|Groq|Kaggle/);
 const d=await duoReply([{role:'user',content:'Who are you?'}],{sparkKey:'s',ultraKey:'u'});assert.match(d.text,/Nebula Duo/);assert.equal(d.collaboration.mode,'direct');
});

test('Cloud tasks finalize results when the database transaction cache is cold',async()=>{
 const store=createStore(memoryDatabase({coldTransactions:true}).db);const h=createCloudHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice'}),config:cloudConfig({})});
 const r=await h(new Request('https://api.test/api/nebula/cloud/run',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer test.valid.token'},body:JSON.stringify({kind:'reminder',instructions:'Saved with a cold cache'})}));assert.equal(r.status,200);const jobs=Object.values((await store.cloudState(accountKey('alice'))).jobs);assert.equal(jobs[0].status,'completed');assert.equal(jobs[0].result.text,'Saved with a cold cache');
 const update=await store.cloudJob(accountKey('alice'),jobs[0].id,j=>({...j,status:'cancelled'}));assert.equal(update.status,'cancelled');assert.equal(await store.cloudJob(accountKey('bob'),jobs[0].id,j=>({...j,status:'completed'})),null);
});
