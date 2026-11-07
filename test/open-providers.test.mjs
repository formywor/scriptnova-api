import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openProviders,openTransport} from '../lib/open-providers.mjs';
import {openReply} from '../lib/assistants.mjs';
import {configFromEnv} from '../lib/app.mjs';

const config={openAccountId:'b'.repeat(32),openKey:'cf-test',sparkKey:'gemini-test',openCerebrasKey:'cerebras-test',openRouterKey:'router-test',openMistralKey:'mistral-test',openGroqKey:'groq-test'};
const init=()=>({method:'POST',signal:new AbortController().signal,headers:{Authorization:'Bearer must-be-replaced'},body:JSON.stringify({model:'old',messages:[{role:'user',content:'Hi'}],max_completion_tokens:256,stream:false})});
const ok=()=>Response.json({choices:[{message:{content:'OK'}}]});

test('primary, three independent backups, then dedicated Groq; no implicit Ultra keys',()=>{
 assert.deepEqual(openProviders(config).map(x=>x.id),['cloudflare','cerebras','openrouter','gemini','groq-final']);
 assert.deepEqual(openProviders({ultraKey:'never',d2Key:'never'}),[]);
 assert.equal(configFromEnv({NEBULA_OPEN_GROQ_FALLBACK_KEY:'last'}).openGroqKey,'last');
});

test('every capacity failure falls through in order, using its own auth; one allowance',async()=>{
 const calls=[],fallbackState={used:false};let charges=0;
 const transport=openTransport({...config,fallbackState,consumeOpenCall:async()=>charges++},{failures:new Map(),fetcher:async(url,opts)=>{
  const p=openProviders(config)[calls.length];calls.push(p.id);
  assert.equal(url,p.url);assert.equal(opts.headers.Authorization,'Bearer '+p.key);
  const body=JSON.parse(opts.body);assert.equal(body.model,p.model);
  if(p.id==='openrouter'){assert.equal(body.model,'openrouter/free');assert.deepEqual(body.provider.ignore,['Groq']);assert.equal(body.provider.require_parameters,undefined);assert.equal(body.parallel_tool_calls,undefined);}
  return p.id==='groq-final'?ok():Response.json({error:{message:'capacity'}},{status:429});
 }});
 assert.equal((await transport('',init())).status,200);
 assert.deepEqual(calls,openProviders(config).map(x=>x.id));assert.equal(charges,1);assert.equal(fallbackState.used,true);
});

test('failover between tool rounds retains results and never reruns a completed action',async()=>{
 let toolRuns=0,cfCalls=0,backupCalls=0;
 const reply=await openReply([{role:'user',content:'Calculate 5 times 6 with the calculator.'}],{...config,openKey:'round-tool-test'},{
  cloud:{calculate:async()=>{toolRuns++;return {value:30};}},
  fetcher:async(url,opts)=>{
   if(url.includes('cloudflare')){
    if(cfCalls++===0)return Response.json({choices:[{message:{content:null,tool_calls:[{id:'original_call_id',type:'function',function:{name:'calculate',arguments:'{"expression":"5*6"}'}}]}}]});
    return new Response('',{status:503});
   }
   backupCalls++;const body=JSON.parse(opts.body);
   assert.equal(body.messages.at(-1).tool_call_id,'original_call_id');
   assert.match(body.messages.at(-1).content,/30/);
   return Response.json({choices:[{message:{content:'30'}}]});
  }
 });
 assert.equal(reply.text,'30');assert.equal(toolRuns,1);assert.equal(backupCalls,1);
});

test('provider cooldown respects Retry-After and missing providers are skipped',async()=>{
 let now=10000,calls=[];const failures=new Map();
 const transport=openTransport({openAccountId:config.openAccountId,openKey:'cooldown-test',openGroqKey:'last'},{failures,now:()=>now,fetcher:async url=>{
  calls.push(url.includes('cloudflare')?'cf':'groq');return url.includes('cloudflare')?new Response('',{status:429,headers:{'Retry-After':'120'}}):ok();
 }});
 await transport('',init());await transport('',init());assert.deepEqual(calls,['cf','groq','groq']);
 now+=120001;await transport('',init());assert.deepEqual(calls,['cf','groq','groq','cf','groq']);
});

test('successful backup stays preferred; Groq still remains last',async()=>{
 const calls=[];let step=0;
 const transport=openTransport(config,{failures:new Map(),fetcher:async(url)=>{
  const id=openProviders(config).find(p=>p.url===url).id;calls.push(id);
  return step++===0?new Response('',{status:503}):ok();
 }});
 await transport('',init());await transport('',init());
 assert.deepEqual(calls,['cloudflare','cerebras','cerebras']);
});

test('HTTP 200 refusals and invalid input do not trigger fallback',async()=>{
 for(const status of [200,400]){
  let calls=0;const transport=openTransport(config,{failures:new Map(),fetcher:async()=>{calls++;return status===200?Response.json({choices:[{message:{content:'I cannot help with that request.'}}]}):new Response('',{status});}});
  assert.equal((await transport('',init())).status,status);assert.equal(calls,1);
 }
});

test('malformed responses and network errors move to a healthy backup',async()=>{
 let calls=0;const transport=openTransport(config,{failures:new Map(),fetcher:async()=>{
  calls++;if(calls===1)throw Error('private network diagnostics');if(calls===2)return new Response('invalid json');return ok();
 }});
 assert.equal((await transport('',init())).status,200);assert.equal(calls,3);
});

test('cancellation and local limits never start another provider',async()=>{
 const controller=new AbortController();let calls=0;
 const transport=openTransport(config,{failures:new Map(),fetcher:async()=>{calls++;controller.abort();throw Error('aborted');}});
 await assert.rejects(transport('',{...init(),signal:controller.signal}));assert.equal(calls,1);
 const limited=openTransport({...config,consumeOpenCall:async()=>{throw Object.assign(Error('limit'),{code:'OPEN_DAILY_LIMIT'});}},{fetcher:async()=>assert.fail('No provider request')});
 await assert.rejects(limited('',init()),{code:'OPEN_DAILY_LIMIT'});
});

test('removed Mistral configuration cannot reactivate the provider',()=>{
 assert.deepEqual(openProviders({openMistralKey:'obsolete'}),[]);
 assert.equal(configFromEnv({NEBULA_OPEN_MISTRAL_KEY:'obsolete'}).openMistralKey,undefined);
});

test('Gemini remains second-to-last even after answering an earlier tool round',async()=>{
 let time=10000;const calls=[];
 const transport=openTransport(config,{failures:new Map(),now:()=>time,fetcher:async url=>{
  const id=openProviders(config).find(p=>p.url===url).id;calls.push(id);
  return id==='gemini'?ok():new Response('',{status:503});
 }});
 await transport('',init());time+=60001;await transport('',init());
 assert.deepEqual(calls,[...Array(2)].flatMap(()=>['cloudflare','cerebras','openrouter','gemini']));
});
