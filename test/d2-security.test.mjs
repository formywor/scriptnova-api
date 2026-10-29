import {test} from 'node:test';
import assert from 'node:assert/strict';
import {securityAccess,scanSecurity} from '../lib/security-review.mjs';
import {d2Reply} from '../lib/assistants.mjs';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const owner={uid:'owner',email:'divedyacoub9@gmail.com',email_verified:true},invite={uid:'invited',email:'invited@example.com',email_verified:true};
const answer=text=>Response.json({choices:[{message:{content:text}}]});
test('security privileges require verified owner or active owner-issued invite',()=>{
 assert.equal(securityAccess(owner,{},null),true);
 assert.equal(securityAccess({...owner,email_verified:false},{},null),false);
 assert.equal(securityAccess(owner,{ownerUid:'other'},null),false);
 assert.equal(securityAccess(invite,{},null),false);
 assert.equal(securityAccess(invite,{}, {tier:'advanced',status:'active'}),false);
 assert.equal(securityAccess(invite,{}, {tier:'invite',status:'active'}),true);
 assert.equal(securityAccess(invite,{}, {tier:'invite',status:'suspended'}),false);
 assert.equal(securityAccess({...invite,email_verified:false},{}, {tier:'invite',status:'active'}),false);
});
test('scanner gates access and public URL before any network work, redacts secrets',async()=>{
 let reads=0;const reader=async url=>{reads++;return {url,text:'<script src="/main.js"></script> const secret="real-sensitive-example-value";',headers:{'content-type':'text/html'},status:200};};
 for(const [identity,grant,url,code] of [[invite,null,'https://scriptnovaa.com','SECURITY_INVITE_REQUIRED'],[owner,null,'http://example.com','INVALID_PUBLIC_URL'],[owner,null,'https://localhost','INVALID_PUBLIC_URL']])await assert.rejects(scanSecurity(url,{identity,grant,reader}),e=>e.code===code);
 assert.equal(reads,0);
 const r=await scanSecurity('https://another-owned-domain.example/',{identity:owner,reader});assert.equal(reads,2);assert.equal(r.mode,'passive-public-source');assert.equal(r.pages[0].secretFindings[0].value,'[REDACTED]');assert.ok(!JSON.stringify(r).includes('real-sensitive-example-value'));
});
test('D2 capacity fallback keeps dedicated key, model identity and current tool results',async()=>{
 let attempts=0,toolRuns=0;const models=[],progress=[];
 const result=await d2Reply([{role:'user',content:'Calculate 1 + 2.'}],{d2Key:'dedicated-test-key',ultraKey:'never-use-this',onProgress:s=>progress.push(s)}, {cloud:{calculate:async()=>{toolRuns++;return {result:3};}},fetcher:async(_,init)=>{
  assert.equal(init.headers.Authorization,'Bearer dedicated-test-key');const body=JSON.parse(init.body);models.push(body.model);assert.ok(body.max_completion_tokens<=4096);
  if(++attempts===1)return Response.json({choices:[{message:{content:null,tool_calls:[{id:'c',function:{name:'calculate',arguments:'{"expression":"1+2"}'}}]}}]});
  assert.ok(body.messages.some(m=>m.role==='tool'&&m.content.includes('3')));
  return attempts===2?new Response('capacity',{status:503}):answer('The result is 3.');
 }});
 assert.equal(result.text,'The result is 3.');assert.equal(toolRuns,1);assert.deepEqual(models,['openai/gpt-oss-120b','openai/gpt-oss-120b','openai/gpt-oss-20b']);assert.equal(progress.length,1);
});
test('D2 limits capacity attempts and never retries authentication failures',async()=>{
 for(const status of [401,429,503]){let calls=0;await assert.rejects(d2Reply([{role:'user',content:'Help me code.'}],{d2Key:'test'},{fetcher:async()=>{calls++;return new Response('private upstream detail',{status});}}));assert.equal(calls,status===401?1:2);}
});
test('chat advertises scanner only for verified owner or active invitation with Cloud enabled',async()=>{
 const old=process.env.NEBULA_ENVIRONMENT_ENABLED;process.env.NEBULA_ENVIRONMENT_ENABLED='true';
 try{for(const [identity,grant,enabled,expected] of [[owner,null,true,true],[invite,{tier:'invite',status:'active'},true,true],[invite,{tier:'invite',status:'suspended'},true,false],[{...owner,email_verified:false},null,true,false],[owner,null,false,false]]){
  const store=createStore(memoryDatabase().db);if(grant)await store.developerSetGrant(identity.email,grant);let received;
  const app=createApp({getStore:async()=>store,verifyToken:async()=>identity,config:{publicTiers:false,origins:[],rateSecret:'x'.repeat(40),d2Key:'test'},log:()=>{},generate:async(_,c)=>{received=c;return {text:'Review ready.'};}});
  const request=(path,method,body)=>app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer test.user.token','Content-Type':'application/json'},body:JSON.stringify(body)}));
  await request('/chats/review','PUT',{revision:0,title:'Review',messages:[{id:'turn',role:'user',content:'Scan scriptnovaa.com for vulnerabilities.'}]});
  const response=await request('/chat','POST',{chatId:'review',turnId:'turn',modelId:'nebula-d2',cloudMode:enabled,messages:[{role:'user',content:'Scan scriptnovaa.com for vulnerabilities.'}]});assert.equal(response.status,200,JSON.stringify(await response.clone().json()));assert.equal(typeof received.cloudTools?.securityScan==='function',expected);
 }}finally{if(old===undefined)delete process.env.NEBULA_ENVIRONMENT_ENABLED;else process.env.NEBULA_ENVIRONMENT_ENABLED=old;}
});
test('explicit invitation unlocks D2 without automatically promoting public account tier',async()=>{
 const {publicPlan}=await import('../lib/public-plans.mjs');const time=Date.now(),p=publicPlan(invite,{createdAt:time},{},time,null,{tier:'invite',status:'active'});
 assert.equal(p.tier,'normal');assert.ok(p.models.includes('nebula-d2'));assert.ok(!p.models.includes('nebula-duo'));
 assert.ok(!publicPlan(invite,{createdAt:time},{},time,null,{tier:'invite',status:'suspended'}).models.includes('nebula-d2'));
});
test('D2 retries a rejected generated tool call once but not unrelated bad requests',async()=>{
 for(const code of ['tool_use_failed','invalid_request_error']){let calls=0;const request=d2Reply([{role:'user',content:'Review my page.'}],{d2Key:'test'},{cloud:{inspect:async()=>({})},fetcher:async(_,init)=>{const b=JSON.parse(init.body);assert.equal(b.parallel_tool_calls,false);return ++calls===1?Response.json({error:{code}},{status:400}):answer('Recovered.');}});
 if(code==='tool_use_failed')assert.equal((await request).text,'Recovered.');else await assert.rejects(request);assert.equal(calls,code==='tool_use_failed'?2:1);
 }
});
test('D2 page excerpts reduce token load without changing full saved inspection data',async()=>{
 const page={url:'https://example.com/',source:'s'.repeat(18000),text:'t'.repeat(14000),network:Array.from({length:50},()=>({status:200})),console:[]};let calls=0;
 const r=await d2Reply([{role:'user',content:'Inspect example.com.'}],{d2Key:'test'},{cloud:{inspect:async()=>page},fetcher:async(_,init)=>{const body=JSON.parse(init.body);if(++calls===1)return Response.json({choices:[{message:{tool_calls:[{id:'page',function:{name:'open_live_page',arguments:'{"url":"https://example.com/"}'}}]}}]});const observed=JSON.parse(body.messages.find(m=>m.role==='tool').content);assert.equal(observed.source.length,3500);assert.equal(observed.text.length,3000);assert.equal(observed.network.length,15);assert.equal(observed.modelViewTruncated,true);return answer('Read the excerpt.');}});
 assert.ok(r.text);assert.equal(page.source.length,18000);assert.equal(page.network.length,50);
});
