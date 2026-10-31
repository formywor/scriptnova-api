import {test} from 'node:test';
import assert from 'node:assert/strict';
import {auditPublicSurface,testPublicApi,discoverSurface} from '../lib/site-diagnostics.mjs';
import {pageInspector,executeCode,inspectPageWithFallback,inspectPage} from '../lib/cloud-environment.mjs';
import {createCloudHandler} from '../lib/cloud.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {d2Reply} from '../lib/assistants.mjs';

const html='<html><title>App</title><script src="/app.js"></script><a href="/admin">Admin</a></html>';
const response=(url,text,status=200)=>({url,text,status,headers:{'content-type':'text/html'},cookies:[],bytes:text.length,milliseconds:1});
test('exposure review detects signatures, withholds secrets, limits requests and does not mistake SPA admin routes for a breach',async()=>{
 const seen=[],secret='gsk_'+'a'.repeat(40),reader=async(url,options)=>{seen.push({url,options});const path=new URL(url).pathname;return response(url,path==='/app.js'?"const base='https://api.owned.test/api/v1'; //# sourceMappingURL=app.js.map":path==='/.git/HEAD'?'ref: refs/heads/main\n':path==='/.env'?'DATABASE_PASSWORD='+secret:path==='/debug'?'Traceback (most recent call last)\n'+secret:path==='/app.js.map'?'{"version":3,"sources":["app.ts"]}':html);};
 const r=await auditPublicSurface('https://owned.test/',{reader,pause:async()=>{}});
 assert.ok(r.findings.some(f=>f.code==='EXPOSED_GIT_METADATA'));assert.ok(r.findings.some(f=>f.code==='EXPOSED_ENV_FILE'));assert.ok(r.findings.some(f=>f.code==='PUBLIC_ERROR_TRACE'));assert.ok(!JSON.stringify(r).includes(secret));
 assert.equal(r.checks.find(c=>c.url.endsWith('/admin')).classification,'matches-missing-page-response');assert.ok(r.discovered.endpoints.includes('https://api.owned.test/api/v1'));assert.ok(r.findings.some(f=>f.code==='PUBLIC_SOURCE_MAP'));
 assert.ok(seen.length<=23);assert.ok(seen.every(c=>!c.options.method||c.options.method==='GET'));assert.ok(seen.every(c=>new URL(c.url).origin==='https://owned.test'));
});
test('API tests check three nonmutating methods, report auth errors and JSON shape without response values',async()=>{
 const methods=[],r=await testPublicApi('https://api.owned.test/api/status',{reader:async(url,options)=>{methods.push(options);return {...response(url,'{"privateExample":"do-not-publish","ok":true}',options.method==='GET'?401:204),headers:{'content-type':'application/json','access-control-allow-origin':'*','access-control-allow-credentials':'true'}};}});
 assert.deepEqual(methods.map(m=>m.method),['GET','HEAD','OPTIONS']);assert.ok(methods.every(m=>m.origin==='https://nebula-diagnostic.invalid'&&m.maxRedirects===0));assert.equal(r.checks[0].status,401);assert.ok(r.checks[0].jsonShape.keys.includes('ok'));assert.ok(!JSON.stringify(r).includes('do-not-publish'));assert.ok(r.findings.some(f=>f.code==='INVALID_CORS_COMBINATION'));
 for(const url of ['https://api.owned.test/logout','https://api.owned.test/api/delete','https://api.owned.test/api?key=secret','https://user:pass@api.owned.test/'])await assert.rejects(testPublicApi(url),e=>e.code==='INVALID_API_TARGET');
});
test('discovery does not schedule mutations, query credentials or arbitrary outbound admin probes',()=>{
 const r=discoverSurface('<a href="https://other.test/admin">Other</a><a href="/logout">Logout</a><script defer src=/app.js?v=cloud-4></script> const a="/api/users"; const b="https://api.owned.test/api?token=sensitive";','https://owned.test/');assert.deepEqual(r.adminPages,[]);assert.deepEqual(r.scripts,['https://owned.test/app.js']);assert.ok(r.endpoints.includes('https://owned.test/api/users'));assert.ok(!r.endpoints.some(u=>u.includes('?')));
});
test('browser traffic collection enforces public scope/read-only methods and removes credential headers',async()=>{
 let routeHandler,wsHandler,written,forwarded,stopped=false;const handlers={};
 const request=(url,method='GET')=>({url:()=>url,method:()=>method,resourceType:()=> 'fetch',isNavigationRequest:()=>false,headers:()=>({cookie:'session=secret',authorization:'Bearer secret','x-api-key':'secret',accept:'application/json',origin:'https://owned.test'}),timing:()=>({domainLookupStart:0,domainLookupEnd:1,connectStart:1,connectEnd:2,requestStart:2,responseStart:4,responseEnd:8}),failure:()=>({errorText:'net::ERR_FAILED'})});
 const page={on:(event,handler)=>{handlers[event]=handler;},goto:async()=>{
  for(const [url,method,expected]of [['https://api.owned.test/status','GET',null],['https://169.254.169.254/latest','GET','host-outside-validated-scope'],['https://api.owned.test/save','POST','write-method-blocked'],['https://api.owned.test/status?token=secret','GET','credential-query-blocked']]){const r=request(url,method);let aborted=false;await routeHandler({request:()=>r,abort:async()=>{aborted=true;},continue:async options=>{forwarded=options.headers;}});assert.equal(aborted,!!expected);if(!aborted){handlers.response({request:()=>r,status:()=>200,headers:()=>({'content-type':'application/json','set-cookie':'secret'})});handlers.requestfinished(r);}}
 },waitForTimeout:async()=>{},url:()=> 'https://owned.test/',title:async()=> 'Test',locator:()=>({innerText:async()=> 'Hello'}),content:async()=> '<p>Hello</p>'};
 const context={route:async(_pattern,h)=>{routeHandler=h;},routeWebSocket:async(_pattern,h)=>{wsHandler=h;},newPage:async()=>page};
 const chromium={launch:async options=>{assert.match(options.args.join(' '),/MAP \* ~NOTFOUND/);return{newContext:async options=>{assert.equal(options.serviceWorkers,'block');return context;},close:async()=>{stopped=true;}};}};
 const fs={readFile:async()=>JSON.stringify({url:'https://owned.test/',hosts:[{host:'owned.test',address:'93.184.216.34'},{host:'api.owned.test',address:'93.184.216.35'}]}),writeFile:async(_p,v)=>{written=JSON.parse(v);}};
 const code=pageInspector.replace("import {chromium} from 'playwright';",'').replace("import fs from 'node:fs/promises';",'');await new (Object.getPrototypeOf(async function(){}).constructor)('chromium','fs',code)(chromium,fs);
 assert.ok(stopped&&wsHandler);assert.equal(forwarded.cookie,undefined);assert.equal(forwarded.authorization,undefined);assert.equal(forwarded['x-api-key'],undefined);assert.equal(written.network[0].timing.totalMs,8);assert.equal(written.network[1].blockedReason,'host-outside-validated-scope');assert.ok(!JSON.stringify(written).includes('token=secret'));assert.ok(!JSON.stringify(written).includes('set-cookie'));
});
test('cross-origin browser hosts must all pass public DNS validation; skipped hosts never enter VM egress allowlist',async()=>{
 let created,input;const Sandbox={create:async options=>{created=options;return{writeFiles:async files=>{input=JSON.parse(files.find(f=>f.path.endsWith('inspect-input.json')).content.toString());},runCommand:async()=>({exitCode:0}),readFileToBuffer:async()=>Buffer.from('{"title":"Test"}'),stop:async()=>{}};}};
 await inspectPage('https://owned.test/',{browserSnapshot:'snap-test'},{Sandbox,networkHosts:['api.owned.test','internal.test'],lookup:async host=>[{family:4,address:host==='internal.test'?'10.0.0.1':'93.184.216.34'}]});
 assert.deepEqual(created.networkPolicy.allow,['owned.test','api.owned.test']);assert.equal(input.hosts.length,2);assert.equal(created.env,undefined);
});
test('Bash commands are run as files in a network-denied temporary VM',async()=>{
 let command,created;const r=await executeCode({language:'bash',code:'printf hello | wc -c'},{Sandbox:{create:async c=>{created=c;return{writeFiles:async()=>{},runCommand:async c=>{command=c;return{exitCode:0};},readFileToBuffer:async({path})=>Buffer.from(path.endsWith('stdout.txt')?'5\n':''),stop:async()=>{}};}}});assert.match(command.args[1],/bash \/vercel\/sandbox\/nebula-run.sh/);assert.equal(created.networkPolicy,'deny-all');assert.equal(r.stdout,'5\n');
});
test('Cloud diagnostics enforce owner/invite gates, meter results, persist reports and refund failed actions',async()=>{
 const previous=process.env.NEBULA_ENVIRONMENT_ENABLED;process.env.NEBULA_ENVIRONMENT_ENABLED='true';try{
 const memory=memoryDatabase(),store=createStore(memory.db),identity={uid:'owner',email:'divedyacoub9@gmail.com',email_verified:true};let reads=0;
 const handler=createCloudHandler({getStore:async()=>store,verifyToken:async()=>identity,config:{origins:[]},sourceReader:async(url)=>{reads++;return response(url,'{}');}});
 const request=()=>handler(new Request('https://api.test/api/nebula/cloud/environment/run',{method:'POST',headers:{Authorization:'Bearer fixture.jwt.token','Content-Type':'application/json','Idempotency-Key':'11111111-1111-4111-8111-111111111111'},body:JSON.stringify({kind:'api',url:'https://api.owned.test/status'})}));
 const r=await request();assert.equal(r.status,200);assert.equal((await r.json()).creditsUsed,2);assert.equal(reads,3);assert.equal((await store.planUsage(accountKey('owner'),Date.now(),'high')).short.used,2);assert.equal(Object.values(memory.records.get('nebulaEnvironment/v1/'+accountKey('owner')+'/history')||{}).length,1);
 const bad=await handler(new Request('https://api.test/api/nebula/cloud/environment/run',{method:'POST',headers:{Authorization:'Bearer fixture.jwt.token','Content-Type':'application/json','Idempotency-Key':'33333333-3333-4333-8333-333333333333'},body:JSON.stringify({kind:'api',url:'https://api.owned.test/logout'})}));assert.equal(bad.status,400);assert.equal((await store.planUsage(accountKey('owner'),Date.now(),'high')).short.used,2);
 const guestHandler=createCloudHandler({getStore:async()=>store,verifyToken:async()=>({uid:'ordinary',email:'other@example.com',email_verified:true}),config:{origins:[]},sourceReader:async()=>{throw Error('Must not read');}});
 assert.equal((await guestHandler(new Request('https://api.test/api/nebula/cloud/environment/run',{method:'POST',headers:{Authorization:'Bearer fixture.jwt.token','Content-Type':'application/json','Idempotency-Key':'22222222-2222-4222-8222-222222222222'},body:JSON.stringify({kind:'audit',url:'https://owned.test/'})}))).status,403);
 }finally{if(previous===undefined)delete process.env.NEBULA_ENVIRONMENT_ENABLED;else process.env.NEBULA_ENVIRONMENT_ENABLED=previous;}
});
test('D2 can call the new diagnostic tools and receives evidence-specific reporting instructions',async()=>{
 let calls=0;const r=await d2Reply([{role:'user',content:'Review my API.'}],{d2Key:'fixture',securityReviewAuthorized:true},{cloud:{testApi:async()=>({mode:'public-api-contract-check',checks:[{method:'GET',status:401}]})},fetcher:async(_u,init)=>{const b=JSON.parse(init.body);assert.ok(b.tools.some(t=>t.function.name==='test_public_api'));assert.match(b.messages[0].content,/not proof of XSS/);if(calls++===0)return Response.json({choices:[{message:{tool_calls:[{id:'api',function:{name:'test_public_api',arguments:'{"url":"https://api.owned.test/status"}'}}]}}]});assert.match(b.messages.at(-1).content,/401/);return Response.json({choices:[{message:{content:'The endpoint requires authentication.'}}]});}});assert.equal(r.activity[0].tool,'test_public_api');assert.equal(r.activity[0].status,'completed');
});
