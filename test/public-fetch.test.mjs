import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {gzipSync,brotliCompressSync} from 'node:zlib';
import {fetchPublic} from '../lib/public-fetch.mjs';
import {inspectPageWithFallback} from '../lib/cloud-environment.mjs';
import {analyzePage,comparePages} from '../lib/page-analysis.mjs';
import {d2Reply} from '../lib/assistants.mjs';
import {createCloudHandler} from '../lib/cloud.mjs';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';

const lookup=async()=>[{address:'93.184.216.34',family:4}];
function fixture(routes){const seen=[];return {seen,request:(u,options,cb)=>{
 const req=new EventEmitter();req.destroy=error=>{if(error)queueMicrotask(()=>req.emit('error',error));};
 req.end=()=>queueMicrotask(()=>{seen.push({url:u.href,options});const spec=routes[u.href];if(spec?.error){req.emit('error',Object.assign(Error(),{code:spec.error}));return;}
 const res=new EventEmitter();res.headers=spec?.headers||{'content-type':'text/html'};res.statusCode=spec?.status||200;res.resume=()=>{};
 res.pipe=dest=>{res.on('data',b=>dest.write(b));res.on('end',()=>dest.end());return dest;};cb(res);res.emit('data',spec?.body||Buffer.from('<p>Public page</p>'));res.emit('end');});return req;
 }};}
test('HTTPS redirects are followed with separately validated pinned DNS and no cookies or credentials',async()=>{
 const f=fixture({'https://owned.test/':{status:301,headers:{location:'https://www.owned.test/'}},'https://www.owned.test/':{headers:{'content-type':'text/html','set-cookie':['session=private-value; Secure; HttpOnly; SameSite=Lax']}}});const hosts=[];
 const result=await fetchPublic('https://owned.test/',{request:f.request,lookup:async host=>{hosts.push(host);return lookup();}});
 assert.deepEqual(hosts,['owned.test','www.owned.test']);assert.equal(result.url,'https://www.owned.test/');assert.equal(result.redirects[0].status,301);
 assert.ok(!JSON.stringify(result).includes('private-value'));assert.equal(result.cookies[0].httpOnly,true);assert.equal(f.seen[1].options.headers.Cookie,undefined);assert.equal(f.seen[1].options.headers.Authorization,undefined);
});
test('redirects cannot reach private addresses, non-HTTPS destinations, credentials or loops',async()=>{
 for(const target of ['https://internal.test/','http://owned.test/','https://user:pass@owned.test/','https://owned.test/']){
  const f=fixture({'https://owned.test/':{status:302,headers:{location:target}}});
  await assert.rejects(fetchPublic('https://owned.test/',{request:f.request,lookup:async host=>[{address:host==='internal.test'?'169.254.169.254':'93.184.216.34',family:4}]}),e=>['PUBLIC_URL_BLOCKED','INVALID_PUBLIC_URL','REDIRECT_LOOP'].includes(e.code));
  assert.equal(f.seen.length,1);
 }
});
test('gzip and brotli decode within a strict output limit; oversized decompression is bounded',async()=>{
 for(const [encoding,compress]of [['gzip',gzipSync],['br',brotliCompressSync]]){
  const f=fixture({'https://owned.test/':{headers:{'content-type':'text/html','content-encoding':encoding},body:compress(Buffer.from('x'.repeat(5000)))}});
  const result=await fetchPublic('https://owned.test/',{lookup,request:f.request,maxBytes:100});assert.equal(result.bytes,100);assert.equal(result.truncated,true);
 }
});
test('a connection failure tries a second public address, while DNS failure stays a precise error',async()=>{
 let calls=0;const f=fixture({'https://owned.test/':{}});const request=(u,o,cb)=>{if(++calls===1){const req=new EventEmitter();req.end=()=>queueMicrotask(()=>req.emit('error',Object.assign(Error(),{code:'ECONNRESET'})));return req;}return f.request(u,o,cb);};
 assert.equal((await fetchPublic('https://owned.test/',{request,lookup:async()=>[{address:'93.184.216.34',family:4},{address:'93.184.216.35',family:4}]})).retries,1);
 await assert.rejects(fetchPublic('https://missing.test/',{lookup:async()=>{throw Object.assign(Error(),{code:'ENOTFOUND'});}}),e=>e.code==='DNS_NOT_FOUND'&&e.status===422);
 const signal=AbortSignal.abort();await assert.rejects(fetchPublic('https://owned.test/',{lookup,request:f.request,signal}),e=>e.code==='CANCELED');
});
const source={url:'https://owned.test/',status:200,headers:{'content-type':'text/html'},text:'<html lang="en"><title>Project</title><h1>Welcome</h1><a href="/help?token=secret">Help</a><img src="test.png"><form method="post" action="/save"></form><p>Public content</p></html>',redirects:[],cookies:[]};
test('browser startup failure returns useful source evidence and explicitly excludes rendered observations',async()=>{
 const result=await inspectPageWithFallback('https://owned.test/',{}, {reader:async()=>source,store:{},prepareBrowser:async()=>{throw Object.assign(Error(),{code:'CLOUD_BROWSER_UNAVAILABLE'});}});
 assert.equal(result.mode,'public-source-fallback');assert.equal(result.fallbackUsed,true);assert.equal(result.title,'Project');assert.deepEqual(result.network,[]);assert.match(result.notice,/JavaScript was not executed/);
});
test('page analysis preserves status, labels heuristics, strips link queries and comparison keeps partial failures',async()=>{
 const result=await analyzePage('https://owned.test/',{reader:async()=>source});assert.equal(result.forms[0].method,'POST');assert.equal(result.accessibilitySignals.imagesWithoutAlt,1);assert.equal(result.links[0].url,'https://owned.test/help');assert.equal(result.headings[0].text,'Welcome');
 const compared=await comparePages('https://owned.test/','https://missing.test/',{reader:async url=>{if(url.includes('missing'))throw Object.assign(Error(),{code:'DNS_NOT_FOUND'});return source;}});assert.equal(compared.pages[1].error,'DNS_NOT_FOUND');assert.equal(compared.pages[0].status,200);
});
test('D2 preserves precise scan errors in both model evidence and activity without suggesting a global outage',async()=>{
 let calls=0;const result=await d2Reply([{role:'user',content:'I own owned.test; review security.'}],{d2Key:'fixture',securityReviewAuthorized:true},{cloud:{securityScan:async()=>{throw Object.assign(Error(),{code:'ENOTFOUND'});}},fetcher:async(_url,init)=>{
  const b=JSON.parse(init.body);if(calls++===0)return Response.json({choices:[{message:{tool_calls:[{id:'scan',function:{name:'scan_website_security',arguments:'{"url":"https://owned.test/"}'}}]}}]});
  assert.match(b.messages.at(-1).content,/DNS_NOT_FOUND/);assert.match(b.messages.at(-1).content,/Only this action failed/);return Response.json({choices:[{message:{content:'This hostname could not be resolved.'}}]});
 }});assert.equal(result.activity[0].code,'DNS_NOT_FOUND');
});
test('authenticated Cloud recovery charges one credit, saves useful evidence and refunds failed analysis',async()=>{
 const before=process.env.NEBULA_ENVIRONMENT_ENABLED;process.env.NEBULA_ENVIRONMENT_ENABLED='true';
 try{
  const identity={uid:'owner',email:'divedyacoub9@gmail.com',email_verified:true},store=createStore(memoryDatabase().db);let failing=false;
  const run=createCloudHandler({getStore:async()=>store,verifyToken:async()=>identity,config:{origins:[]},sourceReader:async()=>{if(failing)throw Object.assign(Error(),{code:'DNS_NOT_FOUND',status:422});return source;},prepareBrowser:async()=>{throw Object.assign(Error(),{code:'CLOUD_BROWSER_UNAVAILABLE'});}});
  const request=(kind,id)=>run(new Request('https://api.test/api/nebula/cloud/environment/run',{method:'POST',headers:{Authorization:'Bearer fixture.jwt.token','Content-Type':'application/json','Idempotency-Key':id},body:JSON.stringify({kind,url:'https://owned.test/'})}));
  const r=await request('inspect','11111111-1111-4111-8111-111111111111');assert.equal(r.status,200);const d=await r.json();assert.equal(d.creditsUsed,1);assert.equal(d.result.mode,'public-source-fallback');
  assert.equal((await store.planUsage(accountKey(identity.uid),Date.now(),'high')).short.used,1);
  failing=true;assert.equal((await request('analyze','22222222-2222-4222-8222-222222222222')).status,422);assert.equal((await store.planUsage(accountKey(identity.uid),Date.now(),'high')).short.used,1);
 }finally{if(before===undefined)delete process.env.NEBULA_ENVIRONMENT_ENABLED;else process.env.NEBULA_ENVIRONMENT_ENABLED=before;}
});
test('chat deduplicates repeated scans and survives a history-storage failure after successful website reads',async()=>{
 const before=process.env.NEBULA_ENVIRONMENT_ENABLED;process.env.NEBULA_ENVIRONMENT_ENABLED='true';
 try{
  const store=createStore(memoryDatabase().db);store.environmentHistory=async()=>{throw Error('storage offline');};let reads=0;
  const app=createApp({getStore:async()=>store,verifyToken:async()=>({uid:'owner',email:'divedyacoub9@gmail.com',email_verified:true}),config:{origins:[],publicTiers:false,rateSecret:'x'.repeat(40),d2Key:'fixture'},cloudRuntime:{reader:async()=>{reads++;return {...source,text:'<p>Public page</p>'};}},generate:async(_m,c)=>{
   await c.cloudTools.securityScan('https://owned.test/');await c.cloudTools.securityScan('https://owned.test/');await c.cloudTools.analyze('https://owned.test/');
   return {text:'The public-source checks completed.'};
  }});
  const req=(path,body,method='POST')=>app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer fixture.jwt.token','Content-Type':'application/json'},body:JSON.stringify(body)}));
  await req('/chats/scan',{revision:0,title:'Review',messages:[{id:'turn',role:'user',content:'Review my website.'}]},'PUT');
  assert.equal((await req('/chat',{chatId:'scan',turnId:'turn',modelId:'nebula-d2',cloudMode:true,messages:[{role:'user',content:'Review my website.'}]})).status,200);assert.equal(reads,2);
 }finally{if(before===undefined)delete process.env.NEBULA_ENVIRONMENT_ENABLED;else process.env.NEBULA_ENVIRONMENT_ENABLED=before;}
});
