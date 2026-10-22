import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {cloudConfig,seal,unseal,validateSchedule,webSearch,weather} from '../lib/cloud-services.mjs';
import {createScheduledWeather,executeJob} from '../lib/cloud-jobs.mjs';
import {createCloudHandler} from '../lib/cloud.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {ultraReply,appearanceRequested} from '../lib/ultra.mjs';
const json=d=>new Response(JSON.stringify(d),{headers:{'Content-Type':'application/json'}}),time=Date.parse('2026-10-22T12:00:00Z'),key=accountKey('alice');
const config={...cloudConfig({}),googleId:'client',googleSecret:'secret',encryptionKey:Buffer.alloc(32,7).toString('base64'),queueToken:'queue-test',workerSecret:'w'.repeat(40),scheduleEnabled:true,searchKey:'search-test'};
const raw={city:'Richmond, Virginia, US',recipient:'example@example.test',runAt:'2026-10-22T15:00:00-04:00',timezone:'America/New_York'};
const location={name:'Richmond',admin1:'Virginia',country:'United States',country_code:'US',latitude:37.54,longitude:-77.43};
const forecast={current:{temperature_2m:21,apparent_temperature:20,wind_speed_10m:5,weather_code:0,time:'2026-10-22T15:00'},current_units:{temperature_2m:'°C',wind_speed_10m:'km/h'}};
function fixture(){const {db}=memoryDatabase();return createStore(db);}
const request=(path,method='GET',body,auth='alice')=>new Request('https://api.test/api/nebula/cloud'+path,{method,headers:{...(auth?{Authorization:'Bearer test.jwt.'+auth}:{}),'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
const appFor=(store,f=async()=>{throw Error('unexpected external call');})=>createCloudHandler({getStore:async()=>store,verifyToken:async t=>({uid:t.split('.').at(-1)}),config,now:()=>time,fetcher:f});
const connected=store=>store.cloudConnection(key,{email:'alice@example.test',encrypted:seal({refreshToken:'private-refresh'},config.encryptionKey)});
const external=(counts,{uncertain=false}={})=>async(url,init={})=>{url=String(url);if(url.includes('geocoding'))return json({results:[location]});if(url.includes('/v2/publish/')){counts.queue++;assert.ok(init.headers['Upstash-Not-Before']);return json({messageId:'queue-id'});}if(url.includes('oauth2.googleapis.com/token'))return json({access_token:'private-access'});if(url.includes('api.open-meteo.com'))return json(forecast);if(url.includes('gmail.googleapis.com')){counts.gmail++;assert.equal(init.headers.Authorization,'Bearer private-access');const message=Buffer.from(JSON.parse(init.body).raw,'base64url').toString();assert.match(message,/To: example@example.test/);if(uncertain)throw Error('connection lost after sending');return json({id:'gmail-message'});}throw Error('unexpected URL');};
test('schedule validates future absolute times, timezone and single recipient; secrets are authenticated-encrypted',()=>{
 assert.equal(validateSchedule(raw,time).dueAt,Date.parse('2026-10-22T19:00:00Z'));
 for(const b of [{...raw,recipient:'x@example.test\r\nBcc: victim@example.test'},{...raw,runAt:'2026-10-22T15:00'},{...raw,timezone:'Not/AZone'},{...raw,city:'x',html:'evil'}])assert.throws(()=>validateSchedule(b,time));
 const encrypted=seal({token:'private'},config.encryptionKey);assert.ok(!encrypted.includes('private'));assert.deepEqual(unseal(encrypted,config.encryptionKey),{token:'private'});assert.throws(()=>unseal(encrypted,Buffer.alloc(32,8).toString('base64')));
});
test('cloud workspace requires authentication and isolates tasks and connected credentials',async()=>{
 const store=fixture();await connected(store);await store.cloudCreate(key,{id:'task',createdAt:time,status:'completed'});const app=appFor(store);
 assert.equal((await app(request('','GET',null,null))).status,401);
 const a=await (await app(request(''))).json();assert.equal(a.connection.email,'alice@example.test');assert.equal(a.jobs.length,1);assert.ok(!JSON.stringify(a).includes('encrypted'));assert.ok(!JSON.stringify(a).includes('private-refresh'));
 const b=await (await app(request('','GET',null,'bob'))).json();assert.equal(b.jobs.length,0);assert.equal(b.connection,null);
});
test('Google consent uses PKCE, state is single-use and bounded to one active authorization per account',async()=>{
 const store=fixture(),app=appFor(store);const r=await app(request('/google/connect','POST',{}));const u=new URL((await r.json()).url);assert.equal(u.origin,'https://accounts.google.com');assert.equal(u.searchParams.get('code_challenge_method'),'S256');assert.equal(u.searchParams.get('access_type'),'offline');assert.match(u.searchParams.get('scope'),/gmail.send/);
 const state=u.searchParams.get('state');assert.equal(await store.cloudTakeOAuth(state+'x',time),null);assert.equal((await store.cloudTakeOAuth(state,time)).key,key);assert.equal(await store.cloudTakeOAuth(state,time),null);
 assert.equal((await app(request('/google/callback?state='+state+'&code=x','GET',null,null))).status,400);
});
test('OAuth callback stores only encrypted refresh token and never returns credentials to browser',async()=>{
 const store=fixture();const f=async u=>String(u).includes('oauth2.googleapis.com')?json({refresh_token:'refresh-secret',access_token:'access-secret',scope:'openid email https://www.googleapis.com/auth/gmail.send'}):json({email:'alice@example.test',email_verified:true});const app=appFor(store,f);
 const start=await (await app(request('/google/connect','POST',{}))).json(),state=new URL(start.url).searchParams.get('state');const r=await app(request('/google/callback?state='+state+'&code=x','GET',null,null));assert.equal(r.status,303);assert.ok(!r.headers.get('location').includes('secret'));const saved=await store.cloudGetConnection(key);assert.equal(unseal(saved.encrypted,config.encryptionKey).refreshToken,'refresh-secret');assert.ok(!JSON.stringify(saved).includes('refresh-secret'));
});
test('confirmed schedule uses durable queue, executes once, and disallows cross-account cancellation',async()=>{
 const store=fixture();await connected(store);const counts={queue:0,gmail:0},f=external(counts);const job=await createScheduledWeather(store,key,raw,config,time,f);assert.equal(job.status,'queued');assert.equal(counts.gmail,0);
 const app=appFor(store,f);assert.equal((await app(request('/jobs/'+job.id,'DELETE',null,'bob'))).status,409);
 await executeJob(store,key,job.id,config,job.dueAt,f);await executeJob(store,key,job.id,config,job.dueAt+200000,f);assert.equal(counts.gmail,1);assert.equal((await store.cloudState(key)).jobs[job.id].status,'completed');
});
test('cancelled and disconnected tasks do not send; ambiguous delivery is never retried',async()=>{
 const store=fixture();await connected(store);const counts={queue:0,gmail:0},f=external(counts,{uncertain:true});const j=await createScheduledWeather(store,key,raw,config,time,f);await executeJob(store,key,j.id,config,j.dueAt,f);await executeJob(store,key,j.id,config,j.dueAt+200000,f);assert.equal(counts.gmail,1);assert.equal((await store.cloudState(key)).jobs[j.id].status,'needs-attention');
 const cancelled=await createScheduledWeather(store,key,raw,config,time,f);await store.cloudJob(key,cancelled.id,j=>({...j,status:'cancelled'}));await executeJob(store,key,cancelled.id,config,cancelled.dueAt,f);assert.equal(counts.gmail,1);
 const disconnected=await createScheduledWeather(store,key,raw,config,time,f);await store.cloudConnection(key,null);await executeJob(store,key,disconnected.id,config,disconnected.dueAt,f);assert.equal(counts.gmail,1);assert.equal((await store.cloudState(key)).jobs[disconnected.id].error,'CONNECTION_REQUIRED');
});
test('dispatcher rejects missing worker authentication; lookup sanitizes links and keeps ambiguity explicit',async()=>{
 const store=fixture();assert.equal((await appFor(store)(request('/dispatch','POST',{key,id:'a'.repeat(36)}))).status,401);
 const data=await webSearch('test',config,async()=>json({web:{results:[{title:'Bad',url:'javascript:alert(1)'},{title:'Good',url:'https://example.test/',description:'<b>safe</b>'}]}}));assert.equal(data.results.length,1);assert.equal(data.results[0].description,'safe');
 const w=await weather('Springfield',async()=>json({results:[location,{...location,name:'Other'}]}));assert.equal(w.needsLocationChoice,true);
});
test('Ultra can dismiss the banner and uses cloud results before answering; no scheduled email is sent by the model',async()=>{
 assert.equal(appearanceRequested('light mode'),true);assert.equal(appearanceRequested('remove the message about being switched to Ultra'),true);
 let step=0,lookups=0;const result=await ultraReply([{role:'user',content:'Search the web for news.'}],{ultraKey:'test'},{cloud:{search:async()=>{lookups++;return {results:[{title:'Source',url:'https://example.test/',description:'A verified result.'}]};}},fetcher:async(_,init)=>{const b=JSON.parse(init.body);if(!step++)return json({choices:[{message:{tool_calls:[{id:'search1',function:{name:'search_web',arguments:'{"query":"news"}'}}]}}]});assert.equal(b.messages.at(-1).role,'tool');return json({choices:[{message:{content:'Here is the search result.'}}]});}});assert.equal(lookups,1);assert.equal(result.sources[0].url,'https://example.test/');
 const draft=await ultraReply([{role:'user',content:'Email weather later'}],{ultraKey:'test'},{cloud:{schedule:true,propose:async x=>x},fetcher:async()=>json({choices:[{message:{tool_calls:[{function:{name:'propose_weather_email',arguments:JSON.stringify(raw)}}]}}]})});assert.deepEqual(draft.scheduleDraft,raw);assert.match(draft.text,/Nothing has been scheduled/);
});

test('idempotency prevents repeated creation and changed payloads cannot reuse the same key',async()=>{const store=fixture();await connected(store);const counts={queue:0,gmail:0},f=external(counts),id='12345678-1234-1234-1234-123456789abc';const a=await createScheduledWeather(store,key,raw,config,time,f,id);const b=await createScheduledWeather(store,key,raw,config,time,f,id);assert.equal(a.id,b.id);assert.equal(counts.queue,1);await assert.rejects(createScheduledWeather(store,key,{...raw,recipient:'different@example.test'},config,time,f,id),e=>e.code==='IDEMPOTENCY_CONFLICT');});
