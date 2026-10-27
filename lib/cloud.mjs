import {readWebpage,calculate} from './cloud-tools.mjs';
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {authenticate,accountKey} from './accounts.mjs';
import {cloudConfig,validateSchedule,connectionReady,scheduleReady,seal,unseal,email,fail,boundedJson,webSearch,weather} from './cloud-services.mjs';
import {createScheduledWeather,executeJob,taskResult} from './cloud-jobs.mjs';
export async function requestJson(request){if(!request.headers.get('content-type')?.startsWith('application/json'))fail('INVALID_INPUT');const r=request.body?.getReader();if(!r)fail('INVALID_INPUT');let n=0;const a=[];try{while(true){const {done,value}=await r.read();if(done)break;n+=value.length;if(n>8000){await r.cancel();fail('INVALID_INPUT',413);}a.push(value);}}finally{r.releaseLock();}try{const b=JSON.parse(Buffer.concat(a));if(!b||typeof b!=='object'||Array.isArray(b))fail('INVALID_INPUT');return b;}catch{fail('INVALID_INPUT');}}
export function createCloudHandler({getStore,verifyToken,config=cloudConfig(),now=Date.now,fetcher=fetch}){return async request=>{
 const u=new URL(request.url),origin=request.headers.get('origin'),p=u.pathname.replace('/api/nebula/cloud','');const headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(origin&&config.origins.includes(origin)?{'Access-Control-Allow-Origin':origin,Vary:'Origin'}:{})};const reply=(s,d)=>new Response(JSON.stringify(d),{status:s,headers});
 if(origin&&!config.origins.includes(origin))return reply(403,{code:'FORBIDDEN'});if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type,Idempotency-Key'}});
 try{
 const store=await getStore();
 if(p==='/dispatch'){
  if(request.method!=='POST')return reply(405,{code:'METHOD_NOT_ALLOWED'});const expected=Buffer.from('Bearer '+config.workerSecret),actual=Buffer.from(request.headers.get('authorization')||'');if(!scheduleReady(config)||actual.length!==expected.length||!timingSafeEqual(actual,expected))return reply(401,{code:'UNAUTHORIZED'});
  const b=await requestJson(request);if(!/^[a-f0-9]{64}$/.test(b.key||'')||!/^[-a-z0-9]{36}$/i.test(b.id||''))fail('INVALID_INPUT');return reply(200,await executeJob(store,b.key,b.id,config,now(),fetcher));
 }
 if(p==='/google/callback'){
  if(request.method!=='GET')return reply(405,{code:'METHOD_NOT_ALLOWED'});const state=u.searchParams.get('state'),code=u.searchParams.get('code');if(!/^[a-f0-9]{64}\.[\w-]{43}$/.test(state||''))fail('OAUTH_STATE_INVALID');const saved=await store.cloudTakeOAuth(state,now());if(!saved)fail('OAUTH_STATE_INVALID');if(!code||code.length>4000)fail('GOOGLE_CONSENT_CANCELLED');
  const d=await boundedJson('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:config.googleId,client_secret:config.googleSecret,code,code_verifier:saved.verifier,grant_type:'authorization_code',redirect_uri:config.apiBase+'/api/nebula/cloud/google/callback'})},fetcher);
  if(!d.refresh_token||!d.access_token||!String(d.scope||'').split(' ').includes('https://www.googleapis.com/auth/gmail.send'))fail('GOOGLE_SCOPE_MISSING');const user=await boundedJson('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:'Bearer '+d.access_token}},fetcher);if(!email(user.email)||user.email_verified!==true)fail('GOOGLE_ACCOUNT_INVALID');
  await store.cloudConnection(saved.key,{email:user.email,connectedAt:now(),encrypted:seal({refreshToken:d.refresh_token},config.encryptionKey)});
  return new Response(null,{status:303,headers:{Location:config.site+'/?nebulaGoogle=connected','Cache-Control':'no-store','Referrer-Policy':'no-referrer'}});
 }
 const identity=await authenticate(request,verifyToken);if(!identity)return reply(401,{code:'UNAUTHORIZED'});const key=accountKey(identity.uid);if(!await store.allow('cloud_'+key,now(),request.method==='GET'?'read':'write'))return reply(429,{code:'RATE_LIMITED'});
 if(p===''&&request.method==='GET'){let s=await store.cloudState(key);for(const j of Object.values(s.jobs||{}))if(['queued','dispatching'].includes(j.status)&&j.dueAt<now()-3600000)await store.cloudJob(key,j.id,old=>['queued','dispatching'].includes(old.status)&&old.dueAt<now()-3600000?{...old,status:'failed',error:'SCHEDULE_TOO_LATE'}:null);for(const j of Object.values(s.jobs||{}))if(['running','sending'].includes(j.status)&&j.leaseUntil<now())await store.cloudJob(key,j.id,old=>old.lease===j.lease&&old.leaseUntil<now()?{...old,status:'needs-attention',error:old.status==='sending'?'DELIVERY_UNCERTAIN':'TASK_INTERRUPTED'}:null);s=await store.cloudState(key);const c=await store.cloudGetConnection(key);return reply(200,{capabilities:{search:Boolean(config.searchKey||config.sparkKey),weather:true,readWebpage:true,calculator:true,runNow:true,assistant:Boolean(config.ultraKey),research:Boolean(config.searchKey||config.sparkKey),google:connectionReady(config),schedule:scheduleReady(config)},connection:c?{email:c.email,connectedAt:c.connectedAt}:null,jobs:Object.values(s.jobs||{}).map(({lease,queueId,...j})=>j).sort((a,b)=>b.createdAt-a.createdAt),notice:'Only listed connected tools are supported. No arbitrary website login or background browser.'});}
 if(p==='/google/connect'&&request.method==='POST'){
  if(!connectionReady(config))fail('GOOGLE_NOT_CONFIGURED',503);const state=key+'.'+randomBytes(32).toString('base64url'),verifier=randomBytes(48).toString('base64url');await store.cloudOAuth(state,{key,verifier,expires:now()+600000});const url=new URL('https://accounts.google.com/o/oauth2/v2/auth');url.search=new URLSearchParams({client_id:config.googleId,redirect_uri:config.apiBase+'/api/nebula/cloud/google/callback',response_type:'code',scope:'openid email https://www.googleapis.com/auth/gmail.send',access_type:'offline',prompt:'consent',state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});return reply(200,{url:url.href});
 }
 if(p==='/google'&&request.method==='DELETE'){const old=await store.cloudGetConnection(key);await store.cloudConnection(key,null);if(old)try{await fetcher('https://oauth2.googleapis.com/revoke',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({token:unseal(old.encrypted,config.encryptionKey).refreshToken}),redirect:'error',signal:AbortSignal.timeout(10000)});}catch{}return reply(200,{disconnected:true});}
 if(p==='/run'&&request.method==='POST'){
  const raw=await requestJson(request);if(!['reminder','assistant','research','weather'].includes(raw.kind)||Object.keys(raw).some(k=>!['kind','instructions','city','timezone'].includes(k)))fail('INVALID_INPUT');
  const v=validateSchedule({...raw,delivery:'workspace',runAt:new Date(now()+120000).toISOString(),timezone:raw.timezone||'UTC'},now());
  if(['assistant','research'].includes(v.kind)&&!await store.allow('cloud_generation_'+key,now()))fail('CLOUD_RATE_LIMITED',429);
  const id=randomBytes(16).toString('hex'),job={...v,id,createdAt:now(),dueAt:now(),leaseUntil:now()+120000,status:'running'};await store.cloudCreate(key,job);
  try{const result=v.kind==='weather'?await weather(v.city,fetcher):await taskResult(job,config,fetcher);if(result.needsLocationChoice)fail('LOCATION_AMBIGUOUS');const saved=await store.cloudJob(key,id,j=>({...j,status:'completed',completedAt:now(),result}));if(saved?.status!=='completed')fail('TASK_SAVE_FAILED',503);return reply(200,{result});}
  catch(e){await store.cloudJob(key,id,j=>({...j,status:'failed',error:/^[A-Z_]+$/.test(e.code||'')?e.code:'CLOUD_UNAVAILABLE'}));throw e;}
 }
 if(p==='/jobs'&&request.method==='POST')return reply(201,{job:await createScheduledWeather(store,key,await requestJson(request),config,now(),fetcher,request.headers.get('Idempotency-Key'))});
 const id=p.match(/^\/jobs\/([-a-z0-9]{36})$/i)?.[1];if(id&&request.method==='DELETE'){const job=await store.cloudJob(key,id,j=>['queued','dispatching'].includes(j.status)?{...j,status:'cancelled',cancelledAt:now()}:null);if(!job)fail('TASK_CANNOT_CANCEL',409);return reply(200,{job});}
 if(p==='/search'&&request.method==='POST')return reply(200,await webSearch((await requestJson(request)).query,config,fetcher));
 if(p==='/read'&&request.method==='POST')return reply(200,await readWebpage((await requestJson(request)).url));
 if(p==='/calculate'&&request.method==='POST')return reply(200,calculate((await requestJson(request)).expression));
 if(p==='/weather'&&request.method==='POST')return reply(200,await weather((await requestJson(request)).city,fetcher));
 return reply(404,{code:'NOT_FOUND'});
 }catch(e){return reply(e.status||503,{code:/^[A-Z_]+$/.test(e.code||'')?e.code:'CLOUD_UNAVAILABLE'});}
};}
