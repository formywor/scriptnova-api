import {randomUUID,createHash} from 'node:crypto';
import {fail,validateSchedule,scheduleReady,places,weatherAt,unseal,boundedJson} from './cloud-services.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
export function createCloudStore(db){const path=k=>`nebulaCloud/v1/${k}`,get=async p=>(await db.ref(p).get()).val();return {
 async cloudState(k){return await get(path(k))||{jobs:{}};},
 async cloudConnection(k,v){await db.ref(`nebulaCloudConnections/v1/${k}`).set(v);},
 async cloudGetConnection(k){return get(`nebulaCloudConnections/v1/${k}`);},
 async cloudOAuth(id,v){await db.ref(`nebulaCloudOAuth/v1/${id.split(".")[0]}`).set({...v,stateHash:hash(id)});},
 async cloudTakeOAuth(id,time){const r=await db.ref(`nebulaCloudOAuth/v1/${id.split(".")[0]}`).transaction(v=>{if(!v||v.stateHash!==hash(id)||v.used||v.expires<time)return;return {...v,used:true};},undefined,false);return r.committed?r.snapshot.val():null;},
 async cloudCreate(k,j){const r=await db.ref(path(k)).transaction(old=>{const s=old||{jobs:{}};s.jobs||={};if(s.jobs[j.id])return;const a=Object.values(s.jobs).filter(j=>['queued','dispatching','running','sending'].includes(j.status));if(a.length>=20)return;const done=Object.values(s.jobs).filter(j=>!a.includes(j)).sort((a,b)=>b.createdAt-a.createdAt);for(const j of done.slice(29))delete s.jobs[j.id];s.jobs[j.id]=j;return s;},undefined,false);if(!r.committed)fail('SCHEDULE_LIMIT',409);return j;},
 async cloudJob(k,id,fn){const r=await db.ref(path(k)).transaction(old=>{if(!old?.jobs?.[id])return;const v=fn(old.jobs[id]);if(!v)return;old.jobs[id]=v;return old;},undefined,false);return r.committed?r.snapshot.val().jobs[id]:null;}
};}
export async function createScheduledWeather(store,key,raw,c,time,f=fetch,idempotencyKey=null){
 if(!scheduleReady(c))fail('SCHEDULE_NOT_CONFIGURED',503);const v=validateSchedule(raw,time);if(idempotencyKey&&!/^[a-f0-9-]{36}$/i.test(idempotencyKey))fail('INVALID_INPUT');const existing=idempotencyKey?(await store.cloudState(key)).jobs?.[idempotencyKey]:null;if(existing){if(existing.city!==v.city||existing.recipient!==v.recipient||existing.dueAt!==v.dueAt||existing.timezone!==v.timezone)fail('IDEMPOTENCY_CONFLICT',409);return existing;}const connection=await store.cloudGetConnection(key);if(!connection)fail('CONNECTION_REQUIRED',409);
 const p=await places(v.city,f);if(!p.length)fail('LOCATION_NOT_FOUND');if(p.length!==1)fail('LOCATION_AMBIGUOUS');const l=p[0];if(!Number.isFinite(l.latitude)||!Number.isFinite(l.longitude))fail('LOCATION_NOT_FOUND');
 const job={...v,connectionEmail:connection.email,connectionCreatedAt:connection.connectedAt||0,id:idempotencyKey||randomUUID(),createdAt:time,status:'dispatching',location:{name:l.name,admin1:l.admin1||'',country:l.country||'',latitude:l.latitude,longitude:l.longitude},attempts:0};await store.cloudCreate(key,job);
 try{const target=c.apiBase+'/api/nebula/cloud/dispatch';const q=await boundedJson(c.queueBase+'/v2/publish/'+target,{method:'POST',headers:{Authorization:'Bearer '+c.queueToken,'Content-Type':'application/json','Upstash-Not-Before':String(Math.ceil(job.dueAt/1000)),'Upstash-Retries':'3','Upstash-Forward-Authorization':'Bearer '+c.workerSecret},body:JSON.stringify({key,id:job.id})},f);if(typeof q.messageId!=='string')fail('SCHEDULE_DISPATCH_FAILED',503);const saved=await store.cloudJob(key,job.id,j=>j.status==='dispatching'?{...j,status:'queued',queueId:q.messageId}:j);return saved;
 }catch(e){await store.cloudJob(key,job.id,j=>j.status==='dispatching'?{...j,status:'failed',error:'SCHEDULE_DISPATCH_FAILED'}:j);throw e;}
}
export async function executeJob(store,key,id,c,time,f=fetch){
 const lease=randomUUID(),job=await store.cloudJob(key,id,j=>{if(j.dueAt>time||['completed','cancelled','failed','needs-attention'].includes(j.status)||j.leaseUntil>time)return;if(j.status==='sending')return {...j,status:'needs-attention',error:'DELIVERY_UNCERTAIN'};if(j.attempts>=3)return {...j,status:'failed',error:'RETRY_LIMIT'};return {...j,status:'running',lease,leaseUntil:time+120000,attempts:j.attempts+1};});
 if(!job||job.status!=='running'||job.lease!==lease)return {handled:true};let sending=false;
 try{
  if(time-job.dueAt>3600000)fail('SCHEDULE_TOO_LATE');const saved=await store.cloudGetConnection(key);if(!saved)fail('CONNECTION_REQUIRED',409);if(saved.email!==job.connectionEmail||(saved.connectedAt||0)!==job.connectionCreatedAt)fail('CONNECTION_CHANGED',409);const refresh=unseal(saved.encrypted,c.encryptionKey).refreshToken;
  const tokens=await boundedJson('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:c.googleId,client_secret:c.googleSecret,refresh_token:refresh,grant_type:'refresh_token'})},f);if(!tokens.access_token)fail('CONNECTION_REQUIRED',409);
  const report=await weatherAt(job.location,f),u=report.units||{},v=report.current;
  const body=`Weather for ${report.location}\n\nTemperature: ${v.temperature_2m} ${u.temperature_2m||'C'}\nFeels like: ${v.apparent_temperature} ${u.apparent_temperature||'C'}\nWind: ${v.wind_speed_10m} ${u.wind_speed_10m||'km/h'}\nWeather code (WMO): ${v.weather_code}\nModel time: ${v.time}\n\nSource: https://open-meteo.com/\nCurrent conditions are model estimates.\nSent by your Nebula Schedule task.`;
  const raw=Buffer.from(`To: ${job.recipient}\r\nSubject: Nebula weather update\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\nMessage-ID: <nebula-${id}@scriptnovaa.com>\r\n\r\n${Buffer.from(body).toString('base64')}`).toString('base64url');
  // Persist the irreversible boundary before contacting Gmail. Unknown delivery is never auto-retried.
  if(!(await store.cloudGetConnection(key)))fail('CONNECTION_REQUIRED',409);
  if(!await store.cloudJob(key,id,j=>j.lease===lease&&j.status==='running'?{...j,status:'sending',result:report}:null))return {handled:true};sending=true;
  const sent=await boundedJson('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',{method:'POST',headers:{Authorization:'Bearer '+tokens.access_token,'Content-Type':'application/json'},body:JSON.stringify({raw})},f);if(!sent.id)fail('DELIVERY_UNCERTAIN',502);
  await store.cloudJob(key,id,j=>j.lease===lease?{...j,status:'completed',completedAt:Date.now(),gmailMessageId:sent.id,leaseUntil:0}:null);return {handled:true};
 }catch(e){await store.cloudJob(key,id,j=>j.lease===lease?{...j,status:sending?'needs-attention':'failed',error:sending?'DELIVERY_UNCERTAIN':/^[A-Z_]+$/.test(e.code||'')?e.code:'CLOUD_SERVICE_UNAVAILABLE',leaseUntil:0}:null);return {handled:true};}
}
