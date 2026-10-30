import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {effectiveApiLimits} from './developer-benefits.mjs';
export const API_LIMITS=Object.freeze({keys:3,requestsPerMinute:6,requestsPerDay:100,tokensPerDay:50000,concurrent:1,maxMessages:40,maxOutputTokens:2048,maxInputBytes:16000,globalTokensPerMinute:8000,globalTokensPerDay:160000});
const hash=s=>createHash('sha256').update(s).digest('hex');
const fault=(code,status=429)=>Object.assign(Error(code),{code,status});
const metadata=({id,name,createdAt,status,prefix})=>({id,name,createdAt,status,prefix});
function windowAt(s,time){
 const day=Math.floor(time/86400000),minute=Math.floor(time/60000);
 if(!s||s.day!==day)s={day,requests:0,tokens:0,pending:s?.pending||{},...(s?{metrics:s.metrics||{},logs:s.logs||[],gift:s.gift||null}:{})};
 if(s.minute!==minute){s.minute=minute;s.minuteRequests=0;s.minuteTokens=0;}
 s.pending||={};for(const [id,p] of Object.entries(s.pending))if(time-p.at>120000)delete s.pending[id];return s;
}
function gifted(s,time){const g=s.gift?.expiresAt>time?s.gift:null;return {requests:Math.max(0,s.requests-(g?.day===s.day?g.requests:0)),tokens:Math.max(0,s.tokens-(g?.day===s.day?g.tokens:0)),minuteRequests:Math.max(0,s.minuteRequests-(g?.minute===s.minute?g.minuteRequests:0)),gift:g};}
function logRequest(s,entry,time){const day=String(Math.floor(time/86400000)),key=entry.keyId||'unknown';s.metrics||={};const row=s.metrics[day]||={};const m=row[key]||={requests:0,errors:0,tokens:0,totalMs:0};m.requests++;if(entry.status>=400)m.errors++;m.tokens+=entry.tokens||0;m.totalMs+=entry.durationMs||0;for(const d of Object.keys(s.metrics))if(Number(d)<Number(day)-13)delete s.metrics[d];s.logs=[...(s.logs||[]),entry].slice(-100);}
export function createDeveloperApiStore(db){const base='nebulaDeveloperApi/v1';return {
 async apiCreateKey(owner,name,time){
  const id=randomBytes(12).toString('hex'),secret='nb_live_'+id+'_'+randomBytes(32).toString('hex'),record={id,name,owner,secretHash:hash(secret),createdAt:time,status:'active',prefix:'nb_live_'+id.slice(0,8)+'…'};
  const ref=db.ref(base+'/accounts/'+owner+'/keys'),r=await ref.transaction(old=>{const keys=old||{};if(Object.values(keys).filter(k=>k.status==='active').length>=API_LIMITS.keys)return;keys[id]=metadata(record);return Object.fromEntries(Object.entries(keys).sort((a,b)=>b[1].createdAt-a[1].createdAt).slice(0,30));},undefined,false);
  if(!r.committed)throw fault('KEY_LIMIT',409);
  try{await db.ref(base+'/keys/'+id).set(record);}catch(e){await ref.transaction(old=>{if(old)delete old[id];return old;},undefined,false);throw e;}
  return {key:secret,...metadata(record)};
 },
 async apiKeys(owner){return Object.values((await db.ref(base+'/accounts/'+owner+'/keys').get()).val()||{}).map(metadata);},
 async apiRevokeKey(owner,id){
  const ref=db.ref(base+'/keys/'+id),existing=(await ref.get()).val();if(existing?.owner!==owner)throw fault('KEY_NOT_FOUND',404);
  const r=await ref.transaction(old=>{const key=old||existing;return key.owner===owner?{...key,status:'revoked'}:undefined;},undefined,false);if(!r.committed)throw fault('KEY_NOT_FOUND',404);
  await db.ref(base+'/accounts/'+owner+'/keys').transaction(old=>{if(old?.[id])old[id].status='revoked';return old;},undefined,false);
 },
 async apiAuthenticate(secret){
  const id=secret.match(/^nb_live_([a-f0-9]{24})_[a-f0-9]{64}$/)?.[1];if(!id)return null;
  const r=(await db.ref(base+'/keys/'+id).get()).val();if(!r||r.status!=='active'||typeof r.secretHash!=='string'||r.secretHash.length!==64)return null;
  return timingSafeEqual(Buffer.from(r.secretHash),Buffer.from(hash(secret)))?{id:r.id,owner:r.owner}:null;
 },
 async apiLimits(owner,time){return effectiveApiLimits(API_LIMITS,this.benefit?await this.benefit(owner,time):null,time);},
 async apiUsage(owner,time){const s=windowAt((await db.ref(base+'/usage/'+owner).get()).val(),time),g=gifted(s,time);return {requests:g.requests,tokens:g.tokens,totalRequestsToday:s.requests,totalTokensToday:s.tokens,gift:g.gift,pending:Object.keys(s.pending).length,dayResetsAt:(s.day+1)*86400000,limits:await this.apiLimits(owner,time),benefit:this.benefit?await this.benefit(owner,time):null};},
 async apiMetrics(owner,time,keyId='all'){const s=windowAt((await db.ref(base+'/usage/'+owner).get()).val(),time);return {days:Array.from({length:14},(_,i)=>{const day=Math.floor(time/86400000)-13+i,rows=Object.entries(s.metrics?.[day]||{}).filter(([k])=>keyId==='all'||k===keyId).map(([,r])=>r);return {day:day*86400000,requests:rows.reduce((n,r)=>n+r.requests,0),errors:rows.reduce((n,r)=>n+r.errors,0),tokens:rows.reduce((n,r)=>n+r.tokens,0),totalMs:rows.reduce((n,r)=>n+r.totalMs,0)};}),logs:(s.logs||[]).filter(r=>keyId==='all'||r.keyId===keyId).slice(-100).reverse(),retention:'14 days of metrics; last 100 request metadata records. Prompts and responses are not logged.'};},
 async apiLog(owner,entry,time){await db.ref(base+'/usage/'+owner).transaction(old=>{const s=windowAt(old,time);logRequest(s,entry,time);return s;},undefined,false);},
 async apiReserve(owner,id,time,tokens,meta={}){
  const limits=await this.apiLimits(owner,time);
  const reserve=async(scope,global)=>{let code='RATE_LIMITED';const r=await db.ref(base+'/usage/'+scope).transaction(old=>{const s=windowAt(old,time),pending=Object.values(s.pending),held=pending.reduce((n,p)=>n+p.tokens,0),minuteHeld=pending.filter(p=>Math.floor(p.at/60000)===s.minute).reduce((n,p)=>n+p.tokens,0);
   if(!global&&pending.length>=API_LIMITS.concurrent){code='CONCURRENT_LIMIT';return;}
   const g=gifted(s,time);if(!global&&(g.minuteRequests>=limits.requestsPerMinute||g.requests+pending.length>=limits.requestsPerDay))return;
   if((global?s.tokens:g.tokens)+held+tokens>(global?API_LIMITS.globalTokensPerDay:limits.tokensPerDay)){code='DAILY_TOKEN_LIMIT';return;}
   if(global&&s.minuteTokens+minuteHeld+tokens>API_LIMITS.globalTokensPerMinute){code='SERVICE_TOKEN_LIMIT';return;}
   s.minuteRequests++;s.pending[id]={tokens,at:time,keyId:meta.keyId||'unknown',model:meta.model||'unknown'};return s;
  },undefined,false);return {allowed:r.committed,code};};
  const global=await reserve('_service',true);if(!global.allowed)return global;const account=await reserve(owner,false);if(!account.allowed)await this.apiFinishScope('_service',id,time,false,0);return account;
 },
 async apiFinishScope(scope,id,time,success,tokens,result={}){await db.ref(base+'/usage/'+scope).transaction(old=>{const s=windowAt(old,time),p=s.pending[id];if(!p)return s;delete s.pending[id];if(success){s.requests++;s.tokens+=tokens;if(Math.floor(p.at/60000)===s.minute)s.minuteTokens+=tokens;}if(scope!=='_service')logRequest(s,{id,keyId:p.keyId||'unknown',model:p.model||'unknown',at:time,status:success?200:result.status||503,code:success?'OK':result.code||'MODEL_UNAVAILABLE',tokens:success?tokens:0,durationMs:Math.max(0,time-p.at)},time);return s;},undefined,false);},
 async apiFinish(owner,id,time,success,tokens,result={}){await this.apiFinishScope(owner,id,time,success,tokens,result);await this.apiFinishScope('_service',id,time,success,tokens,result);}
};}
