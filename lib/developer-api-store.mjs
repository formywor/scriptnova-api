import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
export const API_LIMITS=Object.freeze({keys:3,requestsPerMinute:6,requestsPerDay:100,tokensPerDay:50000,concurrent:1,maxOutputTokens:2048,maxInputBytes:16000,globalTokensPerMinute:8000,globalTokensPerDay:160000});
const hash=s=>createHash('sha256').update(s).digest('hex');
const fault=(code,status=429)=>Object.assign(Error(code),{code,status});
const metadata=({id,name,createdAt,status,prefix})=>({id,name,createdAt,status,prefix});
function windowAt(s,time){
 const day=Math.floor(time/86400000),minute=Math.floor(time/60000);
 if(!s||s.day!==day)s={day,requests:0,tokens:0,pending:{}};
 if(s.minute!==minute){s.minute=minute;s.minuteRequests=0;s.minuteTokens=0;}
 s.pending||={};for(const [id,p] of Object.entries(s.pending))if(time-p.at>120000)delete s.pending[id];return s;
}
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
 async apiUsage(owner,time){const s=windowAt((await db.ref(base+'/usage/'+owner).get()).val(),time);return {requests:s.requests,tokens:s.tokens,pending:Object.keys(s.pending).length,dayResetsAt:(s.day+1)*86400000,limits:API_LIMITS};},
 async apiReserve(owner,id,time,tokens){
  const reserve=async(scope,global)=>{let code='RATE_LIMITED';const r=await db.ref(base+'/usage/'+scope).transaction(old=>{const s=windowAt(old,time),pending=Object.values(s.pending),held=pending.reduce((n,p)=>n+p.tokens,0),minuteHeld=pending.filter(p=>Math.floor(p.at/60000)===s.minute).reduce((n,p)=>n+p.tokens,0);
   if(!global&&pending.length>=API_LIMITS.concurrent){code='CONCURRENT_LIMIT';return;}
   if(!global&&(s.minuteRequests>=API_LIMITS.requestsPerMinute||s.requests+pending.length>=API_LIMITS.requestsPerDay))return;
   if(s.tokens+held+tokens>(global?API_LIMITS.globalTokensPerDay:API_LIMITS.tokensPerDay)){code='DAILY_TOKEN_LIMIT';return;}
   if(global&&s.minuteTokens+minuteHeld+tokens>API_LIMITS.globalTokensPerMinute){code='SERVICE_TOKEN_LIMIT';return;}
   s.minuteRequests++;s.pending[id]={tokens,at:time};return s;
  },undefined,false);return {allowed:r.committed,code};};
  const global=await reserve('_service',true);if(!global.allowed)return global;const account=await reserve(owner,false);if(!account.allowed)await this.apiFinishScope('_service',id,time,false,0);return account;
 },
 async apiFinishScope(scope,id,time,success,tokens){await db.ref(base+'/usage/'+scope).transaction(old=>{const s=windowAt(old,time),p=s.pending[id];if(!p)return s;delete s.pending[id];if(success){s.requests++;s.tokens+=tokens;if(Math.floor(p.at/60000)===s.minute)s.minuteTokens+=tokens;}return s;},undefined,false);},
 async apiFinish(owner,id,time,success,tokens){await this.apiFinishScope(owner,id,time,success,tokens);await this.apiFinishScope('_service',id,time,success,tokens);}
};}
