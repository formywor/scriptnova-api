import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';

const ROOT='nebulaTtsSafety/v1';
const hash=value=>createHash('sha256').update(String(value)).digest('hex');
const hex=n=>randomBytes(n).toString('hex');
const safeEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===64&&b.length===64&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const issue=(code,status=400)=>Object.assign(Error(code),{code,status});

export function createTtsSafetyStore(db,{now=Date.now}={}){return {
 async ttsCreateSession(installationHash,ipHash,time=now()){
  const day=String(Math.floor(time/86400000)),rate=db.ref(ROOT+'/issuance/'+ipHash+'/'+day);
  const limited=await rate.transaction(old=>{if((old?.count||0)>=3)return;return {count:(old?.count||0)+1,expiresAt:(Number(day)+2)*86400000};},undefined,false);
  if(!limited.committed)throw issue('ANONYMOUS_SETUP_LIMIT',429);
  const id=hex(12),secret=hex(32),overlayToken=hex(32),key='nb_tts_'+id+'_'+secret,session={id,installationHash,secretHash:hash(key),overlayToken,createdAt:time,expiresAt:time+30*86400000,usage:{}};
  await db.ref(ROOT+'/sessions/'+id).set(session);
  await db.ref(ROOT+'/overlaySessions/'+overlayToken).set({sessionId:id,expiresAt:session.expiresAt});
  return {key,sessionId:id,overlayToken,expiresAt:session.expiresAt};
 },
 async ttsAuthenticate(key,time=now()){
  const m=typeof key==='string'&&key.match(/^nb_tts_([a-f0-9]{24})_([a-f0-9]{64})$/);if(!m)return null;
  const s=(await db.ref(ROOT+'/sessions/'+m[1]).get()).val();if(!s||s.expiresAt<=time||s.revokedAt||!safeEqual(s.secretHash,hash(key)))return null;
  return {id:s.id,owner:s.owner||null,ownerTier:s.ownerTier||'normal',createdAt:s.createdAt,expiresAt:s.expiresAt,overlayToken:s.overlayToken,aiEnabled:s.aiEnabled===true,model:s.model||'nebula-open'};
 },
 async ttsUse(id,time=now()){
  const ref=db.ref(ROOT+'/sessions/'+id);let remaining=0,resetsAt=null;
  const r=await ref.transaction(s=>{
   if(!s||s.expiresAt<=time||s.revokedAt)return;
   s.usage||={};const hour=Math.floor(time/3600000),start=hour-119;
   for(const h of Object.keys(s.usage))if(Number(h)<start)delete s.usage[h];
   const used=Object.values(s.usage).reduce((n,c)=>n+(Number(c)||0),0),usedHours=Object.keys(s.usage).filter(h=>Number(s.usage[h])>0).map(Number),nextReset=usedHours.length?(Math.min(...usedHours)+120)*3600000:null;if(used>=11000){remaining=0;resetsAt=nextReset;return;}
   s.usage[hour]=(s.usage[hour]||0)+1;remaining=10999-used;resetsAt=nextReset||((hour+120)*3600000);return s;
  },undefined,false);
  if(!r.committed){const s=r.snapshot.val();if(!s)throw issue('INVALID_TTS_KEY',401);if(s.expiresAt<=time||s.revokedAt)throw issue('INVALID_TTS_KEY',401);throw Object.assign(issue('TTS_LIMIT',429),{remaining,resetsAt});}
  return {remaining,resetsAt};
 },
 async ttsUsage(id,time=now()){
  const s=(await db.ref(ROOT+'/sessions/'+id).get()).val();if(!s||s.expiresAt<=time||s.revokedAt)throw issue('INVALID_TTS_KEY',401);
  const hour=Math.floor(time/3600000),start=hour-119,entries=Object.entries(s.usage||{}).filter(([h])=>Number(h)>=start&&Number(h)<=hour&&Number(h)>=0),used=entries.reduce((n,[,c])=>n+(Number(c)||0),0),usedHours=entries.filter(([,c])=>Number(c)>0).map(([h])=>Number(h));
  return {messages:used,limit:11000,remaining:Math.max(0,11000-used),windowHours:120,resetAt:usedHours.length?(Math.min(...usedHours)+120)*3600000:null,expiresAt:s.expiresAt,aiEnabled:s.aiEnabled===true,model:s.model||'nebula-open'};
 },
 async ttsAppendFlag(id,event,time=now()){
  const old=await db.ref(ROOT+'/events/'+id).orderByChild('expiresAt').endAt(time).limitToFirst(100).get();if(old.exists()){const remove={};for(const key of Object.keys(old.val()||{}))remove[ROOT+'/events/'+id+'/'+key]=null;await db.ref().update(remove);}
  const ref=db.ref(ROOT+'/events/'+id+'/'+event.eventId),record={...event,expiresAt:time+7*86400000};
  await ref.set(record);const s=(await db.ref(ROOT+'/sessions/'+id).get()).val();if(s?.owner)await db.ref(ROOT+'/ownerEvents/'+s.owner+'/'+id+'/'+event.eventId).set({at:event.at,expiresAt:record.expiresAt});
  return record;
 },
 async ttsClaim(id,owner,time=now(),ownerTier='normal'){
  const ref=db.ref(ROOT+'/sessions/'+id),r=await ref.transaction(s=>{if(!s||s.expiresAt<=time||s.revokedAt||s.owner&&s.owner!==owner)return;return {...s,owner,ownerTier,claimedAt:time};},undefined,false);
  if(!r.committed)throw issue('TTS_SESSION_CLAIM_FAILED',409);
  const s=r.snapshot.val();await db.ref(ROOT+'/ownerEvents/'+owner+'/'+id).set({claimedAt:time,sessionExpiresAt:s.expiresAt});return true;
 },
 async ttsOwnerEvents(owner,time=now()){
  const sessions=(await db.ref(ROOT+'/ownerEvents/'+owner).get()).val()||{},out=[];
  for(const [id,meta]of Object.entries(sessions)){if(meta?.sessionExpiresAt<=time)continue;const records=(await db.ref(ROOT+'/events/'+id).get()).val()||{};for(const [eventId,e]of Object.entries(records))if(e.expiresAt>time)out.push({...e,eventId});}
  return out.sort((a,b)=>b.at-a.at).slice(0,200);
 },
 async ttsSetPlus(owner,enabled,by,time=now(),expiresAt=null){
  await db.ref(ROOT+'/plus/'+owner).set({enabled:enabled===true,by,at:time,...(expiresAt?{expiresAt}:{} )});
 },
 async ttsHasPlus(owner,time=now()){
  if(!owner)return false;const g=(await db.ref(ROOT+'/plus/'+owner).get()).val();return g?.enabled===true&&(!g.expiresAt||g.expiresAt>time);
 },
 async ttsSettings(id,settings){
  const ref=db.ref(ROOT+'/sessions/'+id);let updated;
  const r=await ref.transaction(s=>{if(!s||s.expiresAt<=now()||s.revokedAt)return;updated={...s,aiEnabled:settings.aiEnabled,model:settings.model,updatedAt:settings.at};return updated;},undefined,false);
  if(!r.committed)throw issue('INVALID_TTS_KEY',401);return {aiEnabled:updated.aiEnabled,model:updated.model};
 },
 async ttsOverlayConfig(token,time=now()){
  const entry=(await db.ref(ROOT+'/overlaySessions/'+token).get()).val();if(!entry||entry.expiresAt<=time)return null;
  const session=(await db.ref(ROOT+'/sessions/'+entry.sessionId).get()).val();if(!session||session.revokedAt||session.expiresAt<=time||session.overlayToken!==token)return null;
  return {token,sessionId:session.id,expiresAt:session.expiresAt};
 },
 async ttsOverlayPublish(token,entry,time=now()){
  const ref=db.ref('nebulaTtsOverlay/v1/'+token+'/queue');
  await ref.transaction(old=>{const q=old||{};for(const [id,e]of Object.entries(q))if(!e||e.expiresAt<=time)delete q[id];q[entry.id]={...entry,expiresAt:time+120000};const ids=Object.keys(q).sort((a,b)=>(q[a]?.createdAt||0)-(q[b]?.createdAt||0));while(ids.length>20)delete q[ids.shift()];return q;},undefined,false);
 },
 async ttsOverlayAck(token,eventId){if(!/^[a-f0-9-]{36}$/i.test(eventId))throw issue('INVALID_EVENT_ID');await db.ref('nebulaTtsOverlay/v1/'+token+'/queue/'+eventId).remove();},
 async ttsOverlayRevoke(id,time=now()){
  const ref=db.ref(ROOT+'/sessions/'+id),old=(await ref.get()).val();if(!old)throw issue('INVALID_TTS_KEY',401);
  await ref.transaction(s=>s?{...s,revokedAt:time}:null,undefined,false);await db.ref(ROOT+'/overlaySessions/'+old.overlayToken).remove();await db.ref('nebulaTtsOverlay/v1/'+old.overlayToken).remove();
 }
};}
