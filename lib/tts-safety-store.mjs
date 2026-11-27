import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';

const ROOT='nebulaTtsSafety/v1';
const hash=value=>createHash('sha256').update(String(value)).digest('hex');
const hex=n=>randomBytes(n).toString('hex');
const safeEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===64&&b.length===64&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const issue=(code,status=400)=>Object.assign(Error(code),{code,status});
const TTS_DEFAULTS={strictness:'balanced',allowOtherLanguages:false,allowEmoji:true,allowSlang:true,skipLinks:true,userCooldownSeconds:0,duplicateWindowSeconds:0,maxSpeechLength:280,allowWords:[],blockKeywords:[],alertMessage:'Moderators, please review a flagged chat message.',voiceURI:'',voiceName:'',voiceLang:'',voiceRate:1,voiceVolume:1};

export function createTtsSafetyStore(db,{now=Date.now}={}){return {
 async ttsCreateSession(installationHash,ipHash,time=now()){
  // Allow normal creators to refresh or recreate connections without a daily quota.
  // Keep only a short burst guard so the public endpoint cannot be hammered to fill RTDB.
  const rate=db.ref(ROOT+'/setupBurst/'+ipHash);let resetsAt=time+60000;
  const limited=await rate.transaction(old=>{const active=old&&Number(old.resetAt)>time?old:{count:0,resetAt:time+60000};resetsAt=Number(active.resetAt);if((active.count||0)>=10)return;return {...active,count:(active.count||0)+1};},undefined,false);
  if(!limited.committed)throw Object.assign(issue('SETUP_BURST_LIMIT',429),{resetsAt});
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
  const ref=db.ref(ROOT+'/sessions/'+id),hour=Math.floor(time/3600000),start=hour-119;
  let remaining=0,resetsAt=null,quotaReached=false;
  const countUsage=usage=>Object.entries(usage||{}).filter(([h])=>Number(h)>=start&&Number(h)<=hour).reduce((n,[,count])=>n+(Number(count)||0),0);
  // Warm this serverless instance's RTDB cache before starting the transaction.
  // If its first updater sees the default null cache, returning undefined would
  // abort before Firebase can reconcile the already-created session record.
  const initial=(await ref.get()).val();
  // Return a new record rather than mutating the RTDB transaction snapshot. The
  // Admin SDK may retry an updater; mutations can leak across retries and cause
  // an update to be treated as an aborted transaction.
  for(let attempt=0;attempt<3;attempt++){
   quotaReached=false;
   const r=await ref.transaction(current=>{
    // When a serverless instance has no local RTDB value, seed its first
    // transaction attempt from the read above instead of aborting on null.
    const state=current||initial;
    if(!state)return;
    if(state.expiresAt<=time||state.revokedAt)return;
    const usage={...(state.usage||{})};
    for(const h of Object.keys(usage))if(Number(h)<start)delete usage[h];
    const used=countUsage(usage),usedHours=Object.keys(usage).filter(h=>Number(usage[h])>0).map(Number),nextReset=usedHours.length?(Math.min(...usedHours)+120)*3600000:null;
    if(used>=11000){quotaReached=true;remaining=0;resetsAt=nextReset;return;}
    usage[hour]=(Number(usage[hour])||0)+1;
    remaining=11000-used-1;resetsAt=nextReset||((hour+120)*3600000);
    return {...state,usage};
   },undefined,false);
   if(r.committed)return {remaining,resetsAt};
   let current=r.snapshot.val();
   // A transaction may abort with an empty local snapshot while the record is
   // still readable from RTDB. Re-read before treating a live key as invalid.
   if(!current)current=(await ref.get()).val();
   if(!current||current.expiresAt<=time||current.revokedAt)throw issue('INVALID_TTS_KEY',401);
   if(quotaReached||countUsage(current.usage)>=11000){const usedHours=Object.keys(current.usage||{}).filter(h=>Number(current.usage[h])>0&&Number(h)>=start&&Number(h)<=hour).map(Number);remaining=0;resetsAt=usedHours.length?(Math.min(...usedHours)+120)*3600000:null;throw Object.assign(issue('TTS_LIMIT',429),{remaining,resetsAt});}
  }
  throw issue('TTS_STORAGE_BUSY',503);
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
  const ref=db.ref(ROOT+'/sessions/'+id),initial=(await ref.get()).val();if(!initial||initial.expiresAt<=time||initial.revokedAt)throw issue('TTS_CONNECTION_NOT_FOUND',404);if(initial.owner&&initial.owner!==owner)throw issue('TTS_CONNECTION_ALREADY_LINKED',409);
  if(initial.owner===owner&&initial.ownerTier===ownerTier){await db.ref(ROOT+'/ownerEvents/'+owner+'/'+id).set({claimedAt:initial.claimedAt||time,sessionExpiresAt:initial.expiresAt});return true;}
  let claimed=null;
  for(let attempt=0;attempt<3;attempt++){
   const result=await ref.transaction(current=>{const session=current||initial;if(!session||session.expiresAt<=time||session.revokedAt||session.owner&&session.owner!==owner)return;claimed={...session,owner,ownerTier,claimedAt:time};return claimed;},undefined,false);
   if(result.committed){claimed=result.snapshot.val();break;}
   let current=result.snapshot.val();if(!current)current=(await ref.get()).val();if(!current||current.expiresAt<=time||current.revokedAt)throw issue('TTS_CONNECTION_NOT_FOUND',404);if(current.owner&&current.owner!==owner)throw issue('TTS_CONNECTION_ALREADY_LINKED',409);
   if(attempt===2)throw issue('TTS_SESSION_CLAIM_FAILED',409);
  }
  await db.ref(ROOT+'/ownerEvents/'+owner+'/'+id).set({claimedAt:time,sessionExpiresAt:claimed.expiresAt});return true;
 },
 async ttsRecover(owner,time=now()){
  const linked=(await db.ref(ROOT+'/ownerEvents/'+owner).get()).val()||{};
  const candidates=[];
  for(const [id,meta]of Object.entries(linked)){
   if(!meta||Number(meta.sessionExpiresAt)<=time)continue;
   const session=(await db.ref(ROOT+'/sessions/'+id).get()).val();
   if(session?.owner===owner&&!session.revokedAt&&session.expiresAt>time)candidates.push({id,session});
  }
  candidates.sort((a,b)=>(Number(b.session.createdAt)||0)-(Number(a.session.createdAt)||0));
  const selected=candidates[0];if(!selected)throw issue('TTS_CONNECTION_NOT_FOUND',404);
  const secret=hex(32),key='nb_tts_'+selected.id+'_'+secret,ref=db.ref(ROOT+'/sessions/'+selected.id);let saved,initial=selected.session;
  for(let attempt=0;attempt<3;attempt++){
   const result=await ref.transaction(current=>{const session=current||initial;if(!session||session.owner!==owner||session.revokedAt||session.expiresAt<=time)return;saved={...session,secretHash:hash(key),credentialRotatedAt:time};return saved;},undefined,false);
   if(result.committed){saved=result.snapshot.val();break;}
   let current=result.snapshot.val();if(!current)current=(await ref.get()).val();if(!current||current.owner!==owner||current.revokedAt||current.expiresAt<=time)throw issue('TTS_CONNECTION_NOT_FOUND',404);
   if(attempt===2)throw issue('TTS_STORAGE_BUSY',503);
  }
  return {apiKey:key,overlayUrl:`https://scriptnovaa.com/tts-safety/overlay/#token=${saved.overlayToken}`,expiresAt:saved.expiresAt};
 },
 async ttsOwnerEvents(owner,time=now()){
  const sessions=(await db.ref(ROOT+'/ownerEvents/'+owner).get()).val()||{},out=[];
  for(const [id,meta]of Object.entries(sessions)){if(meta?.sessionExpiresAt<=time)continue;const records=(await db.ref(ROOT+'/events/'+id).get()).val()||{};for(const [eventId,e]of Object.entries(records))if(e.expiresAt>time)out.push({...e,eventId});}
  return out.sort((a,b)=>b.at-a.at).slice(0,200);
 },
 async ttsSetPlus(owner,enabled,by,time=now(),expiresAt=null){
  await db.ref(ROOT+'/plus/'+owner).set({enabled:enabled===true,by,at:time,...(expiresAt?{expiresAt}:{} )});
 },
 async ttsPreferences(owner){
  if(!owner)return {...TTS_DEFAULTS};
  const saved=(await db.ref(ROOT+'/preferences/'+owner).get()).val();
  return {...TTS_DEFAULTS,...(saved&&typeof saved==='object'?saved:{})};
 },
 async ttsSetPreferences(owner,settings,time=now()){
  await db.ref(ROOT+'/preferences/'+owner).set({...settings,updatedAt:time});return {...settings};
 },
 async ttsHasPlus(owner,time=now()){
  if(!owner)return false;const [g,billing,reward]=await Promise.all([db.ref(ROOT+'/plus/'+owner).get(),db.ref('nebulaBilling/v1/users/'+owner).get(),db.ref('nebulaPlusRewards/v1/'+owner).get()]);const grant=g.val(),plans=billing.val()?.plans||{},paid=plans['nebula-plus'];return grant?.enabled===true&&(!grant.expiresAt||grant.expiresAt>time)||paid?.status==='active'&&Number.isSafeInteger(paid.currentPeriodEnd)&&paid.currentPeriodEnd>time||reward.val()?.status==='active';
 },
 async ttsSpamGuard(id,username,text,settings={},time=now()){
  const cooldown=Math.max(0,Math.min(30,Number(settings.userCooldownSeconds)||0)),duplicate=Math.max(0,Math.min(60,Number(settings.duplicateWindowSeconds)||0));if(!cooldown&&!duplicate)return null;
  const viewer=hash(String(username||'viewer').normalize('NFKC').trim().toLowerCase()),message=hash(String(text).normalize('NFKC').trim().replace(/\s+/g,' ').toLowerCase()),ref=db.ref(ROOT+'/spamGuard/'+id);let reason=null;
  await ref.transaction(old=>{const state=old||{viewers:{},messages:{}},viewers={...(state.viewers||{})},messages={...(state.messages||{})},windowMs=Math.max(cooldown*1000,duplicate*1000);for(const [key,at]of Object.entries(viewers))if(time-Number(at)>windowMs)delete viewers[key];for(const [key,at]of Object.entries(messages))if(time-Number(at)>windowMs)delete messages[key];
   if(cooldown&&Number(viewers[viewer])&&time-Number(viewers[viewer])<cooldown*1000){reason='viewer_cooldown';return;}
   if(duplicate&&Number(messages[message])&&time-Number(messages[message])<duplicate*1000){reason='duplicate_message';return;}
   if(cooldown)viewers[viewer]=time;if(duplicate)messages[message]=time;
   const trim=map=>{const entries=Object.entries(map);if(entries.length<=2000)return map;entries.sort((a,b)=>Number(a[1])-Number(b[1]));return Object.fromEntries(entries.slice(-2000));};return {viewers:trim(viewers),messages:trim(messages),updatedAt:time};
  },undefined,false);return reason;
 },
 async ttsSettings(id,settings){
  const ref=db.ref(ROOT+'/sessions/'+id);let updated;
  const r=await ref.transaction(s=>{if(!s||s.expiresAt<=now()||s.revokedAt)return;updated={...s,aiEnabled:settings.aiEnabled,model:settings.model,updatedAt:settings.at};return updated;},undefined,false);
  if(!r.committed)throw issue('INVALID_TTS_KEY',401);return {aiEnabled:updated.aiEnabled,model:updated.model};
 },
 async ttsOverlayConfig(token,time=now()){
  const entry=(await db.ref(ROOT+'/overlaySessions/'+token).get()).val();if(!entry||entry.expiresAt<=time)return null;
  const session=(await db.ref(ROOT+'/sessions/'+entry.sessionId).get()).val();if(!session||session.revokedAt||session.expiresAt<=time||session.overlayToken!==token)return null;
  return {token,sessionId:session.id,expiresAt:session.expiresAt,owner:session.owner||null};
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
