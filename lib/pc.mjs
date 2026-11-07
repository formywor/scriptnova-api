import {redactCredentials} from './developer-tools.mjs';
import {randomBytes,randomUUID,createHash,timingSafeEqual} from 'node:crypto';
import {authenticate,accountKey} from './accounts.mjs';
import {cloudConfig,fail} from './cloud-services.mjs';
import {requestJson} from './cloud.mjs';

const digest=s=>createHash('sha256').update(s).digest('hex');
const clean=v=>{if(typeof v==='string')return redactCredentials(v);if(Array.isArray(v))return v.map(clean);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).filter(([k])=>!['cookie','cookies','authorization','password','headers','body'].includes(k.toLowerCase())).map(([k,x])=>[k,clean(x)]));return v??null;};
export const PC_CONNECTION_MS=30*86400000;
const UUID=/^[a-f0-9-]{36}$/i;
export const PC_WRITE_ACTIONS=['click','type','press','select_option','set_checked'];
export function pcApprovalRequired(command,target,mode='ask'){if(!PC_WRITE_ACTIONS.includes(command.action))return false;if(mode==='ask')return true;const label=target?.label||'',url=target?.url||'';if(/delete|remove|erase|trash|purchase|buy|pay|checkout|transfer|withdraw|password|security|permission|authorize|subscription|unsubscribe|accept.*terms|sign.*contract/i.test(label+' '+url))return true;if(mode==='auto'&&(/send|submit|publish|post|invite|confirm|save|apply|agree|accept/i.test(label)||command.action==='press'&&command.args.key==='Enter'))return true;return !['auto','full'].includes(mode);}
const terminal=new Set(['completed','failed','canceled','interrupted']);
export function pcJobView(job,time){if(!job)return null;if(!terminal.has(job.status)&&(job.expiresAt<time||job.status==='running'&&job.leaseUntil<time))return {...job,status:'interrupted',error:'PC_ACTION_INTERRUPTED'};return job;}
export function pcUrl(value){let u;try{u=new URL(value);}catch{fail('PC_URL_BLOCKED');}if(u.protocol!=='https:'||u.username||u.password||u.port&&u.port!=='443'||u.href.length>2000||/^(?:localhost|.*\.(?:local|internal)|(?:\d{1,3}\.){3}\d{1,3}|\[.*\])$/.test(u.hostname)||/(?:^|\.)(?:scriptnovaa\.com)$/.test(u.hostname)||[...u.searchParams.keys()].some(k=>/^(?:token|key|api_key|password|secret|code|access_token)$/i.test(k)))fail('PC_URL_BLOCKED');return u.href;}
export function pcCommand(action,args={}){
 if(!['inspect','tabs','open_tabs','navigate','select_tab','click','type','scroll','press','page_status','wait_for_page','find_text','hover','select_option','set_checked'].includes(action)||!args||Array.isArray(args)||typeof args!=='object')fail('INVALID_PC_ACTION');
 const keys={inspect:['tabId','query'],page_status:['tabId'],wait_for_page:['tabId','text','timeoutMs'],find_text:['tabId','text'],open_tabs:['count'],hover:['tabId','snapshotId','elementId'],select_option:['tabId','snapshotId','elementId','value'],set_checked:['tabId','snapshotId','elementId','checked'],tabs:[],navigate:['url','newTab'],select_tab:['tabId'],click:['tabId','snapshotId','elementId'],type:['tabId','snapshotId','elementId','text'],scroll:['tabId','direction'],press:['tabId','snapshotId','elementId','key']}[action];if(Object.keys(args).some(k=>!keys.includes(k)))fail('INVALID_PC_ACTION');
 if(args.query!==undefined&&(typeof args.query!=='string'||args.query.length>100))fail('INVALID_PC_ACTION');
 if(args.tabId!==undefined&&(!Number.isSafeInteger(args.tabId)||args.tabId<0))fail('INVALID_PC_ACTION');
 if(action==='open_tabs'&&(!Number.isInteger(args.count)||args.count<1||args.count>8))fail('INVALID_PC_ACTION');
 if(action==='navigate'){pcUrl(args.url);if(args.newTab!==undefined&&typeof args.newTab!=='boolean')fail('INVALID_PC_ACTION');}
 if(action==='select_tab'&&args.tabId===undefined)fail('INVALID_PC_ACTION');
 if([...PC_WRITE_ACTIONS,'hover'].includes(action)&&(!UUID.test(args.snapshotId||'')||!/^e\d{1,3}$/.test(args.elementId||'')))fail('INVALID_PC_ACTION');
 if(action==='type'&&(typeof args.text!=='string'||args.text.length>4000||/\b(?:gsk_|hf_|sk-|AIza|AQ\.)[A-Za-z0-9_-]{18,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(args.text)))fail('PC_SENSITIVE_INPUT_BLOCKED');
 if(action==='scroll'&&!['up','down'].includes(args.direction))fail('INVALID_PC_ACTION');
 if(action==='press'&&!['Enter','Tab','Escape','ArrowDown','ArrowUp','Space'].includes(args.key))fail('INVALID_PC_ACTION');
 if(action==='find_text'&&(typeof args.text!=='string'||!args.text.trim()||args.text.length>100))fail('INVALID_PC_ACTION');
 if(action==='select_option'&&(typeof args.value!=='string'||args.value.length>500)||action==='set_checked'&&typeof args.checked!=='boolean'||action==='wait_for_page'&&(args.text!==undefined&&(typeof args.text!=='string'||args.text.length>100)||args.timeoutMs!==undefined&&(!Number.isInteger(args.timeoutMs)||args.timeoutMs<500||args.timeoutMs>10000)))fail('INVALID_PC_ACTION');
 return {action,args,requiresApproval:PC_WRITE_ACTIONS.includes(action)};
}
export function createPcStore(db){
 const device=id=>db.ref('nebulaPc/v1/devices/'+id),index=key=>db.ref('nebulaPc/v1/accounts/'+key);
 async function change(id,fn){const r=await device(id).transaction(old=>{if(!old)return null;return fn(old);},undefined,false);if(!r.committed||!r.snapshot.val())fail('PC_ACTION_CONFLICT',409);return r.snapshot.val();}
 return {
  async pcStart(name,time,protocolVersion=1){const id=randomUUID(),token=randomBytes(32).toString('base64url'),code=randomBytes(7).toString('hex').toUpperCase();await device(id).set({id,name,protocolVersion,tokenHash:digest(token),pairExpires:time+600000,expiresAt:0,createdAt:time,jobs:{},issued:0});await db.ref('nebulaPc/v1/pairs/'+digest(code)).set({id,expiresAt:time+600000});return {deviceId:id,token,code,protocolVersion,pairExpires:time+600000};},
  async pcUpgrade(id,time,version=3){return change(id,d=>{if(!d.ownerKey||d.revoked||d.expiresAt<time)return;return {...d,protocolVersion:Math.max(d.protocolVersion||1,version)};});},
  async pcDevice(id){return (await device(id).get()).val();},
  async pcPair(code,key,time,sessionDays){const pair=(await db.ref('nebulaPc/v1/pairs/'+digest(code)).get()).val();if(!pair||pair.expiresAt<time)fail('PC_PAIR_EXPIRED',410);const entry=await this.pcDevice(pair.id);if(!entry||entry.ownerKey||entry.pairExpires<time)fail('PC_PAIR_EXPIRED',410);if(sessionDays===30&&entry.protocolVersion<2)fail('PC_EXTENSION_UPDATE_REQUIRED',409);const duration=sessionDays===30?PC_CONNECTION_MS:3600000;
   const slot=await index(key).transaction(old=>{const v=old||{};const active=Object.fromEntries(Object.entries(v).filter(([,d])=>d.expiresAt>time));if(active[pair.id]||Object.keys(active).length>=3)return;return {...active,[pair.id]:{id:pair.id,expiresAt:time+duration}};},undefined,false);if(!slot.committed)fail('PC_DEVICE_LIMIT',409);
   try{return await change(pair.id,d=>{if(d.ownerKey||d.pairExpires<time)return;return {...d,ownerKey:key,pairedAt:time,expiresAt:time+duration};});}catch(e){await index(key).transaction(old=>{if(old)delete old[pair.id];return old;},undefined,false);throw e;}
  },
  async pcList(key){const refs=(await index(key).get()).val()||{};const ids=Object.values(refs).sort((a,b)=>b.expiresAt-a.expiresAt).slice(0,6).map(d=>d.id);return (await Promise.all(ids.map(id=>this.pcDevice(id)))).filter(d=>d?.ownerKey===key);},
  async pcRevoke(id,key,time){const value=await change(id,d=>{if(d.ownerKey!==key)return;return {...d,revoked:true,expiresAt:time,jobs:Object.fromEntries(Object.entries(d.jobs||{}).map(([id,j])=>[id,terminal.has(j.status)?j:{...j,status:'canceled',error:'PC_STOPPED',updatedAt:time}]))};});await index(key).transaction(old=>old?.[id]?{...old,[id]:{...old[id],expiresAt:time}}:old,undefined,false);return value;},
  async pcQueue(id,key,command,tag,time){const requested=command;return change(id,d=>{let command={...requested};if(d.ownerKey!==key||d.revoked||d.expiresAt<time||time-(d.lastSeen||0)>65000)return;if(d.jobs?.[tag])return d;const issueWindow=Math.floor(time/3600000),issued=d.issueWindow===issueWindow?d.issued||0:0;if(issued>=120||Object.values(d.jobs||{}).filter(j=>!terminal.has(j.status)).length>=3)return;if(command.requiresApproval||command.action==='hover'){const observed=Object.values(d.jobs||{}).find(j=>j.status==='completed'&&j.action==='inspect'&&j.result?.snapshotId===command.args.snapshotId&&time-j.updatedAt<180000),element=observed?.result?.elements?.find(e=>e.id===command.args.elementId);if(!element||command.args.tabId!==undefined&&command.args.tabId!==observed.result.tabId)return;command={...command,args:{...command.args,tabId:observed.result.tabId},target:{url:observed.result.url,label:element.label,role:element.role}};if(command.requiresApproval)command={...command,requiresApproval:pcApprovalRequired(command,command.target,d.approvalMode),...(!pcApprovalRequired(command,command.target,d.approvalMode)?{approvedAt:time,approvalSource:d.approvalMode}:{})};}const jobs=Object.fromEntries(Object.entries(d.jobs||{}).sort((a,b)=>b[1].createdAt-a[1].createdAt).slice(0,19));jobs[tag]={id:tag,...command,status:command.requiresApproval?'awaiting-approval':'queued',createdAt:time,expiresAt:time+180000,updatedAt:time};return {...d,issued:issued+1,issueWindow,jobs,cursorTask:{id:(command.chatId||'')+':'+(command.turnId||''),status:'active',modelId:command.modelId||'nebula-ultra'}};});},
  async pcTaskFinish(id,key,taskId,status,time){return change(id,d=>{if(d.ownerKey!==key||d.revoked||d.expiresAt<time)return;if(d.cursorTask?.id!==taskId)return d;return {...d,cursorTask:{...d.cursorTask,status,updatedAt:time}};});},
  async pcDecision(id,key,jobId,approve,time){return change(id,d=>{const j=d.jobs?.[jobId];if(d.ownerKey!==key||d.revoked||d.expiresAt<time||!j||j.status!=='awaiting-approval'||j.expiresAt<time)return;return {...d,...(!approve&&d.cursorTask?.id===(j.chatId||'')+':'+(j.turnId||'')?{cursorTask:{...d.cursorTask,status:'canceled',updatedAt:time}}:{}),jobs:{...d.jobs,[jobId]:{...j,status:approve?'queued':'canceled',error:approve?null:'PC_USER_DECLINED',approvedAt:approve?time:null,approvalSource:approve?'user':null,updatedAt:time}}};});},
  async pcPolicy(id,key,mode,time){if(!['ask','auto','full'].includes(mode))fail('INVALID_INPUT');return change(id,d=>{if(d.ownerKey!==key||d.revoked||d.expiresAt<time)return;const jobs={...d.jobs};for(const [id,j]of Object.entries(jobs)){if(j.status==='queued'&&['auto','full'].includes(j.approvalSource)&&pcApprovalRequired(j,j.target,mode))jobs[id]={...j,status:'awaiting-approval',requiresApproval:true,approvedAt:null,approvalSource:null};}return {...d,approvalMode:mode,policyChangedAt:time,jobs};});},
  async pcPoll(id,time){let claimed=null;const d=await change(id,d=>{claimed=null;if(!d.ownerKey||d.revoked||d.expiresAt<time)return;const jobs={...d.jobs};for(const [id,j]of Object.entries(jobs)){if(!terminal.has(j.status)&&(j.expiresAt<time||j.status==='running'&&j.leaseUntil<time))jobs[id]={...j,status:'interrupted',error:'PC_ACTION_INTERRUPTED',updatedAt:time};}
   if(!Object.values(jobs).some(j=>j.status==='running')){const j=Object.values(jobs).find(j=>j.status==='queued');if(j){claimed=j.id;jobs[j.id]={...j,status:'running',lease:randomUUID(),leaseUntil:time+45000,updatedAt:time};}}return {...d,lastSeen:time,jobs};});return {expiresAt:d.expiresAt,task:d.cursorTask||null,job:claimed?d.jobs[claimed]:null};},
  async pcResult(id,jobId,lease,result,error,time){return change(id,d=>{const j=d.jobs?.[jobId];if(!j||d.revoked||d.expiresAt<time)return;if(terminal.has(j.status))return d;if(j.status!=='running'||j.lease!==lease||j.leaseUntil<time)return;return {...d,lastSeen:time,jobs:{...d.jobs,[jobId]:{...j,status:error?'failed':'completed',result:clean(result)||null,error:error||null,updatedAt:time}}};});},
 };
}
export function pcView(d,time=Date.now()){return {id:d.id,name:d.name,protocolVersion:d.protocolVersion||1,approvalMode:d.approvalMode||'ask',expiresAt:d.expiresAt,online:!d.revoked&&d.expiresAt>time&&time-(d.lastSeen||0)<65000,revoked:!!d.revoked,jobs:Object.values(d.jobs||{}).sort((a,b)=>b.createdAt-a.createdAt).slice(0,20).map(job=>{const {lease,...view}=pcJobView(job,time);return view;})};}
export async function pcOwnerDevice(store,id,key,time=Date.now()){if(!UUID.test(id||''))fail('PC_NOT_CONNECTED',409);const d=await store.pcDevice(id);if(!d||d.ownerKey!==key)fail('PC_NOT_CONNECTED',404);if(d.revoked||d.expiresAt<time)fail('PC_SESSION_EXPIRED',410);return d;}
export function pcTools(store,key,id,{now=Date.now,signal,turnTag='task',modelId='nebula-ultra',wait=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 let resumedTab=false;
 return {async run(action,raw,{mailIntent,preferExistingTab=false,continueDraft=false}={}){let args;try{args=typeof raw==='string'?JSON.parse(raw):raw;}catch{fail('INVALID_PC_ACTION');}
  const d=await pcOwnerDevice(store,id,key,now());if(now()-(d.lastSeen||0)>65000)fail('PC_OFFLINE',409);if(action==='open_tabs'&&d.protocolVersion<4||['page_status','wait_for_page','find_text','hover','select_option','set_checked'].includes(action)&&d.protocolVersion<3)fail('PC_EXTENSION_UPDATE_REQUIRED',409);const [chatId,turnId='']=turnTag.split(':');
  if(mailIntent&&preferExistingTab&&!resumedTab&&action==='navigate'&&args?.newTab&&/^https:\/\/mail\.google\.com(?:\/|$)/i.test(args.url||'')){
   const prior=Object.values(d.jobs||{}).filter(job=>job.chatId===chatId&&job.status==='completed'&&/^https:\/\/mail\.google\.com(?:\/|$)/i.test(job.result?.url||job.target?.url||'')&&Number.isSafeInteger(job.result?.tabId??job.args?.tabId)).sort((a,b)=>Number(PC_WRITE_ACTIONS.includes(b.action))-Number(PC_WRITE_ACTIONS.includes(a.action))||b.updatedAt-a.updatedAt)[0];
   if(prior){resumedTab=true;action='inspect';args={tabId:prior.result?.tabId??prior.args.tabId};}
  }
  const recent=Object.values(d.jobs||{}).filter(job=>job.chatId===chatId&&job.turnId===turnId&&(job.status==='completed'||job.status==='failed'&&['PC_STALE_SNAPSHOT','PC_TAB_NOT_APPROVED'].includes(job.error))).sort((a,b)=>a.updatedAt-b.updatedAt);
  const changesPage=job=>job.status==='failed'||[...PC_WRITE_ACTIONS,'navigate','select_tab','scroll'].includes(job.action);
  if(args&&[...PC_WRITE_ACTIONS,'hover'].includes(action)&&args.snapshotId===undefined&&/^e\d{1,3}$/.test(args.elementId||'')){
   const snapshot=recent.slice(recent.findLastIndex(changesPage)+1).findLast(job=>job.status==='completed'&&job.action==='inspect'&&(args.tabId===undefined||args.tabId===job.result?.tabId))?.result;
   if(snapshot?.elements?.some(element=>element.id===args.elementId))args={...args,snapshotId:snapshot.snapshotId};
  }
  let command;
  try{command=pcCommand(action,args);}
  catch(error){
   if(error.code==='INVALID_PC_ACTION')error.repair='Use the documented action name and its arguments object only. For click or type, inspect the target control and supply its exact e-number elementId and snapshotId. For type, include text. Do not supply labels, selectors, role names or extra fields as action arguments.';
   throw error;
  }
  args=command.args;
  // Identical reads can be reused until an intervening action changes the page or its active snapshot.
  const anchor=['inspect','tabs','find_text','page_status','wait_for_page'].includes(action)?recent.findLast(job=>
   changesPage(job)||
   action==='inspect'&&job.action==='inspect'&&(job.args?.query!==args.query||job.args?.tabId!==args.tabId)
  ):null;
  const tag=digest(turnTag+JSON.stringify(command)+(anchor?.id||'')).slice(0,32);
  if(mailIntent&&['click','press'].includes(action)){
   const jobs=Object.values(d.jobs||{});
   const snapshot=jobs.find(job=>job.action==='inspect'&&job.status==='completed'&&job.result?.snapshotId===args.snapshotId)?.result;
   const label=snapshot?.elements?.find(element=>element.id===args.elementId)?.label||'';
   const mailUrl=/^https:\/\/mail\.google\.com(?:\/|$)/i;
   const control=/^(compose|send)(?:\b|$)/i.exec(label)?.[1].toLowerCase();
   if(control&&mailUrl.test(snapshot?.url||'')){
    if(control==='compose'&&continueDraft)throw Object.assign(Error('INVALID_PC_ACTION'),{code:'INVALID_PC_ACTION',repair:'The user asked to send the existing draft. Do not click Compose, create another draft or type the message again. Inspect the existing compose dialog, verify recipient and body against the user request, then use its Send control. If the existing draft cannot be identified, ask the user which draft to use.'});
    if(control==='send'&&mailIntent==='draft')fail('PC_EMAIL_DRAFT_ONLY',409);
    const previous=jobs.find(job=>job.id!==tag&&job.chatId===chatId&&job.turnId===turnId&&['click','press'].includes(job.action)&&mailUrl.test(job.target?.url||'')&&new RegExp('^'+control+'\\b','i').test(job.target?.label||'')&&!['failed','canceled'].includes(job.status));
    if(previous){const prior=pcJobView(previous,now());return {jobId:prior.id,status:prior.status,result:prior.result||null,error:prior.error||null,deduplicated:true,notice:'This Gmail control already has an action. Inspect the existing compose window or delivery confirmation before proceeding.'};}
   }
  }
  command={...command,modelId,chatId,turnId};const queued=await store.pcQueue(id,key,command,tag,now()),job=queued.jobs[tag];if(job.status==='awaiting-approval')return {jobId:tag,status:'awaiting-approval',notice:'This action has not executed. The user must approve this exact action in the PC panel. Stop here and explain what needs approval.'};
   for(let n=0;n<(['navigate','wait_for_page','inspect','find_text'].includes(action)?44:30);n++){signal?.throwIfAborted();const current=await pcOwnerDevice(store,id,key,now()),j=pcJobView(current.jobs?.[tag],now());if(terminal.has(j?.status))return {jobId:tag,status:j.status,...(j.result?{result:j.result}:{}),...(j.error?{error:j.error}:{})};await wait(500);}return {jobId:tag,status:'queued',notice:'Waiting for the computer. Do not repeat this action. Check pc_action_result or use Continue from the PC panel.'};},
  async result(jobId){if(!/^[a-f0-9]{32}$/.test(jobId||''))fail('INVALID_PC_ACTION');for(let n=0;n<17;n++){signal?.throwIfAborted();const d=await pcOwnerDevice(store,id,key,now()),j=pcJobView(d.jobs?.[jobId],now());if(!j)fail('PC_ACTION_NOT_FOUND',404);if(terminal.has(j.status)||j.status==='awaiting-approval'||n===16)return {jobId,status:j.status,result:j.result||null,error:j.error||null,notice:'Only completed results establish that an action occurred. Awaiting approval is not completion.'};await wait(500);}}
 };
}
export function createPcHandler({getStore,verifyToken,config=cloudConfig(),now=Date.now}={}){return async request=>{
 const path=new URL(request.url).pathname.replace('/api/nebula/pc',''),origin=request.headers.get('origin'),agentPath=path.startsWith('/agent/')||path==='/pair/start';const allowed=origin&&config.origins.includes(origin)||agentPath&&/^chrome-extension:\/\/[a-p]{32}$/.test(origin||'');const headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(allowed?{'Access-Control-Allow-Origin':origin,Vary:'Origin'}:{})};const reply=(status,data)=>new Response(JSON.stringify(data),{status,headers});
 if(origin&&!allowed)return reply(403,{code:'FORBIDDEN'});if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type'}});
 try{const store=await getStore();
  if(path==='/pair/start'&&request.method==='POST'){const ip=request.headers.get('x-forwarded-for')?.split(',')[0]||'unknown';if(!await store.allow('pc_pair_'+digest(ip),now(),'write'))fail('RATE_LIMITED',429);const b=await requestJson(request);if(typeof b.name!=='string'||b.name.length<1||b.name.length>60||/[\x00-\x1f]/.test(b.name))fail('INVALID_INPUT');if(b.protocolVersion!==undefined&&![2,3,4].includes(b.protocolVersion))fail('INVALID_INPUT');return reply(201,await store.pcStart(b.name.trim(),now(),b.protocolVersion||1));}
  if(path.startsWith('/agent/')){const match=path.match(/^\/agent\/([a-f0-9-]{36})\/(status|poll|result|validate|stop|upgrade)$/i);if(!match)fail('NOT_FOUND',404);const [,id,op]=match,d=await store.pcDevice(id),token=request.headers.get('authorization')?.replace(/^Bearer /,'')||'';const a=Buffer.from(d?.tokenHash||''),b=Buffer.from(digest(token));if(!d||a.length!==b.length||!timingSafeEqual(a,b))fail('UNAUTHORIZED',401);if(d.revoked||d.ownerKey&&d.expiresAt<now()||!d.ownerKey&&d.pairExpires<now())fail('PC_SESSION_EXPIRED',410);
   if(op==='status'&&request.method==='GET')return reply(200,{paired:!!d.ownerKey,expiresAt:d.expiresAt,name:d.name});if(!d.ownerKey)fail('PC_PAIR_PENDING',409);
   if(!await store.allow('pc_agent_'+id,now(),request.method==='GET'?'read':'write'))fail('RATE_LIMITED',429);
   if(op==='upgrade'&&request.method==='POST'){const b=await requestJson(request);if(![3,4].includes(b.protocolVersion))fail('INVALID_INPUT');const updated=await store.pcUpgrade(id,now(),b.protocolVersion);return reply(200,{protocolVersion:updated.protocolVersion,expiresAt:d.expiresAt});}
   if(op==='poll'&&request.method==='POST')return reply(200,await store.pcPoll(id,now()));
   if(op==='stop'&&request.method==='POST'){await store.pcRevoke(id,d.ownerKey,now());return reply(200,{stopped:true});}
   if(op==='validate'&&request.method==='POST'){const b=await requestJson(request),j=d.jobs?.[b.jobId];if(!j||j.status!=='running'||j.lease!==b.lease||j.leaseUntil<now())fail('PC_STOPPED',409);return reply(200,{valid:true});}
   if(op==='result'&&request.method==='POST'){const b=await requestJson(request);if(!/^[a-f0-9]{32}$/.test(b.jobId||'')||!UUID.test(b.lease||'')||b.error&& !/^[A-Z_]{1,70}$/.test(b.error))fail('INVALID_PC_RESULT');if(JSON.stringify(b.result||{}).length>50000)fail('PC_RESULT_TOO_LARGE',413);await store.pcResult(id,b.jobId,b.lease,clean(b.result||null),b.error,now());return reply(200,{saved:true});}fail('METHOD_NOT_ALLOWED',405);
  }
  const identity=await authenticate(request,verifyToken);if(!identity)fail('UNAUTHORIZED',401);if(identity.email_verified!==true)fail('EMAIL_VERIFICATION_REQUIRED',403);const key=accountKey(identity.uid);if(!await store.allow('pc_account_'+key,now(),request.method==='GET'?'read':'write'))fail('RATE_LIMITED',429);
  if(path===''&&request.method==='GET')return reply(200,{devices:(await store.pcList(key)).map(d=>pcView(d,now())),sessionDays:30,sessionMinutes:43200,approvalPolicy:'Ask for Approval is the default. The account owner can choose automatic routine actions or Full Browser Access in PC controls. Read and navigation actions run only within browser permissions granted on the computer.'});
  if(path==='/pair/approve'&&request.method==='POST'){const b=await requestJson(request);if(b.consent!==true||!/^[A-F0-9]{14}$/.test(b.code||''))fail('PC_CONSENT_REQUIRED');if(b.sessionDays!==undefined&&b.sessionDays!==30)fail('INVALID_INPUT');const d=await store.pcPair(b.code,key,now(),b.sessionDays);return reply(200,{device:pcView(d,now())});}
  const match=path.match(/^\/([a-f0-9-]{36})\/(stop|decision|policy)$/i);if(match&&request.method==='POST'){const [,id,op]=match;await pcOwnerDevice(store,id,key,now());if(op==='stop'){await store.pcRevoke(id,key,now());return reply(200,{stopped:true});}const b=await requestJson(request);if(op==='policy'){if(b.consent!==true||!['ask','auto','full'].includes(b.approvalMode))fail('PC_CONSENT_REQUIRED');const d=await store.pcPolicy(id,key,b.approvalMode,now());return reply(200,{device:pcView(d,now())});}if(!/^[a-f0-9]{32}$/.test(b.jobId||'')||typeof b.approve!=='boolean')fail('INVALID_INPUT');const d=await store.pcDecision(id,key,b.jobId,b.approve,now());return reply(200,{device:pcView(d,now())});}
  fail('NOT_FOUND',404);
 }catch(e){return reply(e.status||503,{code:/^[A-Z_]+$/.test(e.code||'')?e.code:'PC_UNAVAILABLE'});}
};}
