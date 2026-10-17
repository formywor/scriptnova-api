import {createHash,randomUUID,timingSafeEqual} from 'node:crypto';

export const BENCHMARK='nebula-research-v1';
const HASH=/^[a-f0-9]{64}$/;
const fail=(status,code)=>{throw Object.assign(new Error(code),{status,code});};
const fresh=()=>({revision:0,files:{},head:null,dataset:null,candidate:null,lease:null});
const validFile=(state,id)=>{const file=state.files?.[id];if(!file||file.status!=='ready')fail(409,'CHECKPOINT_NOT_READY');return file;};
function lease(state,role,body,now){
  const value=state.lease;
  if(!value||value.role!==role||value.id!==body.lease||value.expiresAt<=now||value.base!==state.head)fail(409,'LEASE_LOST');
  return value;
}
export function acceptable(base,next){
  const keys=['identity','math','memory','extraction','health'];
  for(const result of [base,next]){
    if(!result||result.benchmark!==BENCHMARK||!Number.isFinite(result.loss)||result.loss<=0)fail(400,'INVALID_REPORT');
    for(const key of keys)if(!Number.isFinite(result[key])||result[key]<0||result[key]>1)fail(400,'INVALID_REPORT');
  }
  const score=x=>keys.slice(0,4).reduce((sum,k)=>sum+x[k],0)/4;
  return keys.every(k=>next[k]>=base[k]-.05)&&next.health>=base.health&&next.loss<=base.loss*1.10&&
    (score(next)>=score(base)+.025||score(next)>=score(base)&&next.loss<base.loss*.995);
}
export function changeResearch(previous,role,action,body,now,id=randomUUID()){
  const state=structuredClone(previous||fresh());state.files||={};
  if(action==='upload'){
    const seed=!state.head;
    if(!['checkpoint','dataset'].includes(body.kind)||!Number.isSafeInteger(body.bytes)||body.bytes<1||body.bytes>100*1024*1024||!HASH.test(body.sha256||'')||!/^[A-Za-z0-9+/]{22}==$/.test(body.md5||''))fail(400,'INVALID_UPLOAD');
    if(body.kind==='dataset'&&(!seed||role!=='trainer'))fail(403,'FORBIDDEN');
    if(seed&&role!=='trainer')fail(403,'FORBIDDEN');
    if(!seed){
      const job=lease(state,role,body,now);
      const expected=role==='trainer'?state.head:state.candidate;
      if(body.parent!==expected||role==='evaluator'&&job.candidate!==state.candidate)fail(409,'STALE_PARENT');
    }
    if(Object.keys(state.files).length>=32)fail(429,'CHECKPOINT_STORAGE_FULL');
    const recent=Object.values(state.files).filter(x=>x.createdAt>now-3600000).length;
    if(recent>=12)fail(429,'UPLOAD_BUDGET_REACHED');
    state.files[id]={id,kind:body.kind,bytes:body.bytes,sha256:body.sha256,md5:body.md5,
      parent:body.parent||null,role,createdAt:now,status:'pending',expiresAt:now+15*60000};
  }else if(action==='finish'){
    const file=state.files[body.id];
    if(!file||file.role!==role||file.expiresAt<now)fail(409,'UPLOAD_EXPIRED');
    file.status='ready';
  }else if(action==='seed'){
    if(role!=='trainer')fail(403,'FORBIDDEN');
    if(state.head)fail(409,'ALREADY_INITIALIZED');
    if(validFile(state,body.dataset).kind!=='dataset'||validFile(state,body.checkpoint).kind!=='checkpoint'||!HASH.test(body.dataSha256||''))fail(400,'INVALID_SEED');
    state.dataset=body.dataset;state.head=body.checkpoint;state.dataSha256=body.dataSha256;state.revision++;
  }else if(action==='claim'){
    if(!state.head)fail(409,'NOT_INITIALIZED');
    if(role==='trainer'&&(state.rejectedRounds||0)>=3)fail(409,'RESEARCH_PAUSED_NO_IMPROVEMENT');
    if(state.lease&&state.lease.expiresAt>now)fail(409,'WORKER_BUSY');
    if(role!==(state.candidate?'evaluator':'trainer'))fail(409,'WAITING_FOR_OTHER_WORKER');
    state.lease={id,role,base:state.head,candidate:state.candidate||null,createdAt:now,expiresAt:now+10*60000};
  }else if(action==='heartbeat'){
    const job=lease(state,role,body,now);
    if(now-job.createdAt>2*3600000)fail(409,'ROUND_TIME_LIMIT');
    job.expiresAt=now+10*60000;
  }else if(action==='submit'){
    if(role!=='trainer')fail(403,'FORBIDDEN');lease(state,role,body,now);
    const file=validFile(state,body.id);
    if(file.role!==role||file.parent!==state.head||file.kind!=='checkpoint'||state.candidate)fail(409,'STALE_PARENT');
    state.candidate=body.id;state.lease=null;
  }else if(action==='decide'){
    if(role!=='evaluator')fail(403,'FORBIDDEN');
    const job=lease(state,role,body,now);
    if(job.candidate!==state.candidate||body.candidate!==state.candidate)fail(409,'STALE_EVALUATION');
    const baseline=body.baseline;let selected=state.head,selectedReport=baseline;
    if(acceptable(baseline,body.trained)){selected=state.candidate;selectedReport=body.trained;}
    if(body.experiment){
      const file=validFile(state,body.experiment.id);
      if(file.role!=='evaluator'||file.parent!==state.candidate||file.kind!=='checkpoint')fail(409,'INVALID_EXPERIMENT');
      if(acceptable(baseline,body.experiment.report)&&acceptable(selectedReport,body.experiment.report)){
        selected=body.experiment.id;selectedReport=body.experiment.report;
      }
    }
    state.rejectedRounds=selected===state.head?(state.rejectedRounds||0)+1:0;
    state.head=selected;state.lastEvaluation={candidate:state.candidate,selected,report:selectedReport,at:now};
    state.candidate=null;state.lease=null;state.revision++;
  }else if(action==='gc'){
    const protectedIds=new Set([state.head,state.dataset,state.candidate,state.lease?.base,state.lease?.candidate]);
    let parent=state.files[state.head]?.parent;
    for(let i=0;i<2&&parent;i++){protectedIds.add(parent);parent=state.files[parent]?.parent;}
    const old=Object.values(state.files).filter(x=>!protectedIds.has(x.id)).sort((a,b)=>b.createdAt-a.createdAt);
    state.garbage||={};
    for(const file of old.slice(6))if(file.expiresAt<now){state.garbage[file.id]=file;delete state.files[file.id];}
  }else fail(404,'NOT_FOUND');
  return state;
}

async function jsonBody(request){
  if(!request.headers.get('content-type')?.startsWith('application/json'))fail(415,'JSON_REQUIRED');
  const reader=request.body?.getReader();if(!reader)fail(400,'INVALID_INPUT');
  let count=0;const chunks=[];
  try{while(true){const {done,value}=await reader.read();if(done)break;count+=value.length;if(count>16000){await reader.cancel();fail(413,'TOO_LARGE');}chunks.push(value);}}
  finally{reader.releaseLock();}
  let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail(400,'INVALID_INPUT');}
  if(!body||typeof body!=='object'||Array.isArray(body))fail(400,'INVALID_INPUT');return body;
}
export function createResearchHandler({services,env=process.env,now=Date.now}){
  return async request=>{
    const reply=(status,data)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
    try{
      if(request.headers.has('origin'))return reply(403,{code:'SERVER_WORKERS_ONLY'});
      if(env.NEBULA_RESEARCH_ENABLED!=='true')return reply(503,{code:'RESEARCH_NOT_CONFIGURED'});
      const tokens={trainer:env.NEBULA_TRAINER_TOKEN,evaluator:env.NEBULA_EVALUATOR_TOKEN};
      if(Object.values(tokens).some(x=>typeof x!=='string'||x.length<32)||tokens.trainer===tokens.evaluator)fail(503,'RESEARCH_NOT_CONFIGURED');
      const supplied=request.headers.get('authorization')?.match(/^Bearer ([^\s]{1,256})$/)?.[1]||'';
      const digest=x=>createHash('sha256').update(x).digest();
      const role=Object.keys(tokens).find(k=>timingSafeEqual(digest(tokens[k]),digest(supplied)));
      if(!role)fail(401,'UNAUTHORIZED');
      const action=new URL(request.url).pathname.replace(/^\/api\/nebula\/research\/?/,'');
      if(!['GET','POST'].includes(request.method))fail(405,'METHOD_NOT_ALLOWED');
      if(action==='state'&&request.method==='GET')return reply(200,await (await services()).read()||fresh());
      if(request.method!=='POST')fail(405,'METHOD_NOT_ALLOWED');
      const body=await jsonBody(request);const service=await services();
      if(action==='download'){
        const file=validFile(await service.read()||fresh(),body.id);
        return reply(200,{url:await service.download(file),sha256:file.sha256,bytes:file.bytes});
      }
      if(action==='finish'){
        const state=await service.read();const file=state?.files?.[body.id];
        if(!file||file.role!==role)fail(404,'NOT_FOUND');
        if(!await service.verify(file))fail(409,'UPLOAD_CHECK_FAILED');
      }
      if(action==='upload'){
        const cleaned=await service.update(state=>changeResearch(state,role,'gc',{},now()));
        for(const file of Object.values(cleaned.garbage||{})){
          await service.remove(file);
          await service.update(state=>{if(state?.garbage)delete state.garbage[file.id];return state;});
        }
      }
      const id=randomUUID();
      const state=await service.update(state=>changeResearch(state,role,action,body,now(),id));
      if(action==='upload')return reply(200,{id,...await service.upload(state.files[id])});
      return reply(200,state);
    }catch(error){return reply(error.status||503,{code:error.code||'RESEARCH_UNAVAILABLE'});}
  };
}
