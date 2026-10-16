import {createHmac,createHash} from 'node:crypto';
import {accountKey,accountOwner,accountView,authenticate,publicAuthConfig} from './accounts.mjs';

const TOKEN = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{1,80}$/;
const MAX_BYTES = 160000;
const hash = value => createHash('sha256').update(value).digest('hex');
export function configFromEnv(env=process.env) {
  return {
    origins:(env.NEBULA_ALLOWED_ORIGINS || 'https://scriptnovaa.com,https://www.scriptnovaa.com').split(',').map(s=>s.trim()).filter(Boolean),
    training:env.NEBULA_TRAINING_ENABLED === 'true',
    modelUrl:env.NEBULA_MODEL_URL || '', modelKey:env.NEBULA_MODEL_KEY || '', modelName:env.NEBULA_MODEL_NAME || 'nebula',
    rateSecret:env.NEBULA_RATE_LIMIT_SECRET || '', production:Boolean(env.VERCEL),
    auth:publicAuthConfig(env),
  };
}
function invalid() {return Object.assign(new Error('Invalid request'),{status:400,code:'INVALID_INPUT'});}
async function readJson(request) {
  if(!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) throw Object.assign(invalid(),{status:415});
  if(Number(request.headers.get('content-length') || 0)>MAX_BYTES) throw Object.assign(invalid(),{status:413});
  const reader=request.body?.getReader();if(!reader)throw invalid();
  let bytes=0;const chunks=[];
  try {
    while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>MAX_BYTES){await reader.cancel();throw Object.assign(invalid(),{status:413});}chunks.push(value);}
    const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if(!body || typeof body!=='object' || Array.isArray(body))throw invalid();return body;
  } catch(e){if(e.status)throw e;throw invalid();}
  finally {reader.releaseLock();}
}
function validateMessages(messages) {
  if(!Array.isArray(messages)||!messages.length||messages.length>200)throw invalid();
  let total=0;
  const clean=messages.map(m=>{
    if(!m||!['user','assistant'].includes(m.role)||typeof m.content!=='string'||!m.content.trim()||m.content.length>(m.role==='user'?16000:100000))throw invalid();
    total+=m.content.length;return {role:m.role,content:m.content};
  });
  if(total>100000||clean.at(-1).role!=='user')throw invalid();return clean;
}
export function redact(text) {
  return text.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,'[email removed]')
    .replace(/\b(?:sk-|AIza)[A-Za-z0-9_-]{15,}\b/g,'[credential removed]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]{12,}=*/gi,'Bearer [credential removed]');
}
async function modelReply(messages, config) {
  const url=new URL(config.modelUrl);
  if(url.protocol!=='https:' && !(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))throw new Error('Invalid model server configuration');
  const response=await fetch(url,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json',...(config.modelKey?{Authorization:`Bearer ${config.modelKey}`}:{})},body:JSON.stringify({model:config.modelName,messages,stream:false}),signal:AbortSignal.timeout(70000)});
  if(!response.ok)throw new Error('Model request failed');
  // Bound upstream response memory; return only the text field, never upstream metadata.
  const reader=response.body.getReader();let size=0;const chunks=[];
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>500000){await reader.cancel();throw new Error('Reply too large');}chunks.push(value);}}
  finally{reader.releaseLock();}
  const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const reply=data.reply??data.choices?.[0]?.message?.content;
  if(typeof reply!=='string'||!reply.trim()||reply.length>100000)throw new Error('Invalid model reply');
  return reply;
}
export function createApp({getStore,verifyToken=async()=>{throw new Error('Authentication unavailable');},config=configFromEnv(),generate=modelReply,now=Date.now,log=(code)=>console.error('Nebula request failed:',code)}) {
  return async request => {
    const origin=request.headers.get('origin');
    const cors=origin&&config.origins.includes(origin)?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{};
    const headers={...cors,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Type':'application/json'};
    const reply=(status,data)=>new Response(JSON.stringify(data),{status,headers});
    if(origin&&!config.origins.includes(origin))return reply(403,{code:'FORBIDDEN'});
    if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET, POST, PATCH, DELETE, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'600'}});
    const path=new URL(request.url).pathname;
    if(path==='/api/nebula/auth/config')return request.method==='GET'?(config.auth?reply(200,config.auth):reply(503,{code:'AUTH_UNAVAILABLE'})):reply(405,{code:'METHOD_NOT_ALLOWED'});
    const accountRoute=path==='/api/nebula/account';
    if(!['/api/nebula/chat','/api/nebula/training','/api/nebula/account'].includes(path))return reply(404,{code:'NOT_FOUND'});
    if((path.endsWith('/chat')&&request.method!=='POST')||(path.endsWith('/training')&&request.method!=='DELETE')||(accountRoute&&!['GET','PATCH'].includes(request.method)))return reply(405,{code:'METHOD_NOT_ALLOWED'});
    try {
      const identity=await authenticate(request,verifyToken);
      if(accountRoute&&!identity)return reply(401,{code:'UNAUTHORIZED'});
      const body=request.method==='GET'?{}:await readJson(request);
      if(accountRoute&&request.method==='PATCH'&&typeof body.improve!=='boolean')throw invalid();
      const messages=path.endsWith('/chat')?validateMessages(body.messages):null;
      if(!accountRoute&&!messages&&!identity&&!TOKEN.test(body.token || ''))throw invalid();
      const training=body.training;
      if(messages&&training?.enabled===true&&(!TOKEN.test(training.token || '')||!ID.test(training.chatId || '')||!ID.test(training.turnId || '')||training.consentVersion!==1))throw invalid();
      if(config.rateSecret.length<32)return reply(503,{code:'UNAVAILABLE'});
      const store=await getStore();
      // Vercel supplies this header. Locally use a common bucket rather than trusting spoofable IP headers.
      const network=config.production?request.headers.get('x-vercel-forwarded-for')?.split(',')[0]?.trim()||'unknown':'local';
      const networkKey=createHmac('sha256',config.rateSecret).update(network).digest('hex');
      if(!await store.allow(networkKey,now()))return reply(429,{code:'RATE_LIMITED'});
      const key=identity?accountKey(identity.uid):null;
      let profile=identity?await store.account(key,now()):null;
      if(accountRoute) {
        if(request.method==='PATCH')profile=await store.preferences(key,body.improve,now());
        return reply(200,{account:accountView(identity,profile)});
      }
      if(!messages){
        await store.deleteOwner(identity?accountOwner(identity.uid,profile.trainingGeneration):hash(body.token));
        if(identity)await store.rotateTraining(key,now());
        return reply(200,{deleted:true});
      }
      const contribution=config.training&&training?.enabled===true&&(!identity||profile.improve===true);
      const owner=identity?accountOwner(identity.uid,profile.trainingGeneration):training?.token?hash(training.token):null;
      const save=async assistant=>{
        if(!contribution)return false;
        // Recheck account consent and generation after a potentially slow model reply.
        if(identity){const latest=await store.account(key,now());if(!latest.improve||latest.trainingGeneration!==profile.trainingGeneration)return false;}
        const sample={schemaVersion:1,consentVersion:1,createdAt:now(),reviewStatus:'pending',messages:[{role:'user',content:redact(messages.at(-1).content)},...(assistant?[{role:'assistant',content:redact(assistant).slice(0,24000)}]:[])]};
        try {return await store.save(owner,training.chatId,training.turnId,sample) === true;}
        catch{log('TRAINING_WRITE_FAILED');return false;}
      };
      if(!config.modelUrl){const trainingSaved=await save();return reply(503,{code:'MODEL_NOT_READY',trainingSaved});}
      let text;
      try{text=await generate(messages,config);}catch{const trainingSaved=await save();log('MODEL_UNAVAILABLE');return reply(503,{code:'UNAVAILABLE',trainingSaved});}
      const trainingSaved=await save(text);
      return reply(200,{reply:text,trainingSaved});
    } catch(e){if(e.status)return reply(e.status,{code:e.code});log('UNAVAILABLE');return reply(503,{code:'UNAVAILABLE'});}
  };
}
