import crypto from 'node:crypto';
import family from './family/family-protection.js';
import {createPinFamilyAuth} from './family-pin-auth.mjs';

const fail=(message,statusCode=400)=>{throw Object.assign(new Error(message),{statusCode});};
const sha=value=>crypto.createHash('sha256').update(String(value)).digest('hex');
function secret(env,name){const value=env[name];if(!value||value.length<24)fail('Family authentication is not configured.',503);return value;}
function hashToken(token,env){return crypto.createHmac('sha256',secret(env,'SESSION_PEPPER')).update(token).digest('hex');}
function verifies(pin,stored,name,env){
 // Recompute with the original account's pepper; this preserves the old PIN.
 const expected=Buffer.from(stored?.hash||'0'.repeat(128),'hex');
 const value=crypto.scryptSync(String(pin)+secret(env,name),stored?.salt||'0'.repeat(32),64);
 return !!stored?.hash&&expected.length===value.length&&crypto.timingSafeEqual(value,expected);
}
export function createFamilyAuth(root,env=process.env){
 const read=async path=>(await root.child(path).get()).val();
 async function rateLimit(key,action,maximum,seconds){
  const at=Date.now(),ref=root.child('familyProtection/rateLimits/'+sha(action+':'+key));
  const tx=await ref.transaction(value=>{
   if(!value||at-Number(value.windowStartedAt||0)>=seconds*1000)return {count:1,windowStartedAt:at};
   if(Number(value.count||0)>=maximum)return;
   return {...value,count:Number(value.count||0)+1};
  });
  if(!tx.committed)fail('Too many attempts. Please try again later.',429);
 }
 if(env.FAMILY_PIN_AUTH)return createPinFamilyAuth(root,env,rateLimit);
 function permitted(account){
  if(!account||String(account.username||'').toLowerCase()!=='iii_dev')fail('Authentication required.',401);
  if(account.accountStatus&&account.accountStatus!=='ACTIVE')fail('This account is restricted.',403);
  if(account.recoveryPromptRequired===true&&!account.recoveryAcknowledgedAt)fail('Account recovery confirmation is required.',428);
  return account;
 }
 async function requireAccount(req){
  const token=String(req.headers.authorization||'').match(/^Bearer\s+(.+)$/i)?.[1];
  if(!token||token.length>512)fail('Authentication required.',401);
  const loginId=hashToken(token,env);
  const login=await read('familyProtection/loginSessions/'+loginId)||await read('loginSessions/'+loginId);
  if(!login||login.revoked||!(Number(login.expiresAt)>Date.now()))fail('Authentication required.',401);
  const account=permitted(await read('accounts/'+login.accountId));
  return {id:login.accountId,data:account,loginId};
 }
 async function login(req,res){
  const username=String(req.body.username||'').trim().toLowerCase();
  await rateLimit(req.ip,'family-login-network',8,900);
  await rateLimit(username==='iii_dev'?'iii_dev':'other','family-login-account',12,3600);
  if(typeof req.body.pin!=='string'||req.body.pin.length>128)fail('Incorrect username or PIN.',401);
  const record=username==='iii_dev'?await read('usernames/iii_dev'):null;
  const account=record?await read('accounts/'+record.accountId):null;
  const good=verifies(req.body.pin,account?.pinCredential,'PIN_PEPPER',env);
  if(!good||!account)fail('Incorrect username or PIN.',401);
  permitted(account);
  const guard=await read('loginGuards/'+record.accountId);
  if(Number(guard?.lockedUntil)>Date.now())fail('Sign-in temporarily locked. Please try again later.',429);
  const token=crypto.randomBytes(32).toString('base64url'),at=Date.now();
  await root.child('familyProtection/loginSessions/'+hashToken(token,env)).set({accountId:record.accountId,revoked:false,createdAt:at,expiresAt:at+30*86400000});
  res.json({ok:true,loginToken:token});
 }
 return {requireAccount,rateLimit,login,verifies:(pin,stored,name)=>verifies(pin,stored,name,env)};
}

async function jsonBody(request,limit){
 if(!request.body)return {};
 const reader=request.body.getReader(),parts=[];let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel();fail('Request is too large.',413);}parts.push(value);}}
 finally{reader.releaseLock();}
 let body;try{body=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{fail('Invalid JSON request.');}
 if(!body||typeof body!=='object'||Array.isArray(body))fail('Invalid JSON request.');return body;
}
export function createFamilyHandler({getDatabase,env=process.env,fetcher=fetch}={}){
 let initialized;
 async function routes(){
  if(!initialized)initialized=(async()=>{
   const root=(await getDatabase()).ref(),auth=createFamilyAuth(root,env),map=new Map();
   const app={post:(path,fn)=>map.set('POST '+path,fn),get:(path,fn)=>map.set('GET '+path,fn)};
   family.mountFamilyProtection(app,{root,route:fn=>fn,...auth});
   app.post('/api/family/login',auth.login);return map;
  })().catch(error=>{initialized=undefined;throw error;});
  return initialized;
 }
 return async request=>{
  const path=new URL(request.url).pathname,origin=request.headers.get('origin');
  const origins=new Set(['https://scriptnovaa.com','https://www.scriptnovaa.com',...(env.EXTRA_ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean)]);
  const headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Vary':'Origin, Authorization'};
  if(origin&&origins.has(origin))Object.assign(headers,{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'Content-Type, Authorization, X-Family-Grant','Access-Control-Allow-Methods':'GET, POST, OPTIONS'});
  const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
  try{
   if(origin&&!origins.has(origin))fail('Origin is not allowed.',403);
   if(request.method==='OPTIONS')return origin?new Response(null,{status:204,headers}):response({error:'Origin required.'},403);
   // Updates remain usable even if the account database is temporarily offline.
   if(request.method==='GET'&&path==='/api/family/update'){
    let manifest;try{manifest=JSON.parse(env.FAMILY_UPDATE_MANIFEST||'null');}catch{}
    if(!manifest){const r=await fetcher('https://raw.githubusercontent.com/formywor/Ooga-Booga/main/family-update.json',{signal:AbortSignal.timeout(4000),cache:'no-store'});if(r.ok)manifest=await r.json();}
    return response(manifest&&['version','url','sha256','signature'].every(k=>typeof manifest[k]==='string')?manifest:{available:false});
   }
   if(request.method==='GET'&&path==='/api/family/extension'){
    const valid=s=>/^[a-p]{32}$/.test(s||'')?s:'';
    return response({chromeId:valid(env.FAMILY_CHROME_EXTENSION_ID),edgeId:valid(env.FAMILY_EDGE_EXTENSION_ID)});
   }
   const map=await routes(),handler=map.get(request.method+' '+path);
   if(!handler)return response({error:'Family route not found.'},404);
   const body=request.method==='POST'?await jsonBody(request,['/api/family/device/heartbeat','/api/family/device/review'].includes(path)?600*1024:64*1024):{};
   const req={body,path,headers:Object.fromEntries(request.headers),ip:(request.headers.get('x-vercel-forwarded-for')||request.headers.get('x-real-ip')||'unknown').slice(0,100)};
   let result;await handler(req,{json:body=>{result=response(body);}});return result||response({ok:true});
  }catch(error){const status=Number(error.statusCode)||503;return response({ok:false,error:status>=500?'Family service temporarily unavailable. Please try again.':error.message},status);}
 };
}
