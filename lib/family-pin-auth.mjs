import crypto from 'node:crypto';
const fail=(message,statusCode)=>{throw Object.assign(Error(message),{statusCode});};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function configuration(env){
 let c;try{c=JSON.parse(env.FAMILY_PIN_AUTH);}catch{}
 if(!c||!/^[a-f0-9]{32}$/.test(c.salt||'')||!/^[a-f0-9]{64}$/.test(c.pepper||'')||!/^[a-f0-9]{128}$/.test(c.hash||'')||!/^[a-f0-9]{32}$/.test(c.revision||''))fail('Family PIN is not configured.',503);
 return c;
}
export function createPinFamilyAuth(root,env,rateLimit){
 const config=configuration(env),read=async path=>(await root.child(path).get()).val();
 function verifies(pin){
  if(typeof pin!=='string'||!/^\d{4,12}$/.test(pin))return false;
  const actual=crypto.scryptSync(pin+config.pepper,config.salt,64),expected=Buffer.from(config.hash,'hex');
  return expected.length===actual.length&&crypto.timingSafeEqual(actual,expected);
 }
 function tokenKey(token){if(!env.SESSION_PEPPER||env.SESSION_PEPPER.length<24)fail('Family sessions are not configured.',503);return crypto.createHmac('sha256',env.SESSION_PEPPER).update(token).digest('hex');}
 async function profile(){
  const ref=root.child('familyProtection/parentAccess'),existing=await read('familyProtection/parentAccess');
  if(/^[a-f0-9]{64}$/.test(existing?.ownerHash||''))return existing;
  const legacy=await read('usernames/iii_dev'),owners=await read('familyProtection/owners')||{};
  const oldHash=typeof legacy?.accountId==='string'?sha(legacy.accountId):'';
  let ownerHash=oldHash&&owners[oldHash]?oldHash:'';
  const keys=Object.keys(owners).filter(key=>/^[a-f0-9]{64}$/.test(key));
  if(!ownerHash){
   if(keys.length>1)fail('Multiple saved Family profiles need parent recovery.',409);
   ownerHash=keys[0]||oldHash||sha('scriptnovaa-private-family-v1');
  }
  const tx=await ref.transaction(value=>value||{ownerHash,createdAt:Date.now()});
  const saved=tx.snapshot.val();if(!/^[a-f0-9]{64}$/.test(saved?.ownerHash||''))fail('Family profile needs recovery.',409);
  return saved;
 }
 async function requireAccount(req){
  const token=String(req.headers.authorization||'').match(/^Bearer\s+(.+)$/i)?.[1];
  if(!token||token.length>512)fail('Enter your family PIN to unlock.',401);
  const session=await read('familyProtection/pinSessions/'+tokenKey(token));
  if(!session||session.revoked||session.pinRevision!==config.revision||!(session.expiresAt>Date.now()))fail('Enter your family PIN to unlock.',401);
  const saved=await read('familyProtection/parentAccess');
  if(saved?.ownerHash!==session.ownerHash)fail('Family session expired.',401);
  return {id:'private-family-parent',familyOwnerHash:session.ownerHash,data:{username:'iii_dev',pinCredential:{kind:'family-pin-v1'}}};
 }
 async function login(req,res){
  await rateLimit(req.ip,'family-pin-network',5,900);
  await rateLimit('private-family','family-pin-global',40,3600);
  if(!verifies(req.body.pin))fail('Incorrect family PIN.',401);
  const saved=await profile(),at=Date.now(),token=crypto.randomBytes(32).toString('base64url');
  const expiresAt=at+(req.body.remember===true?30*86400000:600000);
  await root.child('familyProtection/pinSessions/'+tokenKey(token)).set({ownerHash:saved.ownerHash,pinRevision:config.revision,createdAt:at,expiresAt,revoked:false});
  res.json({ok:true,loginToken:token});
 }
 return {requireAccount,rateLimit,login,verifies};
}
