import {createHash} from 'node:crypto';

export const accountKey = uid => createHash('sha256').update(uid).digest('hex');
export const accountOwner = (uid,generation=0) => createHash('sha256').update(`account:${uid}:${generation}`).digest('hex');
export function publicAuthConfig(env=process.env) {
  const {FIREBASE_WEB_API_KEY:apiKey,FIREBASE_AUTH_DOMAIN:authDomain,FIREBASE_PROJECT_ID:projectId,FIREBASE_WEB_APP_ID:appId}=env;
  if(!apiKey||!authDomain||!projectId||!appId)return null;
  // Only Firebase's intentionally public web configuration is exposed.
  return {firebase:{apiKey,authDomain,projectId,appId},providers:{email:env.NEBULA_AUTH_EMAIL!=='false',google:env.NEBULA_AUTH_GOOGLE!=='false',apple:env.NEBULA_AUTH_APPLE==='true',phone:env.NEBULA_AUTH_PHONE==='true'}};
}
export async function authenticate(request,verifyToken) {
  const authorization=request.headers.get('authorization');
  if(!authorization)return null;
  const match=authorization.match(/^Bearer ([A-Za-z0-9_.-]{10,10000})$/);
  if(!match)throw Object.assign(new Error('Unauthorized'),{status:401,code:'UNAUTHORIZED'});
  try {
    const identity=await verifyToken(match[1]);
    if(!identity||typeof identity.uid!=='string'||!identity.uid||identity.uid.length>128)throw new Error('Invalid token');
    return identity;
  } catch {throw Object.assign(new Error('Unauthorized'),{status:401,code:'UNAUTHORIZED'});}
}
export function accountView(identity,profile) {
  return {uid:identity.uid,displayName:typeof identity.name==='string'?identity.name.slice(0,80):'Nebula explorer',email:typeof identity.email==='string'?identity.email:null,emailVerified:identity.email_verified===true,phoneNumber:typeof identity.phone_number==='string'?identity.phone_number:null,provider:identity.firebase?.sign_in_provider||'unknown',improve:profile.improve===true,createdAt:profile.createdAt};
}
