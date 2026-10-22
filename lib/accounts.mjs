import {preferenceView} from './personalization.mjs';
import {createHash} from 'node:crypto';

export const accountKey = uid => createHash('sha256').update(uid).digest('hex');
export const accountOwner = (uid,generation=0) => createHash('sha256').update(`account:${uid}:${generation}`).digest('hex');
export function publicAuthConfig(env=process.env) {
  const {FIREBASE_WEB_API_KEY:apiKey,FIREBASE_AUTH_DOMAIN:authDomain,FIREBASE_PROJECT_ID:projectId,FIREBASE_WEB_APP_ID:appId}=env;
  if(!apiKey||!authDomain||!projectId||!appId)return null;
  // Only Firebase's intentionally public web configuration is exposed.
  return {firebase:{apiKey,authDomain,projectId,appId},providers:{email:env.NEBULA_AUTH_EMAIL!=='false',google:env.NEBULA_AUTH_GOOGLE!=='false',apple:env.NEBULA_AUTH_APPLE==='true',phone:env.NEBULA_AUTH_PHONE==='true'}};
}
export async function authenticate(request,verifyToken,onFailure=()=>{}) {
  const authorization=request.headers.get('authorization');
  if(!authorization)return null;
  const match=authorization.match(/^Bearer ([A-Za-z0-9_.-]{10,10000})$/);
  if(!match){onFailure('AUTH_HEADER_MALFORMED');throw Object.assign(new Error('Unauthorized'),{status:401,code:'UNAUTHORIZED'});}
  try {
    const identity=await verifyToken(match[1]);
    if(!identity||typeof identity.uid!=='string'||!identity.uid||identity.uid.length>128)throw Object.assign(new Error('Invalid token'),{code:'auth/invalid-id-token'});
    return identity;
  } catch(error) {
    // Never log SDK messages, which can contain token/credential details.
    const runtimeReasons={ERR_MODULE_NOT_FOUND:'AUTH_SDK_MODULE_MISSING',MODULE_NOT_FOUND:'AUTH_SDK_MODULE_MISSING',ERR_PACKAGE_PATH_NOT_EXPORTED:'AUTH_SDK_EXPORT_MISSING',ERR_REQUIRE_ESM:'AUTH_SDK_MODULE_FORMAT',ENOTFOUND:'AUTH_DNS_FAILED',EAI_AGAIN:'AUTH_DNS_FAILED',ETIMEDOUT:'AUTH_NETWORK_TIMEOUT',ECONNRESET:'AUTH_NETWORK_RESET',ERR_OSSL_PEM_NO_START_LINE:'AUTH_PRIVATE_KEY_INVALID',ERR_OSSL_UNSUPPORTED:'AUTH_PRIVATE_KEY_INVALID'};
    const reason=/^(auth|app)\/[a-z-]{1,60}$/.test(error?.code||'')?error.code:runtimeReasons[error?.code]||((error?.errorType||error?.name)==='TypeError'?'AUTH_VERIFIER_TYPE_ERROR':'AUTH_VERIFY_FAILED');
    const stage=['sdk_import','admin_initialization','token_verification'].includes(error?.authStage)?error.authStage:undefined;
    onFailure(reason,stage?{stage}:undefined);
    const rejected=new Set(['auth/id-token-expired','auth/id-token-revoked','auth/invalid-id-token','auth/argument-error','auth/invalid-argument','auth/user-disabled','auth/user-not-found','auth/tenant-id-mismatch']);
    if(rejected.has(reason))throw Object.assign(new Error('Unauthorized'),{status:401,code:'UNAUTHORIZED'});
    throw Object.assign(new Error('Authentication service unavailable'),{status:503,code:'AUTH_UNAVAILABLE'});
  }
}
export function accountView(identity,profile) {
  return {uid:identity.uid,displayName:profile.displayName||(typeof identity.name==='string'?identity.name.slice(0,80):'Nebula explorer'),email:typeof identity.email==='string'?identity.email:null,emailVerified:identity.email_verified===true,phoneNumber:typeof identity.phone_number==='string'?identity.phone_number:null,provider:identity.firebase?.sign_in_provider||'unknown',improve:profile.improve!==false,memoryEnabled:profile.memoryEnabled===true,theme:['dark','dim','light','system'].includes(profile.theme)?profile.theme:'dark',createdAt:profile.createdAt,...preferenceView(profile)};
}
