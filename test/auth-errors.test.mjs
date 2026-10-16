import {test} from 'node:test';
import assert from 'node:assert/strict';
import {authenticate} from '../lib/accounts.mjs';
import {adminOptionsFromEnv,createTokenVerifier} from '../lib/firebase.mjs';
import {createApp} from '../lib/app.mjs';

const request=()=>new Request('https://api.scriptnovaa.com/api/nebula/account',{headers:{Authorization:'Bearer valid.test.token'}});
test('expired/revoked tokens remain rejected, while admin/network failures are unavailable',async()=>{
 for(const code of ['auth/id-token-expired','auth/id-token-revoked','auth/argument-error','auth/user-disabled'])await assert.rejects(authenticate(request(),async()=>{throw Object.assign(Error('sensitive token contents'),{code});}),e=>e.status===401&&e.code==='UNAUTHORIZED');
 for(const code of ['auth/insufficient-permission','auth/internal-error','app/invalid-credential','app/network-error'])await assert.rejects(authenticate(request(),async()=>{throw Object.assign(Error('sensitive admin credential'),{code});}),e=>e.status===503&&e.code==='AUTH_UNAVAILABLE');
});
test('unknown verification errors fail closed without claiming a bad login',async()=>{
 await assert.rejects(authenticate(request(),async()=>{throw Error('private URL or credential');}),e=>e.status===503&&e.code==='AUTH_UNAVAILABLE');
});
test('verification diagnostics log only safe codes, not SDK messages or token contents',async()=>{
 const events=[];const app=createApp({getStore:async()=>{throw Error('must not reach store');},verifyToken:async()=>{throw Object.assign(Error('secret-token private-key private-model-url'),{code:'auth/insufficient-permission'});},config:{origins:[]},log:e=>events.push(e)});
 const response=await app(request());assert.equal(response.status,503);assert.deepEqual(await response.json(),{code:'AUTH_UNAVAILABLE'});assert.deepEqual(events,[{event:'AUTH_VERIFICATION_FAILED',reason:'auth/insufficient-permission'}]);assert.equal(JSON.stringify(events).includes('secret'),false);
});
test('missing bearer header is separately diagnosable without weakening account authorization',async()=>{
 const events=[];const app=createApp({getStore:async()=>{throw Error('must not reach store');},config:{origins:[]},log:e=>events.push(e)});const response=await app(new Request('https://api.scriptnovaa.com/api/nebula/account'));assert.equal(response.status,401);assert.equal(events[0].reason,'AUTH_HEADER_MISSING');
});
test('admin setup accepts escaped and JSON-quoted PEMs without requiring a database for auth',()=>{
 const pem='-----BEGIN PRIVATE KEY-----\nTEST-PLACEHOLDER\n-----END PRIVATE KEY-----';
 for(const value of [pem,pem.replace(/\n/g,'\\n'),JSON.stringify(pem),"'"+pem.replace(/\n/g,'\\n')+"'"]){const options=adminOptionsFromEnv({FIREBASE_PROJECT_ID:' project ',FIREBASE_CLIENT_EMAIL:' admin@example.com ',FIREBASE_PRIVATE_KEY:value});assert.equal(options.credentials.privateKey,pem);assert.equal(options.credentials.projectId,'project');assert.equal(options.databaseURL,undefined);}
 assert.throws(()=>adminOptionsFromEnv({}),e=>e.code==='app/invalid-credential');
});
test('SDK and runtime errors are identified by stage without exposing raw error messages',async()=>{
 const cases=[
  {loadAuth:async()=>{throw Object.assign(Error('credential-bearing module path'),{code:'ERR_MODULE_NOT_FOUND'});},expected:{reason:'AUTH_SDK_MODULE_MISSING',stage:'sdk_import'}},
  {loadAuth:async()=>({getAuth:()=>({})}),getApp:async()=>{throw Object.assign(Error('private PEM'),{code:'app/invalid-credential'});},expected:{reason:'app/invalid-credential',stage:'admin_initialization'}},
  {loadAuth:async()=>({getAuth:()=>({verifyIdToken:async()=>{throw Object.assign(Error('private service URL'),{code:'ETIMEDOUT'});}})}),getApp:async()=>({}),expected:{reason:'AUTH_NETWORK_TIMEOUT',stage:'token_verification'}},
  {loadAuth:async()=>({}),getApp:async()=>({}),expected:{reason:'AUTH_VERIFIER_TYPE_ERROR',stage:'token_verification'}},
 ];
 for(const options of cases){const events=[];await assert.rejects(authenticate(request(),createTokenVerifier(options),(reason,details)=>events.push({reason,...details})),e=>e.status===503);assert.deepEqual(events,[options.expected]);assert.equal(JSON.stringify(events).includes('private'),false);}
});
test('token verifier preserves revocation checks and passes the actual token only to the SDK',async()=>{
 let actual;const verify=createTokenVerifier({loadAuth:async()=>({getAuth:()=>({verifyIdToken:async(...args)=>{actual=args;return{uid:'alice'};}})}),getApp:async()=>({})});assert.deepEqual(await verify('test.token'),{uid:'alice'});assert.deepEqual(actual,['test.token',true]);
});
test('missing rate-limit configuration has a safe explicit diagnostic after identity verification',async()=>{
 const events=[];const app=createApp({getStore:async()=>{throw Error('must not reach store');},verifyToken:async()=>({uid:'alice'}),config:{origins:[],rateSecret:''},log:e=>events.push(e)});const response=await app(request());assert.equal(response.status,503);assert.deepEqual(events,[{event:'API_REQUEST_FAILED',stage:'configuration',reason:'RATE_LIMIT_SECRET_MISSING_OR_SHORT'}]);assert.deepEqual(await response.json(),{code:'UNAVAILABLE'});
});
test('database failures identify the phase without exposing server credentials',async()=>{
 for(const [store,stage] of [[async()=>{throw Object.assign(Error('private URL'),{code:'DATABASE_URL_MISSING'});},'storage_initialization'],[async()=>({allow:async()=>{throw Error('private database contents');}}),'rate_limit_storage'],[async()=>({allow:async()=>true,account:async()=>{throw Error('private user contents');}}),'account_storage']]){
  const events=[];const app=createApp({getStore:store,verifyToken:async()=>({uid:'alice'}),config:{origins:[],rateSecret:'x'.repeat(40)},log:e=>events.push(e)});assert.equal((await app(request())).status,503);assert.equal(events[0].stage,stage);assert.equal(JSON.stringify(events).includes('private'),false);
 }
});
