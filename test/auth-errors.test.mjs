import {test} from 'node:test';
import assert from 'node:assert/strict';
import {authenticate} from '../lib/accounts.mjs';
import {adminOptionsFromEnv} from '../lib/firebase.mjs';
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
