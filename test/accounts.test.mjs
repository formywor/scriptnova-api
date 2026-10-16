import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {accountKey,accountOwner,publicAuthConfig} from '../lib/accounts.mjs';

const identities={
 'user.a.token':{uid:'alice',name:'Alice',email:'alice@example.com',email_verified:true,firebase:{sign_in_provider:'google.com'}},
 'user.b.token':{uid:'bob',name:'Bob',phone_number:'+12025550123',firebase:{sign_in_provider:'phone'}},
};
function fixture(generate=async()=> 'Model reply') {
 const records=new Map();const db={ref:path=>({transaction:async update=>{const next=update(structuredClone(records.get(path)??null));if(next===undefined)return{committed:false,snapshot:{val:()=>structuredClone(records.get(path)??null)}};records.set(path,next);return{committed:true,snapshot:{val:()=>structuredClone(next)}};},set:async value=>{records.set(path,structuredClone(value));}})};
 const auth=publicAuthConfig({FIREBASE_WEB_API_KEY:'public-web-key',FIREBASE_AUTH_DOMAIN:'test.firebaseapp.com',FIREBASE_PROJECT_ID:'test',FIREBASE_WEB_APP_ID:'public-app-id',NEBULA_AUTH_APPLE:'true',NEBULA_AUTH_PHONE:'true',FIREBASE_PRIVATE_KEY:'NEVER-PUBLISH'});
 const app=createApp({getStore:async()=>createStore(db),verifyToken:async token=>{if(!identities[token])throw Error('invalid signature, expired, or revoked');return identities[token];},config:{origins:['https://scriptnovaa.com'],training:true,modelUrl:'https://model.invalid',rateSecret:'x'.repeat(40),auth},generate,now:()=>1700000000000,log:()=>{}});
 const request=async(path='/account',method='GET',body,token='user.a.token')=>{
  const response=await app(new Request('https://api.scriptnovaa.com/api/nebula'+path,{method,headers:{Origin:'https://scriptnovaa.com','Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})}));
  return{status:response.status,body:await response.json(),headers:response.headers};
 };
 return{request,records,app};
}
const turn={messages:[{role:'user',content:'Contribute this turn'}],training:{enabled:true,consentVersion:1,token:'a'.repeat(64),chatId:'chat',turnId:'turn'}};
test('public auth configuration is an explicit allowlist and never exposes admin credentials',async()=>{
 const{request}=fixture();const r=await request('/auth/config','GET',undefined,null);assert.equal(r.status,200);assert.equal(r.body.firebase.apiKey,'public-web-key');assert.equal(r.body.providers.apple,true);assert.equal(JSON.stringify(r.body).includes('NEVER-PUBLISH'),false);assert.equal('privateKey' in r.body.firebase,false);
 assert.equal(publicAuthConfig({FIREBASE_PROJECT_ID:'test'}),null);
});
test('account API requires a verified identity; expired or spoofed tokens do not become guests',async()=>{
 const{request}=fixture();assert.equal((await request('/account','GET',undefined,null)).status,401);assert.equal((await request('/account','GET',undefined,'forged.jwt.token')).status,401);assert.equal((await request('/chat','POST',turn,'expired.jwt.token')).status,401);
});
test('accounts default to no training and resolve identity only from the token',async()=>{
 const{request,records}=fixture();const a=await request();assert.equal(a.body.account.uid,'alice');assert.equal(a.body.account.improve,false);assert.equal(a.body.account.email,'alice@example.com');
 const b=await request('/account?uid=alice','GET',undefined,'user.b.token');assert.equal(b.body.account.uid,'bob');assert.equal(b.body.account.email,null);assert.equal(b.body.account.phoneNumber,'+12025550123');assert.equal(records.size,3); // one shared rate bucket plus two account records
});
test('preference updates cannot change another account or the model name',async()=>{
 const{request,records}=fixture();await request('/account','PATCH',{improve:true,uid:'bob',model:'fake'});assert.equal(records.get('nebulaAccounts/v1/'+accountKey('alice')).improve,true);assert.equal(records.has('nebulaAccounts/v1/'+accountKey('bob')),false);assert.equal((await request('/account','PATCH',{improve:'true'})).status,400);
});
test('server account preference blocks client-forged training consent until opted in',async()=>{
 const{request,records}=fixture();assert.equal((await request('/chat','POST',turn)).body.trainingSaved,false);assert.equal(records.has('nebulaTraining/v1/'+accountOwner('alice',0)),false);await request('/account','PATCH',{improve:true});assert.equal((await request('/chat','POST',turn)).body.trainingSaved,true);assert.equal(records.get('nebulaTraining/v1/'+accountOwner('alice',0)).count,1);
});
test('turning off sharing during an in-flight reply prevents its contribution',async()=>{
 let entered,finish;const ready=new Promise(r=>entered=r),model=new Promise(r=>finish=r);const{request,records}=fixture(async()=>{entered();return model;});await request('/account','PATCH',{improve:true});const pending=request('/chat','POST',turn);await ready;await request('/account','PATCH',{improve:false});finish('Late reply');assert.equal((await pending).body.trainingSaved,false);assert.equal(records.has('nebulaTraining/v1/'+accountOwner('alice',0)),false);
});
test('account training deletion revokes old generation and resets sharing without touching another user',async()=>{
 const{request,records}=fixture();await request('/account','PATCH',{improve:true});await request('/chat','POST',turn);await request('/account','PATCH',{improve:true},'user.b.token');await request('/chat','POST',turn,'user.b.token');
 assert.equal((await request('/training','DELETE',{})).body.deleted,true);const profile=records.get('nebulaAccounts/v1/'+accountKey('alice'));assert.equal(profile.improve,false);assert.equal(profile.trainingGeneration,1);assert.deepEqual(records.get('nebulaTraining/v1/'+accountOwner('alice',0)),{revoked:true});assert.equal(records.get('nebulaTraining/v1/'+accountOwner('bob',0)).count,1);
 await request('/account','PATCH',{improve:true});await request('/chat','POST',turn);assert.equal(records.get('nebulaTraining/v1/'+accountOwner('alice',1)).count,1);
});
test('authenticated CORS preflight supports account methods and bearer headers',async()=>{
 const{app}=fixture();const response=await app(new Request('https://api.scriptnovaa.com/api/nebula/account',{method:'OPTIONS',headers:{Origin:'https://scriptnovaa.com'}}));assert.equal(response.status,204);assert.match(response.headers.get('Access-Control-Allow-Headers'),/Authorization/);assert.match(response.headers.get('Access-Control-Allow-Methods'),/PATCH/);
});
