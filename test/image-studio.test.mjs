import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createImageHandler,renderImage} from '../lib/image-studio.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {accountKey} from '../lib/accounts.mjs';
const png='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZ8sAAAAASUVORK5CYII=';
const config={origins:['https://scriptnovaa.com'],openAccountId:'a'.repeat(32),openKey:'private-test',ultraKey:'moderation-test'};
function fixture(generate=async()=>({data:png,operation:'create'})){
 const {db,records}=memoryDatabase({coldTransactions:true}),original=db.ref;
 db.ref=path=>{const ref=original(path);return {...ref,async get(){if(records.has(path))return ref.get();const bits=path.split('/');let value;for(let i=bits.length-1;i>0;i--){const p=bits.slice(0,i).join('/');if(records.has(p)){value=records.get(p);for(const k of bits.slice(i))value=value?.[k];break;}}return {val:()=>structuredClone(value??null)};}};};
 const store=createStore(db);let verified=true,calls=0;
 const handler=createImageHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice',email:'alice@example.test',email_verified:verified}),config,now:()=>1700000000000,generate:async b=>{calls++;return generate(b);}});
 const body={id:randomUUID(),prompt:'A watercolor mountain',operation:'create',modelId:'nebula-ultra'};
 const request=(b=body,token=true,method='POST')=>handler(new Request('https://api.scriptnovaa.com/api/nebula/images',{method,headers:{Origin:'https://scriptnovaa.com','Content-Type':'application/json',...(token?{Authorization:'Bearer alice.valid.token'}:{})},...(method==='POST'?{body:JSON.stringify(b)}:{})}));
 return {request,store,body,records,get calls(){return calls;},unverify(){verified=false;}};
}
test('image service requires verified sign-in and refuses Lite / unsupported inputs',async()=>{
 const f=fixture();assert.equal((await f.request(undefined,false)).status,401);f.unverify();assert.equal((await f.request()).status,403);
 const g=fixture();assert.equal((await g.request({...g.body,modelId:'nebula-d2-lite'})).status,400);assert.equal((await g.request({...g.body,operation:'edit'})).status,400);assert.equal(g.calls,0);
});
test('image retries are idempotent and successful work consumes the advertised allowance once',async()=>{
 const f=fixture(),r=await f.request();assert.equal(r.status,200);assert.equal((await r.json()).cost,8);assert.equal((await f.request()).status,200);assert.equal(f.calls,1);
 assert.equal((await f.store.planUsage(accountKey('alice'),1700000000000,'normal')).short.used,8);
 assert.equal((await f.request({...f.body,prompt:'Different prompt same id'})).status,400);
});
test('unavailable or policy-blocked image requests release reserved credits',async()=>{
 const f=fixture(async()=>{throw Object.assign(Error('Blocked'),{code:'IMAGE_POLICY_BLOCKED',status:422});});assert.equal((await f.request()).status,422);assert.equal((await f.store.planUsage(accountKey('alice'),1700000000000,'normal')).short.used,0);assert.equal((await f.store.planUsage(accountKey('alice'),1700000000000,'normal')).pending,0);
});
test('native image generation sends private server credentials, bounded output and multipart parameters',async()=>{
 let calls=0;const r=await renderImage({prompt:'A cozy room',operation:'create'},config,{fetcher:async(url,init)=>{calls++;if(calls===1)return Response.json({choices:[{message:{content:'{"allow":true}'}}]});assert.match(url,/flux-2-klein-4b$/);assert.ok(init.body instanceof FormData);assert.equal(init.body.get('width'),'512');assert.equal(init.body.get('prompt'),'A cozy room');assert.equal(init.headers.Authorization,'Bearer private-test');return Response.json({result:{image:png.split(',')[1]}});}});assert.equal(r.data,png);
});
