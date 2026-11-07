import {test} from 'node:test';
import assert from 'node:assert/strict';
import {accountKey} from '../lib/accounts.mjs';
import {createApp} from '../lib/app.mjs';
import {createDeveloperApiHandler} from '../lib/developer-api.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';

const day=86400000,time=30*day+123000,expiresAt=time+120000;
const owner={uid:'owner',email:'divedyacoub9@gmail.com',email_verified:true};
const alice={uid:'alice',email:'alice@example.com',email_verified:true};
const bob={uid:'bob',email:'bob@example.com',email_verified:true};

function fixture(){
 const {db}=memoryDatabase({coldTransactions:true}),store=createStore(db);
 let identity=owner,clock=time;
 const config={origins:[],rateSecret:'x'.repeat(40),publicTiers:true,openAccountId:'a'.repeat(32),openKey:'test'};
 const options={getStore:async()=>store,verifyToken:async()=>identity,now:()=>clock,config,log:()=>{}};
 const app=createApp(options),developer=createDeveloperApiHandler({...options,lookupUser:async email=>email===alice.email?alice:null});
 return {db,store,user:id=>{identity=id;},clock:t=>{clock=t;},async call(path,body){
  const headers={'Content-Type':'application/json',...(identity?{Authorization:'Bearer test.user.token'}:{})};
  const request=new Request('https://api.test/api/nebula'+path,{method:body?'POST':'GET',headers,...(body?{body:JSON.stringify(body)}:{})});
  const response=await (path.startsWith('/developer-platform')?developer:app)(request);
  return {status:response.status,body:await response.json()};
 }};
}

test('owner offers by verified email, users claim once, and expiry never restores spent credits',async()=>{
 const f=fixture(),key=accountKey(alice.uid);
 await f.db.ref('nebulaPublicPlans/v1/'+key).set({tier:'normal',short:{started:time,used:90},week:{started:time,used:200},pending:{},completed:{prior:time}});
 const offered=await f.call('/developer-platform/reset-offers',{audience:'email',email:alice.email,scopes:['website','open'],expiresAt});
 assert.equal(offered.status,201);
 const {id}=offered.body.gift;
 f.user(bob);
 assert.deepEqual((await f.call('/usage')).body.resetGifts,[]);
 assert.equal((await f.call('/reset-gifts',{id})).status,404);
 assert.equal((await f.call('/developer-platform/reset-offers',{audience:'all',scopes:['api'],expiresAt})).status,403);
 f.user(null);
 assert.equal((await f.call('/reset-gifts',{id})).status,401);
 f.user(alice);
 const usage=await f.call('/usage');
 assert.equal(usage.body.limits.short.remaining,60);
 assert.deepEqual(usage.body.resetGifts,[{id,expiresAt,scopes:['website','open']}]);
 await Promise.all([f.call('/reset-gifts',{id}),f.call('/reset-gifts',{id})]).then(results=>assert.ok(results.every(r=>r.status===200)));
 assert.equal((await f.store.planUsage(key,time,'normal')).short.remaining,150);
 assert.equal((await f.store.reservePlan(key,'new',time,'normal','nebula-ultra')).allowed,true);
 await f.store.finishPlan(key,'new',time,true);
 assert.equal((await f.call('/reset-gifts',{id})).status,200);
 f.clock(expiresAt+1);
 assert.equal((await f.store.planUsage(key,expiresAt+1,'normal')).short.remaining,149);
 assert.equal((await f.store.planUsage(key,expiresAt+1,'normal')).week.remaining,749);
 assert.deepEqual((await f.call('/usage')).body.resetGifts,[]);
});

test('group offers follow current tier and optional Open reset leaves shared API accounting intact',async()=>{
 const f=fixture(),key=accountKey(alice.uid);
 await f.store.setPublicGrant(key,{tier:'medium',status:'active',reason:'Test grant',at:time,by:'owner'});
 await f.store.developerSetGrant(alice.email,{tier:'invite',status:'active',reason:'Preview test',by:'owner',at:time});
 await f.db.ref('nebulaDeveloperApi/v1/usage/'+key).set({day:Math.floor(time/day),minute:Math.floor(time/60000),requests:27,tokens:1033,minuteRequests:2,pending:{},metrics:{},logs:[]});
 for(let i=0;i<120;i++)assert.equal(await f.store.consumeOpenCall(key,time),true);
 assert.equal(await f.store.consumeOpenCall(key,time),false);
 const {body:{gift}}=await f.call('/developer-platform/reset-offers',{audience:'medium-high',scopes:['api','open'],expiresAt});
 const {body:{gift:open}}=await f.call('/developer-platform/reset-offers',{audience:'all',scopes:['open'],expiresAt});
 f.user(bob);
 assert.deepEqual((await f.call('/usage')).body.resetGifts,[{id:open.id,expiresAt,scopes:['open']}]);
 f.user(alice);
 assert.equal((await f.call('/usage')).body.resetGifts.length,2);
 assert.equal((await f.call('/reset-gifts',{id:gift.id})).status,200);
 const api=await f.store.apiUsage(key,time);
 assert.equal(api.requests,0);assert.equal(api.tokens,0);assert.equal(api.totalRequestsToday,27);
 assert.equal(await f.store.consumeOpenCall(key,time),true);
 assert.equal((await f.call('/reset-gifts',{id:gift.id})).status,200);
 const current=(await f.db.ref('nebulaOpenUsage/v1/'+key).get()).val();
 assert.equal(current.calls,1);
 f.clock(expiresAt+1);
 assert.equal((await f.call('/reset-gifts',{id:open.id})).status,404);
 assert.equal((await f.store.apiUsage(key,expiresAt+1)).requests,0);
});
