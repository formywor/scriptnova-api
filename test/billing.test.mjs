import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {createBillingHandler} from '../lib/billing.mjs';

function fixture(){
 const {db}=memoryDatabase({coldTransactions:true}),store=createStore(db),time=1_800_000_000_000;
 const config={origins:['https://scriptnovaa.com'],stripeSecret:'sk_test_example',stripeWebhookSecret:'whsec_example',stripePlusPrice:'price_plus',stripeD2ApiPrice:'price_d2',stripeCreditsPrice:'price_credits'},stripeRequests=[];
 const handler=createBillingHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice',email:'alice@example.com',email_verified:true}),config,now:()=>time,fetcher:async(url,init)=>{assert.match(url,/^https:\/\/api\.stripe\.com\/v1\//);assert.equal(init.headers.Authorization,'Bearer sk_test_example');stripeRequests.push({url,params:Object.fromEntries(new URLSearchParams(init.body))});return Response.json({url:'https://checkout.stripe.com/c/pay/example'});}});
 const request=async(path,{method='GET',body,headers={}}={})=>{const response=await handler(new Request('https://api.scriptnovaa.com'+path,{method,headers:{Origin:'https://scriptnovaa.com',Authorization:'Bearer testtoken123',...(body?{'Content-Type':'application/json'}:{}),...headers},...(body?{body:JSON.stringify(body)}:{})}));return {status:response.status,data:await response.json()};};
 return {db,store,time,request,config,handler,stripeRequests};
}
test('billing requires a verified signed-in account and only accepts known plan identifiers',async()=>{
 const f=fixture();assert.equal((await f.request('/api/nebula/billing/status',{headers:{Authorization:''}})).status,401);
 assert.equal((await f.request('/api/nebula/billing/checkout',{method:'POST',body:{plan:'arbitrary'}})).status,400);
 const result=await f.request('/api/nebula/billing/checkout',{method:'POST',body:{plan:'nebula-plus'}});assert.equal(result.status,200);assert.match(result.data.url,/^https:\/\/checkout\.stripe\.com\//);
});
test('signed Stripe subscription event enables only the mapped account plan and deduplicates',async()=>{
 const f=fixture(),owner=accountKey('alice'),event={id:'evt_one',type:'customer.subscription.updated',created:1700000000,data:{object:{id:'sub_1',customer:'cus_1',status:'active',current_period_end:Math.floor(f.time/1000)+3600,cancel_at_period_end:false,metadata:{nebulaUid:'alice'},items:{data:[{price:{id:'price_plus'}}]}}}};
 const body=Buffer.from(JSON.stringify(event)),stamp=Math.floor(f.time/1000),sig=createHmac('sha256',f.config.stripeWebhookSecret).update(String(stamp)+'.').update(body).digest('hex');
 const send=()=>f.handler(new Request('https://api.scriptnovaa.com/api/nebula/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${sig}`},body}));
 assert.equal((await send()).status,200);assert.equal((await f.store.billingAccess('alice',f.time)).nebulaPlus,true);assert.equal((await send()).status,200);assert.equal((await f.store.billingRecord(owner)).plans['nebula-plus'].currentPeriodEnd,f.time+3600000);
});
test('billing webhook rejects invalid signatures',async()=>{
 const f=fixture(),response=await f.handler(new Request('https://api.scriptnovaa.com/api/nebula/billing/webhook',{method:'POST',headers:{'Stripe-Signature':'t=1,v1=00'},body:'{}'}));assert.equal(response.status,400);assert.equal((await response.json()).code,'INVALID_WEBHOOK_SIGNATURE');
});
test('one-time credit checkout is allowlisted and only a paid signed event grants credits once',async()=>{
 const f=fixture(),checkout=await f.request('/api/nebula/billing/checkout',{method:'POST',body:{package:'nebula-credits-500'}});assert.equal(checkout.status,200);assert.equal(f.stripeRequests[0].params['mode'],'payment');assert.equal(f.stripeRequests[0].params['line_items[0][price]'],'price_credits');assert.equal(f.stripeRequests[0].params['metadata[nebulaCreditPackage]'],'nebula-credits-500');assert.equal(f.stripeRequests[0].params['metadata[nebulaUid]'],'alice');
 const event={id:'evt_credit_paid',type:'checkout.session.completed',created:1700000000,data:{object:{id:'cs_test_123',mode:'payment',payment_status:'paid',currency:'usd',amount_total:499,customer:'cus_credits',metadata:{nebulaUid:'alice',nebulaCreditPackage:'nebula-credits-500'}}}},body=Buffer.from(JSON.stringify(event)),stamp=Math.floor(f.time/1000),sig=createHmac('sha256',f.config.stripeWebhookSecret).update(String(stamp)+'.').update(body).digest('hex'),send=()=>f.handler(new Request('https://api.scriptnovaa.com/api/nebula/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${sig}`},body}));assert.equal((await send()).status,200);assert.equal((await send()).status,200);assert.equal((await f.store.billingAccess('alice',f.time)).credits,500);
 const key=accountKey('alice'),limit='nebulaPublicPlans/v1/'+key;await f.db.ref(limit).transaction(s=>({...s,short:{started:f.time,used:150},week:{started:f.time,used:750},tier:'normal'}),undefined,false);const reserve=await f.store.reservePlan(key,'paid-credit-use',f.time,'normal','nebula-ultra');assert.equal(reserve.allowed,true);await f.store.finishPlan(key,'paid-credit-use',f.time,true,1);assert.equal((await f.store.billingAccess('alice',f.time)).credits,499);
});
