import {createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
import {authenticate,accountKey} from './accounts.mjs';
import {configFromEnv} from './app.mjs';

const plans=new Set(['nebula-plus','nebula-d2-api']);
const creditPackages=new Set(['nebula-credits-500']);
const priceFor=(config,plan)=>plan==='nebula-plus'?config.stripePlusPrice:config.stripeD2ApiPrice;
const fail=(code,status=400)=>{throw Object.assign(Error(code),{code,status});};
function safeOrigin(request,config){const origin=request.headers.get('origin');return !origin||config.origins.includes(origin);}
function signatureValid(body,header,secret,time){
 if(typeof header!=='string'||typeof secret!=='string'||!secret)return false;
 const fields=Object.fromEntries(header.split(',').map(x=>x.split('=',2)));
 const stamp=Number(fields.t),supplied=fields.v1;
 if(!Number.isSafeInteger(stamp)||Math.abs(time/1000-stamp)>300||!supplied||!/^[a-f0-9]{64}$/i.test(supplied))return false;
 const expected=createHmac('sha256',secret).update(String(stamp)+'.').update(body).digest();
 let received;try{received=Buffer.from(supplied,'hex');}catch{return false;}
 return received.length===expected.length&&timingSafeEqual(received,expected);
}
async function stripeRequest(path,params,config,fetcher=fetch){
 if(!config.stripeSecret)fail('BILLING_UNAVAILABLE',503);
 const response=await fetcher('https://api.stripe.com/v1/'+path,{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+config.stripeSecret,'Content-Type':'application/x-www-form-urlencoded','Idempotency-Key':params.__idempotency||randomUUID()},body:new URLSearchParams(Object.entries(params).filter(([k])=>k!=='__idempotency'))});
 let data;try{data=await response.json();}catch{fail('BILLING_UNAVAILABLE',503);}
 if(!response.ok)fail('BILLING_UNAVAILABLE',503);return data;
}
function planFromSubscription(subscription,config){const ids=new Set((subscription.items?.data||[]).map(x=>x.price?.id));if(config.stripePlusPrice&&ids.has(config.stripePlusPrice))return 'nebula-plus';if(config.stripeD2ApiPrice&&ids.has(config.stripeD2ApiPrice))return 'nebula-d2-api';return null;}
export function createBillingHandler({getStore,verifyToken,config={...configFromEnv(),stripeSecret:process.env.STRIPE_SECRET_KEY||'',stripeWebhookSecret:process.env.STRIPE_WEBHOOK_SECRET||'',stripePlusPrice:process.env.STRIPE_PRICE_NEBULA_PLUS||'',stripeD2ApiPrice:process.env.STRIPE_PRICE_NEBULA_D2_API||'',stripeCreditsPrice:process.env.STRIPE_PRICE_NEBULA_CREDITS_500||'',d2Key:process.env.NEBULA_D2_API_KEY||''},now=Date.now,fetcher=fetch}={}){return async request=>{
 const url=new URL(request.url),path=url.pathname,origin=request.headers.get('origin'),headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Vary':'Origin',...(origin&&config.origins.includes(origin)?{'Access-Control-Allow-Origin':origin}:{})};
 const reply=(status,data)=>new Response(JSON.stringify(data),{status,headers});
 if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type'}});
 try{
  if(path==='/api/nebula/billing/webhook'){
   if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
   const raw=Buffer.from(await request.arrayBuffer());if(raw.length>1024*1024)fail('REQUEST_TOO_LARGE',413);
   if(!signatureValid(raw,request.headers.get('stripe-signature'),config.stripeWebhookSecret,now()))fail('INVALID_WEBHOOK_SIGNATURE',400);
   let event;try{event=JSON.parse(raw.toString('utf8'));}catch{fail('INVALID_WEBHOOK',400);}
   if(!event||typeof event.id!=='string'||!Number.isSafeInteger(event.created)||!event.data?.object)fail('INVALID_WEBHOOK',400);
   const store=await getStore();if(await store.billingEventSeen(event.id))return reply(200,{received:true,duplicate:true});
   const subscription=event.data.object;
   if(['customer.subscription.created','customer.subscription.updated','customer.subscription.deleted'].includes(event.type)){
    const plan=planFromSubscription(subscription,config),uid=subscription.metadata?.nebulaUid;
    if(plan&&typeof uid==='string'&&uid.length<=128){const status=event.type==='customer.subscription.deleted'?'canceled':String(subscription.status||'unknown');await store.billingUpdate(accountKey(uid),plan,{...subscription,status},event);}
   }
   if(['checkout.session.completed','checkout.session.async_payment_succeeded'].includes(event.type)){
    const session=event.data.object,uid=session.metadata?.nebulaUid,pkg=session.metadata?.nebulaCreditPackage;
    if(session.mode==='payment'&&session.payment_status==='paid'&&session.currency==='usd'&&creditPackages.has(pkg)&&typeof uid==='string'&&uid.length<=128&&typeof session.id==='string'&&Number(session.amount_total)===499){
     if(!store.billingGrantCredits)fail('BILLING_UNAVAILABLE',503);
     await store.billingGrantCredits(uid,500,session.id,event.id,now());
     if(typeof session.customer==='string')await store.billingSaveCustomer(accountKey(uid),session.customer);
    }
   }
   await store.billingMarkEvent(event.id,now());return reply(200,{received:true});
  }
  if(!safeOrigin(request,config))fail('FORBIDDEN',403);
  const identity=await authenticate(request,verifyToken);if(!identity)fail('UNAUTHORIZED',401);if(identity.email_verified!==true||!identity.email)fail('VERIFIED_EMAIL_REQUIRED',403);
  const store=await getStore(),owner=accountKey(identity.uid);
  if(path==='/api/nebula/billing/status'&&request.method==='GET'){
   const access=await store.billingAccess(identity.uid,now());return reply(200,{plans:{nebulaPlus:access.nebulaPlus,d2Api:access.d2Api},credits:access.credits||0,checkoutAvailable:{'nebula-plus':Boolean(config.stripeSecret&&config.stripeWebhookSecret&&config.stripePlusPrice),'nebula-d2-api':Boolean(config.stripeSecret&&config.stripeWebhookSecret&&config.stripeD2ApiPrice&&config.d2Key),'nebula-credits-500':Boolean(config.stripeSecret&&config.stripeWebhookSecret&&config.stripeCreditsPrice)},customerPortalAvailable:Boolean(access.customerId)});
  }
  if(path==='/api/nebula/billing/checkout'&&request.method==='POST'){
   if(!await store.allow('billing_'+owner,now(),'write'))fail('RATE_LIMITED',429);
   let body;try{body=await request.json();}catch{fail('INVALID_INPUT');}
   if(!body||Array.isArray(body)||Object.keys(body).some(k=>k!=='plan'&&k!=='package')||Boolean(body.plan)===Boolean(body.package))fail('INVALID_INPUT');
   const access=await store.billingAccess(identity.uid,now());
   if(body.package){if(!creditPackages.has(body.package))fail('INVALID_INPUT');const price=config.stripeCreditsPrice;if(!price||!/^price_[A-Za-z0-9]+$/.test(price)||!config.stripeWebhookSecret)fail('CREDITS_UNAVAILABLE',503);const params={'mode':'payment','line_items[0][price]':price,'line_items[0][quantity]':'1','client_reference_id':identity.uid,...(access.customerId?{customer:access.customerId}:{customer_email:identity.email}),'metadata[nebulaUid]':identity.uid,'metadata[nebulaCreditPackage]':body.package,'success_url':'https://scriptnovaa.com/?billing=credits-success#usage','cancel_url':'https://scriptnovaa.com/?billing=credits-cancel#usage','__idempotency':randomUUID()};const session=await stripeRequest('checkout/sessions',params,config,fetcher);if(typeof session.url!=='string'||!session.url.startsWith('https://checkout.stripe.com/'))fail('BILLING_UNAVAILABLE',503);return reply(200,{url:session.url});}
   if(!plans.has(body.plan))fail('INVALID_INPUT');
   if(access[body.plan==='nebula-plus'?'nebulaPlus':'d2Api'])fail('ALREADY_SUBSCRIBED',409);
   const price=priceFor(config,body.plan);if(!price||!/^price_[A-Za-z0-9]+$/.test(price)||!config.stripeWebhookSecret||body.plan==='nebula-d2-api'&&!config.d2Key)fail('PLAN_UNAVAILABLE',503);
   const params={'mode':'subscription','line_items[0][price]':price,'line_items[0][quantity]':'1','client_reference_id':identity.uid,...(access.customerId?{customer:access.customerId}:{customer_email:identity.email}),'metadata[nebulaUid]':identity.uid,'metadata[nebulaPlan]':body.plan,'subscription_data[metadata][nebulaUid]':identity.uid,'subscription_data[metadata][nebulaPlan]':body.plan,'success_url':'https://scriptnovaa.com/developers/?billing=success#usage','cancel_url':'https://scriptnovaa.com/developers/?billing=cancel#usage','allow_promotion_codes':'true','__idempotency':randomUUID()};
   const session=await stripeRequest('checkout/sessions',params,config,fetcher);if(typeof session.url!=='string'||!session.url.startsWith('https://checkout.stripe.com/'))fail('BILLING_UNAVAILABLE',503);return reply(200,{url:session.url});
  }
  if(path==='/api/nebula/billing/portal'&&request.method==='POST'){
   const access=await store.billingAccess(identity.uid,now());if(!access.customerId)fail('BILLING_CUSTOMER_NOT_FOUND',404);
   const session=await stripeRequest('billing_portal/sessions',{customer:access.customerId,return_url:'https://scriptnovaa.com/plans/'},config,fetcher);if(typeof session.url!=='string'||!session.url.startsWith('https://billing.stripe.com/'))fail('BILLING_UNAVAILABLE',503);return reply(200,{url:session.url});
  }
  fail('NOT_FOUND',404);
 }catch(error){return reply(error.status||503,{code:/^[A-Z_]+$/.test(error.code||'')?error.code:'BILLING_UNAVAILABLE'});}
};}
