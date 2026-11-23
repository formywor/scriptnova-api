import {accountKey} from './accounts.mjs';

const active=(value,time)=>value?.status==='active'&&Number.isSafeInteger(value.currentPeriodEnd)&&value.currentPeriodEnd>time;
export function createBillingStore(db){
 const base='nebulaBilling/v1';
 const userPath=uid=>base+'/users/'+accountKey(uid);
 return {
  async billingAccess(uid,time){const value=(await db.ref(userPath(uid)).get()).val()||{},usage=(await db.ref('nebulaPublicPlans/v1/'+accountKey(uid)).get()).val()||{};const plans=value.plans||{};return {nebulaPlus:active(plans['nebula-plus'],time),d2Api:active(plans['nebula-d2-api'],time),credits:Math.max(0,Number(usage.purchasedCredits)||0),customerId:typeof value.customerId==='string'?value.customerId:null,plans};},
  async billingAccessByOwner(owner,time){const value=(await db.ref(base+'/users/'+owner).get()).val()||{};const plans=value.plans||{};return {nebulaPlus:active(plans['nebula-plus'],time),d2Api:active(plans['nebula-d2-api'],time),plans};},
  async billingRecord(owner){return (await db.ref(base+'/users/'+owner).get()).val()||{};},
  async billingSaveCustomer(owner,customerId){if(typeof customerId!=='string'||!/^cus_[A-Za-z0-9]+$/.test(customerId))return false;await db.ref(base+'/users/'+owner).transaction(old=>({...old,customerId}),undefined,false);return true;},
  async billingGrantCredits(uid,amount,sessionId,eventId,time){if(!Number.isSafeInteger(amount)||amount<1||amount>5000||typeof sessionId!=='string'||!/^cs_[A-Za-z0-9_]+$/.test(sessionId))return false;const result=await db.ref('nebulaPublicPlans/v1/'+accountKey(uid)).transaction(old=>{const value=old||{},sessions=value.creditSessions||{};if(sessions[sessionId])return value;sessions[sessionId]={amount,eventId,at:time};for(const id of Object.keys(sessions).slice(0,-1000))delete sessions[id];return {...value,purchasedCredits:Math.min(1000000,Math.max(0,Number(value.purchasedCredits)||0)+amount),creditSessions:sessions};},undefined,false);return result.committed;},
  async billingUpdate(owner,plan,subscription,event){
   if(!['nebula-plus','nebula-d2-api'].includes(plan))return false;
   await db.ref(base+'/users/'+owner).transaction(old=>{const value=old||{},plans=value.plans||{},prior=plans[plan];if(prior&&prior.eventCreated>event.created)return value;plans[plan]={subscriptionId:subscription.id,customerId:subscription.customer,status:subscription.status,currentPeriodEnd:(Number(subscription.current_period_end)||0)*1000,cancelAtPeriodEnd:subscription.cancel_at_period_end===true,eventCreated:event.created,eventId:event.id};return {...value,customerId:subscription.customer||value.customerId,plans};},undefined,false);return true;
  },
  async billingEventSeen(id){return Boolean((await db.ref(base+'/events/'+id).get()).val());},
  async billingMarkEvent(id,time){await db.ref(base+'/events/'+id).set({at:time});}
 };
}
