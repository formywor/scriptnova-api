import {createHash,randomBytes} from 'node:crypto';
const hash=s=>createHash('sha256').update(s).digest('hex');
const fail=(code,status=400)=>{throw Object.assign(Error(code),{code,status});};
export const BOOST_FIELDS=['requestsPerMinute','requestsPerDay','tokensPerDay','maxMessages','maxOutputTokens'];
export function validateBenefit(b,time){
 if(!b||Object.keys(b).some(k=>!['code','boosts','expiresAt','maxRedemptions','label'].includes(k))||typeof b.code!=='string'||!/^[-A-Za-z0-9]{6,40}$/.test(b.code)||typeof b.label!=='string'||!b.label.trim()||b.label.length>80||!Number.isInteger(b.expiresAt)||b.expiresAt<time+60000||b.expiresAt>time+366*86400000||!Number.isInteger(b.maxRedemptions)||b.maxRedemptions<1||b.maxRedemptions>10000||!b.boosts||Array.isArray(b.boosts)||Object.keys(b.boosts).some(k=>!BOOST_FIELDS.includes(k))||!Object.values(b.boosts).some(v=>v>0))fail('INVALID_CODE');
 for(const v of Object.values(b.boosts))if(!Number.isInteger(v)||v<0||v>120)fail('INVALID_BOOST');
 return {...b,code:b.code.toUpperCase(),label:b.label.trim()};
}
export function effectiveApiLimits(base,benefit,time){
 const limits={...base};if(!benefit||benefit.disabled||benefit.expiresAt<=time)return limits;
 for(const field of BOOST_FIELDS){const percent=benefit.boosts?.[field]||0;if(Number.isInteger(percent)&&percent>=0&&percent<=120)limits[field]=Math.floor(base[field]*(1+percent/100));}
 // Input bytes grow alongside message-history allowance, but service capacity never changes.
 limits.maxInputBytes=Math.floor(base.maxInputBytes*(1+Math.min(120,benefit.boosts?.maxMessages||0)/100));return limits;
}
export function createBenefitsStore(db){const base='nebulaDeveloperBenefits/v1';return {
 async benefit(owner,time){const pointer=(await db.ref(base+'/accounts/'+owner+'/codeId').get()).val();if(!pointer)return null;const code=((await db.ref(base+'/index').get()).val()||{})[pointer];return code&&!code.disabled&&code.expiresAt>time?{label:code.label,expiresAt:code.expiresAt,boosts:code.boosts}:null;},
 async benefitCodes(){return Object.values((await db.ref(base+'/index').get()).val()||{});},
 async createBenefit(body,actor,time){const b=validateBenefit(body,time),id=hash(b.code),record={id,label:b.label,boosts:b.boosts,expiresAt:b.expiresAt,maxRedemptions:b.maxRedemptions,createdAt:time,by:actor,disabled:false,claims:{}};
  const {claims,...summary}=record;const index=db.ref(base+'/index');const r=await index.transaction(old=>{const codes=old||{};if(codes[id])return;if(Object.keys(codes).length>=100)return;codes[id]={...summary,redeemed:0};return codes;},undefined,false);if(!r.committed)fail('CODE_EXISTS_OR_LIMIT',409);try{await db.ref(base+'/codes/'+id).set(record);}catch(error){await index.transaction(old=>{if(old)delete old[id];return old;},undefined,false);throw error;}return {id,label:b.label,code:b.code,expiresAt:b.expiresAt,boosts:b.boosts};},
 async disableBenefit(id,actor,time){if(!/^[a-f0-9]{64}$/.test(id))fail('INVALID_CODE');const ref=db.ref(base+'/codes/'+id),existing=(await ref.get()).val();const r=await ref.transaction(old=>{const c=old||existing;return c?{...c,disabled:true,disabledAt:time,disabledBy:actor}:undefined;},undefined,false);if(!r.committed)fail('CODE_NOT_FOUND',404);await db.ref(base+'/index').transaction(old=>{const s=old||{};if(s[id])s[id]={...s[id],disabled:true,disabledAt:time};return s;},undefined,false);},
 async redeemBenefit(owner,input,time){if(typeof input!=='string'||!/^[-A-Za-z0-9]{6,40}$/.test(input.trim()))fail('CODE_INVALID_OR_EXPIRED');const id=hash(input.trim().toUpperCase());
  const ref=db.ref(base+'/codes/'+id),existing=(await ref.get()).val();const r=await ref.transaction(old=>{const c=old||existing;if(!c||c.disabled||c.expiresAt<=time)return;c.claims||={};if(!c.claims[owner]&&Object.keys(c.claims).length>=c.maxRedemptions)return;c.claims[owner]||={at:time};return c;},undefined,false);if(!r.committed)fail('CODE_INVALID_OR_EXPIRED');const redeemed=Object.keys(r.snapshot.val().claims||{}).length;await db.ref(base+'/index').transaction(old=>{const s=old||{};if(s[id])s[id].redeemed=Math.max(s[id].redeemed||0,redeemed);return s;},undefined,false);await db.ref(base+'/accounts/'+owner+'/codeId').set(id);return this.benefit(owner,time);},
 async resetGift(owner,scope,expiresAt,actor,time){if(!['api','website','both'].includes(scope)||!Number.isInteger(expiresAt)||expiresAt<time+60000||expiresAt>time+90*86400000)fail('INVALID_RESET');const id=randomBytes(12).toString('hex'),result={id,scope,createdAt:time,expiresAt,by:actor};
  // Offsets preserve accounting, pending reservations, and historical metrics.
  if(scope==='api'||scope==='both')await db.ref('nebulaDeveloperApi/v1/usage/'+owner).transaction(old=>{const s=old||{};s.gift={...result,day:s.day??Math.floor(time/86400000),minute:s.minute??Math.floor(time/60000),requests:s.requests||0,tokens:s.tokens||0,minuteRequests:s.minuteRequests||0};return s;},undefined,false);
  if(scope==='website'||scope==='both')await db.ref('nebulaPublicPlans/v1/'+owner).transaction(old=>{const s=old||{};s.gift={...result,shortStarted:s.short?.started??null,weekStarted:s.week?.started??null,shortUsed:s.short?.used||0,weekUsed:s.week?.used||0};return s;},undefined,false);
  await db.ref(base+'/gifts/'+owner).transaction(old=>[...(old||[]),result].slice(-20),undefined,false);return result;
 }
};}
