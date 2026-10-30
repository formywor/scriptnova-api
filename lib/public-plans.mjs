import {owner,developerConfig} from './developer.mjs';
export const PLANS=Object.freeze({normal:{name:'Normal',shortHours:10,shortLimit:150,weekLimit:750,models:['nebula-ultra','nebula-classic','nebula-v4','nebula-v1-lite','nebula-v2-1']},medium:{name:'Medium',shortHours:10,shortLimit:400,weekLimit:2000,models:['nebula-ultra','nebula-spark','nebula-duo','nebula-classic','nebula-v4','nebula-v1-lite','nebula-v2-1']},high:{name:'High',shortHours:1,shortLimit:150,weekLimit:5000,models:['nebula-ultra','nebula-spark','nebula-duo','nebula-classic','nebula-v4','nebula-v1-lite','nebula-v2-1']}});
export const WEEK=7*86400000;
export const planCatalog=()=>Object.entries(PLANS).map(([id,p])=>({id,...p,weekHours:168,duoCost:3,unlock:id==='normal'?'Available when you sign in':id==='medium'?'20 successful replies and an account age of 1 day':'150 successful replies and an account age of 7 days'}));
export function publicPlan(identity,profile,usage,time,grant,developerGrant){
 const replies=usage?.totalQuestions||0,age=Math.max(0,time-(profile?.createdAt||time)),isOwner=identity&&owner(identity,developerConfig()),restricted=grant?.status==='restricted';
 const automatic=replies>=150&&age>=WEEK?'high':replies>=20&&age>=86400000?'medium':'normal';
 const tier=isOwner?'high':restricted?'normal':Object.hasOwn(PLANS,grant?.tier)?grant.tier:automatic;
 const invited=identity?.email_verified===true&&developerGrant?.tier==='invite'&&developerGrant?.status==='active'&&!restricted;
 return {tier,...PLANS[tier],models:[...PLANS[tier].models.filter(m=>m!=='nebula-d2'),...(isOwner||invited?['nebula-d2']:[])],standing:restricted?'restricted':'good',owner:!!isOwner,automaticTier:automatic,successfulReplies:replies,accountAgeDays:Math.floor(age/86400000),progress:{medium:{replies:20,ageDays:1},high:{replies:150,ageDays:7}},plans:planCatalog()};
}
function freshWindow(value,time,duration){return value&&time-value.started<duration?value:{started:time,used:0};}
function giftUsed(state,window,name,time){const g=state?.gift;return Math.max(0,window.used-(g?.expiresAt>time&&g[name+'Started']===window.started?g[name+'Used']||0:0));}
export function planUsage(state,time,tier){const p=PLANS[tier]||PLANS.normal,short=freshWindow(state?.short,time,p.shortHours*3600000),week=freshWindow(state?.week,time,WEEK);const pending=Object.values(state?.pending||{}).filter(x=>time-x.at<120000).reduce((n,x)=>n+x.cost,0);return {tier,unit:'credits',gift:state?.gift?.expiresAt>time?state.gift:null,short:{used:giftUsed(state,short,'short',time),limit:p.shortLimit,remaining:Math.max(0,p.shortLimit-giftUsed(state,short,'short',time)-pending),resetsAt:short.started+p.shortHours*3600000,hours:p.shortHours},week:{used:giftUsed(state,week,'week',time),limit:p.weekLimit,remaining:Math.max(0,p.weekLimit-giftUsed(state,week,'week',time)-pending),resetsAt:week.started+WEEK,hours:168},costs:{standard:1,duo:3,image:4,voice:2,cloudAction:4,cloudTask:5},pending};}
export function createPlanStore(db){const path=k=>'nebulaPublicPlans/v1/'+k;return {
 async publicGrant(k){return (await db.ref('nebulaPublicGrants/v1/'+k).get()).val();},
 async setPublicGrant(k,value){await db.ref('nebulaPublicGrants/v1/'+k).transaction(old=>({...value,audit:[...(old?.audit||[]),{by:value.by,at:value.at,tier:value.tier,status:value.status,reason:value.reason}].slice(-50)}),undefined,false);},
 async planUsage(k,time,tier){return planUsage((await db.ref(path(k)).get()).val(),time,tier);},
 async reservePlan(k,id,time,tier,model,extraCost=0){let reason='PLAN_LIMIT',resetAt=null;const cost=(model==='nebula-duo'?3:1)+Math.max(0,Math.min(24,Number.isInteger(extraCost)?extraCost:0)),p=PLANS[tier];const r=await db.ref(path(k)).transaction(old=>{
  const state=old||{};state.short=state.tier===tier?freshWindow(state.short,time,p.shortHours*3600000):{started:time,used:0};state.week=freshWindow(state.week,time,WEEK);state.tier=tier;state.pending||={};state.completed||={};
  for(const [key,v] of Object.entries(state.pending))if(time-v.at>=120000)delete state.pending[key];
  if(state.pending[id]||state.completed[id]){reason='DUPLICATE_TURN';return;}
  const pending=Object.values(state.pending).reduce((n,v)=>n+v.cost,0);
  if(giftUsed(state,state.week,'week',time)+pending+cost>p.weekLimit){resetAt=state.week.started+WEEK;return;}
  if(giftUsed(state,state.short,'short',time)+pending+cost>p.shortLimit){resetAt=state.short.started+p.shortHours*3600000;return;}
  state.pending[id]={at:time,cost};return state;
 },undefined,false);return {allowed:r.committed,reason,resetAt,usage:planUsage(r.snapshot.val(),time,tier)};},
 async finishPlan(k,id,time,success,actualCost=null){await db.ref(path(k)).transaction(s=>{if(!s?.pending?.[id])return s??null;const pending=s.pending[id];delete s.pending[id];if(success){const cost=Number.isInteger(actualCost)&&actualCost>=1&&actualCost<=pending.cost?actualCost:pending.cost;s.short.used+=cost;s.week.used+=cost;s.completed||={};s.completed[id]=time;for(const id of Object.keys(s.completed).slice(0,-1000))delete s.completed[id];}return s;},undefined,false);}
};}
