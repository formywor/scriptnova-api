import {randomBytes} from 'node:crypto';

const DAY=86400000;
const MINUTE=60000;
const BASE='nebulaResetOffers/v1';
const audiences=['email','all','normal','medium','high','medium-high'];
const resetScopes=['website','api','open'];
const fail=(code,status=400)=>{throw Object.assign(Error(code),{code,status});};
const windowSnapshot=state=>({
 day:state.day??null,minute:state.minute??null,requests:state.requests||0,tokens:state.tokens||0,minuteRequests:state.minuteRequests||0
});
const eligible=(offer,key,tier,allowed)=>(
 (offer.audience==='all'||offer.audience==='email'&&offer.recipient===key||
  offer.audience===tier||offer.audience==='medium-high'&&['medium','high'].includes(tier))
 ?offer.scopes.filter(scope=>allowed.includes(scope)):[]
);

export function createResetOfferStore(db){
 const offers=db.ref(BASE+'/offers');
 const claims=key=>db.ref(BASE+'/claims/'+key);
 const counters={
  website:key=>'nebulaPublicPlans/v1/'+key,
  api:key=>'nebulaDeveloperApi/v1/usage/'+key,
  open:key=>'nebulaOpenUsage/v1/'+key
 };
 function applyReset(scope,key,claim){
  return db.ref(counters[scope](key)).transaction(old=>{
   const state=old||{};
   if(state.resetClaims?.[claim.id])return;
   const receipts=Object.fromEntries(Object.entries(state.resetClaims||{}).filter(([,expiry])=>expiry>claim.at));
   state.resetClaims={...receipts,[claim.id]:claim.expiresAt+DAY};
   if(scope==='website'){
    state.reset={shortStarted:state.short?.started??null,weekStarted:state.week?.started??null,shortUsed:state.short?.used||0,weekUsed:state.week?.used||0};
    delete state.gift;
   }else if(scope==='api'){
    state.reset=windowSnapshot(state);
    delete state.gift;
   }else if(state.day===Math.floor(claim.at/DAY)){
    state.calls=0;
   }
   return state;
  },undefined,false);
 }
 return {
  async createResetOffer({audience,recipient,scopes,expiresAt},actor,time){
   if(!audiences.includes(audience)||audience==='email'&&!recipient||!Array.isArray(scopes)||!scopes.length||new Set(scopes).size!==scopes.length||scopes.some(scope=>!resetScopes.includes(scope))||!Number.isInteger(expiresAt)||expiresAt<time+MINUTE||expiresAt>time+90*DAY)fail('INVALID_RESET');
   const id=randomBytes(12).toString('hex'),offer={id,audience,...(recipient?{recipient}:{}),scopes,expiresAt,createdAt:time,by:actor};
   const tx=await offers.transaction(old=>{
    const active=Object.fromEntries(Object.entries(old||{}).filter(([,item])=>item.expiresAt>time));
    if(Object.keys(active).length>=100)return;
    return {...active,[id]:offer};
   },undefined,false);
   if(!tx.committed)fail('RESET_OFFER_LIMIT',409);
   return {id,audience,scopes,expiresAt};
  },
  async resetOffers(key,tier,allowed,time){
   const [items,used]=await Promise.all([offers.get(),claims(key).get()]);
   const state=used.val()||{};
   return Object.values(items.val()||{}).filter(offer=>offer.expiresAt>time&&!state[offer.id]?.completed)
    .map(offer=>({id:offer.id,expiresAt:offer.expiresAt,scopes:state[offer.id]?.scopes||eligible(offer,key,tier,allowed)}))
    .filter(offer=>offer.scopes.length).sort((a,b)=>a.expiresAt-b.expiresAt);
  },
  async claimResetOffer(key,id,tier,allowed,time){
   if(typeof id!=='string'||!/^[a-f0-9]{24}$/.test(id))fail('INVALID_RESET');
   const [item,used]=await Promise.all([offers.get(),claims(key).get()]);
   const offer=item.val()?.[id],previous=used.val()?.[id];
   const scopes=offer?.expiresAt>time?eligible(offer,key,tier,allowed):[];
   if(!previous&&!scopes.length)fail('RESET_NOT_AVAILABLE',404);
   if(previous?.completed)return {scopes:previous.scopes};
   if(previous&&previous.expiresAt+DAY<=time)fail('RESET_NOT_AVAILABLE',404);
   const ref=claims(key);
   const tx=await ref.transaction(old=>{
    const records=Object.fromEntries(Object.entries(old||used.val()||{}).filter(([,claim])=>claim.expiresAt+DAY>time));
    if(!records[id]&&!scopes.length)return;
    records[id]||={id,at:time,expiresAt:offer.expiresAt,scopes,completed:false};
    return records;
   },undefined,false);
   if(!tx.committed)fail('RESET_NOT_AVAILABLE',404);
   const claim=tx.snapshot.val()[id];
   if(!claim.completed){
    await Promise.all(claim.scopes.map(scope=>applyReset(scope,key,claim)));
    const completed=await ref.transaction(old=>{
     const records=old||tx.snapshot.val();
     if(!records?.[id])return;
     return {...records,[id]:{...records[id],completed:true}};
    },undefined,false);
    if(!completed.committed)fail('RESET_NOT_AVAILABLE',409);
   }
   return {scopes:claim.scopes};
  }
 };
}
