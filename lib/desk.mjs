import {authenticate,accountKey} from './accounts.mjs';
export const CARD_KINDS=['note','decision','assumption','question','task'];
const fail=(code,status=400)=>{throw Object.assign(Error(code),{code,status});};
const idOK=s=>typeof s==='string'&&/^[-a-zA-Z0-9]{1,80}$/.test(s);
function fields(b){
 if(!CARD_KINDS.includes(b.kind)||typeof b.title!=='string'||!b.title.trim()||b.title.length>120||typeof b.text!=='string'||b.text.length>2000||typeof b.done!=='boolean'||typeof b.checked!=='boolean'||typeof b.archived!=='boolean')fail('INVALID_CARD');
 return {kind:b.kind,title:b.title.trim(),text:b.text.trim(),done:b.done,checked:b.checked,archived:b.archived};
}
export function createDeskStore(db){const path=k=>'nebulaDesk/v1/'+k;return {
 async deskCards(k){return Object.values((await db.ref(path(k)).get()).val()||{}).sort((a,b)=>b.updatedAt-a.updatedAt);},
 async deskDelete(k,id,revision){
  const ref=db.ref(path(k)),snapshot=(await ref.get()).val()||{};let reason='CARD_CONFLICT';const r=await ref.transaction(old=>{const cards=old||snapshot;if(!cards[id])return cards;if(cards[id].revision!==revision)return;delete cards[id];return cards;},undefined,false);if(!r.committed)fail(reason,409);
 },
 async deskSave(k,id,body,time,source=null){
  const clean=fields(body);if(!Number.isSafeInteger(body.revision)||body.revision<0)fail('INVALID_CARD');let reason='CARD_CONFLICT';
  const ref=db.ref(path(k)),snapshot=(await ref.get()).val()||{};
  const r=await ref.transaction(old=>{const cards=old||snapshot,existing=cards[id];if(body.revision===0&&existing?.revision===1&&Object.entries(clean).every(([k,v])=>existing[k]===v)&&(!source&&!existing.source||source&&existing.source?.chatId===source.chatId&&existing.source?.messageId===source.messageId))return cards;if((existing?.revision||0)!==body.revision)return;
   if(!existing&&Object.keys(cards).length>=80){reason='CARD_LIMIT';return;}
   cards[id]={...clean,id,revision:body.revision+1,createdAt:existing?.createdAt||time,updatedAt:time,...(existing?.source?{source:existing.source}:source?{source}:{})};return cards;
  },undefined,false);if(!r.committed)fail(reason,409);return r.snapshot.val()[id];
 }
};}
async function json(request){if(!request.headers.get('content-type')?.startsWith('application/json'))fail('INVALID_INPUT');const reader=request.body?.getReader();if(!reader)fail('INVALID_INPUT');let n=0,parts=[];try{for(;;){const p=await reader.read();if(p.done)break;n+=p.value.length;if(n>20000){await reader.cancel();fail('REQUEST_TOO_LARGE',413);}parts.push(p.value);}}finally{reader.releaseLock();}let v;try{v=JSON.parse(Buffer.concat(parts));}catch{fail('INVALID_INPUT');}if(!v||Array.isArray(v)||typeof v!=='object')fail('INVALID_INPUT');return v;}
export function createDeskHandler({getStore,verifyToken,origins=['https://scriptnovaa.com','https://www.scriptnovaa.com'],now=Date.now}){return async request=>{
 const origin=request.headers.get('origin'),path=new URL(request.url).pathname.replace('/api/nebula/desk',''),headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',Vary:'Origin',...(origins.includes(origin)?{'Access-Control-Allow-Origin':origin}:{})},reply=(status,data)=>new Response(JSON.stringify(data),{status,headers});
 if(origin&&!origins.includes(origin))return reply(403,{code:'FORBIDDEN'});if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET,PUT,POST,DELETE,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type'}});
 try{const identity=await authenticate(request,verifyToken);if(!identity)return reply(401,{code:'UNAUTHORIZED'});const store=await getStore(),key=accountKey(identity.uid);if(!await store.allow('desk_'+key,now(),request.method==='GET'?'read':'write'))fail('RATE_LIMITED',429);
  if(path===''&&request.method==='GET')return reply(200,{cards:await store.deskCards(key),limit:80});
  if(path==='/fork'&&request.method==='POST'){const b=await json(request);if(Object.keys(b).some(k=>!['chatId','through','id','title'].includes(k))||![b.chatId,b.through,b.id].every(idOK)||typeof b.title!=='string'||!b.title.trim()||b.title.length>100||b.id===b.chatId)fail('INVALID_INPUT');return reply(201,{chat:await store.forkChat(key,b.chatId,b.through,b.id,b.title,now())});}
  const id=path.match(/^\/([-a-zA-Z0-9]{1,80})$/)?.[1];if(id&&request.method==='DELETE'){const b=await json(request);if(Object.keys(b).length!==1||!Number.isSafeInteger(b.revision)||b.revision<1)fail('INVALID_CARD');await store.deskDelete(key,id,b.revision);return reply(200,{deleted:true});}if(id&&request.method==='PUT'){
   const b=await json(request);if(Object.keys(b).some(k=>!['kind','title','text','done','checked','archived','revision','source'].includes(k)))fail('INVALID_CARD');let source=null;
   if(b.source!==undefined){if(b.revision!==0||!idOK(b.source?.chatId)||!idOK(b.source?.messageId)||Object.keys(b.source).some(k=>!['chatId','messageId'].includes(k)))fail('INVALID_CARD');const chat=await store.getChat(key,b.source.chatId),m=chat.messages.find(m=>m.id===b.source.messageId);if(!m)fail('NOT_FOUND',404);source={chatId:chat.id,messageId:m.id,title:chat.title,quote:m.content.slice(0,6000),truncated:m.content.length>6000,...(m.modelId?{modelId:m.modelId}:{})};}
   return reply(200,{card:await store.deskSave(key,id,b,now(),source)});
  }
  return reply(404,{code:'NOT_FOUND'});
 }catch(e){return reply(e.status||503,{code:/^[A-Z_]+$/.test(e.code||'')?e.code:'DESK_UNAVAILABLE'});}
};}
