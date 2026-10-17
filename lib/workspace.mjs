import {randomUUID} from 'node:crypto';

export const WINDOW=48*60*60*1000;
export const ACTIVE=15*60*1000;
export const RECENT=5*60*1000;
const fail=(code,status=400)=>{throw Object.assign(new Error(code),{code,status});};
export function validChat(body,id) {
  if(!body||typeof body.title!=='string'||!body.title.trim()||body.title.length>100||!Array.isArray(body.messages)||body.messages.length>200)fail('INVALID_INPUT');
  let chars=0;const ids=new Set();
  const messages=body.messages.map(m=>{
    if(!m||!['user','assistant'].includes(m.role)||typeof m.content!=='string'||!m.content.trim()||m.content.length>100000||!/^[-a-zA-Z0-9]{1,80}$/.test(m.id||'')||ids.has(m.id))fail('INVALID_INPUT');
    ids.add(m.id);chars+=m.content.length;
    return {id:m.id,role:m.role,content:m.content,trainingEligible:m.trainingEligible===true,...(m.reviewEligible===true?{reviewEligible:true}:{}),...(m.replyTo?{replyTo:m.replyTo}:{})};
  });
  if(chars>100000)fail('CHAT_TOO_LONG',413);
  return {id,title:body.title.trim(),archived:body.archived===true,messages};
}
const summary=c=>({id:c.id,title:c.title,archived:c.archived===true,updated:c.updated,revision:c.revision});
export function capacityView(state,time,config={}) {
  const actors=Object.values(state?.actors||{}).filter(a=>time-a.seen<ACTIVE);
  const asking=actors.filter(a=>Object.values(a.leases||{}).some(until=>until>time)).length;
  const heavy=actors.filter(a=>(a.recent||[]).filter(t=>time-t<RECENT).length>=(config.heavyQuestions||5)).length;
  const total=actors.length;
  return {activeUsers:total,askingUsers:asking,heavyUsers:heavy,askingPercent:total?100*asking/total:0,heavyPercent:total?100*heavy/total:0,guestPaused:total>0&&(asking/total>=(config.askingFraction??.15)||heavy/total>=(config.heavyFraction??.08)),activeWindowMinutes:15,heavyWindowMinutes:5,heavyQuestions:config.heavyQuestions||5};
}
export function usageView(state,time,guest,limit=10) {
  const fresh=state&&time-state.started<WINDOW;
  return {questions:fresh?state.questions||0:0,totalQuestions:state?.totalQuestions||0,inputCharacters:state?.inputCharacters||0,outputCharacters:state?.outputCharacters||0,remaining:guest?Math.max(0,limit-(fresh?(state.questions||0)+Object.keys(state.pending||{}).length:0)):null,limit:guest?limit:null,resetsAt:fresh?state.started+WINDOW:time+WINDOW,windowHours:48};
}
export function createWorkspaceStore(db) {
  async function get(path){return (await db.ref(path).get()).val();}
  const chatPath=(key,id)=>`nebulaChats/v1/${key}/${id}`;
  const indexPath=key=>`nebulaChatIndex/v1/${key}`;
  async function updateIndex(key,chat){await db.ref(indexPath(key)).transaction(old=>{const index=old||{};if((index[chat.id]?.revision||0)>chat.revision)return;index[chat.id]=chat.deleted?{deleted:true,revision:chat.revision,updated:chat.updated}:summary(chat);return index;},undefined,false);}
  return {
    async listChats(key){return Object.values(await get(indexPath(key))||{}).filter(c=>!c.deleted).sort((a,b)=>b.updated-a.updated);},
    async getChat(key,id){const c=await get(chatPath(key,id));if(!c||c.deleted)fail('NOT_FOUND',404);return c;},
    async putChat(key,id,body,time){
      const clean=validChat(body,id);let reason='CHAT_CONFLICT';
      if(body.revision===0){const result=await db.ref(indexPath(key)).transaction(old=>{const index=old||{};if(index[id]?.deleted){reason='CHAT_CONFLICT';return;}if(!index[id]&&Object.values(index).filter(c=>!c.deleted).length>=100){reason='CHAT_LIMIT';return;}index[id] ||= {id,title:clean.title,updated:time,revision:0,archived:false};return index;},undefined,false);if(!result.committed)fail(reason,409);}
      const result=await db.ref(chatPath(key,id)).transaction(old=>{
        // A cold Firebase client first calls back with a speculative null. Let
        // it compare with the server before deciding an existing edit is stale.
        if(old==null&&body.revision>0)return null;
        if(old?.deleted||(old?.revision||0)!==body.revision)return;
        // Answers are server-owned. Clients may only append user turns to existing messages.
        const previous=old?.messages||[];
        const importing=!old&&body.importLegacy===true;
        if(clean.messages.length<previous.length||previous.some((m,i)=>['id','role','content','replyTo','trainingEligible','reviewEligible'].some(k=>m[k]!==clean.messages[i]?.[k]))||(!importing&&clean.messages.slice(previous.length).some(m=>m.role!=='user'))){reason='INVALID_CHAT_EDIT';return;}
        return {...clean,...(importing?{messages:clean.messages.map(m=>({...m,trainingEligible:false})),imported:true}:{}),updated:time,revision:(old?.revision||0)+1};
      },undefined,false);
      const chat=result.snapshot.val();if(!result.committed||!chat)fail(reason,409);await updateIndex(key,chat);return chat;
    },
    async patchChat(key,id,body,time){let reason='CHAT_CONFLICT';const result=await db.ref(chatPath(key,id)).transaction(old=>{if(!old||old.deleted){reason='NOT_FOUND';return old??null;}if(body.revision!==old.revision)return;return {...old,...(typeof body.title==='string'?{title:body.title.trim()}:{}),...(typeof body.archived==='boolean'?{archived:body.archived}:{}),updated:time,revision:old.revision+1};},undefined,false);if(!result.committed)fail(reason,reason==='NOT_FOUND'?404:409);const chat=result.snapshot.val();if(!chat||chat.deleted)fail('NOT_FOUND',404);await updateIndex(key,chat);return chat;},
    async deleteChat(key,id,time){const result=await db.ref(chatPath(key,id)).transaction(old=>({id,deleted:true,updated:time,revision:(old?.revision||0)+1}),undefined,false);await updateIndex(key,result.snapshot.val());},
    async clearChats(key,time){const list=await this.listChats(key);for(const c of list)await this.deleteChat(key,c.id,time);},
    async appendReply(key,id,turnId,text,time){
      let answer;const result=await db.ref(chatPath(key,id)).transaction(old=>{
        if(!old||old.deleted)return old??null;
        const existing=(old.messages||[]).find(m=>m.replyTo===turnId);if(existing){answer=existing;return old;}
        if(old.messages?.at(-1)?.id!==turnId||old.messages.at(-1).role!=='user')return;
        answer={id:randomUUID(),role:'assistant',content:text,replyTo:turnId,trainingEligible:false};
        return {...old,messages:[...old.messages,answer],updated:time,revision:old.revision+1};
      },undefined,false);
      if(result.committed){const c=result.snapshot.val();if(!c||c.deleted)return null;await updateIndex(key,c);return c;}
      const existing=result.snapshot.val();return existing?.deleted?null:existing||null;
    },
    async memory(key){return Object.entries(await get(`nebulaMemory/v1/${key}`)||{}).map(([id,value])=>({id,...value}));},
    async addMemory(key,text,time){const id=randomUUID();const result=await db.ref(`nebulaMemory/v1/${key}`).transaction(old=>{const data=old||{};if(Object.keys(data).length>=50)return;data[id]={text,createdAt:time};return data;},undefined,false);if(!result.committed)fail('MEMORY_LIMIT',409);return {id,text,createdAt:time};},
    async deleteMemory(key,id){await db.ref(`nebulaMemory/v1/${key}/${id}`).remove();},
    async clearMemory(key){await db.ref(`nebulaMemory/v1/${key}`).remove();},
    async presence(actor,time,config){
      const result=await db.ref('nebulaRuntime/v1').transaction(old=>{const state=old||{actors:{}};state.actors ||= {};for(const [id,a] of Object.entries(state.actors))if(time-a.seen>=ACTIVE)delete state.actors[id];state.actors[actor] ||= {leases:{},recent:[]};state.actors[actor].seen=time;return state;},undefined,false);
      return capacityView(result.snapshot.val(),time,config);
    },
    async reserveCapacity(actor,guest,time,id,config){let view;const result=await db.ref('nebulaRuntime/v1').transaction(old=>{
      const state=old||{actors:{}};state.actors ||= {};for(const [key,a] of Object.entries(state.actors))if(time-a.seen>=ACTIVE)delete state.actors[key];
      const a=state.actors[actor] ||= {seen:time,leases:{},recent:[]};a.seen=time;a.leases ||= {};a.recent=(a.recent||[]).filter(t=>time-t<RECENT);for(const [key,until] of Object.entries(a.leases))if(until<=time)delete a.leases[key];
      view=capacityView(state,time,config);if(guest&&view.guestPaused)return;
      a.leases[id]=time+110000;return state;
    },undefined,false);return {allowed:result.committed,capacity:view};},
    async releaseCapacity(actor,id,time,success){await db.ref('nebulaRuntime/v1').transaction(old=>{if(!old?.actors?.[actor])return old??null;const a=old.actors[actor];delete a.leases?.[id];a.recent=(a.recent||[]).filter(t=>time-t<RECENT);if(success)a.recent.push(time);a.seen=time;return old;},undefined,false);},
    async usage(actor,time,guest,limit){return usageView(await get(`nebulaUsage/v1/${actor}`),time,guest,limit);},
    async reserveUsage(actor,id,time,guest,limit){let reason='GUEST_LIMIT';const result=await db.ref(`nebulaUsage/v1/${actor}`).transaction(old=>{
      const state=old||{totalQuestions:0,inputCharacters:0,outputCharacters:0};
      if(!state.started||time-state.started>=WINDOW){state.started=time;state.questions=0;state.pending={};state.completed={};}
      state.pending ||= {};state.completed ||= {};for(const [key,at] of Object.entries(state.pending))if(time-at>110000)delete state.pending[key];
      if(state.pending[id]||state.completed[id]){reason='DUPLICATE_TURN';return;}
      if(guest&&(state.questions||0)+Object.keys(state.pending).length>=limit)return;
      state.pending[id]=time;return state;
    },undefined,false);return {allowed:result.committed,reason,usage:usageView(result.snapshot.val(),time,guest,limit)};},
    async finishUsage(actor,id,time,success,input,output){await db.ref(`nebulaUsage/v1/${actor}`).transaction(state=>{if(!state?.pending?.[id])return state??null;delete state.pending[id];if(success){state.questions=(state.questions||0)+1;state.totalQuestions=(state.totalQuestions||0)+1;state.inputCharacters=(state.inputCharacters||0)+input;state.outputCharacters=(state.outputCharacters||0)+output;state.completed ||= {};state.completed[id]=time;const keys=Object.keys(state.completed);for(const old of keys.slice(0,Math.max(0,keys.length-1000)))delete state.completed[old];}return state;},undefined,false);},
  };
}
