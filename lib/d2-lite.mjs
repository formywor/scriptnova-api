import {workerReply} from './vd2-worker.mjs';
export const D2_LITE_ID='nebula-d2-lite';
export function d2LiteReady(c){try{const u=new URL(c.d2LiteUrl);return c.d2LiteEnabled===true&&u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&c.d2LiteToken?.length>=32;}catch{return false;}}
export async function d2LiteReply(messages,c,{fetcher=fetch}={}){
 const fail=code=>{throw Object.assign(Error(code),{code});};
 if(!d2LiteReady(c))fail('D2_LITE_NOT_READY');
 if(c.cloudTools||c.pcContext)fail('D2_LITE_TEXT_ONLY');
 // Fixed identity only: no conversation summaries, memory or injected history.
 const system='You are Nebula D2 Lite by ScriptNovaa. Answer only the latest user message. No previous conversation or tools are available.';
 const user=messages.filter(m=>m.role==='user').at(-1)?.content;
 if(!user||system.length+user.length>6000)fail('MODEL_CONTEXT_LIMIT');
 const result=await workerReply({model:'nebula-v-d2',messages:[{role:'system',content:system||'You are Nebula D2 Lite by ScriptNovaa. Review only supplied text. Do not claim tool access or verified live findings.'},{role:'user',content:user}],maxNewTokens:Math.min(512,c.maxReplyTokens||512)}, {workerUrl:c.d2LiteUrl,workerToken:c.d2LiteToken},fetcher,c.signal||new AbortController().signal);
 return {text:result.text,modelRevision:result.checkpoint.slice(7),activity:[],contextMessages:1,contextShortened:messages.filter(m=>m.role!=='system').length>1};
}
