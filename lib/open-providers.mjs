import {createHash} from 'node:crypto';

// Independent service credentials; never reuse Ultra's or D2's Groq keys here.
export function openProviders(c){return [
 {id:'cloudflare',key:c.openKey,model:'@cf/openai/gpt-oss-20b',url:/^[a-f0-9]{32}$/i.test(c.openAccountId||'')?'https://api.cloudflare.com/client/v4/accounts/'+c.openAccountId+'/ai/v1/chat/completions':null},
 {id:'cerebras',key:c.openCerebrasKey,model:c.openCerebrasModel||'gpt-oss-120b',url:'https://api.cerebras.ai/v1/chat/completions'},
 {id:'openrouter',key:c.openRouterKey,model:'openrouter/free',url:'https://openrouter.ai/api/v1/chat/completions'},
 {id:'mistral',key:c.openMistralKey,model:c.openMistralModel||'mistral-small-latest',url:'https://api.mistral.ai/v1/chat/completions'},
 {id:'gemini',key:c.openGeminiKey||c.sparkKey,model:c.openGeminiModel||'gemini-2.5-flash',url:'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'},
 {id:'groq-final',key:c.openGroqKey,model:'openai/gpt-oss-20b',url:'https://api.groq.com/openai/v1/chat/completions'}
].filter(p=>p.key&&p.url);}

const cooldowns=new Map();
function payloadFor(p,source){
 const {max_completion_tokens,parallel_tool_calls,...body}=structuredClone(source);
 body.model=p.model;body.max_tokens=max_completion_tokens;
 body.messages=body.messages.map(m=>m.content===null?{...m,content:''}:m);
 if(body.tools&&!['cloudflare','gemini','openrouter'].includes(p.id))body.parallel_tool_calls=parallel_tool_calls;
 if(p.id==='cloudflare'||p.id==='groq-final'||p.id==='cerebras')body.reasoning_effort='low';
 if(p.id==='groq-final'){body.max_completion_tokens=body.max_tokens;delete body.max_tokens;}
 if(p.id==='openrouter')body.provider={ignore:['Groq']};
 // Mistral requires exactly nine alphanumeric characters for tool call IDs.
 if(p.id==='mistral')for(const m of body.messages){
  const id=value=>createHash('sha256').update(value).digest('hex').slice(0,9);
  if(m.tool_call_id)m.tool_call_id=id(m.tool_call_id);
  for(const call of m.tool_calls||[])call.id=id(call.id);
 }
 return body;
}

async function boundedText(response){
 const reader=response.body?.getReader();if(!reader)return '';
 const chunks=[];let bytes=0;
 try{for(;;){const part=await reader.read();if(part.done)break;bytes+=part.value.length;if(bytes>1048576){await reader.cancel();throw Error('INVALID_UPSTREAM');}chunks.push(part.value);}return Buffer.concat(chunks).toString('utf8');}
 finally{reader.releaseLock();}
}

export function openTransport(c,{fetcher=fetch,now=Date.now,failures=cooldowns,attemptMs=7000}={}){
 const routes=openProviders(c);let preferred=0;
 return async(_url,init)=>{
  init.signal?.throwIfAborted();
  // One logical inference allowance, regardless of how many providers fail.
  await c.consumeOpenCall?.();
  init.signal?.throwIfAborted();
  const source=JSON.parse(init.body),order=[...routes.slice(preferred),...routes.slice(0,preferred)];
  // Keep Gemini second-to-last and dedicated Groq last across every tool round.
  const priority=p=>p.id==='groq-final'?2:p.id==='gemini'?1:0;
  order.sort((a,b)=>priority(a)-priority(b));
  for(const p of order){
   init.signal?.throwIfAborted();
   const fingerprint=createHash('sha256').update(p.id+':'+p.key).digest('hex');
   if((failures.get(fingerprint)||0)>now())continue;
   const signal=AbortSignal.any([...(init.signal?[init.signal]:[]),AbortSignal.timeout(attemptMs)]);
   let status=0;
   try{
    const response=await fetcher(p.url,{...init,signal,headers:{'Content-Type':'application/json',Authorization:'Bearer '+p.key},body:JSON.stringify(payloadFor(p,source))});
    status=response.status;
    if(response.ok){
     const text=await boundedText(response);let result;try{result=JSON.parse(text);}catch{throw Error('INVALID_UPSTREAM');}
     if(!result.choices?.[0]?.message)throw Error('INVALID_UPSTREAM');
     preferred=routes.indexOf(p);failures.delete(fingerprint);
     if(c.fallbackState&&p.id!=='cloudflare')c.fallbackState.used=true;
     return new Response(text,{status:200,headers:{'Content-Type':'application/json'}});
    }
    if(![401,402,403,404,408,429,500,502,503,504].includes(status))return response;
    const retry=response.headers.get('retry-after'),seconds=Number(retry);
    const wait=retry?(Number.isFinite(seconds)?seconds*1000:Date.parse(retry)-now()):60000;
    failures.set(fingerprint,now()+Math.min(3600000,Math.max(status===401||status===403?600000:1000,Number.isFinite(wait)?wait:60000)));
    await response.body?.cancel();
   }catch(error){
    init.signal?.throwIfAborted();
    failures.set(fingerprint,now()+30000);
   }
   if(c.production)console.info('NEBULA_OPEN_FALLBACK',{provider:p.id,status});
   c.onProgress?.('Capacity is busy; trying backup service…');
  }
  // Bound warm-instance state. Fingerprints are never logged or exposed.
  if(failures.size>200)for(const [key,until] of failures)if(until<=now())failures.delete(key);
  return Response.json({error:{code:'capacity_unavailable'}},{status:429});
 };
}
