import {fail} from './cloud-services.mjs';
async function boundedText(response,max=160000){
 const chunks=[],reader=response.body?.getReader();let bytes=0;if(!reader)fail('VD2_RESPONSE_INVALID',502);
 try{for(;;){const part=await reader.read();if(part.done)break;bytes+=part.value.length;if(bytes>max){await reader.cancel();fail('VD2_RESPONSE_INVALID',502);}chunks.push(part.value);}}finally{reader.releaseLock();}
 return Buffer.concat(chunks).toString('utf8');
}
const checked=d=>{if(d?.model!=='nebula-v-d2'||typeof d.text!=='string'||!d.text.trim()||d.text.length>24000||!/^sha256:[a-f0-9]{64}$/.test(d.checkpoint||''))fail('VD2_RESPONSE_INVALID',502);return d;};
export async function workerReply(payload,c,fetcher,signal){
 if(!c.workerUrl||c.workerToken.length<32)fail('VD2_NOT_DEPLOYED',503);
 const url=new URL(c.workerUrl);if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search)fail('VD2_CONFIGURATION_INVALID',503);
 const gradio=/\/gradio_api\/call\/generate$/.test(url.pathname),headers={'Content-Type':'application/json',...(gradio?{'X-Nebula-Worker-Key':c.workerToken}:{Authorization:'Bearer '+c.workerToken})},abort=AbortSignal.any([signal,AbortSignal.timeout(80000)]);
 const request=async(target,options)=>{const r=await fetcher(target,{...options,redirect:'error',headers,signal:abort});if(!r.ok)fail(r.status===413?'VD2_CONTEXT_TOO_LONG':r.status===429||r.status===503?'VD2_BUSY':'VD2_UNAVAILABLE',r.status===413?413:503);return r;};
 const r=await request(url,{method:'POST',body:JSON.stringify(gradio?{data:[payload]}:payload)});
 let d;try{d=JSON.parse(await boundedText(r));}catch(e){if(e.code)throw e;fail('VD2_RESPONSE_INVALID',502);}
 if(!gradio)return checked(d);
 if(typeof d.event_id!=='string'||!/^[-a-zA-Z0-9_]{1,80}$/.test(d.event_id))fail('VD2_RESPONSE_INVALID',502);
 const stream=await boundedText(await request(new URL(url.href+'/'+d.event_id),{method:'GET'}));
 for(const block of stream.replaceAll('\r\n','\n').split('\n\n')){
  const event=/^event: (.+)$/m.exec(block)?.[1],data=block.split('\n').filter(l=>l.startsWith('data: ')).map(l=>l.slice(6)).join('\n');
  if(event==='error'){if(/D2_CONTEXT_TOO_LONG/.test(data))fail('VD2_CONTEXT_TOO_LONG',413);fail(/quota|GPU|queue|timeout|busy/i.test(data)?'VD2_BUSY':'VD2_RESPONSE_INVALID',503);}
  if(event==='complete'){try{let result=JSON.parse(data)?.[0];if(typeof result==='string')result=JSON.parse(result);return checked(result);}catch(e){if(e.code)throw e;fail('VD2_RESPONSE_INVALID',502);}}
 }
 fail('VD2_RESPONSE_INVALID',502);
}
