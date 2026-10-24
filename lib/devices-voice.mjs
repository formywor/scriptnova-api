import {fail} from './cloud-services.mjs';
const groqVoices=['autumn','diana','hannah','austin','daniel','troy'];
export function devicesConfig(e=process.env){
 const groqKey=e.NEBULA_TTS_API_KEY||e.NEBULA_ULTRA_API_KEY||e.GROQ_API_KEY||'';
 const provider=e.NEBULA_TTS_PROVIDER||(groqKey?'groq':e.ELEVENLABS_API_KEY?'elevenlabs':'none');
 const key=provider==='groq'?groqKey:provider==='elevenlabs'?(e.NEBULA_TTS_API_KEY||e.ELEVENLABS_API_KEY||''):'';
 let voices=[];try{voices=JSON.parse(e.NEBULA_TTS_VOICES||'null')|| (provider==='groq'?[{id:'troy',label:'Troy'},{id:'hannah',label:'Hannah'}]:[]);}catch{}
 if(!Array.isArray(voices)||voices.length>12)voices=[];
 voices=voices.filter(v=>v&&/^[a-zA-Z0-9_-]{1,80}$/.test(v.id)&&typeof v.label==='string'&&v.label.length>0&&v.label.length<=60&&(provider!=='groq'||groqVoices.includes(v.id))).map(({id,label})=>({id,label}));
 let protocol=null;try{const p=JSON.parse(e.NEBULA_GLASSES_PROTOCOL_JSON||'null'),uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
  if(e.NEBULA_GLASSES_PROTOCOL_VERIFIED==='true'&&p&&['serviceUuid','infoUuid','controlUuid'].every(k=>uuid.test(p[k]))&&p.protocol==='nebula-ble-control'&&p.version===1&&typeof p.model==='string'&&p.model.length>0&&p.model.length<80&&new URL(p.documentationUrl).protocol==='https:')protocol={serviceUuid:p.serviceUuid,infoUuid:p.infoUuid,controlUuid:p.controlUuid,protocol:p.protocol,version:1,model:p.model,documentationUrl:p.documentationUrl};
 }catch{}
 return {voice:{provider,key,voices,configured:!!key&&voices.length>0&&['groq','elevenlabs'].includes(provider),maxCharacters:provider==='groq'?200:2000},glasses:{configured:!!protocol,protocol}};
}
export function publicDevicesConfig(c){return {voice:{configured:c.voice.configured,voices:c.voice.configured?c.voice.voices:[],maxCharacters:c.voice.maxCharacters},glasses:c.glasses};}
export async function synthesizeVoice(body,c,{fetcher=fetch,signal}={}){
 if(!body||Object.keys(body).some(k=>!['text','voice','consent'].includes(k))||body.consent!==true||typeof body.text!=='string'||!body.text.trim()||body.text.length>c.maxCharacters||/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(body.text)||typeof body.voice!=='string')fail('INVALID_VOICE_REQUEST');
 if(!c.configured)fail('API_VOICE_NOT_CONFIGURED',503);
 if(!c.voices.some(v=>v.id===body.voice))fail('VOICE_NOT_ALLOWED');
 const groq=c.provider==='groq',url=groq?'https://api.groq.com/openai/v1/audio/speech':'https://api.elevenlabs.io/v1/text-to-speech/'+encodeURIComponent(body.voice)+'?output_format=mp3_44100_128';
 const response=await fetcher(url,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json',...(groq?{Authorization:'Bearer '+c.key}:{'xi-api-key':c.key})},body:JSON.stringify(groq?{model:'canopylabs/orpheus-v1-english',input:body.text,voice:body.voice,response_format:'wav'}:{text:body.text,model_id:'eleven_multilingual_v2'}),signal:AbortSignal.any([AbortSignal.timeout(20000),...(signal?[signal]:[])])});
 if(!response.ok){await response.body?.cancel();fail(response.status===429?'API_VOICE_RATE_LIMITED':'API_VOICE_UNAVAILABLE',503);}
 const type=(response.headers.get('content-type')||'').split(';')[0];if(!['audio/mpeg','audio/wav','audio/x-wav','audio/wave'].includes(type)){await response.body?.cancel();fail('API_VOICE_INVALID',503);}
 const reader=response.body?.getReader();if(!reader)fail('API_VOICE_INVALID',503);const chunks=[];let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4*1024*1024){await reader.cancel();fail('API_VOICE_TOO_LARGE',503);}chunks.push(value);}}finally{reader.releaseLock();}
 if(size<12)fail('API_VOICE_INVALID',503);const bytes=Buffer.concat(chunks);
 if(type==='audio/mpeg'&&!(bytes.subarray(0,3).toString()==='ID3'||bytes[0]===255&&(bytes[1]&224)===224)||type!=='audio/mpeg'&&!(bytes.subarray(0,4).toString()==='RIFF'&&bytes.subarray(8,12).toString()==='WAVE'))fail('API_VOICE_INVALID',503);
 return {bytes,type};
}
