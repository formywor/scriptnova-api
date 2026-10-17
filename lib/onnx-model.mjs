// Server-only CPU inference for published owned checkpoints.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fitPromptContext} from './native-model.mjs';
const require=createRequire(import.meta.url),IDs=new Set(['nebula-v1-lite','nebula-v2-1']);
const fault=code=>Object.assign(Error(code),{code});
const sha=data=>createHash('sha256').update(data).digest('hex');
export function loadGraphRelease(modelId,directory=new URL('../model-assets/',import.meta.url)){
 if(!IDs.has(modelId))throw fault('MODEL_ARTIFACT_INVALID');
 let release;const base=new URL(modelId+'/',directory);
 try{release=JSON.parse(readFileSync(new URL('release.json',base),'utf8'));}catch{throw fault('MODEL_RELEASE_MISSING');}
 const c=release.config;
 if(release.format!=='nebula-onnx-1'||release.id!==modelId||!c||![c.width,c.heads,c.layers,c.context].every(Number.isInteger)||c.width<1||c.width>768||c.heads<1||c.heads>24||c.width%c.heads||c.layers<1||c.layers>14||c.context<2||c.context>1024||!Number.isInteger(release.bytes)||release.bytes<1||release.bytes>160*1024*1024||!/^[a-f0-9]{64}$/.test(release.sha256)||!Array.isArray(release.parts)||release.parts.length<1||release.parts.length>24)throw fault('MODEL_RELEASE_INVALID');
 const seen=new Set(),parts=[];
 for(const part of release.parts){
  if(!new RegExp('^'+modelId+'-[0-9]{2}\\.part$').test(part.name)||seen.has(part.name)||!Number.isInteger(part.bytes)||part.bytes<1||part.bytes>8*1024*1024||!/^[a-f0-9]{64}$/.test(part.sha256))throw fault('MODEL_RELEASE_INVALID');
  seen.add(part.name);let data;try{data=readFileSync(new URL(part.name,base));}catch{throw fault('MODEL_SHARD_MISSING');}
  if(data.length!==part.bytes||sha(data)!==part.sha256)throw fault('MODEL_RELEASE_CHECKSUM_MISMATCH');parts.push(data);
 }
 const bytes=Buffer.concat(parts);if(bytes.length!==release.bytes||sha(bytes)!==release.sha256)throw fault('MODEL_RELEASE_CHECKSUM_MISMATCH');
 return {release,bytes};
}
const sessions=new Map();let busy=false;
async function load(modelId){
 if(!sessions.has(modelId))sessions.set(modelId,(async()=>{const {release,bytes}=loadGraphRelease(modelId),ort=require('onnxruntime-node');const session=await ort.InferenceSession.create(bytes,{executionProviders:['cpu'],intraOpNumThreads:1,interOpNumThreads:1,graphOptimizationLevel:'all',executionMode:'sequential',logSeverityLevel:3});return {release,session,ort};})().catch(error=>{sessions.delete(modelId);throw error;}));
 return sessions.get(modelId);
}
export async function graphReply(messages,{modelId,maxTokens=1024,maxMilliseconds=65000}={}){
 if(busy)throw fault('MODEL_BUSY');busy=true;
 try{
  const deadline=performance.now()+maxMilliseconds,{release,session,ort}=await load(modelId),c=release.config;
  const prompt=fitPromptContext(messages,c.context),shape=[c.layers,1,c.heads,0,c.width/c.heads];
  let k=new ort.Tensor('float32',new Float32Array(0),shape),v=new ort.Tensor('float32',new Float32Array(0),shape),ids=prompt;const out=[];
  for(let i=0;i<Math.min(maxTokens,c.context-prompt.length);i++){
   if(performance.now()>deadline)throw fault('MODEL_INFERENCE_TIMEOUT');
   const result=await session.run({tokens:new ort.Tensor('int64',BigInt64Array.from(ids,BigInt),[1,ids.length]),past_k:k,past_v:v});
   const scores=result.logits.data;let token=257,max=scores[257];for(let n=0;n<256;n++)if(scores[n]>max){max=scores[n];token=n;}
   if(!Number.isFinite(max))throw fault('MODEL_ARTIFACT_INVALID');if(token===257)break;
   out.push(token);ids=[token];k=result.present_k;v=result.present_v;
  }
  return Buffer.from(out).toString('utf8').trim();
 }finally{busy=false;}
}
