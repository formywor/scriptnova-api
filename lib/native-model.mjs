// CPU inference for Nebula's owned causal Transformer. No teacher/provider calls.
import {readFileSync} from 'node:fs';
const BOS=256,EOS=257,SYSTEM=258,USER=259,ASSISTANT=260;
const roles={system:SYSTEM,user:USER,assistant:ASSISTANT};
function encode(messages){const tokens=[BOS];for(const m of messages){if(!(m.role in roles)||typeof m.content!=='string')throw Error('Invalid message');tokens.push(roles[m.role],...Buffer.from(m.content,'utf8'),EOS);}return tokens;}
export function packPrompt(messages,context){
 const systems=messages.filter(m=>m.role==='system'),history=messages.filter(m=>m.role!=='system');
 if(history.at(-1)?.role!=='user')throw Error('User question required');
 const prefix=encode(systems),selected=[];let available=context-prefix.length-2;
 for(let i=history.length-1;i>=0;i--){const part=encode([history[i]]).slice(1);if(part.length>available){if(!selected.length)throw Error('Model context exceeded');break;}selected.unshift(part);available-=part.length;}
 return [...prefix,...selected.flat(),ASSISTANT];
}
function linear(x,w,b){const out=new Float64Array(w.shape[0]),width=x.length;for(let row=0;row<out.length;row++){let sum=b?.data[row]||0,offset=row*width;for(let col=0;col<width;col++)sum+=w.data[offset+col]*x[col];out[row]=sum;}return out;}
function norm(x,w,b){let mean=0;for(const v of x)mean+=v;mean/=x.length;let variance=0;for(const v of x)variance+=(v-mean)**2;const scale=1/Math.sqrt(variance/x.length+1e-5);return Float64Array.from(x,(v,i)=>(v-mean)*scale*w.data[i]+b.data[i]);}
function add(x,y){return Float64Array.from(x,(v,i)=>v+y[i]);}
function gelu(x){const z=x/Math.SQRT2,sign=z<0?-1:1,a=Math.abs(z),t=1/(1+.3275911*a);const erf=sign*(1-(((((1.061405429*t-1.453152027)*t)+1.421413741)*t-.284496736)*t+.254829592)*t*Math.exp(-a*a));return .5*x*(1+erf);}
function decodeWeight(w){if(!Array.isArray(w.shape)||w.shape.some(n=>!Number.isInteger(n)||n<1))throw Error('Invalid tensor');const raw=Buffer.from(w.data,'base64'),count=w.shape.reduce((a,b)=>a*b,1);if(raw.length!==4*count)throw Error('Invalid tensor length');const data=new Float32Array(count);for(let i=0;i<count;i++)data[i]=raw.readFloatLE(i*4);return {shape:w.shape,data};}
export class NativeNebula {
 constructor(artifact){
  if(artifact.format!==1)throw Error('Invalid model format');this.config=artifact.config;const {width,heads,layers,context}=this.config;
  if(![width,heads,layers,context].every(Number.isInteger)||width<1||width>512||heads<1||width%heads||layers<1||layers>8||context<2||context>2048)throw Error('Invalid model dimensions');
  this.weights=Object.fromEntries(Object.entries(artifact.weights).map(([k,v])=>[k,decodeWeight(v)]));this.metadata=artifact.metadata;
  const shape=(name,expected)=>{const w=this.weights[name];if(!w||w.shape.join(',')!==expected.join(','))throw Error('Model tensor mismatch');};
  shape('token.weight',[262,width]);shape('position.weight',[context,width]);shape('norm.weight',[width]);shape('norm.bias',[width]);
  for(let i=0;i<layers;i++){const p='blocks.'+i+'.';for(const n of ['norm1','norm2']){shape(p+n+'.weight',[width]);shape(p+n+'.bias',[width]);}shape(p+'self_attn.in_proj_weight',[width*3,width]);shape(p+'self_attn.in_proj_bias',[width*3]);shape(p+'self_attn.out_proj.weight',[width,width]);shape(p+'self_attn.out_proj.bias',[width]);shape(p+'linear1.weight',[width*4,width]);shape(p+'linear1.bias',[width*4]);shape(p+'linear2.weight',[width,width*4]);shape(p+'linear2.bias',[width]);}
 }
 session(){return {position:0,keys:Array.from({length:this.config.layers},()=>[]),values:Array.from({length:this.config.layers},()=>[])};}
 step(token,state){
  const w=this.weights,{width,heads,layers,context}=this.config,pos=state.position;
  if(!Number.isInteger(token)||token<0||token>=262||pos>=context)throw Error('Invalid model position');
  let x=Float64Array.from({length:width},(_,i)=>w['token.weight'].data[token*width+i]+w['position.weight'].data[pos*width+i]);
  const headSize=width/heads;
  for(let layer=0;layer<layers;layer++){
   const p='blocks.'+layer+'.',normal=norm(x,w[p+'norm1.weight'],w[p+'norm1.bias']);
   const qkv=linear(normal,w[p+'self_attn.in_proj_weight'],w[p+'self_attn.in_proj_bias']);
   const q=qkv.slice(0,width),k=qkv.slice(width,width*2),v=qkv.slice(width*2);state.keys[layer].push(k);state.values[layer].push(v);
   const attention=new Float64Array(width);
   for(let head=0;head<heads;head++){
    const offset=head*headSize,scores=new Float64Array(pos+1);let max=-Infinity;
    for(let t=0;t<=pos;t++){let dot=0;for(let i=0;i<headSize;i++)dot+=q[offset+i]*state.keys[layer][t][offset+i];scores[t]=dot/Math.sqrt(headSize);max=Math.max(max,scores[t]);}
    let total=0;for(let t=0;t<=pos;t++){scores[t]=Math.exp(scores[t]-max);total+=scores[t];}
    for(let t=0;t<=pos;t++){const probability=scores[t]/total;for(let i=0;i<headSize;i++)attention[offset+i]+=probability*state.values[layer][t][offset+i];}
   }
   x=add(x,linear(attention,w[p+'self_attn.out_proj.weight'],w[p+'self_attn.out_proj.bias']));
   const hidden=linear(norm(x,w[p+'norm2.weight'],w[p+'norm2.bias']),w[p+'linear1.weight'],w[p+'linear1.bias']);
   for(let i=0;i<hidden.length;i++)hidden[i]=gelu(hidden[i]);
   x=add(x,linear(hidden,w[p+'linear2.weight'],w[p+'linear2.bias']));
  }
  state.position++;return linear(norm(x,w['norm.weight'],w['norm.bias']),w['token.weight']);
 }
 logits(tokens){const session=this.session();let logits;for(const token of tokens)logits=this.step(token,session);return logits;}
 reply(messages,{maxTokens=160,temperature=.7,random=Math.random}={}){
  const tokens=packPrompt(messages,this.config.context),session=this.session();let logits;for(const token of tokens)logits=this.step(token,session);
  const output=[],count=Math.min(maxTokens,this.config.context-tokens.length);
  for(let n=0;n<count;n++){
   let token=EOS,max=-Infinity;const allowed=[...Array(256).keys(),EOS];for(const i of allowed)if(logits[i]>max){max=logits[i];token=i;}
   if(temperature>0){const probs=allowed.map(i=>Math.exp((logits[i]-max)/temperature));let value=random()*probs.reduce((a,b)=>a+b,0);for(let i=0;i<allowed.length;i++){value-=probs[i];if(value<=0){token=allowed[i];break;}}}
   if(token===EOS)break;output.push(token);if(n<count-1)logits=this.step(token,session);
  }
  return Buffer.from(output).toString('utf8').trim();
 }
}
let model;
export function embeddedReply(messages){model ||= new NativeNebula(JSON.parse(readFileSync(new URL('../model-assets/nebula-pilot.json',import.meta.url),'utf8')));return model.reply(messages);}
