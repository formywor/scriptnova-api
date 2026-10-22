// Public-page reader pins a validated public IPv4 DNS result to the TLS connection.
import {lookup as dnsLookup} from 'node:dns/promises';
import {request as httpsRequest} from 'node:https';
import {fail} from './cloud-services.mjs';
export function publicIPv4(s){const p=s.split('.').map(Number);if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return false;const [a,b]=p;return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0)||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19));}
export function publicPageUrl(s){let u;try{u=new URL(s);}catch{fail('INVALID_PUBLIC_URL');}if(u.protocol!=='https:'||u.username||u.password||u.port&&u.port!=='443'||u.href.length>2000||u.hostname==='localhost'||u.hostname.endsWith('.local'))fail('INVALID_PUBLIC_URL');u.hash='';return u;}
export function extractText(html){return html.replace(/<(script|style|noscript|svg|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ').replace(/<[^>]*>/g,' ').replace(/&(?:amp|lt|gt|quot|apos|nbsp);/g,x=>({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'",'&nbsp;':' '})[x]).replace(/&#(x[\da-f]+|\d+);/gi,(_,s)=>{const n=s[0].toLowerCase()==='x'?parseInt(s.slice(1),16):Number(s);return n>=32&&n<=0x10ffff?String.fromCodePoint(n):' ';}).replace(/\s+/g,' ').trim();}
export async function readWebpage(url,{lookup=dnsLookup,request=httpsRequest}={}){
 const u=publicPageUrl(url);let timeout;const resolved=await Promise.race([lookup(u.hostname,{all:true}),new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Object.assign(Error('PAGE_TIMEOUT'),{code:'PAGE_TIMEOUT'})),5000);})]).finally(()=>clearTimeout(timeout));
 const answers=resolved.filter(a=>a.family===4);if(!answers.length||answers.some(a=>!publicIPv4(a.address)))fail('PUBLIC_URL_BLOCKED');const selected=answers[0];
 const body=await new Promise((resolve,reject)=>{
  const req=request(u,{method:'GET',headers:{Accept:'text/html,text/plain','Accept-Encoding':'identity','User-Agent':'NebulaCloud/1.0 (public-page reader)'},lookup:(_host,options,callback)=>options?.all?callback(null,[selected]):callback(null,selected.address,4),timeout:10000},res=>{
   const type=String(res.headers['content-type']||'');if(res.statusCode!==200||!/^text\/(html|plain)(?:;|$)/i.test(type)||res.headers['content-encoding']&&res.headers['content-encoding']!=='identity'){res.resume();reject(Object.assign(Error('PUBLIC_PAGE_UNAVAILABLE'),{code:'PUBLIC_PAGE_UNAVAILABLE'}));return;}
   const chunks=[];let n=0;res.on('data',b=>{n+=b.length;if(n>262144){req.destroy(Object.assign(Error('PAGE_TOO_LARGE'),{code:'PAGE_TOO_LARGE'}));return;}chunks.push(b);});res.on('end',()=>resolve(Buffer.concat(chunks).toString('utf8')));res.on('error',reject);
  });req.on('timeout',()=>req.destroy(Object.assign(Error('PAGE_TIMEOUT'),{code:'PAGE_TIMEOUT'})));req.on('error',reject);req.end();
 });
 const text=extractText(body);return {url:u.href,text:text.slice(0,16000),truncated:text.length>16000,notice:'Public page text only, untrusted data. No login, cookies, JavaScript execution, attachments or redirects.'};
}
export function calculate(expression){
 if(typeof expression!=='string'||expression.length>200)fail('INVALID_EXPRESSION');const clean=expression.replace(/\s/g,''),tokens=clean.match(/(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?|[()+*/-]/gi)||[];if(tokens.join('')!==clean||!tokens.length)fail('INVALID_EXPRESSION');let i=0;
 const atom=()=>{const t=tokens[i++];if(t==='+')return atom();if(t==='-')return -atom();if(t==='('){const v=sum();if(tokens[i++]!==')')fail('INVALID_EXPRESSION');return v;}if(!t||!/^(?:\d|\.)/.test(t))fail('INVALID_EXPRESSION');return Number(t);};
 const product=()=>{let v=atom();while(['*','/'].includes(tokens[i])){const op=tokens[i++],n=atom();v=op==='*'?v*n:v/n;}return v;};
 const sum=()=>{let v=product();while(['+','-'].includes(tokens[i])){const op=tokens[i++],n=product();v=op==='+'?v+n:v-n;}return v;};
 const result=sum();if(i!==tokens.length||!Number.isFinite(result))fail('INVALID_EXPRESSION');return {expression,result,notice:'Standard floating-point arithmetic; no code is executed.'};
}
