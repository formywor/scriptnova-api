// Credential-free HTTPS reads. Validate and pin DNS again on EVERY redirect/retry.
import {lookup as dnsLookup} from 'node:dns/promises';
import {request as httpsRequest} from 'node:https';
import {createGunzip,createInflate,createBrotliDecompress} from 'node:zlib';
import {publicPageUrl,publicIPv4} from './cloud-tools.mjs';

const fault=code=>Object.assign(new Error(code),{code});
export function publicError(error){
 const code=String(error?.code||error?.cause?.code||'');
 if(['ENOTFOUND','ENODATA','EAI_NONAME'].includes(code))return 'DNS_NOT_FOUND';
 if(['EAI_AGAIN','DNS_TIMEOUT'].includes(code))return 'DNS_TIMEOUT';
 if(['ETIMEDOUT','ESOCKETTIMEDOUT','UND_ERR_CONNECT_TIMEOUT'].includes(code)||error?.name==='TimeoutError')return 'SOURCE_TIMEOUT';
 if(/CERT|TLS|SSL|SELF_SIGNED/.test(code))return 'TLS_UNAVAILABLE';
 if(['ECONNRESET','ECONNREFUSED','EHOSTUNREACH','ENETUNREACH','EPIPE','EADDRNOTAVAIL'].includes(code))return 'SOURCE_CONNECTION_FAILED';
 if(error?.name==='AbortError')return 'CANCELED';
 return /^[A-Z_]+$/.test(code)?code:'CLOUD_UNAVAILABLE';
}
export const publicErrorMessage=code=>({DNS_NOT_FOUND:'This hostname could not be found in DNS. Check the spelling and whether the www subdomain exists.',DNS_TIMEOUT:'The website’s DNS lookup timed out.',SOURCE_TIMEOUT:'The website did not respond before the time limit.',SOURCE_CONNECTION_FAILED:'The connection to this website failed.',TLS_UNAVAILABLE:'The website’s HTTPS certificate or TLS connection could not be verified.',PUBLIC_URL_BLOCKED:'This URL resolves to a private or unsupported network address.',INVALID_PUBLIC_URL:'Use a public HTTPS URL without credentials.',REDIRECT_LIMIT:'The website redirected too many times.',REDIRECT_LOOP:'The website returned a redirect loop.',SOURCE_TYPE_UNSUPPORTED:'This response format cannot be inspected as a webpage.',SOURCE_TOO_LARGE:'This response exceeded the inspection size limit.',ENCODING_UNSUPPORTED:'The website returned an unsupported response encoding.',CLOUD_BROWSER_UNAVAILABLE:'Rendered browsing is unavailable; a public-source view may still work.',CLOUD_BROWSER_PREPARING:'The rendered browser is starting; a public-source view may still work.',CLOUD_TOOL_LIMIT:'This response reached its Cloud action budget. Narrow the request or continue in another turn.',CANCELED:'The action was canceled.'})[code]||'This action could not finish. The error code identifies which check failed.';
export function safePublicUrl(value){try{const u=new URL(value);return u.origin+u.pathname;}catch{return '';}}

async function addresses(host,lookup,signal){
 signal?.throwIfAborted();let timer;
 const abort=()=>{throw signal.reason||fault('CANCELED');};
 const result=await Promise.race([lookup(host,{all:true}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fault('DNS_TIMEOUT')),4000);timer.unref?.();})]).finally(()=>clearTimeout(timer));
 if(signal?.aborted)abort();
 const ipv4=result.filter(a=>a.family===4);
 if(!ipv4.length||ipv4.some(a=>!publicIPv4(a.address)))throw fault('PUBLIC_URL_BLOCKED');
 return ipv4.slice(0,2);
}

function readOnce(u,selected,{request,signal,maxBytes,timeoutMs,truncate}){
 return new Promise((resolve,reject)=>{
  let settled=false,totalTimer,decoder;
  const done=(error,value)=>{if(settled)return;settled=true;clearTimeout(totalTimer);error?reject(error):resolve(value);};
  const req=request(u,{method:'GET',signal,timeout:timeoutMs,headers:{Accept:'text/html,text/plain,text/css,application/javascript,text/javascript,application/json,application/xml,text/xml','Accept-Encoding':'gzip, deflate, br','User-Agent':'NebulaCloud/3.0 (authorized public-source inspection)'},lookup:(_host,options,callback)=>options?.all?callback(null,[selected]):callback(null,selected.address,4)},res=>{
   const status=res.statusCode||0,headers=res.headers;
   if([301,302,303,307,308].includes(status)&&headers.location){res.resume();try{done(null,{redirect:new URL(headers.location,u).href,status});}catch{done(fault('INVALID_PUBLIC_URL'));}return;}
   const type=String(headers['content-type']||'');
   if(!/^(?:text\/(?:html|plain|javascript|css|xml)|application\/(?:javascript|json|xml|xhtml\+xml))(?:;|$)/i.test(type)){res.resume();done(fault('SOURCE_TYPE_UNSUPPORTED'));return;}
   const encoding=String(headers['content-encoding']||'identity').toLowerCase();
   decoder=encoding==='gzip'?createGunzip():encoding==='deflate'?createInflate():encoding==='br'?createBrotliDecompress():null;
   if(!decoder&&encoding!=='identity'){res.resume();done(fault('ENCODING_UNSUPPORTED'));return;}
   let bytes=0,wireBytes=0;const chunks=[],stream=decoder||res;
   const finish=truncated=>done(null,{url:u.href,status,headers,text:Buffer.concat(chunks).toString('utf8'),bytes,truncated});
   res.on('data',b=>{wireBytes+=b.length;if(wireBytes>Math.max(262144,maxBytes*2)){done(fault('SOURCE_TOO_LARGE'));req.destroy();decoder?.destroy();}});
   stream.on('data',b=>{if(settled)return;const keep=b.subarray(0,Math.max(0,maxBytes-bytes));chunks.push(keep);bytes+=keep.length;if(keep.length<b.length){if(truncate)finish(true);else done(fault('SOURCE_TOO_LARGE'));req.destroy();decoder?.destroy();}});
   stream.on('end',()=>{if(!settled)finish(false);});stream.on('error',error=>done(error));res.on('error',error=>done(error));res.on('aborted',()=>done(fault('SOURCE_CONNECTION_FAILED')));
   if(decoder)res.pipe(decoder);
  });
  req.on('error',error=>done(error));req.on('timeout',()=>req.destroy(fault('SOURCE_TIMEOUT')));
  totalTimer=setTimeout(()=>req.destroy(fault('SOURCE_TIMEOUT')),timeoutMs);totalTimer.unref?.();req.end();
 });
}

export async function fetchPublic(url,{lookup=dnsLookup,request=httpsRequest,signal,maxBytes=262144,maxRedirects=3,timeoutMs=8000,truncate=true}={}){
 const started=Date.now(),seen=new Set(),redirects=[];let u=publicPageUrl(url),retries=0;
 if(/[?&](?:token|key|secret|api[_-]?key|password|authorization)=/i.test(u.search))throw fault('INVALID_PUBLIC_URL');
 try{
  for(let hop=0;;hop++){
   signal?.throwIfAborted();u=publicPageUrl(u.href);
   if(/[?&](?:token|key|secret|api[_-]?key|password|authorization)=/i.test(u.search))throw fault('INVALID_PUBLIC_URL');
   if(seen.has(u.href))throw fault('REDIRECT_LOOP');seen.add(u.href);
   let response,lastError;const ips=await addresses(u.hostname,lookup,signal);
   for(let i=0;i<ips.length;i++){
    try{response=await readOnce(u,ips[i],{request,signal,maxBytes,timeoutMs,truncate});break;}
    catch(error){lastError=error;if(!['SOURCE_TIMEOUT','SOURCE_CONNECTION_FAILED'].includes(publicError(error))||i===ips.length-1)throw error;retries++;signal?.throwIfAborted();}
   }
   if(!response)throw lastError||fault('SOURCE_CONNECTION_FAILED');
   if(response.redirect){if(hop>=maxRedirects)throw fault('REDIRECT_LIMIT');const next=publicPageUrl(response.redirect);redirects.push({from:safePublicUrl(u.href),to:safePublicUrl(next.href),status:response.status});u=next;continue;}
   const allow=['content-type','content-security-policy','content-security-policy-report-only','strict-transport-security','x-content-type-options','referrer-policy','permissions-policy','x-frame-options','cache-control','server','x-powered-by','x-robots-tag'];
   const headers=Object.fromEntries(allow.filter(k=>response.headers[k]).map(k=>[k,String(response.headers[k]).slice(0,2500)]));
   const cookies=[].concat(response.headers['set-cookie']||[]).slice(0,15).map(v=>({secure:/;\s*secure(?:;|$)/i.test(v),httpOnly:/;\s*httponly(?:;|$)/i.test(v),sameSite:v.match(/;\s*samesite=(strict|lax|none)/i)?.[1]?.toLowerCase()||'unspecified'}));
   return {...response,headers,cookies,requestedUrl:safePublicUrl(url),redirects,retries,milliseconds:Date.now()-started};
  }
 }catch(error){const code=publicError(error);throw Object.assign(fault(code),{status:['INVALID_PUBLIC_URL','PUBLIC_URL_BLOCKED'].includes(code)?400:code==='DNS_NOT_FOUND'?422:502,reason:publicErrorMessage(code)});}
}
