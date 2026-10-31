import {randomUUID,createHash} from 'node:crypto';
import {fetchPublic,publicError,safePublicUrl} from './public-fetch.mjs';
import {publicPageUrl,extractText} from './cloud-tools.mjs';
import {exposedSecrets,redactCredentials} from './developer-tools.mjs';

const issue=(code,severity,url,evidence,fix,confidence='observed')=>({code,severity,url:safePublicUrl(url),evidence,fix,confidence});
const hash=s=>createHash('sha256').update(s).digest('hex');
const cleanHeaders=h=>Object.fromEntries(Object.entries(h||{}).map(([k,v])=>[k,redactCredentials(String(v)).slice(0,800)]));
const pageSummary=p=>({url:safePublicUrl(p.url),status:p.status,bytes:p.bytes,truncated:!!p.truncated,milliseconds:p.milliseconds,headers:cleanHeaders(p.headers),cookies:p.cookies||[],connection:p.connection||{},redirects:p.redirects||[]});
const bounded=signal=>AbortSignal.any([...(signal?[signal]:[]),AbortSignal.timeout(45000)]);
export function relatedHost(host,target){const base=target.replace(/^www\./,'');return host===target||host===base||host==='www.'+base||host==='api.'+base;}
const safeCandidate=(value,base)=>{try{const u=publicPageUrl(new URL(value,base).href);if(u.search||/\b(?:logout|signout|delete|remove|destroy|unsubscribe|activate|reset|verify|callback|checkout|purchase|send)\b/i.test(u.pathname))return null;return u;}catch{return null;}};
export function discoverSurface(text,base){
 const root=new URL(base),scripts=[],endpoints=[],adminPages=[],sourceMaps=[];
 const add=(list,value)=>{const u=safeCandidate(value,base);if(u&&!list.includes(u.href)&&list.length<30)list.push(u.href);};
 for(const m of text.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi))add(scripts,m[1]);
 for(const m of text.matchAll(/(?:https:\/\/[^\s"'<>`\\)\]}]+|["'`](\/(?:api(?:\/|$)|v[1-9]\/|graphql(?:[\/"'`]|$))[^"'`\s<>]*))/gi)){
  const value=m[1]||m[0],u=safeCandidate(value,base);if(u&&(/\/(?:api|v\d+|graphql|openapi|swagger)(?:[/.]|$)/i.test(u.pathname)||/^(?:api|graphql)\./i.test(u.hostname)))add(endpoints,u.href);
 }
 for(const m of text.matchAll(/(?:href|action)=["']([^"']+)["']/gi)){const u=safeCandidate(m[1],base);if(u&&u.origin===root.origin&&/\/(?:admin|administrator|dashboard|debug|manage)(?:[/.]|$)/i.test(u.pathname))add(adminPages,u.href);}
 for(const m of text.matchAll(/[#@]\s*sourceMappingURL=([^\s*]+)/g)){const u=safeCandidate(m[1],base);if(u&&u.origin===root.origin)add(sourceMaps,u.href);}
 return {scripts,endpoints,adminPages,sourceMaps};
}
export function sourceIssues(p){
 const out=[],text=p.text||'',url=p.url;
 for(const secret of exposedSecrets(text))out.push({...issue('POSSIBLE_EXPOSED_CREDENTIAL','high',url,'Credential-like '+secret.kind+' at line '+secret.line+'. Value withheld.','Verify this is a private credential. If so, rotate it and remove it from public delivery. Public client configuration identifiers are not automatically secrets.','needs-verification'),fingerprint:secret.fingerprint});
 if(/(?:Traceback \(most recent call last\)|(?:Fatal error|Warning):[^\n]{0,160}\bon line \d+|SQLSTATE\[[\w]+\]|Exception in thread|\bat [\w.$]+\([^\n]*:\d+:\d+\))/i.test(text))out.push(issue('PUBLIC_ERROR_TRACE','medium',url,'Response contains a stack-trace or database-error signature; raw details withheld.','Log details privately and return a generic public error.'));
 if(/<title>\s*(?:Index of|Directory listing for)\b/i.test(text))out.push(issue('DIRECTORY_LISTING','medium',url,'Response title identifies a directory listing.','Disable listing where unintended and review accessible files.'));
 return out;
}
function exposure(p,baseline){
 const t=p.text||'',path=new URL(p.url).pathname,issues=[];
 if(p.status<200||p.status>=300)return issues;
 if(baseline?.text&&hash(t)===hash(baseline.text))return issues;
 if(path.endsWith('/.git/HEAD')&&/^(?:ref: refs\/[\w/-]+|[a-f0-9]{40})\s*$/i.test(t.trim()))issues.push(issue('EXPOSED_GIT_METADATA','high',p.url,'Public Git HEAD signature returned. No repository objects were downloaded.','Block .git at the server and check whether source or old credentials were exposed.'));
 if(/\/.env(?:\.[\w-]+)?$/.test(path)&&/^(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=/m.test(t)&&!/<html/i.test(t))issues.push(issue('EXPOSED_ENV_FILE','high',p.url,'Environment-file assignment syntax returned; values withheld.','Deny environment/config files in public hosting. Review and rotate any private credentials.'));
 if(/\.sql$/.test(path)&&/\b(?:CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump)\b/i.test(t))issues.push(issue('PUBLIC_DATABASE_DUMP','high',p.url,'SQL dump signature found in a bounded response prefix. Contents withheld.','Remove the public backup and assess data exposure.'));
 if(/\/server-status$/.test(path)&&/Apache Server Status|Server Version:.*Apache|Total accesses:/i.test(t))issues.push(issue('PUBLIC_SERVER_STATUS','medium',p.url,'Server status signature returned.','Restrict status/debug endpoints to trusted administrators.'));
 if(/\.(?:map)$/.test(path)){try{const v=JSON.parse(t);if(v.version===3&&Array.isArray(v.sources))issues.push(issue('PUBLIC_SOURCE_MAP','info',p.url,'JavaScript source map is public. This alone is not a vulnerability.','Review included source for credentials or internal information; publish intentionally.'));}catch{}}
 return issues;
}
const PATHS=['/.git/HEAD','/.env','/.env.local','/backup.sql','/admin','/administrator','/dashboard','/debug','/server-status','/robots.txt','/sitemap.xml','/openapi.json','/swagger.json','/api-docs','/.well-known/security.txt'];
export async function auditPublicSurface(url,{reader=fetchPublic,signal,pause=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 const scope=publicPageUrl(url),stop=bounded(signal),started=Date.now(),pages=[],findings=[],discovered={scripts:[],endpoints:[],adminPages:[],sourceMaps:[]};
 let reads=0;
 const read=async (target,follow=false)=>{stop.throwIfAborted();reads++;const p=await reader(target,{signal:stop,maxBytes:65536,maxRedirects:follow?3:0,timeoutMs:4500,allowOpaque:true});pages.push(p);findings.push(...sourceIssues(p));return p;};
 const first=await read(scope.href,true),root=new URL(first.url);Object.assign(discovered,discoverSurface(first.text||'',root));
 // Prioritize application scripts; never crawl arbitrary outbound links.
 const scripts=discovered.scripts.filter(s=>new URL(s).origin===root.origin).sort((a,b)=>Number(/(?:app|main|bundle|config)/i.test(new URL(b).pathname))-Number(/(?:app|main|bundle|config)/i.test(new URL(a).pathname))).slice(0,3);
 const checks=[];
 for(const target of scripts){try{const p=await read(target),more=discoverSurface(p.text||'',root);for(const k of Object.keys(discovered))discovered[k]=[...new Set([...discovered[k],...more[k]])].slice(0,30);}catch(e){checks.push({url:safePublicUrl(target),error:publicError(e)});}}
 let baseline;try{baseline=await read(new URL('/nebula-check-not-found-'+randomUUID(),root).href);}catch{}
 const targets=[...new Set([...PATHS.map(p=>new URL(p,root).href),...discovered.adminPages,...discovered.sourceMaps])].slice(0,18);
 for(const target of targets){
  if(stop.aborted)break;
  try{const p=await read(target),soft=!!baseline?.text&&(hash(p.text||'')===hash(baseline.text)||/<html/i.test(p.text||'')&&extractText(p.text||'')===extractText(baseline.text));findings.push(...exposure(p,baseline));
   checks.push({...pageSummary(p),classification:soft?'matches-missing-page-response':p.status===401||p.status===403?'access-restricted':p.status>=300&&p.status<400?'redirect-not-followed':p.status>=400?'not-publicly-readable':'public-response',...(p.status>=200&&p.status<300&&!soft&&/\/(?:admin|administrator|dashboard|debug)(?:[/.]|$)/i.test(new URL(target).pathname)?{review:'Public entry point. Does not establish privileged access or missing authentication.'}:{})});
  }catch(e){checks.push({url:safePublicUrl(target),error:publicError(e)});}
  await pause(150);
 }
 if(first.status>=200&&first.status<300&&/text\/html/i.test(first.headers?.['content-type']||'')){
  for(const h of ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy'])if(!first.headers[h])findings.push(issue('MISSING_'+h.toUpperCase().replaceAll('-','_'),'low',first.url,'Header absent in this response.','Review the appropriate server policy. Missing headers alone do not prove XSS, compromise or exploitability.','configuration-observation'));
 }
 return {mode:'bounded-public-surface-review',url:safePublicUrl(first.url),summary:{requests:reads,findings:findings.length,elapsedMs:Date.now()-started,partial:stop.aborted},findings:findings.slice(0,60),discovered,connection:first.connection||{},page:pageSummary(first),checks,limits:{maximumLogicalReads:23,concurrency:1,maxBytesPerResponse:65536,timeoutSeconds:45,methods:['GET'],maxInitialPageRedirects:3,maxProbeRedirects:0},notice:'Only public, credential-free reads on the requested origin. No login bypass, payload injection, port scan, brute force or server-log connection. Admin pages, API documentation, robots.txt, sitemap.xml and public source maps are discovery leads, not vulnerabilities by themselves. A missing-page comparison reduces false positives but cannot eliminate them. Findings cover only checked responses; absence of matches does not prove the site secure.'};
}
export async function testPublicApi(url,{reader=fetchPublic,signal}={}){
 const u=safeCandidate(url,url);if(!u)throw Object.assign(Error('Read-only endpoint required'),{code:'INVALID_API_TARGET',status:400});const stop=bounded(signal),checks=[];
 for(const method of ['GET','HEAD','OPTIONS']){try{const p=await reader(u.href,{signal:stop,method,origin:'https://nebula-diagnostic.invalid',maxBytes:32768,maxRedirects:0,timeoutMs:5000,allowOpaque:true});
  let shape=null;try{const v=JSON.parse(p.text);shape={type:Array.isArray(v)?'array':v===null?'null':typeof v,keys:v&&typeof v==='object'&&!Array.isArray(v)?Object.keys(v).slice(0,25):[],items:Array.isArray(v)?v.length:undefined};}catch{}
  checks.push({...pageSummary(p),method,jsonShape:shape,findings:sourceIssues(p)});
 }catch(e){checks.push({method,url:safePublicUrl(u.href),error:publicError(e)});}}
 if(checks.every(c=>c.error))throw Object.assign(Error('API checks failed'),{code:checks[0].error,status:502});
 const response=checks.find(c=>c.method==='GET'&&!c.error),headers=response?.headers||{},findings=checks.flatMap(c=>c.findings||[]);
 if(headers['access-control-allow-origin']==='*'&&headers['access-control-allow-credentials']==='true')findings.push(issue('INVALID_CORS_COMBINATION','low',u.href,'Wildcard origin and credentials=true observed. Browsers reject this combination for credentialed reads.','Configure explicit trusted origins for credentialed access. This is not evidence of an authentication bypass.','configuration-observation'));
 if(headers['access-control-allow-origin']==='https://nebula-diagnostic.invalid')findings.push(issue('CORS_REFLECTS_TEST_ORIGIN','info',u.href,'The diagnostic Origin was allowed. No credentials or private account data were sent.','Review whether this endpoint is intentionally public. Origin reflection alone does not prove private-data exposure.','needs-verification'));
 return {mode:'public-api-contract-check',url:safePublicUrl(u.href),summary:{requests:checks.length,successfulReads:checks.filter(c=>!c.error).length},findings,checks,notice:'Three bounded unauthenticated GET/HEAD/OPTIONS checks. JSON structure only; no response values, cookies or secret values are exposed. 401/403 can indicate expected access control. OPTIONS may be disabled intentionally. No POST, mutations, authentication bypass, load test or internal/server traffic visibility.'};
}
