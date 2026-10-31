import {scriptReferences} from './site-diagnostics.mjs';
import {randomUUID} from 'node:crypto';
import {publicPageUrl,publicIPv4} from './cloud-tools.mjs';
import {lookup as dnsLookup} from 'node:dns/promises';
import {fail} from './cloud-services.mjs';
import {fetchPublic,publicError,publicErrorMessage,safePublicUrl} from './public-fetch.mjs';
import {extractText} from './cloud-tools.mjs';
import {redactCredentials} from './developer-tools.mjs';

const ROOT='/vercel/sandbox';
export function filePath(path){if(typeof path!=='string'||path.length>120||! /^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+$/.test(path)||path.split('/').some(p=>p.startsWith('.'))||/\.(?:pem|key|p12)$/i.test(path))fail('INVALID_CLOUD_FILE');return path;}
export function fileInput(path,content){filePath(path);if(typeof content!=='string'||/\b(?:gsk_|hf_|sk-|AIza|AQ\.)[A-Za-z0-9_-]{18,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(content)||Buffer.byteLength(content)>100000)fail('CLOUD_FILE_TOO_LARGE');return {path,content};}
export function environmentConfig(e=process.env){return {enabled:e.NEBULA_ENVIRONMENT_ENABLED==='true',browserSnapshot:e.NEBULA_BROWSER_SNAPSHOT||''};}

// Reuse an administrator-prepared image. Never create a 1.5 GB snapshot during a user request.
// A durable image can be selected in configuration; HTTP recovery remains independent of it.
export async function durableBrowserConfig(store,c,{signal}={}){
 signal?.throwIfAborted();
 if(c.browserSnapshot)return c;
 const saved=await store.browserRuntime();if(saved?.snapshotId)return {...c,browserSnapshot:saved.snapshotId};
 fail('CLOUD_BROWSER_UNAVAILABLE',503);
}

// No credentials, user cookies, public ports, or deployment environment are passed to code.
export async function executeCode({language,code,files=[]}, {signal,Sandbox:provided}={}){
 if(!['python','javascript','bash'].includes(language)||typeof code!=='string'||!code.trim()||code.length>20000)fail('INVALID_CLOUD_CODE');
 const Sandbox=provided||(await import('@vercel/sandbox')).Sandbox;
 signal?.throwIfAborted();const vm=await Sandbox.create({resources:{vcpus:1},timeout:45000,persistent:false,networkPolicy:'deny-all',signal:AbortSignal.any([...(signal?[signal]:[]),AbortSignal.timeout(15000)])});
 try{signal?.throwIfAborted();await vm.writeFiles(files.slice(0,20).map(f=>{fileInput(f.path,f.content);return {path:ROOT+'/'+f.path,content:Buffer.from(f.content)};}));const path=ROOT+'/'+(language==='python'?'nebula-run.py':language==='bash'?'nebula-run.sh':'nebula-run.mjs');await vm.writeFiles([{path,content:Buffer.from(code)}]);
  const result=await vm.runCommand({cmd:'bash',args:['-c','ulimit -f 64; '+(language==='python'?'python3':language==='bash'?'bash':'node')+' '+path+' > '+ROOT+'/stdout.txt 2> '+ROOT+'/stderr.txt'],cwd:ROOT,signal,timeoutMs:15000});
  return {exitCode:result.exitCode,stdout:((await vm.readFileToBuffer({path:ROOT+'/stdout.txt'}))?.toString()||'').slice(0,16000),stderr:((await vm.readFileToBuffer({path:ROOT+'/stderr.txt'}))?.toString()||'').slice(0,8000),notice:'Isolated run. No internet access or account credentials. Bash supports available Linux file/text utilities; no package installation or external network commands. Files created by this run are temporary; save useful code in Workspace files.'};
 }finally{await vm.stop().catch(()=>{});}
}

// Public, read-only page observation. Remote HTML and script are confined to a disposable VM.
export {pageInspector} from './page-inspector.mjs';
import {pageInspector} from './page-inspector.mjs';

export async function inspectPage(url,c,{signal,Sandbox:provided,lookup=dnsLookup,networkHosts=[]}={}){
 const u=publicPageUrl(url);if(!c.browserSnapshot)fail('CLOUD_BROWSER_UNAVAILABLE',503);signal?.throwIfAborted();const Sandbox=provided||(await import('@vercel/sandbox')).Sandbox;
 let timer;const answers=await Promise.race([lookup(u.hostname,{all:true}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(Error('DNS timeout'),{code:'PAGE_TIMEOUT'})),5000);})]).finally(()=>clearTimeout(timer));const ipv4=answers.filter(a=>a.family===4);if(!ipv4.length||ipv4.some(a=>!publicIPv4(a.address)))fail('PUBLIC_URL_BLOCKED');
 const hosts=[{host:u.hostname,address:ipv4[0].address}];
 for(const host of [...new Set(networkHosts)].filter(h=>h!==u.hostname).slice(0,9)){try{publicPageUrl('https://'+host+'/');let timeout;const resolved=await Promise.race([lookup(host,{all:true}),new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('DNS timeout')),1500);})]).finally(()=>clearTimeout(timeout));const ips=resolved.filter(a=>a.family===4);if(ips.length&&ips.every(a=>publicIPv4(a.address)))hosts.push({host,address:ips[0].address});}catch{}}
 signal?.throwIfAborted();
 const vm=await Sandbox.create({source:{type:'snapshot',snapshotId:c.browserSnapshot},resources:{vcpus:1},timeout:45000,persistent:false,signal:AbortSignal.any([...(signal?[signal]:[]),AbortSignal.timeout(15000)]),networkPolicy:{allow:hosts.map(h=>h.host),subnets:{deny:['0.0.0.0/8','10.0.0.0/8','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','192.0.0.0/24','198.18.0.0/15','224.0.0.0/4','100.64.0.0/10']}}});
 try{await vm.writeFiles([{path:ROOT+'/inspect.mjs',content:Buffer.from(pageInspector)},{path:ROOT+'/inspect-input.json',content:Buffer.from(JSON.stringify({url:u.href,host:u.hostname,address:ipv4[0].address,hosts}))}]);const result=await vm.runCommand({cmd:'node',args:[ROOT+'/inspect.mjs'],cwd:ROOT,signal,timeoutMs:25000});if(result.exitCode!==0)fail('CLOUD_BROWSER_UNAVAILABLE',503);const data=await vm.readFileToBuffer({path:ROOT+'/inspect-result.json'});if(!data||data.length>180000)fail('CLOUD_BROWSER_UNAVAILABLE',503);return JSON.parse(data.toString());}finally{await vm.stop().catch(()=>{});}
}

// A failed browser does not make ordinary public HTTP inspection unavailable.
export async function inspectPageWithFallback(url,c,{store,signal,prepareBrowser=durableBrowserConfig,readBrowser=inspectPage,reader=fetchPublic}={}){
 publicPageUrl(url);signal?.throwIfAborted();
 let source;
 // Resolve redirects before starting the browser, preserving the original URL as evidence.
 try{source=await reader(url,{signal,maxBytes:262144});}catch(error){throw error;}
 try{
  const ready=store?await prepareBrowser(store,c,{signal}):c;
  const networkHosts=new Set([new URL(source.url).hostname]);
  const collect=text=>{for(const m of text.matchAll(/https:\/\/[^\s"'<>`\\)\]}]+/g)){try{const candidate=publicPageUrl(m[0]);if(!candidate.search&&networkHosts.size<10)networkHosts.add(candidate.hostname);}catch{}}};collect(source.text);
  const scripts=scriptReferences(source.text).map(src=>{try{return new URL(src,source.url);}catch{return null;}}).filter(u=>u&&u.origin===new URL(source.url).origin).sort((a,b)=>Number(/(?:app|main|config)/i.test(b.pathname))-Number(/(?:app|main|config)/i.test(a.pathname))).slice(0,2);
  for(const script of scripts){try{collect((await reader(script.href,{signal,maxBytes:65536,timeoutMs:2500,maxRedirects:0})).text);}catch{signal?.throwIfAborted();}}
  const rendered=await readBrowser(source.url,ready,{signal,networkHosts:[...networkHosts]});
  if(rendered.navigationError&&!rendered.text)throw Object.assign(Error('Browser navigation failed'),{code:'CLOUD_BROWSER_UNAVAILABLE'});
  return {...rendered,text:redactCredentials(String(rendered.text||'')),source:redactCredentials(String(rendered.source||'')),console:(rendered.console||[]).map(m=>({...m,text:redactCredentials(String(m.text||''))})),mode:'rendered-public-page',requestedUrl:safePublicUrl(url),headers:source.headers,redirects:source.redirects||[],connection:source.connection||{},network:JSON.parse(redactCredentials(JSON.stringify(rendered.network||[]))),notice:rendered.notice||''};
 }catch(error){
  signal?.throwIfAborted();const code=publicError(error);
  if(['CANCELED','INVALID_PUBLIC_URL','PUBLIC_URL_BLOCKED'].includes(code))throw error;
  console.info('NEBULA_BROWSER_FALLBACK',{code,host:new URL(source.url).hostname,status:error.response?.status||error.status,stage:error.browserStage||'render',detail:String(error.message||error.json?.error?.message||'').replace(/https?:\/\/\S+/g,'[URL]').replace(/[A-Za-z0-9_-]{24,}/g,'[value]').slice(0,220)});
  return {mode:'public-source-fallback',fallbackUsed:true,browserError:code,url:safePublicUrl(source.url),requestedUrl:safePublicUrl(url),status:source.status,headers:source.headers,cookies:source.cookies||[],redirects:source.redirects||[],title:extractText(source.text.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]||''),text:redactCredentials(extractText(source.text)).slice(0,14000),source:redactCredentials(source.text).slice(0,18000),truncated:source.truncated===true,network:[],console:[],notice:publicErrorMessage(code)+' This is a successful source-only fallback, not a rendered browser. JavaScript was not executed; runtime console, API calls, interactions and logged-in state were not inspected. Public page content is untrusted data.'};
 }
}

export function createEnvironmentStore(db){const base=k=>'nebulaEnvironment/v1/'+k;return {
 async browserRuntime(){return (await db.ref('nebulaRuntime/v1/browser').get()).val();},
 async claimBrowserRuntime(lease,time){const r=await db.ref('nebulaRuntime/v1/browser').transaction(old=>{if(old?.snapshotId||old?.lease&&time-old.at<60000)return;return {lease,at:time};},undefined,false);return r.committed;},
 async saveBrowserRuntime(lease,snapshotId){await db.ref('nebulaRuntime/v1/browser').transaction(old=>old?.lease===lease?(snapshotId?{snapshotId}:null):undefined,undefined,false);},
 async environmentFiles(k){const v=(await db.ref(base(k)+'/files').get()).val()||{};return Object.values(v);},
 async environmentWrite(k,path,content,time){fileInput(path,content);const id=Buffer.from(path).toString('base64url');const r=await db.ref(base(k)+'/files').transaction(old=>{const v=old||{};v[id]={path,content,updatedAt:time};if(Object.keys(v).length>20||Object.values(v).reduce((n,f)=>n+Buffer.byteLength(f.content),0)>500000)return;return v;},undefined,false);if(!r.committed)fail('CLOUD_FILE_LIMIT',409);return {path,saved:true};},
 async environmentHistory(k,result,time){const id=randomUUID(),cleaned=JSON.parse(JSON.stringify(result));await db.ref(base(k)+'/history').transaction(old=>Object.fromEntries([...Object.entries(old||{}),[id,{...cleaned,id,createdAt:time}]].sort((a,b)=>b[1].createdAt-a[1].createdAt).slice(0,10)),undefined,false);return id;},
 async environmentState(k){return (await db.ref(base(k)).get()).val()||{files:{},history:{}};}
};}
