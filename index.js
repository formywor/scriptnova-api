import {createDeskHandler} from './lib/desk.mjs';
import {createDeveloperApiHandler} from './lib/developer-api.mjs';
import {createDeveloperHandler} from './lib/developer.mjs';
import {createDevicesHandler} from './lib/devices.mjs';
import {createCloudHandler} from './lib/cloud.mjs';
import {readReviewTraining} from './lib/review-training.mjs';
import {Readable} from 'node:stream';
import {once} from 'node:events';
import {createApp} from './lib/app.mjs';
import {getStore,verifyToken,getAdminDatabase} from './lib/firebase.mjs';
import {readLearningTopics} from './lib/learning.mjs';
import {createResearchHandler} from './lib/research.mjs';
import {researchServices} from './lib/research-storage.mjs';

export function createNodeHandler(app) {
  return async function handler(req,res) {
    const abort=new AbortController(),onAborted=()=>abort.abort(),onClose=()=>{if(!res.writableEnded)abort.abort();};
    req.on?.('aborted',onAborted);res.on?.('close',onClose);
    try {
      const headers=new Headers();
      for(const [name,value] of Object.entries(req.headers || {})) {
        if(value !== undefined)headers.set(name,Array.isArray(value)?value.join(', '):String(value));
      }
      const method=req.method || 'GET';
      let body;
      if(!['GET','HEAD'].includes(method)) {
        // Vercel may have parsed req.body; local HTTP requests are raw streams.
        if(req.body !== undefined)body=typeof req.body==='string'||Buffer.isBuffer(req.body)?req.body:JSON.stringify(req.body);
        else body=Readable.toWeb(req);
      }
      const request=new Request(new URL(req.url || '/', 'https://nebula.invalid'),{method,headers,signal:abort.signal,...(body!==undefined?{body,duplex:'half'}:{})});
      const response=await app(request);
      res.writeHead(response.status,Object.fromEntries(response.headers));
      if(response.headers.get('content-type')?.startsWith('text/event-stream')){
        res.flushHeaders?.();
        for await(const chunk of response.body){if(abort.signal.aborted)break;if(!res.write(Buffer.from(chunk)))await once(res,'drain',{signal:abort.signal});}
        res.end();
      }else res.end(Buffer.from(await response.arrayBuffer()));
    } catch(error) {
      if(!abort.signal.aborted)console.error('NEBULA_ADAPTER_FAILED',{name:String(error?.name||'Error').slice(0,50),code:/^[A-Z_]{1,60}$/.test(error?.code||'')?error.code:'ADAPTER_ERROR'});
      if(!res.headersSent)res.writeHead(503,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
      res.end('{"code":"UNAVAILABLE"}');
    }finally{req.removeListener?.('aborted',onAborted);res.removeListener?.('close',onClose);}
  };
}

const deskApp=createDeskHandler({getStore,verifyToken});
const developerApi=createDeveloperApiHandler({getStore,verifyToken});
const developerApp=createDeveloperHandler({getStore,verifyToken});
const devicesApp=createDevicesHandler({getStore,verifyToken});
const cloudApp=createCloudHandler({getStore,verifyToken});
const publicApp=createApp({getStore,verifyToken});
const researchApp=createResearchHandler({services:researchServices,learning:async now=>readLearningTopics(await getAdminDatabase(),now),reviewTraining:async now=>readReviewTraining(await getAdminDatabase(),now)});
export default createNodeHandler(request=>/^\/api\/nebula\/desk(?:\/|$)/.test(new URL(request.url).pathname)?deskApp(request):/^\/v1(?:\/|$)/.test(new URL(request.url).pathname)||/^\/api\/nebula\/api-keys(?:\/|$)/.test(new URL(request.url).pathname)?developerApi(request):/^\/api\/nebula\/developer(?:\/|$)/.test(new URL(request.url).pathname)?developerApp(request):/^\/api\/nebula\/devices(?:\/|$)/.test(new URL(request.url).pathname)?devicesApp(request):new URL(request.url).pathname.startsWith('/api/nebula/cloud')?cloudApp(request):new URL(request.url).pathname.startsWith('/api/nebula/research/')?researchApp(request):publicApp(request));
