import {createCloudHandler} from './lib/cloud.mjs';
import {readReviewTraining} from './lib/review-training.mjs';
import {Readable} from 'node:stream';
import {createApp} from './lib/app.mjs';
import {getStore,verifyToken,getAdminDatabase} from './lib/firebase.mjs';
import {readLearningTopics} from './lib/learning.mjs';
import {createResearchHandler} from './lib/research.mjs';
import {researchServices} from './lib/research-storage.mjs';

export function createNodeHandler(app) {
  return async function handler(req,res) {
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
      const request=new Request(new URL(req.url || '/', 'https://nebula.invalid'),{method,headers,...(body!==undefined?{body,duplex:'half'}:{})});
      const response=await app(request);
      res.writeHead(response.status,Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if(!res.headersSent)res.writeHead(503,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
      res.end('{"code":"UNAVAILABLE"}');
    }
  };
}

const cloudApp=createCloudHandler({getStore,verifyToken});
const publicApp=createApp({getStore,verifyToken});
const researchApp=createResearchHandler({services:researchServices,learning:async now=>readLearningTopics(await getAdminDatabase(),now),reviewTraining:async now=>readReviewTraining(await getAdminDatabase(),now)});
export default createNodeHandler(request=>new URL(request.url).pathname.startsWith('/api/nebula/cloud')?cloudApp(request):new URL(request.url).pathname.startsWith('/api/nebula/research/')?researchApp(request):publicApp(request));
