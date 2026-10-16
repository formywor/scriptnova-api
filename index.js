import {Readable} from 'node:stream';
import {createApp} from './lib/app.mjs';
import {getStore} from './lib/firebase.mjs';

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

export default createNodeHandler(createApp({getStore}));
