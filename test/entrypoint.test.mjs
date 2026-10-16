import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {readFileSync,existsSync} from 'node:fs';
import {createNodeHandler} from '../index.js';

function result(){return {headersSent:false,writeHead(status,headers){this.status=status;this.headers=headers;this.headersSent=true;},end(body){this.body=Buffer.from(body).toString();}};}
test('Vercel parsed bodies retain JSON, path, origin, and trusted network identity',async()=>{
  const req={method:'POST',url:'/api/nebula/chat',headers:{'content-type':'application/json',origin:'https://scriptnovaa.com','x-vercel-forwarded-for':'203.0.113.1'},body:{messages:[{role:'user',content:'hello'}]}};
  const handler=createNodeHandler(async request=>{assert.equal(new URL(request.url).pathname,'/api/nebula/chat');assert.equal(request.headers.get('origin'),'https://scriptnovaa.com');assert.equal(request.headers.get('x-vercel-forwarded-for'),'203.0.113.1');assert.deepEqual(await request.json(),req.body);return Response.json({reply:'hello'},{headers:{'Cache-Control':'no-store'}});});
  const res=result();await handler(req,res);assert.equal(res.status,200);assert.equal(res.headers['cache-control'],'no-store');assert.deepEqual(JSON.parse(res.body),{reply:'hello'});
});
test('raw Node requests and bodyless CORS preflight work with the same entrypoint',async()=>{
  const raw=Readable.from([Buffer.from('{"token":"abc"}')]);raw.method='DELETE';raw.url='/api/nebula/training';raw.headers={'content-type':'application/json'};
  const handler=createNodeHandler(async request=>{if(request.method==='OPTIONS')return new Response(null,{status:204});assert.deepEqual(await request.json(),{token:'abc'});return Response.json({deleted:true});});
  const res=result();await handler(raw,res);assert.equal(res.status,200);
  const preflight=Readable.from([]);preflight.method='OPTIONS';preflight.url='/api/nebula/chat';preflight.headers={};const options=result();await handler(preflight,options);assert.equal(options.status,204);assert.equal(options.body,'');
});
test('entrypoint errors return safe JSON without internal details',async()=>{
  const res=result();await createNodeHandler(async()=>{throw Error('private model URL and credentials');})({method:'GET',headers:{},url:'/'},res);assert.equal(res.status,503);assert.deepEqual(JSON.parse(res.body),{code:'UNAVAILABLE'});
});
test('explicit Vercel build target and local start target both exist',()=>{
  const root=new URL('../',import.meta.url);const config=JSON.parse(readFileSync(new URL('vercel.json',root)));const pkg=JSON.parse(readFileSync(new URL('package.json',root)));
  assert.equal(config.builds.length,1);assert.equal(config.builds[0].src,'index.js');assert.ok(existsSync(new URL(config.builds[0].src,root)));assert.equal(config.routes[0].dest,'index.js');assert.equal(pkg.main,'index.js');assert.ok(existsSync(new URL(pkg.scripts.start.slice(5),root)));assert.ok(!existsSync(new URL('server.mjs',root)));assert.ok(!existsSync(new URL('api/index.mjs',root)));
});
