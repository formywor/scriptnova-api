import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import handler from '../index.js';
test('deployed Node entrypoint routes Devices and CORS without weakening authentication',async()=>{
 const server=createServer(handler);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 try{
  const response=await fetch(base+'/api/nebula/devices');assert.equal(response.status,401);assert.equal((await response.json()).code,'UNAUTHORIZED');
  const pre=await fetch(base+'/api/nebula/devices/settings',{method:'OPTIONS',headers:{Origin:'https://scriptnovaa.com'}});assert.equal(pre.status,204);assert.match(pre.headers.get('Access-Control-Allow-Methods'),/PUT/);
  const forbidden=await fetch(base+'/api/nebula/devices',{headers:{Origin:'https://evil.test'}});assert.equal(forbidden.status,403);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
