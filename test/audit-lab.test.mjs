import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createAuditLabHandler} from '../lib/audit-lab.mjs';
test('audit fixtures are disabled by default and have no application dependencies',async()=>{
 const app=createAuditLabHandler({enabled:()=>false});assert.equal((await app(new Request('https://api.test/api/nebula/audit-lab/debug'))).status,404);
});
test('enabled lab exposes synthetic records only, never accepts mutations or arbitrary IDs',async()=>{
 const app=createAuditLabHandler({enabled:()=>true});const call=(p,method='GET')=>app(new Request('https://api.test/api/nebula/audit-lab'+p,{method}));
 for(const id of ['1001','1002']){const r=await call('/records/'+id);const body=await r.json();assert.equal(body.synthetic,true);assert.equal(body.id,id);assert.match(body.text,/No real user/);}
 assert.equal((await call('/records/1003')).status,404);assert.equal((await call('/records/1001','POST')).status,405);assert.equal(await (await call('/debug','HEAD')).text(),'');assert.equal((await call('/debug','OPTIONS')).status,204);
});
