"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),mount=require("../lib/website-sessions");
test("catalog requires explicit approval, HTTPS and permission",()=>{
  const list=mount.catalog({no:{status:"PENDING",url:"https://example.com"},bad:{status:"ACTIVE",permissionConfirmed:true,url:"javascript:alert(1)"},good:{status:"ACTIVE",permissionConfirmed:true,url:"https://example.com",name:"Example",mode:"embed"}});
  assert.deepEqual(list.map(s=>s.id),["scriptnovaa","good"]);
});
test("website sessions are account scoped, untimed, idempotent and safely revocable",async()=>{
  const routes={},data={},read=async p=>p.split('/').reduce((x,k)=>x?.[k],data);let id="alice",result;
  mount({get:(p,h)=>routes[p]=h,post:(p,h)=>routes[p]=h},{route:f=>f,requireAccount:async()=>({id}),read,atomic:async f=>{const next=f(structuredClone(data));Object.assign(data,next);},rateLimit:async()=>{}});
  const call=async(path,body={})=>{await routes[path]({body},{json:x=>result=x});return result;};
  const first=(await call('/api/website/session/start',{sponsorId:'scriptnovaa'})).session;
  assert.equal(first.expiresAt,undefined);
  assert.equal((await call('/api/website/session/start',{sponsorId:'scriptnovaa'})).session.id,first.id);
  id='bob';assert.equal((await call('/api/website/session')).session,null);
  await call('/api/website/session/end',{sessionId:first.id});id='alice';assert.ok((await call('/api/website/session')).session);
  await call('/api/website/session/end',{sessionId:'old'});assert.ok((await call('/api/website/session')).session);
  await call('/api/website/session/end',{sessionId:first.id});assert.equal((await call('/api/website/session')).session,null);
  await assert.rejects(call('/api/website/session/start',{sponsorId:'unknown'}));
});
