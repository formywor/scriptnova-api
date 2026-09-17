"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const mount=require('../lib/galaxy-link');
test('website approval requires ownership; polling requires the private launcher secret',async()=>{
  const routes={},data={}; let accountId='alice';
  const fail=(message)=>{throw new Error(message)};
  mount({post:(path,handler)=>{routes[path]=handler}}, {
    route:fn=>fn,requireVersion:()=>{},rateLimit:async()=>{},hmac:x=>'hash:'+x,fail,
    requireAccount:async()=>({id:accountId}),read:async path=>data[path],
    root:{child:path=>({set:async value=>{data[path]=value},transaction:async fn=>{
      const value=fn(data[path]);if(value===undefined)return {committed:false};data[path]=value;return {committed:true};
    }})}
  });
  let result; const res={json:value=>{result=value}};
  await routes['/api/galaxy/link/start']({ip:'local',body:{}},res);
  const {id,secret}=result;
  data['devicePairings/hash:ABCDE12345']={accountId:'alice',status:'OPEN',expiresAt:Date.now()+60000};
  accountId='bob';
  await assert.rejects(routes['/api/galaxy/link/approve']({body:{id,code:'ABCDE12345'}},res));
  accountId='alice';await routes['/api/galaxy/link/approve']({body:{id,code:'ABCDE12345'}},res);
  await assert.rejects(routes['/api/galaxy/link/poll']({body:{id,secret:'wrong'}},res));
  await routes['/api/galaxy/link/poll']({body:{id,secret}},res);
  assert.equal(result.code,'ABCDE12345');
  data['galaxyLinks/'+id].expiresAt=0;
  await assert.rejects(routes['/api/galaxy/link/poll']({body:{id,secret}},res));
});
