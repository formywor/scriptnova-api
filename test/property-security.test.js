"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {token,verify,clipData,prune,cameraId}=require("../lib/property-security");
const core=require("../../main-website/property-security-core");
test("camera credentials cannot act for another slot and expire",()=>{const secret="x".repeat(48),t=token(secret,"garage",1000);assert(verify(secret,t,"garage",2000));assert(!verify(secret,t,"room",2000));assert(!verify(secret,t+"x","garage",2000));assert(!verify(secret,t,"garage",1000+31*86400000));assert.throws(()=>cameraId("../other"));});
test("clips are bounded and retention caps expired and excess clips",()=>{assert.equal(clipData("data:video/webm;base64,AQID"),"data:video/webm;base64,AQID");assert.throws(()=>clipData("data:text/html;base64,AQID"));assert.throws(()=>clipData("data:video/webm;base64,"+Buffer.alloc(1024*1024+1).toString("base64")));const now=10*86400000;const c=Object.fromEntries(Array.from({length:25},(_,i)=>["c"+i,{createdAt:now-i}]));c.old={createdAt:0};const p=prune(c,now);assert.equal(Object.keys(p).length,20);assert(!p.old);assert(!p.c24);});
test("warning and countdown cancel on departure, disarm, and lost video",()=>{const input={present:true,armed:true,connected:true,now:0,grace:5,countdown:3,response:"alarm"};let s=core.step({phase:"idle"},input);s=core.step(s,{...input,now:1100});assert.equal(s.event,"warn");s=core.step(s,{...input,now:6200});assert.equal(s.phase,"countdown");for(const change of [{present:false},{armed:false},{connected:false}])assert.equal(core.step(s,{...input,now:6300,...change}).phase,"idle");s=core.step(s,{...input,now:9300});assert.equal(s.event,"alarm");assert.equal(core.step(s,{...input,now:25000}).phase,"cooldown");});
test("record-only locations never enter alarm and zones use foot point",()=>{const i={present:true,armed:true,connected:true,now:0,grace:1,countdown:3,response:"record"};let s=core.step({phase:"idle"},i);s=core.step(s,{...i,now:1200});assert.equal(s.event,"record");assert.equal(s.phase,"cooldown");assert(core.inside([10,10,20,30],100,100,{x:0,y:0,w:.5,h:.5}));assert(!core.inside([70,10,20,30],100,100,{x:0,y:0,w:.5,h:.5}));});

test("API pairing isolates cameras and denies clip access to phones",async()=>{
 const {mountPropertySecurity}=require("../lib/property-security");
 const previous=process.env.PROPERTY_SECURITY_SECRET;process.env.PROPERTY_SECURITY_SECRET="owner-"+"s".repeat(48);
 const routes=new Map();let middleware;const app={use:(path,fn)=>{middleware=fn;}};
 for(const method of ["get","post","delete"])app[method]=(path,fn)=>routes.set(method+" "+path,fn);
 const store={};const root={child:path=>({get:async()=>({val:()=>store[path]??(path.startsWith("propertySecurityClips/")?store.propertySecurityClips?.[path.split("/")[1]]:null)??null}),set:async v=>{store[path]=v;},remove:async()=>{delete store[path];if(path.startsWith("propertySecurityClips/"))delete store.propertySecurityClips?.[path.split("/")[1]];},transaction:async fn=>{const next=fn(store[path]??null);if(next===undefined)return {committed:false,snapshot:{val:()=>store[path]}};store[path]=next;return {committed:true,snapshot:{val:()=>next}};}})};
 try{mountPropertySecurity(app,{root});
 async function call(method,path,key,body={},params={}){
  const req={headers:{authorization:"Bearer "+key},body,params};const res={statusCode:200,status(n){this.statusCode=n;return this;},json(v){this.body=v;return this;}};
  let next=false;middleware(req,res,()=>{next=true;});if(next)await routes.get(method+" "+path)(req,res);return res;
 }
 const owner=process.env.PROPERTY_SECURITY_SECRET;
 const paired=await call("post","/api/property-security/pair",owner,{cameraId:"garage"});assert.equal(paired.statusCode,200);const phone=paired.body.token;
 const denied=await call("get","/api/property-security/clips",phone);assert.equal(denied.statusCode,401);
 const other=await call("get","/api/property-security/signal/:id",phone,{}, {id:"bedroom"});assert.equal(other.statusCode,401);
 const generation="a".repeat(32),offer={type:"offer",sdp:"v=0"},answer={type:"answer",sdp:"v=0"};
 assert.equal((await call("post","/api/property-security/signal/:id",phone,{generation,description:offer},{id:"garage"})).statusCode,400);
 assert.equal((await call("post","/api/property-security/signal/:id",owner,{generation,description:offer},{id:"garage"})).statusCode,200);
 assert.equal((await call("post","/api/property-security/signal/:id",phone,{generation:"b".repeat(32),description:answer},{id:"garage"})).statusCode,400);
 assert.equal((await call("post","/api/property-security/signal/:id",phone,{generation,description:answer},{id:"garage"})).statusCode,200);
 const upload=await call("post","/api/property-security/clips",owner,{cameraId:"garage",location:"Garage",data:"data:video/webm;base64,AQID"});assert.equal(upload.statusCode,200);
 const list=await call("get","/api/property-security/clips",owner);assert.equal(list.body.clips.length,1);assert.equal(list.body.clips[0].data,undefined);
 assert.equal((await call("get","/api/property-security/clips/:id",phone,{}, {id:upload.body.id})).statusCode,401);
 assert.equal((await call("get","/api/property-security/clips/:id",owner,{}, {id:upload.body.id})).body.clip.location,"Garage");
 assert.equal((await call("delete","/api/property-security/clips/:id",owner,{}, {id:upload.body.id})).statusCode,200);
 assert.equal((await call("get","/api/property-security/clips",owner)).body.clips.length,0);
 }finally{if(previous===undefined)delete process.env.PROPERTY_SECURITY_SECRET;else process.env.PROPERTY_SECURITY_SECRET=previous;}
});
test("disconnected idle cameras do not cancel another camera's voice",()=>{
 assert.equal(core.step({phase:"idle"},{connected:false,armed:true,now:1}).event,"");
 assert.equal(core.step({phase:"warning"},{connected:false,armed:true,now:1}).event,"cancel");
});
