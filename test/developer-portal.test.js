"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), crypto = require("node:crypto");
const mount = require("../lib/developer-portal");
test("DNS names reject unsafe, reserved and first-party custom domains", () => {
  assert.equal(mount.slug("iii-dev"), "iii-dev");
  for (const name of ["iii_dev", "api", "-test", "test-", "a.b", "__proto__"]) assert.throws(() => mount.slug(name));
  assert.equal(mount.domain("Play.Example.com"), "play.example.com");
  for(const name of ["https://example.com", "a.scriptnovaa.com", "localhost", "127.0.0.1", "example.com/path"]) assert.throws(()=>mount.domain(name));
});
test("first-party auto approval is 90 percent with a stable account bucket; custom domains never auto approve",()=>{
  let accepted=0;
  for(let i=0;i<100;i++) {const hash=()=>Math.floor((i+0.5)/100*0x100000000).toString(16).padStart(8,'0');if(mount.automaticApproval('account','',hash))accepted++;assert.equal(mount.automaticApproval('account','play.example.com',hash),false);}
  assert.equal(accepted,90);
  assert.throws(()=>mount.slug('admin-team'));
});
function fixture() {
  const routes = {}, data = {accounts:{alice:{username:"alice", registeredDeviceId:"d",activeSessionId:"g"},bob:{username:"bob"}},devices:{d:{accountId:"alice",status:"ACTIVE"}},sessions:{g:{product:"galaxy",status:"ACTIVE",accountId:"alice",deviceId:"d",tokenId:"t",startedAt:Date.now()-1000,expiresAt:Date.now()+60000,leaseExpiresAt:Date.now()+30000}},tokens:{t:{status:"ACTIVE",sessionId:"g",ownerAccountId:"alice"}}};
  let user="alice",admin=false,result;
  const read=async p=>p.split("/").reduce((x,k)=>x?.[k],data);
  mount({get:(p,h)=>routes[p]=h,post:(p,h)=>routes[p]=h},{route:f=>f,requireAccount:async()=>({id:user,data:data.accounts[user]}),requireAdmin:async()=>{if(!admin)throw new Error("Admin required");return {id:user,data:data.accounts[user]};},read,atomic:async fn=>{const next=fn(structuredClone(data));for(const key of Object.keys(data))delete data[key];Object.assign(data,next);return data;},root:{child:p=>({set:async value=>{const keys=p.split("/"),last=keys.pop();let node=data;for(const key of keys)node=node[key]||=( {} );node[last]=value;}})},rateLimit:async()=>{},adminAudit:async()=>{},hmac:x=>crypto.createHmac("sha256","test-key").update(x).digest("hex")});
  return {data,setUser:value=>user=value,setAdmin:value=>admin=value,call:async(p,body={},headers={})=>{result=undefined;await routes[p]({body,headers},{json:x=>result=x});return result;}};
}
test("DNS verification explains missing ownership and routing separately", async () => {
  const dns = require("node:dns/promises"), oldTxt = dns.resolveTxt, oldCname = dns.resolveCname;
  const target = process.env.HOSTING_TARGET_DOMAIN;
  process.env.HOSTING_TARGET_DOMAIN = "hosting.scriptnovaa.com";
  try {
    const f = fixture();
    f.data.hostingSites = {alice:{customDomain:"play.example.com",verificationToken:"test"}};
    dns.resolveTxt = async () => []; dns.resolveCname = async () => ["hosting.scriptnovaa.com"];
    await assert.rejects(f.call("/api/developer/domain/verify"), e => /Ownership TXT/.test(e.message) && !/Routing CNAME/.test(e.message));
    dns.resolveTxt = async () => [["scriptnovaa-verification=test"]]; dns.resolveCname = async () => [];
    await assert.rejects(f.call("/api/developer/domain/verify"), e => /Routing CNAME/.test(e.message) && !/Ownership TXT/.test(e.message));
    dns.resolveCname = async () => ["hosting.scriptnovaa.com."];
    await f.call("/api/developer/domain/verify");
    assert.ok(f.data.hostingSites.alice.domainVerifiedAt);
  } finally {
    dns.resolveTxt = oldTxt; dns.resolveCname = oldCname;
    if (target === undefined) delete process.env.HOSTING_TARGET_DOMAIN; else process.env.HOSTING_TARGET_DOMAIN = target;
  }
});
test("programs prevent duplicates and enforce administrator review; developer approval grants beta",async()=>{
  const f=fixture();await f.call("/api/developer/requests",{type:"DEVELOPER",message:"I want to build a safe static educational browser project."});
  await assert.rejects(f.call("/api/developer/requests",{type:"DEVELOPER",message:"A duplicate application that should not be accepted."}));
  await assert.rejects(f.call("/api/admin/program-review",{accountId:"alice",type:"DEVELOPER",decision:"APPROVED",reason:"Reviewed the complete proposal."}));
  f.setAdmin(true);await f.call("/api/admin/program-review",{accountId:"alice",type:"DEVELOPER",decision:"APPROVED",reason:"Reviewed the complete proposal."});
  assert.equal(f.data.accounts.alice.betaProgramStatus,"ACTIVE");assert.equal(f.data.accounts.alice.developerProgramStatus,"APPROVED");assert.equal(Object.keys(f.data.adminAuditLog).length,1);
  await assert.rejects(f.call("/api/admin/program-review",{accountId:"alice",type:"DEVELOPER",decision:"DECLINED",reason:"Second decision blocked."}));
});
test("hosting reservation checks approval and slug collisions",async()=>{
  const f=fixture();await assert.rejects(f.call("/api/developer/site",{slug:"alice"}));
  f.data.accounts.alice.developerProgramStatus="APPROVED";await f.call("/api/developer/site",{slug:"alice"});
  f.setUser("bob");f.data.accounts.bob.developerProgramStatus="APPROVED";
  await assert.rejects(f.call("/api/developer/site",{slug:"alice"}));
  await f.call("/api/developer/site",{slug:"bob-site",customDomain:"play.example.com"});assert.equal(f.data.hostingSites.bob.status,"PENDING");
});
test("explicit root domains show TXT only and subdomains have relative host fields",async()=>{
  const f=fixture();f.data.accounts.alice.developerProgramStatus="APPROVED";
  await f.call("/api/developer/site",{slug:"example",customDomain:"example.com",domainKind:"ROOT",dnsZone:"example.com"});
  let portal=await f.call("/api/developer/portal");assert.equal(portal.site.dns.length,1);assert.equal(portal.site.dns[0].host,"_scriptnovaa");
  f.setUser("bob");f.data.accounts.bob.developerProgramStatus="APPROVED";
  await assert.rejects(f.call("/api/developer/site",{slug:"other",customDomain:"play.example.org",domainKind:"SUBDOMAIN",dnsZone:"wrong.org"}));
  await f.call("/api/developer/site",{slug:"other",customDomain:"play.example.org",domainKind:"SUBDOMAIN",dnsZone:"example.org"});
  portal=await f.call("/api/developer/portal");assert.equal(portal.site.dns[0].host,"_scriptnovaa.play");assert.equal(portal.site.dns[1].host,"play");
});
test("timed grants bind hostname and enforce revocation, device state and expiry",async()=>{
  const previous={...process.env};process.env.HOSTING_ENABLED="true";process.env.HOSTING_GATEWAY_SECRET="a-long-private-test-key-at-least-32-characters";process.env.HOSTING_TARGET_DOMAIN="hosting.scriptnovaa.com";
  try {
    const f=fixture();f.data.accounts.alice.developerProgramStatus="APPROVED";await f.call("/api/developer/site",{slug:"alice"});f.setAdmin(true);
    await assert.rejects(f.call("/api/admin/hosting-review",{accountId:"alice",decision:"ACTIVE",reason:"Verified the routing and TLS."}));
    await f.call("/api/admin/hosting-review",{accountId:"alice",decision:"ACTIVE",reason:"Verified the routing and TLS.",tlsReady:true});
    const launch=await f.call("/api/hosting/launch",{slug:"alice"});const access=new URLSearchParams(new URL(launch.url).hash.slice(1)).get("access");
    const body={access,host:"alice.scriptnovaa.com"},headers={"x-hosting-key":process.env.HOSTING_GATEWAY_SECRET};
    await assert.rejects(f.call("/api/hosting/render",body,{}));
    assert.equal((await f.call("/api/hosting/render",body,headers)).site.slug,"alice");
    await assert.rejects(f.call("/api/hosting/render",{...body,host:"bob.scriptnovaa.com"},headers));
    await assert.rejects(f.call("/api/hosting/render",{...body,access:access+"tampered"},headers));
    f.data.devices.d.status="REVOKED";await assert.rejects(f.call("/api/hosting/render",body,headers));f.data.devices.d.status="ACTIVE";
    f.data.sessions.g.leaseExpiresAt=0;await assert.rejects(f.call("/api/hosting/render",body,headers));f.data.sessions.g.leaseExpiresAt=Date.now()+30000;
    f.data.sessions.g.status="FINISHED";await assert.rejects(f.call("/api/hosting/render",body,headers));
  } finally {for(const key of ["HOSTING_ENABLED","HOSTING_GATEWAY_SECRET","HOSTING_TARGET_DOMAIN"]) {if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}}
});
