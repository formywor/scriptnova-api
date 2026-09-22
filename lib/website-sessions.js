"use strict";
const crypto = require("node:crypto");
function catalog(records) {
  const demo = {id:"scriptnovaa", name:"ScriptNovaa demonstration", url:"https://scriptnovaa.com/features", description:"Our own demonstration, not an outside sponsor.", mode:"embed"};
  return [demo, ...Object.entries(records || {}).filter(([id,s]) => id !== demo.id && /^[a-z0-9-]{1,64}$/.test(id) && s?.status === "ACTIVE" && s.permissionConfirmed === true).flatMap(([id,s]) => {
    try { const url = new URL(s.url); if(url.protocol !== "https:" || url.username || url.password || url.hash) return [];
      return [{id,name:String(s.name || id).slice(0,100),description:String(s.description || "").slice(0,500),url:url.href,mode:s.mode === "embed" ? "embed" : "link"}];
    } catch {return [];}
  })];
}
module.exports = function mount(app,{route,requireAccount,read,atomic,rateLimit}) {
  const list = async () => catalog(await read("sponsors"));
  app.get("/api/sponsors",route(async(req,res)=>res.json({ok:true,sponsors:await list()})));
  app.get("/api/website/session",route(async(req,res)=>{
    const user = await requireAccount(req), session = await read(`websiteSessions/${user.id}`);
    const sponsor = session?.status === "ACTIVE" && (await list()).find(s=>s.id===session.sponsorId);
    res.json({ok:true,session:sponsor ? {...session,sponsor} : null});
  }));
  app.post("/api/website/session/start",route(async(req,res)=>{
    const user=await requireAccount(req); await rateLimit(user.id,"website-start",20,3600);
    const available=await list(), sponsor=available.find(s=>s.id===req.body.sponsorId);
    if(!sponsor) throw Object.assign(new Error("This sponsor is unavailable."),{statusCode:404});
    let session;
    await atomic(data=>{
      data.websiteSessions ||= {};
      const old=data.websiteSessions[user.id];
      const reusable=old?.status === "ACTIVE" && available.some(s=>s.id===old.sponsorId);
      if(reusable && old.sponsorId !== sponsor.id) throw Object.assign(new Error("End your current website session before choosing another sponsor."),{statusCode:409});
      session=reusable ? old : {id:crypto.randomUUID(),sponsorId:sponsor.id,status:"ACTIVE",startedAt:Date.now()};
      data.websiteSessions[user.id]=session;return data;
    });
    res.json({ok:true,session:{...session,sponsor}});
  }));
  app.post("/api/website/session/end",route(async(req,res)=>{
    const user=await requireAccount(req);await rateLimit(user.id,"website-end",30,3600);
    await atomic(data=>{
      const session=data.websiteSessions?.[user.id];
      // A stale tab must never end a newer session.
      if(session?.status === "ACTIVE" && session.id === req.body.sessionId) Object.assign(session,{status:"ENDED",endedAt:Date.now()});
      return data;
    });res.json({ok:true});
  }));
};
module.exports.catalog=catalog;
