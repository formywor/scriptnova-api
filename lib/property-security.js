"use strict";
const crypto = require("crypto");
const MAX_CLIP = 1024 * 1024, MAX_CLIPS = 20, TTL = 7 * 86400000;
function cameraId(value) {
  if (!/^[a-z0-9-]{1,48}$/.test(String(value || ""))) throw new Error("Invalid camera ID.");
  return value;
}
function same(a,b) {const x=Buffer.from(String(a||"")),y=Buffer.from(String(b||""));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
function token(secret,id,now=Date.now()) {
  const data=Buffer.from(JSON.stringify({id:cameraId(id),exp:now+30*86400000})).toString("base64url");
  return data+"."+crypto.createHmac("sha256",secret).update(data).digest("base64url");
}
function verify(secret,value,id,now=Date.now()) {
  try {const [data,sig,...extra]=String(value).split(".");if(extra.length||!same(sig,crypto.createHmac("sha256",secret).update(data).digest("base64url")))return false;
    const p=JSON.parse(Buffer.from(data,"base64url"));return p.id===id&&Number(p.exp)>now;
  }catch{return false;}
}
function clipData(value) {
  if(typeof value!=="string" || value.length>MAX_CLIP*1.34+100)throw new Error("Clip exceeds 1 MB.");
  const m=value.match(/^data:video\/(webm|mp4)(?:;codecs=[a-zA-Z0-9.,-]+)?;base64,([A-Za-z0-9+/]+={0,2})$/);
  if(!m||!m[2]||Buffer.from(m[2],"base64").length>MAX_CLIP||Buffer.from(m[2],"base64").toString("base64")!==m[2])throw new Error("Invalid video clip.");
  return value;
}
function prune(clips,now=Date.now()) {
  return Object.fromEntries(Object.entries(clips||{}).filter(([,v])=>Number(v.createdAt)>now-TTL).sort((a,b)=>b[1].createdAt-a[1].createdAt).slice(0,MAX_CLIPS));
}
async function acceptAnswer(ref, generation, description, now) {
  const result = await ref.transaction(old => {
    // A fresh serverless instance may first see null even when the offer exists.
    // Returning null lets Firebase compare with the server and retry with real data.
    // Never seed the callback with a previously fetched offer: that could revive
    // an offer that was removed or overwrite a newer dashboard connection.
    if (old === null) return null;
    if (old.generation !== generation) return undefined;
    return {...old, answer: description, updatedAt: now};
  });
  const saved = result.snapshot.val();
  if (!result.committed || !saved || saved.generation !== generation ||
      saved.answer?.type !== "answer" || saved.answer?.sdp !== description.sdp) {
    const error = new Error("A newer dashboard connection is waiting. The camera will retry automatically.");
    error.status = 409;
    throw error;
  }
}
function mountPropertySecurity(app,{root}) {
  const secret=process.env.PROPERTY_SECURITY_SECRET||"";
  const enabled=secret.length>=32;
  const wrap=fn=>async(req,res)=>{try{await fn(req,res);}catch(e){res.status(e.status||400).json({ok:false,error:e.message||"Security request failed."});}};
  function auth(req,res,next) {
    if(!enabled)return res.status(503).json({ok:false,error:"Property security is not configured. Set PROPERTY_SECURITY_SECRET in Vercel."});
    req.securityKey=String(req.headers.authorization||"").replace(/^Bearer /,"");
    req.securityOwner=same(req.securityKey,secret);
    next();
  }
  function owner(req) {if(!req.securityOwner){const e=new Error("Dashboard key required.");e.status=401;throw e;}}
  function access(req,id) {if(!req.securityOwner&&!verify(secret,req.securityKey,id)){const e=new Error("Camera pairing expired or invalid.");e.status=401;throw e;}}
  app.use("/api/property-security",auth);
  app.get("/api/property-security/config",wrap(async(req,res)=>{
    owner(req);
    const iceServers=[{urls:"stun:stun.l.google.com:19302"}];
    if(process.env.PROPERTY_TURN_URL&&process.env.PROPERTY_TURN_USERNAME&&process.env.PROPERTY_TURN_PASSWORD)
      iceServers.push({urls:process.env.PROPERTY_TURN_URL.split(","),username:process.env.PROPERTY_TURN_USERNAME,credential:process.env.PROPERTY_TURN_PASSWORD});
    res.json({ok:true,iceServers,relayConfigured:iceServers.length>1,maxClipBytes:MAX_CLIP,retentionDays:7,maxClips:MAX_CLIPS});
  }));
  app.post("/api/property-security/pair",wrap(async(req,res)=>{
    owner(req);const id=cameraId(req.body.cameraId);
    const iceServers=[{urls:"stun:stun.l.google.com:19302"}];
    if(process.env.PROPERTY_TURN_URL&&process.env.PROPERTY_TURN_USERNAME&&process.env.PROPERTY_TURN_PASSWORD)iceServers.push({urls:process.env.PROPERTY_TURN_URL.split(","),username:process.env.PROPERTY_TURN_USERNAME,credential:process.env.PROPERTY_TURN_PASSWORD});
    res.json({ok:true,token:token(secret,id),iceServers});
  }));
  app.get("/api/property-security/signal/:id",wrap(async(req,res)=>{
    const id=cameraId(req.params.id);access(req,id);
    const data=(await root.child("propertySecuritySignals/"+id).get()).val();
    res.json({ok:true,signal:data&&Number(data.updatedAt)>Date.now()-120000?data:null});
  }));
  app.post("/api/property-security/signal/:id",wrap(async(req,res)=>{
    const id=cameraId(req.params.id);access(req,id);
    const {generation,description}=req.body;
    if(!/^[a-f0-9]{32}$/.test(String(generation))||!description||typeof description.sdp!=="string"||description.sdp.length>48000||description.type!==(req.securityOwner?"offer":"answer"))throw new Error("Invalid connection signal.");
    const ref=root.child("propertySecuritySignals/"+id),now=Date.now();
    if(req.securityOwner)await ref.set({generation,offer:description,updatedAt:now});
    else await acceptAnswer(ref, generation, description, now);
    res.json({ok:true});
  }));
  app.get("/api/property-security/clips",wrap(async(req,res)=>{
    owner(req);const ref=root.child("propertySecurityClips");
    const result=await ref.transaction(old=>prune(old));
    res.json({ok:true,clips:Object.entries(result.snapshot.val()||{}).map(([id,{data,...meta}])=>({id,...meta})).sort((a,b)=>b.createdAt-a.createdAt)});
  }));
  app.post("/api/property-security/clips",wrap(async(req,res)=>{
    owner(req);const data=clipData(req.body.data),id=crypto.randomBytes(16).toString("hex"),now=Date.now();
    const clip={data,cameraId:cameraId(req.body.cameraId),location:String(req.body.location||"Camera").slice(0,80),createdAt:now};
    await root.child("propertySecurityClips").transaction(old=>prune({...old,[id]:clip},now));
    res.json({ok:true,id});
  }));
  app.get("/api/property-security/clips/:id",wrap(async(req,res)=>{
    owner(req);if(!/^[a-f0-9]{32}$/.test(req.params.id))throw new Error("Invalid clip ID.");
    const clip=(await root.child("propertySecurityClips/"+req.params.id).get()).val();
    if(!clip||clip.createdAt<Date.now()-TTL)return res.status(404).json({ok:false,error:"Clip unavailable or expired."});res.json({ok:true,clip});
  }));
  app.delete("/api/property-security/clips/:id",wrap(async(req,res)=>{
    owner(req);if(!/^[a-f0-9]{32}$/.test(req.params.id))throw new Error("Invalid clip ID.");
    await root.child("propertySecurityClips/"+req.params.id).remove();res.json({ok:true});
  }));
}
module.exports={mountPropertySecurity,cameraId,token,verify,clipData,prune,MAX_CLIP,acceptAnswer};
