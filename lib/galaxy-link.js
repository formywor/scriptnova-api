"use strict";
const crypto = require("node:crypto");
module.exports = function(app, {route, root, read, requireAccount, requireVersion, rateLimit, fail, hmac}) {
  app.post('/api/galaxy/link/start', route(async (req,res) => {
    requireVersion(req); await rateLimit(req.ip, 'GALAXY_LINK', 10, 900);
    const id=crypto.randomBytes(16).toString('hex'), secret=crypto.randomBytes(32).toString('hex');
    await root.child('galaxyLinks/'+id).set({secretHash:hmac(secret), expiresAt:Date.now()+600000});
    res.json({ok:true,id,secret,url:'https://scriptnovaa.com/galaxy-connect?id='+id});
  }));
  app.post('/api/galaxy/link/approve', route(async(req,res)=>{
    const account=await requireAccount(req), id=String(req.body.id||'');
    if(!/^[a-f0-9]{32}$/.test(id))fail('Invalid connection request.');
    const code=String(req.body.code||'').replace(/[^A-F0-9]/gi,'').toUpperCase();
    const pairing=await read('devicePairings/'+hmac(code));
    if(!pairing||pairing.accountId!==account.id||pairing.status!=='OPEN'||pairing.expiresAt<=Date.now())fail('Generate a current connection code first.');
    const result=await root.child('galaxyLinks/'+id).transaction(current=>{
      if(!current||current.expiresAt<=Date.now()||current.code)return;
      return {...current,code,accountId:account.id};
    },undefined,false);
    if(!result.committed)fail('Connection request expired or already approved.',409);
    res.json({ok:true});
  }));
  app.post('/api/galaxy/link/poll',route(async(req,res)=>{
    requireVersion(req); const id=String(req.body.id||'');
    if(!/^[a-f0-9]{32}$/.test(id))fail('Invalid request.');
    const value=await read('galaxyLinks/'+id);
    if(!value||value.expiresAt<=Date.now()||value.secretHash!==hmac(String(req.body.secret||'')))fail('Connection request expired.',403);
    res.json({ok:true,code:value.code||null});
  }));
};
