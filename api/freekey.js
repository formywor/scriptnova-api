const crypto = require('crypto');
const { getRedis } = require('./_redis');
const { rateLimit } = require('./_rate');
const { BUILD, getJsonBody, freeKeyRedisKey, incrementCounter, dateKey } = require('./_admin');

function cors(res){ res.setHeader('Access-Control-Allow-Origin','https://scriptnovaa.com'); res.setHeader('Vary','Origin'); res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type'); }
function isFromScriptNovaa(req){
  const host=String(req.headers.host||'').toLowerCase();
  const origin=String(req.headers.origin||'').toLowerCase();
  const referer=String(req.headers.referer||'').toLowerCase();
  return host==='scriptnovaa.com'||host.endsWith('.scriptnovaa.com')||origin==='https://scriptnovaa.com'||referer.indexOf('https://scriptnovaa.com/')===0;
}
function makeFreeKey(){
  const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out='';
  for(let i=0;i<6;i++) out+=alphabet[Math.floor(Math.random()*alphabet.length)];
  return 'FREE-'+out;
}

module.exports = async function handler(req,res){
  cors(res);
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST') return res.status(405).json({ok:false,error:'method_not_allowed',build:BUILD});
  if(!isFromScriptNovaa(req)) return res.status(403).json({ok:false,error:'domain_blocked',build:BUILD});

  const rl=await rateLimit(req,'freekey',8,60);
  if(!rl.ok){
    res.setHeader('Retry-After', String(rl.retryAfter));
    return res.status(429).json({ok:false,error:'rate_limited',retryAfter:rl.retryAfter,build:BUILD});
  }

  let redis;
  try{redis=getRedis();}catch{return res.status(500).json({ok:false,error:'redis_not_configured',build:BUILD});}

  const body=await getJsonBody(req);
  const proof=String(body.proof||'').trim();
  const proofSecret=String(process.env.FREEKEY_PROOF_SECRET||'');
  if(proofSecret){
    if(!proof) return res.status(403).json({ok:false,error:'proof_required',build:BUILD});
    const parts=proof.split(':');
    if(parts.length!==3) return res.status(403).json({ok:false,error:'bad_proof',build:BUILD});
    const ts=parseInt(parts[0],10)||0;
    const nonce=String(parts[1]||'');
    const sig=String(parts[2]||'');
    const now=Math.floor(Date.now()/1000);
    if(!ts||Math.abs(now-ts)>180) return res.status(403).json({ok:false,error:'proof_expired',build:BUILD});
    const expected=crypto.createHmac('sha256', proofSecret).update(String(ts)+'|'+nonce).digest('hex');
    if(expected!==sig) return res.status(403).json({ok:false,error:'bad_proof',build:BUILD});
    const replayKey='sn:freekey:proof:'+sig;
    const seen=await redis.get(replayKey);
    if(seen) return res.status(403).json({ok:false,error:'proof_used',build:BUILD});
    await redis.set(replayKey,'1',{ ex:180 });
  }

  const key=makeFreeKey();
  const now=Math.floor(Date.now()/1000);
  const exp=now+900;
  await redis.set(freeKeyRedisKey(key), JSON.stringify({ exp, issuedAt: now }), { ex:900 });
  await incrementCounter(redis, dateKey('sn:metric:freekey'));

  return res.status(200).json({ ok:true, key, exp, ttlSeconds:900, build:BUILD });
};