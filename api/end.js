const crypto = require('crypto');
const { getRedis } = require('./_redis');
const { rateLimit } = require('./_rate');
const { BUILD, getJsonBody, incrementCounter, dateKey } = require('./_admin');

function cors(res){ res.setHeader('Access-Control-Allow-Origin','*'); res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization'); }
function b64urlToBuffer(s){ s=String(s||'').replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Buffer.from(s,'base64'); }
function safeJsonParse(str){ try{return JSON.parse(str);}catch{return null;} }
function isSafeClientId(s){ return !!s && s.length>=16 && s.length<=80 && /^[A-Za-z0-9\-_.]+$/.test(s); }
function verifyToken(token, secret){
  if(!token||token.indexOf('.')===-1) return {ok:false,error:'bad_token'};
  const parts=token.split('.');
  if(parts.length!==2) return {ok:false,error:'bad_token'};
  const payloadB64=parts[0], sigB64=parts[1];
  const expected=crypto.createHmac('sha256', secret).update(payloadB64).digest().toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  const a=Buffer.from(expected), b=Buffer.from(sigB64);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return {ok:false,error:'bad_sig'};
  const payload=safeJsonParse(b64urlToBuffer(payloadB64).toString('utf8'));
  if(!payload||!payload.lic||!payload.sid||!payload.cid) return {ok:false,error:'bad_payload'};
  return {ok:true,payload};
}
function sessionKey(lic,sid){ return 'sn:session:'+lic+':'+sid; }
function activeSetKey(lic){ return 'sn:active:'+lic; }

module.exports = async function handler(req,res){
  cors(res);
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST') return res.status(405).json({ok:false,error:'method_not_allowed',build:BUILD});

  const rl=await rateLimit(req,'end',240,60);
  if(!rl.ok){
    res.setHeader('Retry-After', String(rl.retryAfter));
    return res.status(429).json({ok:false,error:'rate_limited',retryAfter:rl.retryAfter,build:BUILD});
  }

  const secret=String(process.env.SECRET_SALT||'');
  if(!secret||secret.length<16) return res.status(500).json({ok:false,error:'server_misconfigured_secret',build:BUILD});

  const body=await getJsonBody(req);
  const token=String(body.token||'');
  const cid=String(body.clientId||'').trim();
  if(!isSafeClientId(cid)) return res.status(400).json({ok:false,error:'bad_client_id',build:BUILD});

  const vt=verifyToken(token, secret);
  if(!vt.ok) return res.status(403).json({ok:false,error:vt.error,build:BUILD});

  const {lic,sid,cid:tokenCid}=vt.payload;
  if(cid!==tokenCid) return res.status(403).json({ok:false,error:'client_mismatch',build:BUILD});

  let redis;
  try{redis=getRedis();}catch{return res.status(500).json({ok:false,error:'redis_not_configured',build:BUILD});}

  await redis.del(sessionKey(lic,sid));
  await redis.srem(activeSetKey(lic), sid);
  await incrementCounter(redis, dateKey('sn:metric:end'));

  return res.status(200).json({ok:true,build:BUILD});
};