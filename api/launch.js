const crypto = require('crypto');
const { getRedis } = require('./_redis');
const { rateLimit } = require('./_rate');
const { BUILD, getJsonBody, incrementCounter, dateKey, trackError, getLicenseMeta, globalPausedKey, getConfig } = require('./_admin');

function cors(res){ res.setHeader('Access-Control-Allow-Origin','*'); res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization'); }
function b64urlToBuffer(s){ s=String(s||'').replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Buffer.from(s,'base64'); }
function b64urlFromBuffer(buf){ return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,''); }
function safeJsonParse(str){ try{return JSON.parse(str);}catch{return null;} }
function parseRedisJson(raw){ if(raw==null) return null; if(typeof raw==='object') return raw; if(typeof raw==='string') return safeJsonParse(raw); return safeJsonParse(String(raw)); }
function isSafeClientId(s){ return !!s && s.length>=16 && s.length<=80 && /^[A-Za-z0-9\-_.]+$/.test(s); }
function isSafeHttpUrl(u){ u=String(u||'').trim(); if(!u||u.includes('"')||u.includes("'")||u.includes('\r')||u.includes('\n')) return false; const low=u.toLowerCase(); return low.startsWith('http://')||low.startsWith('https://'); }
function verifyToken(token, secret){
  if(!token||token.indexOf('.')===-1) return {ok:false,error:'bad_token'};
  const parts=token.split('.');
  if(parts.length!==2) return {ok:false,error:'bad_token'};
  const payloadB64=parts[0], sigB64=parts[1];
  const expected=crypto.createHmac('sha256', secret).update(payloadB64).digest();
  const expectedB64=b64urlFromBuffer(expected);
  const a=Buffer.from(expectedB64), b=Buffer.from(sigB64);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return {ok:false,error:'bad_sig'};
  const payload=safeJsonParse(b64urlToBuffer(payloadB64).toString('utf8'));
  if(!payload||!payload.lic||!payload.plan||!payload.exp||!payload.sid||!payload.cid||!payload.hw) return {ok:false,error:'bad_payload'};
  const now=Math.floor(Date.now()/1000);
  if(now>(payload.exp+15)) return {ok:false,error:'expired'};
  return {ok:true,payload};
}
function sessionKey(lic,sid){ return 'sn:session:'+lic+':'+sid; }
function nonceUsedKey(lic,sid,nonce){ return `sn:launchnonce:${lic}:${sid}:${nonce}`; }
function makeLaunchSig(secret,sid,cid,nonce,exp,profileId){
  const msg=`sid=${sid}&cid=${cid}&nonce=${nonce}&exp=${exp}&profile=${profileId}`;
  return b64urlFromBuffer(crypto.createHmac('sha256', secret).update(msg).digest());
}
function normalizeFlagServer(flag){
  const ALLOW={ '--no-first-run':1,'--force-dark-mode':1,'--disable-renderer-backgrounding':1,'--dns-over-https-templates':1,'--user-agent':1,'--disable-extensions':1,'--disable-default-apps':1,'--disable-component-update':1};
  let f=String(flag||'').trim();
  if(!f||/[\r\n\t\0]/.test(f)||!f.startsWith('--')||f.includes('"')) return '';
  const eq=f.indexOf('=');
  const name=eq===-1?f:f.substring(0,eq);
  if(!ALLOW[name]) return '';
  if(eq===-1) return name;
  const val=f.substring(eq+1).trim();
  if(!val) return '';
  return `${name}=${val}`;
}
function getProfileFlags(){
  const ua='Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.110 Safari/537.36';
  return ['--no-first-run','--force-dark-mode','--disable-renderer-backgrounding','--disable-extensions','--disable-default-apps','--disable-component-update','--dns-over-https-templates=https://chrome.cloudflare-dns.com/dns-query','--user-agent='+ua];
}

module.exports = async function handler(req,res){
  cors(res);
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST') return res.status(405).json({ok:false,error:'method_not_allowed',build:BUILD});

  const rl=await rateLimit(req,'launch',240,60);
  if(!rl.ok){
    res.setHeader('Retry-After', String(rl.retryAfter));
    return res.status(429).json({ok:false,error:'rate_limited',retryAfter:rl.retryAfter,build:BUILD});
  }

  const secret=String(process.env.SECRET_SALT||'');
  if(!secret||secret.length<16) return res.status(500).json({ok:false,error:'server_misconfigured_secret',build:BUILD});

  const body=await getJsonBody(req);
  const token=String(body.token||'').trim();
  const clientId=String(body.clientId||'').trim();
  const startUrl=String(body.startUrl||'').trim();
  const launchNonce=String(body.launchNonce||'').trim();
  const launchExp=parseInt(body.launchExp,10)||0;
  const launchSig=String(body.launchSig||'').trim();
  const launchProfileId=String(body.launchProfileId||'').trim();

  if(!isSafeClientId(clientId)) return res.status(400).json({ok:false,error:'bad_client_id',build:BUILD});
  if(!isSafeHttpUrl(startUrl)) return res.status(400).json({ok:false,error:'unsafe_url',build:BUILD});
  if(!launchNonce||launchNonce.length<16) return res.status(400).json({ok:false,error:'bad_nonce',build:BUILD});
  if(!launchExp) return res.status(400).json({ok:false,error:'bad_launch_exp',build:BUILD});
  if(!launchSig) return res.status(400).json({ok:false,error:'bad_launch_sig',build:BUILD});
  if(!launchProfileId) return res.status(400).json({ok:false,error:'bad_profile',build:BUILD});

  const now=Math.floor(Date.now()/1000);
  if(now>launchExp) return res.status(403).json({ok:false,error:'launch_expired',build:BUILD});
  if(launchExp>(now+60)) return res.status(403).json({ok:false,error:'launch_exp_too_far',build:BUILD});

  const vt=verifyToken(token, secret);
  if(!vt.ok) return res.status(403).json({ok:false,error:vt.error,build:BUILD});

  const {lic, plan, sid, hw}=vt.payload;
  if(clientId!==vt.payload.cid) return res.status(403).json({ok:false,error:'client_mismatch',build:BUILD});

  let redis;
  try{redis=getRedis();}catch{return res.status(500).json({ok:false,error:'redis_not_configured',build:BUILD});}

  await incrementCounter(redis, dateKey('sn:metric:launch'));

  if(await redis.get(globalPausedKey())) {
    await trackError(redis,'launcher_paused');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'launcher_paused',build:BUILD});
  }

  const meta=await getLicenseMeta(redis, lic);
  if(!meta.ok){
    await trackError(redis, meta.error || 'not_found');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(200).json({ok:false,plan:'none',error:meta.error,build:BUILD});
  }

  const sk=sessionKey(lic,sid);
  const raw=await redis.get(sk);
  if(!raw){
    await trackError(redis,'session_not_found');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'session_not_found',build:BUILD});
  }

  const s=parseRedisJson(raw);
  if(!s){
    await trackError(redis,'session_corrupt');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'session_corrupt',build:BUILD});
  }

  const expStored=parseInt(s.exp,10)||0;
  if(expStored<=now){
    await redis.del(sk);
    await trackError(redis,'session_expired');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'session_expired',build:BUILD});
  }

  if(String(s.cid||'')!==clientId) return res.status(403).json({ok:false,error:'client_mismatch',build:BUILD});
  if(String(s.hw||'')!==String(hw)) return res.status(403).json({ok:false,error:'hwid_mismatch',build:BUILD});

  const expectedSig=makeLaunchSig(secret,sid,clientId,launchNonce,launchExp,launchProfileId);
  if(expectedSig.length!==launchSig.length || !crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(launchSig))){
    await trackError(redis,'bad_launch_sig');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'bad_launch_sig',build:BUILD});
  }

  const nk=nonceUsedKey(lic,sid,launchNonce);
  const already=await redis.get(nk);
  if(already){
    await trackError(redis,'nonce_used');
    await incrementCounter(redis, dateKey('sn:metric:launch_fail'));
    return res.status(403).json({ok:false,error:'nonce_used',build:BUILD});
  }

  const cfg=await getConfig(redis);
  await redis.set(nk,'1',{ ex: parseInt(cfg.nonceTTLSeconds,10)||30 });

  const chromeFlags=getProfileFlags(plan).map(normalizeFlagServer).filter(Boolean);

  return res.status(200).json({
    ok:true,
    bundle:{
      exp: now+20,
      url:startUrl,
      flags:chromeFlags
    },
    maintenanceMessage: cfg.maintenanceMessage || '',
    emergencyBanner: cfg.emergencyBanner || '',
    build:BUILD
  });
};