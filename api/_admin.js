const crypto = require('crypto');
const { getRedis } = require('./_redis');

const BUILD = 'sn-admin-2026-03-09a';
const ROLES = { owner: 100, ulises: 50, other: 10 };
const DEFAULT_CONFIG = {
  planDefaults: {
    free: { ttlSeconds: 900, sessionLimit: 1, deviceLimit: 1 },
    basic: { ttlSeconds: 32 * 60, sessionLimit: 2, deviceLimit: 2 },
    pro: { ttlSeconds: 118 * 60 * 60, sessionLimit: 4, deviceLimit: 4 }
  },
  forceMinVersion: 'v13.13.14',
  maintenanceMessage: '',
  emergencyBanner: '',
  heartbeatTimeoutSeconds: 60,
  nonceTTLSeconds: 30,
  featureToggles: {
    adminPanel: true,
    customKeys: true,
    hwidBan: true,
    emergencyTools: true
  },
  uiPreview: {
    showProModeToggle: true,
    showMediaModeToggle: true,
    showThemePicker: true
  }
};

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function getIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return String(xf).split(',')[0].trim();
  return String(req.socket?.remoteAddress || 'unknown').trim();
}

function safeJsonParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

function parseRedisJson(raw) {
  if (raw == null) return null;
  if (typeof raw === 'object') return raw;
  if (typeof raw === 'string') return safeJsonParse(raw);
  return safeJsonParse(String(raw));
}

async function getJsonBody(req) {
  try {
    if (req.body) {
      if (typeof req.body === 'string') return JSON.parse(req.body);
      if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString('utf8'));
      if (typeof req.body === 'object') return req.body;
    }
  } catch {}
  try {
    const raw = await new Promise((resolve) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => resolve(data));
      req.on('error', () => resolve(''));
    });
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function b64urlEncodeUtf8(str) {
  return Buffer.from(String(str), 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlToBuffer(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function b64urlFromBuffer(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncodeUtf8(payloadJson);
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  return payloadB64 + '.' + b64urlFromBuffer(sig);
}

function verifySignedToken(token, secret) {
  if (!token || token.indexOf('.') === -1) return { ok: false, error: 'bad_token' };
  const parts = token.split('.');
  if (parts.length !== 2) return { ok: false, error: 'bad_token' };
  const payloadB64 = parts[0];
  const sigB64 = parts[1];
  const expected = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  const expectedB64 = b64urlFromBuffer(expected);
  const a = Buffer.from(expectedB64);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length) return { ok: false, error: 'bad_sig' };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: 'bad_sig' };
  const payloadJson = b64urlToBuffer(payloadB64).toString('utf8');
  const payload = safeJsonParse(payloadJson);
  if (!payload) return { ok: false, error: 'bad_payload' };
  return { ok: true, payload };
}

function adminSecret() {
  return String(process.env.ADMIN_SECRET || process.env.SECRET_SALT || 'scriptnova-admin-secret-fallback').trim();
}

function adminPasswordMap() {
  return {
    owner: String(process.env.ADMIN_OWNER_PASSWORD || 'SNOVAOWNERpassword1'),
    ulises: String(process.env.ADMIN_ULISES_PASSWORD || 'Ulisesadmin4811'),
    other: String(process.env.ADMIN_OTHER_PASSWORD || 'other1234')
  };
}

function roleAllowed(role, need) {
  return (ROLES[role] || 0) >= (ROLES[need] || 999);
}

function adminSessionKey(tokenId) { return 'sn:admin:session:' + tokenId; }
function adminDisabledKey(role) { return 'sn:admin:disabled:' + role; }
function adminRolesKey() { return 'sn:admin:roles'; }
function customKeyKey(lic) { return 'sn:customkey:' + String(lic); }
function disabledKeyKey(lic) { return 'sn:disabled:' + String(lic); }
function freeKeyRedisKey(lic) { return 'sn:freekey:' + String(lic); }
function bannedHwidKey(hwHash) { return 'sn:banned:hwid:' + String(hwHash); }
function suspiciousHwidKey(hwHash) { return 'sn:suspicious:hwid:' + String(hwHash); }
function globalPausedKey() { return 'sn:global:paused'; }
function globalDisableAllKey() { return 'sn:global:disable_all'; }
function globalConfigKey() { return 'sn:global:config'; }
function sessionKey(lic, sid) { return 'sn:session:' + lic + ':' + sid; }
function activeSetKey(lic) { return 'sn:active:' + lic; }
function hwidSetKey(lic) { return 'sn:hwids:' + lic; }
function auditKey(id) { return 'sn:admin:audit:' + id; }
function auditListKey() { return 'sn:admin:audit:list'; }
function adminAccessKey(id) { return 'sn:admin:access:' + id; }

async function logAudit(redis, entry) {
  const now = Math.floor(Date.now() / 1000);
  const id = now + '-' + crypto.randomBytes(6).toString('hex');
  const obj = Object.assign({ id, ts: now }, entry || {});
  await redis.set(auditKey(id), JSON.stringify(obj), { ex: 60 * 60 * 24 * 30 });
  await redis.lpush(auditListKey(), id);
  await redis.ltrim(auditListKey(), 0, 499);
  return obj;
}

async function incrementCounter(redis, key, amount = 1, ttlSeconds = 60 * 60 * 24 * 14) {
  const n = await redis.incrby(key, amount);
  if (n === amount) await redis.expire(key, ttlSeconds);
  return n;
}

function dateKey(prefix, d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${prefix}:${y}-${m}-${day}`;
}

async function getConfig(redis) {
  const raw = await redis.get(globalConfigKey());
  const parsed = parseRedisJson(raw) || {};
  return deepMerge(DEFAULT_CONFIG, parsed);
}

function deepMerge(base, incoming) {
  const out = Array.isArray(base) ? base.slice() : Object.assign({}, base);
  if (!incoming || typeof incoming !== 'object') return out;
  for (const k of Object.keys(incoming)) {
    const bv = out[k];
    const iv = incoming[k];
    if (bv && typeof bv === 'object' && !Array.isArray(bv) && iv && typeof iv === 'object' && !Array.isArray(iv)) {
      out[k] = deepMerge(bv, iv);
    } else {
      out[k] = iv;
    }
  }
  return out;
}

async function setConfig(redis, patch) {
  const current = await getConfig(redis);
  const next = deepMerge(current, patch || {});
  await redis.set(globalConfigKey(), JSON.stringify(next));
  return next;
}

function planForLicense(lic) {
  const s = String(lic || '');
  if (s.startsWith('FREE-')) return 'free';
  return s.startsWith('PRO-') ? 'pro' : 'basic';
}

async function getCustomKey(redis, lic) {
  return parseRedisJson(await redis.get(customKeyKey(lic)));
}

async function getLicenseMeta(redis, lic) {
  lic = String(lic || '').trim();
  if (!lic) return { ok: false, error: 'missing_license' };

  const disabled = await redis.get(disabledKeyKey(lic));
  if (disabled) return { ok: false, error: 'license_disabled' };
  const allDisabled = await redis.get(globalDisableAllKey());
  if (allDisabled) return { ok: false, error: 'all_keys_disabled' };

  if (lic.startsWith('FREE-')) {
    const freeRaw = await redis.get(freeKeyRedisKey(lic));
    if (!freeRaw) return { ok: false, error: 'not_found' };
    const freeObj = parseRedisJson(freeRaw) || {};
    return {
      ok: true,
      source: 'free',
      key: lic,
      plan: 'free',
      ttlSeconds: 900,
      sessionLimit: 1,
      deviceLimit: 1,
      exp: parseInt(freeObj.exp, 10) || 0,
      raw: freeObj
    };
  }

  const custom = await getCustomKey(redis, lic);
  if (custom && custom.enabled !== false) {
    return {
      ok: true,
      source: 'custom',
      key: lic,
      plan: String(custom.plan || planForLicense(lic)),
      ttlSeconds: parseInt(custom.ttlSeconds, 10) || 0,
      sessionLimit: parseInt(custom.sessionLimit, 10) || 1,
      deviceLimit: parseInt(custom.deviceLimit, 10) || 1,
      exp: parseInt(custom.exp, 10) || 0,
      raw: custom
    };
  }

  const list = String(process.env.LICENSES || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (list.includes(lic)) {
    const cfg = DEFAULT_CONFIG.planDefaults[planForLicense(lic)] || DEFAULT_CONFIG.planDefaults.basic;
    return {
      ok: true,
      source: 'env',
      key: lic,
      plan: planForLicense(lic),
      ttlSeconds: cfg.ttlSeconds,
      sessionLimit: cfg.sessionLimit,
      deviceLimit: cfg.deviceLimit,
      exp: 0,
      raw: null
    };
  }

  return { ok: false, error: 'not_found' };
}

function hwidHash(raw, secret) {
  return crypto.createHash('sha256').update(String(secret) + '|' + String(raw)).digest('hex');
}

async function isHwidBanned(redis, hwHash) {
  const raw = await redis.get(bannedHwidKey(hwHash));
  return parseRedisJson(raw);
}

async function trackError(redis, type) {
  await incrementCounter(redis, dateKey('sn:metric:error:' + String(type || 'unknown')));
}

async function listSessionKeys(redis) {
  const keys = await redis.keys('sn:session:*');
  return Array.isArray(keys) ? keys : [];
}

async function getAllSessions(redis) {
  const keys = await listSessionKeys(redis);
  const out = [];
  for (const key of keys) {
    const raw = await redis.get(key);
    const obj = parseRedisJson(raw);
    if (!obj) continue;
    const parts = String(key).split(':');
    const lic = parts[2] || '';
    const sid = parts.slice(3).join(':');
    out.push({
      key,
      license: lic,
      sessionId: sid,
      plan: planForLicense(lic),
      exp: parseInt(obj.exp, 10) || 0,
      cid: String(obj.cid || ''),
      hw: String(obj.hw || ''),
      seen: parseInt(obj.seen, 10) || 0,
      createdAt: parseInt(obj.createdAt, 10) || 0,
      ip: String(obj.ip || ''),
      hwidRaw: String(obj.hwidRaw || ''),
      userAgent: String(obj.userAgent || '')
    });
  }
  out.sort((a, b) => (b.seen || 0) - (a.seen || 0));
  return out;
}

async function requireAdmin(req, res, needRole = 'other') {
  cors(res);
  const secret = adminSecret();
  const auth = String(req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : String(req.headers['x-admin-token'] || '').trim();
  if (!token) {
    res.status(401).json({ ok: false, error: 'missing_admin_token', build: BUILD });
    return null;
  }
  const vt = verifySignedToken(token, secret);
  if (!vt.ok) {
    res.status(403).json({ ok: false, error: vt.error, build: BUILD });
    return null;
  }
  const payload = vt.payload || {};
  const now = Math.floor(Date.now() / 1000);
  if ((parseInt(payload.exp, 10) || 0) < now) {
    res.status(403).json({ ok: false, error: 'admin_token_expired', build: BUILD });
    return null;
  }
  const redis = getRedis();
  const sess = parseRedisJson(await redis.get(adminSessionKey(payload.tid)));
  if (!sess || sess.disabled) {
    res.status(403).json({ ok: false, error: 'admin_session_not_found', build: BUILD });
    return null;
  }
  if (await redis.get(adminDisabledKey(payload.role))) {
    res.status(403).json({ ok: false, error: 'admin_role_disabled', build: BUILD });
    return null;
  }
  if (!roleAllowed(payload.role, needRole)) {
    res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });
    return null;
  }
  sess.lastSeen = now;
  await redis.set(adminSessionKey(payload.tid), JSON.stringify(sess), { ex: 60 * 60 * 24 });
  return { redis, token, payload, session: sess };
}

async function loginAdmin(req, role, password) {
  const pw = adminPasswordMap();
  const redis = getRedis();
  const now = Math.floor(Date.now() / 1000);
  const ip = getIp(req);
  if (await redis.get(adminDisabledKey(role))) {
    await logAudit(redis, { type: 'admin_login_blocked', role, ip, success: false, reason: 'role_disabled' });
    return { ok: false, error: 'admin_role_disabled' };
  }
  if (String(password || '') !== String(pw[role] || '')) {
    await incrementCounter(redis, dateKey('sn:metric:admin_login_fail'));
    await logAudit(redis, { type: 'admin_login_failed', role, ip, success: false, reason: 'bad_password' });
    return { ok: false, error: 'bad_credentials' };
  }
  const tid = crypto.randomBytes(18).toString('hex');
  const exp = now + 60 * 60 * 12;
  const token = signToken({ role, exp, tid }, adminSecret());
  const session = { tid, role, createdAt: now, lastSeen: now, ip, userAgent: String(req.headers['user-agent'] || '') };
  await redis.set(adminSessionKey(tid), JSON.stringify(session), { ex: 60 * 60 * 24 });
  await logAudit(redis, { type: 'admin_login', role, ip, success: true });
  return { ok: true, token, role, exp, session };
}

module.exports = {
  BUILD,
  ROLES,
  DEFAULT_CONFIG,
  cors,
  getIp,
  safeJsonParse,
  parseRedisJson,
  getJsonBody,
  sha256Hex,
  signToken,
  verifySignedToken,
  adminSecret,
  adminPasswordMap,
  roleAllowed,
  adminSessionKey,
  adminDisabledKey,
  adminRolesKey,
  customKeyKey,
  disabledKeyKey,
  freeKeyRedisKey,
  bannedHwidKey,
  suspiciousHwidKey,
  globalPausedKey,
  globalDisableAllKey,
  globalConfigKey,
  sessionKey,
  activeSetKey,
  hwidSetKey,
  auditKey,
  auditListKey,
  adminAccessKey,
  logAudit,
  incrementCounter,
  dateKey,
  getConfig,
  setConfig,
  planForLicense,
  getCustomKey,
  getLicenseMeta,
  hwidHash,
  isHwidBanned,
  trackError,
  listSessionKeys,
  getAllSessions,
  requireAdmin,
  loginAdmin
};