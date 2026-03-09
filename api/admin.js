const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-admin-2026-03-09a";

// ===== admin credentials =====
// Keep these on the backend only.
// Later, we can move these to env vars without changing the frontend.
const ADMIN_USERS = {
  owner: {
    username: "Owner",
    role: "owner",
    password: "SNOVAOWNERpassword1",
    disabled: false
  },
  ulises: {
    username: "Ulises",
    role: "ulises",
    password: "Ulisesadmin4811",
    disabled: false
  },
  other: {
    username: "Other",
    role: "other",
    password: "other1234",
    disabled: false
  }
};

const ADMIN_SESSION_TTL = 12 * 60 * 60; // 12h
const AUDIT_KEEP = 800;
const ALERT_KEEP = 300;

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Token");
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s || "")).digest("hex");
}

function randHex(n) {
  return crypto.randomBytes(n).toString("hex");
}

function safeJsonParse(v, fallback) {
  try {
    if (v == null) return fallback;
    if (typeof v === "object") return v;
    return JSON.parse(String(v));
  } catch {
    return fallback;
  }
}

function toInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function lower(s) {
  return String(s || "").trim().toLowerCase();
}

function getIp(req) {
  const xf =
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.headers["cf-connecting-ip"] ||
    "";
  if (xf) return String(xf).split(",")[0].trim();
  return String(req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || "unknown").trim();
}

function getBearerToken(req, body) {
  const h = String(req.headers.authorization || "");
  if (/^Bearer\s+/i.test(h)) return h.replace(/^Bearer\s+/i, "").trim();

  const x = String(req.headers["x-admin-token"] || "").trim();
  if (x) return x;

  if (body && body.token) return String(body.token).trim();
  if (req.query && req.query.token) return String(req.query.token).trim();

  return "";
}

async function getJsonBody(req) {
  try {
    if (req.body) {
      if (typeof req.body === "string") return JSON.parse(req.body);
      if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString("utf8"));
      if (typeof req.body === "object") return req.body;
    }
  } catch {}

  try {
    const raw = await new Promise((resolve) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => resolve(data));
      req.on("error", () => resolve(""));
    });
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function isSafeClientId(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 16 || s.length > 80) return false;
  return /^[A-Za-z0-9\-_.]+$/.test(s);
}

function isSafeHwidRaw(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 8 || s.length > 240) return false;
  if (/[\r\n\t\0]/.test(s)) return false;
  return true;
}

function planForLicense(lic) {
  lic = String(lic || "").trim().toUpperCase();
  if (lic.indexOf("FREE-") === 0) return "free";
  if (lic.indexOf("PRO-") === 0) return "pro";
  return "basic";
}

function defaultLimitForPlan(plan) {
  if (plan === "free") return 1;
  if (plan === "pro") return 4;
  return 2;
}

function defaultTtlForPlan(plan) {
  if (plan === "free") return 15 * 60;
  if (plan === "pro") return 118 * 60 * 60;
  return 32 * 60;
}

function defaultMaxDevicesForPlan(plan) {
  if (plan === "free") return 1;
  return 2; // preserve current backend behavior
}

function hwidHash(raw, secret) {
  return crypto
    .createHash("sha256")
    .update(String(secret) + "|" + String(raw))
    .digest("hex");
}

function sessionKey(lic, sid) {
  return "sn:session:" + String(lic) + ":" + String(sid);
}

function activeSetKey(lic) {
  return "sn:active:" + String(lic);
}

function hwidSetKey(lic) {
  return "sn:hwids:" + String(lic);
}

function freeKeyRedisKey(k) {
  return "sn:freekey:" + String(k);
}

function adminSessionKey(token) {
  return "sn:admin:session:" + String(token);
}

function customKeyKey(license) {
  return "sn:custom:" + String(license);
}

function disabledKeyKey(license) {
  return "sn:disabled:" + String(license);
}

function bannedHwidKey(hwHash) {
  return "sn:banned:hwid:" + String(hwHash);
}

function suspiciousHwidKey(hwHash) {
  return "sn:suspicious:hwid:" + String(hwHash);
}

function globalKey(name) {
  return "sn:global:" + String(name);
}

function auditListKey() {
  return "sn:admin:audit";
}

function alertsListKey() {
  return "sn:admin:alerts";
}

function metricsKey(day) {
  return "sn:metrics:" + String(day);
}

function todayKeyDate() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${dd}`;
}

function userKeyForLogin(username) {
  const u = lower(username);
  if (u === "owner") return "owner";
  if (u === "ulises") return "ulises";
  if (u === "other") return "other";
  return "";
}

function canReadDashboard(role) {
  return role === "owner" || role === "ulises" || role === "other";
}

function canReadSessions(role) {
  return role === "owner" || role === "ulises";
}

function canEndSessions(role) {
  return role === "owner";
}

function canReadKeys(role) {
  return role === "owner" || role === "ulises";
}

function canWriteKeys(role) {
  return role === "owner";
}

function canReadFreeKeys(role) {
  return role === "owner" || role === "ulises";
}

function canWriteFreeKeys(role) {
  return role === "owner";
}

function canReadHWID(role) {
  return role === "owner" || role === "ulises";
}

function canWriteHWID(role) {
  return role === "owner";
}

function canReadAudit(role) {
  return role === "owner" || role === "ulises";
}

function canReadAnalytics(role) {
  return role === "owner" || role === "ulises";
}

function canReadAlerts(role) {
  return role === "owner" || role === "ulises" || role === "other";
}

function canWriteLauncher(role) {
  return role === "owner";
}

function canReadAdminAccounts(role) {
  return role === "owner";
}

function canWriteAdminAccounts(role) {
  return role === "owner";
}

function canReadConfig(role) {
  return role === "owner";
}

function canWriteConfig(role) {
  return role === "owner";
}

function canEmergency(role) {
  return role === "owner";
}

async function audit(redis, entry) {
  const row = JSON.stringify({
    id: randHex(10),
    ts: nowSec(),
    ...entry
  });

  try {
    await redis.lpush(auditListKey(), row);
    await redis.ltrim(auditListKey(), 0, AUDIT_KEEP - 1);
  } catch {}
}

async function addAlert(redis, entry) {
  const row = JSON.stringify({
    id: randHex(10),
    ts: nowSec(),
    ...entry
  });

  try {
    await redis.lpush(alertsListKey(), row);
    await redis.ltrim(alertsListKey(), 0, ALERT_KEEP - 1);
  } catch {}
}

async function metricIncr(redis, field, by) {
  try {
    const key = metricsKey(todayKeyDate());
    await redis.hincrby(key, field, by || 1);
    await redis.expire(key, 60 * 60 * 24 * 10);
  } catch {}
}

async function readAdminSession(redis, token) {
  if (!token) return null;
  const raw = await redis.get(adminSessionKey(token));
  if (!raw) return null;

  const obj = safeJsonParse(raw, null);
  if (!obj || typeof obj !== "object") return null;

  const exp = toInt(obj.exp, 0);
  if (exp && exp <= nowSec()) {
    try { await redis.del(adminSessionKey(token)); } catch {}
    return null;
  }

  return obj;
}

async function requireAdmin(req, res, redis, body) {
  const token = getBearerToken(req, body);
  if (!token) {
    return { ok: false, status: 401, error: "admin_unauthorized" };
  }

  const sess = await readAdminSession(redis, token);
  if (!sess) {
    return { ok: false, status: 401, error: "admin_unauthorized" };
  }

  if (sess.disabled === true) {
    return { ok: false, status: 403, error: "admin_account_disabled" };
  }

  return { ok: true, token, session: sess };
}

async function listActiveSessionRecords(redis, licFilter) {
  const out = [];
  const licenses = [];

  if (licFilter) {
    licenses.push(String(licFilter).trim());
  } else {
    const envLic = getLicenseList();
    for (const lic of envLic) licenses.push(lic);

    try {
      const customKeys = await redis.keys("sn:custom:*");
      for (const k of customKeys || []) {
        const lic = String(k).replace(/^sn:custom:/, "");
        if (lic) licenses.push(lic);
      }
    } catch {}

    try {
      const freeKeys = await redis.keys("sn:freekey:*");
      for (const k of freeKeys || []) {
        const lic = String(k).replace(/^sn:freekey:/, "");
        if (lic) licenses.push(lic);
      }
    } catch {}
  }

  const uniqLic = Array.from(new Set(licenses.filter(Boolean)));

  for (const lic of uniqLic) {
    const setKey = activeSetKey(lic);
    let sids = [];
    try {
      sids = await redis.smembers(setKey);
    } catch {
      sids = [];
    }
    if (!sids || !sids.length) continue;

    for (const sid of sids) {
      const raw = await redis.get(sessionKey(lic, sid));
      if (!raw) continue;

      const obj = safeJsonParse(raw, null);
      if (!obj) continue;

      out.push({
        license: lic,
        plan: planForLicense(lic),
        sessionId: String(sid),
        exp: toInt(obj.exp, 0),
        clientId: String(obj.cid || ""),
        hwidHash: String(obj.hw || ""),
        lastSeen: toInt(obj.seen, 0),
        createdAt: toInt(obj.createdAt, 0),
        ip: String(obj.ip || ""),
        hwidRawPreview: String(obj.hwidRawPreview || ""),
        active: (toInt(obj.exp, 0) > nowSec())
      });
    }
  }

  out.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  return out;
}

async function getCustomKey(redis, license) {
  const raw = await redis.get(customKeyKey(license));
  return safeJsonParse(raw, null);
}

async function resolveLicenseInfo(redis, license) {
  license = String(license || "").trim();
  if (!license) return { exists: false };

  const disabled = !!(await redis.get(disabledKeyKey(license)));
  const custom = await getCustomKey(redis, license);

  if (custom) {
    return {
      exists: true,
      source: "custom",
      disabled,
      license,
      plan: String(custom.plan || planForLicense(license)),
      ttlSeconds: toInt(custom.ttlSeconds, defaultTtlForPlan(String(custom.plan || planForLicense(license)))),
      sessionLimit: toInt(custom.sessionLimit, defaultLimitForPlan(String(custom.plan || planForLicense(license)))),
      maxDevices: toInt(custom.maxDevices, defaultMaxDevicesForPlan(String(custom.plan || planForLicense(license)))),
      exp: toInt(custom.exp, 0),
      note: String(custom.note || ""),
      createdAt: toInt(custom.createdAt, 0),
      createdBy: String(custom.createdBy || "")
    };
  }

  if (license.indexOf("FREE-") === 0) {
    const free = await redis.get(freeKeyRedisKey(license));
    if (!free) return { exists: false };

    return {
      exists: true,
      source: "free",
      disabled,
      license,
      plan: "free",
      ttlSeconds: 900,
      sessionLimit: 1,
      maxDevices: 1,
      exp: 0
    };
  }

  const envList = getLicenseList();
  if (!envList.includes(license)) return { exists: false };

  const plan = planForLicense(license);
  return {
    exists: true,
    source: "env",
    disabled,
    license,
    plan,
    ttlSeconds: defaultTtlForPlan(plan),
    sessionLimit: defaultLimitForPlan(plan),
    maxDevices: defaultMaxDevicesForPlan(plan),
    exp: 0
  };
}

async function listCustomKeys(redis) {
  let keys = [];
  try {
    keys = await redis.keys("sn:custom:*");
  } catch {
    keys = [];
  }

  const out = [];
  for (const k of keys || []) {
    const license = String(k).replace(/^sn:custom:/, "");
    const obj = await getCustomKey(redis, license);
    if (!obj) continue;
    out.push({
      license,
      ...obj
    });
  }

  out.sort((a, b) => (toInt(b.createdAt, 0) - toInt(a.createdAt, 0)));
  return out;
}

async function listFreeKeys(redis) {
  let keys = [];
  try {
    keys = await redis.keys("sn:freekey:*");
  } catch {
    keys = [];
  }

  const out = [];
  for (const k of keys || []) {
    const license = String(k).replace(/^sn:freekey:/, "");
    const ttl = await redis.ttl(k);
    const raw = await redis.get(k);
    const obj = safeJsonParse(raw, {});
    out.push({
      license,
      ttlSeconds: Math.max(0, toInt(ttl, 0)),
      exp: toInt(obj.exp, 0),
      createdAt: toInt(obj.createdAt, 0),
      createdBy: String(obj.createdBy || "")
    });
  }

  out.sort((a, b) => (b.exp || 0) - (a.exp || 0));
  return out;
}

async function countBannedHwids(redis) {
  try {
    const keys = await redis.keys("sn:banned:hwid:*");
    return (keys || []).length;
  } catch {
    return 0;
  }
}

async function countSuspiciousHwids(redis) {
  try {
    const keys = await redis.keys("sn:suspicious:hwid:*");
    return (keys || []).length;
  } catch {
    return 0;
  }
}

async function getGlobalState(redis) {
  const paused = !!(await redis.get(globalKey("paused")));
  const disableAll = !!(await redis.get(globalKey("disable_all")));
  const maintenanceMode = !!(await redis.get(globalKey("maintenance_mode")));
  const maintenanceMessage = String((await redis.get(globalKey("maintenance_message"))) || "");
  const minVersion = String((await redis.get(globalKey("min_version"))) || "");
  const htaPausedReason = String((await redis.get(globalKey("paused_reason"))) || "");
  return {
    paused,
    disableAll,
    maintenanceMode,
    maintenanceMessage,
    minVersion,
    pausedReason: htaPausedReason
  };
}

async function serviceStatusFromUrl(url) {
  // lightweight placeholder for UI use, actual live health checks can be added later
  return { url, status: "unknown" };
}

async function makeDashboard(redis) {
  const global = await getGlobalState(redis);
  const sessions = await listActiveSessionRecords(redis);
  const freeKeys = await listFreeKeys(redis);
  const customKeys = await listCustomKeys(redis);

  let visitors = 0;
  let trusted = 0;
  let downloads = 0;
  try { visitors = toInt(await redis.get("sn:count:visitors"), 0); } catch {}
  try { trusted = toInt(await redis.get("sn:count:trusted"), 0); } catch {}
  try { downloads = toInt(await redis.get("sn:count:downloads"), 0); } catch {}

  let versionTxt = "";
  try { versionTxt = String((await redis.get(globalKey("version_txt_cache"))) || ""); } catch {}

  let metrics = {};
  try {
    metrics = await redis.hgetall(metricsKey(todayKeyDate()));
    if (!metrics || typeof metrics !== "object") metrics = {};
  } catch {
    metrics = {};
  }

  const planCounts = {
    free: 0,
    basic: 0,
    pro: 0
  };
  for (const s of sessions) {
    if (s.plan === "free") planCounts.free++;
    else if (s.plan === "pro") planCounts.pro++;
    else planCounts.basic++;
  }

  return {
    services: {
      api: { online: true },
      publicSite: await serviceStatusFromUrl("https://scriptnovaa.com"),
      redis: { online: true },
      launcherVersion: {
        requiredMinVersion: global.minVersion || "v13.13.14",
        cachedVersionTxt: versionTxt || null
      }
    },
    counts: {
      activeSessions: sessions.length,
      activeByPlan: planCounts,
      freeKeys: freeKeys.length,
      customKeys: customKeys.length,
      bannedHwids: await countBannedHwids(redis),
      suspiciousHwids: await countSuspiciousHwids(redis),
      visitors,
      trustedVisitors: trusted,
      downloads
    },
    launcher: {
      paused: global.paused,
      pausedReason: global.pausedReason,
      maintenanceMode: global.maintenanceMode,
      maintenanceMessage: global.maintenanceMessage,
      disableAllKeys: global.disableAll
    },
    analyticsToday: {
      keyChecks: toInt(metrics.keyChecks, 0),
      verifyAttempts: toInt(metrics.verifyAttempts, 0),
      launchAttempts: toInt(metrics.launchAttempts, 0),
      launchFailures: toInt(metrics.launchFailures, 0),
      freeKeysGenerated: toInt(metrics.freeKeysGenerated, 0),
      sessionsEnded: toInt(metrics.sessionsEnded, 0),
      adminLoginFailures: toInt(metrics.adminLoginFailures, 0)
    }
  };
}

function matchSearch(hay, q) {
  if (!q) return true;
  return String(hay).toLowerCase().indexOf(String(q).toLowerCase()) !== -1;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });
  }

  const rl = await rateLimit(req, "admin", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({
      ok: false,
      error: "rate_limited",
      retryAfter: rl.retryAfter,
      build: BUILD
    });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  const body = req.method === "POST" ? await getJsonBody(req) : {};
  const q = req.method === "GET" ? req.query || {} : body || {};
  const action = lower(q.action);

  // ========= LOGIN =========
  if (action === "login") {
    const username = String(q.username || "").trim();
    const password = String(q.password || "").trim();
    const userKey = userKeyForLogin(username);
    const adminDef = userKey ? ADMIN_USERS[userKey] : null;

    if (!adminDef || adminDef.disabled === true || password !== adminDef.password) {
      await metricIncr(redis, "adminLoginFailures", 1);
      await audit(redis, {
        type: "login",
        actor: username || "unknown",
        role: "unknown",
        action: "login_failed",
        ip: getIp(req),
        success: false
      });
      await addAlert(redis, {
        type: "admin_login_failed",
        actor: username || "unknown",
        ip: getIp(req),
        level: "warning"
      });
      return res.status(401).json({ ok: false, error: "invalid_admin_login", build: BUILD });
    }

    const token = randHex(24);
    const exp = nowSec() + ADMIN_SESSION_TTL;

    const sess = {
      username: adminDef.username,
      role: adminDef.role,
      exp,
      ip: getIp(req),
      createdAt: nowSec(),
      disabled: false
    };

    await redis.set(adminSessionKey(token), JSON.stringify(sess), { ex: ADMIN_SESSION_TTL });

    await audit(redis, {
      type: "login",
      actor: adminDef.username,
      role: adminDef.role,
      action: "login_success",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({
      ok: true,
      token,
      admin: {
        username: adminDef.username,
        role: adminDef.role
      },
      exp,
      build: BUILD
    });
  }

  // ========= everything else requires admin =========
  const auth = await requireAdmin(req, res, redis, body);
  if (!auth.ok) {
    return res.status(auth.status).json({
      ok: false,
      error: auth.error,
      build: BUILD
    });
  }

  const admin = auth.session;
  const token = auth.token;

  if (action === "logout") {
    await redis.del(adminSessionKey(token));
    await audit(redis, {
      type: "login",
      actor: admin.username,
      role: admin.role,
      action: "logout",
      ip: getIp(req),
      success: true
    });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "me") {
    return res.status(200).json({
      ok: true,
      admin: {
        username: admin.username,
        role: admin.role,
        exp: admin.exp
      },
      build: BUILD
    });
  }

  // ========= DASHBOARD =========
  if (action === "dashboard") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const dashboard = await makeDashboard(redis);
    await audit(redis, {
      type: "access",
      actor: admin.username,
      role: admin.role,
      action: "dashboard_view",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({
      ok: true,
      dashboard,
      build: BUILD
    });
  }

  // ========= SESSIONS =========
  if (action === "sessions_list") {
    if (!canReadSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const plan = lower(q.plan);
    const clientId = String(q.clientId || "").trim();
    const hwidHashQ = String(q.hwidHash || q.hwid || "").trim();
    const sessionId = String(q.sessionId || "").trim();
    const search = String(q.search || "").trim();

    let rows = await listActiveSessionRecords(redis, license);
    rows = rows.filter((r) => {
      if (license && r.license !== license) return false;
      if (plan && r.plan !== plan) return false;
      if (clientId && r.clientId !== clientId) return false;
      if (hwidHashQ && r.hwidHash !== hwidHashQ) return false;
      if (sessionId && r.sessionId !== sessionId) return false;

      if (search) {
        const hay = [
          r.license, r.plan, r.clientId, r.hwidHash, r.sessionId, r.ip, r.hwidRawPreview
        ].join(" ");
        if (!matchSearch(hay, search)) return false;
      }
      return true;
    });

    return res.status(200).json({
      ok: true,
      items: rows,
      count: rows.length,
      build: BUILD
    });
  }

  if (action === "session_end_one") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const sid = String(q.sessionId || "").trim();
    if (!license || !sid) {
      return res.status(400).json({ ok: false, error: "missing_license_or_session", build: BUILD });
    }

    await redis.del(sessionKey(license, sid));
    await redis.srem(activeSetKey(license), sid);
    await metricIncr(redis, "sessionsEnded", 1);

    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "session_end_one",
      target: license + ":" + sid,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "sessions_end_all") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listActiveSessionRecords(redis);
    for (const r of rows) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
    }
    await metricIncr(redis, "sessionsEnded", rows.length);

    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "sessions_end_all",
      target: "all",
      ip: getIp(req),
      success: true,
      details: { count: rows.length }
    });

    return res.status(200).json({ ok: true, ended: rows.length, build: BUILD });
  }

  if (action === "sessions_end_by_hwid") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const hw = String(q.hwidHash || q.hwid || "").trim();
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });

    const rows = await listActiveSessionRecords(redis);
    const hit = rows.filter((r) => r.hwidHash === hw);

    for (const r of hit) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
    }
    await metricIncr(redis, "sessionsEnded", hit.length);

    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "sessions_end_by_hwid",
      target: hw,
      ip: getIp(req),
      success: true,
      details: { count: hit.length }
    });

    return res.status(200).json({ ok: true, ended: hit.length, build: BUILD });
  }

  // ========= KEYS =========
  if (action === "key_search") {
    if (!canReadKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    const info = await resolveLicenseInfo(redis, license);
    if (!info.exists) {
      return res.status(200).json({ ok: false, exists: false, build: BUILD });
    }

    let hwids = [];
    try {
      hwids = await redis.smembers(hwidSetKey(license));
    } catch {
      hwids = [];
    }

    const sessions = (await listActiveSessionRecords(redis, license)).length;

    return res.status(200).json({
      ok: true,
      exists: true,
      key: {
        ...info,
        hwids: hwids || [],
        activeSessions: sessions
      },
      build: BUILD
    });
  }

  if (action === "key_disable") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }
    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    await redis.set(disabledKeyKey(license), "1");
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_disable",
      target: license,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "key_enable") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }
    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    await redis.del(disabledKeyKey(license));
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_enable",
      target: license,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "key_create_custom") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const plan = lower(q.plan || planForLicense(license));
    const ttlSeconds = clamp(toInt(q.ttlSeconds, defaultTtlForPlan(plan)), 60, 60 * 60 * 24 * 365);
    const sessionLimit = clamp(toInt(q.sessionLimit, defaultLimitForPlan(plan)), 1, 50);
    const maxDevices = clamp(toInt(q.maxDevices, defaultMaxDevicesForPlan(plan)), 1, 50);
    const exp = Math.max(0, toInt(q.exp, 0));
    const note = String(q.note || "").trim();

    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    if (!/^(FREE|BASIC|PRO)-[A-Za-z0-9._-]+$/i.test(license)) {
      return res.status(400).json({ ok: false, error: "invalid_license_format", build: BUILD });
    }

    const row = {
      plan,
      ttlSeconds,
      sessionLimit,
      maxDevices,
      exp,
      note,
      createdAt: nowSec(),
      createdBy: admin.username
    };

    await redis.set(customKeyKey(license), JSON.stringify(row));
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_create_custom",
      target: license,
      ip: getIp(req),
      success: true,
      details: row
    });

    return res.status(200).json({ ok: true, license, key: row, build: BUILD });
  }

  if (action === "key_delete_custom") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    await redis.del(customKeyKey(license));
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_delete_custom",
      target: license,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "key_update_custom") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const old = await getCustomKey(redis, license);
    if (!old) return res.status(404).json({ ok: false, error: "custom_key_not_found", build: BUILD });

    const row = {
      ...old,
      plan: q.plan ? lower(q.plan) : String(old.plan || planForLicense(license)),
      ttlSeconds: q.ttlSeconds != null ? clamp(toInt(q.ttlSeconds, old.ttlSeconds), 60, 60 * 60 * 24 * 365) : toInt(old.ttlSeconds, 0),
      sessionLimit: q.sessionLimit != null ? clamp(toInt(q.sessionLimit, old.sessionLimit), 1, 50) : toInt(old.sessionLimit, 0),
      maxDevices: q.maxDevices != null ? clamp(toInt(q.maxDevices, old.maxDevices), 1, 50) : toInt(old.maxDevices, 0),
      exp: q.exp != null ? Math.max(0, toInt(q.exp, old.exp)) : toInt(old.exp, 0),
      note: q.note != null ? String(q.note || "").trim() : String(old.note || ""),
      updatedAt: nowSec(),
      updatedBy: admin.username
    };

    await redis.set(customKeyKey(license), JSON.stringify(row));
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_update_custom",
      target: license,
      ip: getIp(req),
      success: true,
      oldValue: old,
      newValue: row
    });

    return res.status(200).json({ ok: true, key: row, build: BUILD });
  }

  if (action === "key_reset_hwid_bindings") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    await redis.del(hwidSetKey(license));
    await audit(redis, {
      type: "key",
      actor: admin.username,
      role: admin.role,
      action: "key_reset_hwid_bindings",
      target: license,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "keys_list_custom") {
    if (!canReadKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listCustomKeys(redis);
    return res.status(200).json({ ok: true, items: rows, count: rows.length, build: BUILD });
  }

  // ========= FREE KEYS =========
  if (action === "freekeys_list") {
    if (!canReadFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listFreeKeys(redis);
    return res.status(200).json({ ok: true, items: rows, count: rows.length, build: BUILD });
  }

  if (action === "freekey_add") {
    if (!canWriteFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim() || ("FREE-" + randHex(5).toUpperCase());
    const ttlSeconds = clamp(toInt(q.ttlSeconds, 900), 60, 86400);
    const exp = nowSec() + ttlSeconds;

    await redis.set(
      freeKeyRedisKey(license),
      JSON.stringify({
        exp,
        createdAt: nowSec(),
        createdBy: admin.username
      }),
      { ex: ttlSeconds }
    );

    await audit(redis, {
      type: "freekey",
      actor: admin.username,
      role: admin.role,
      action: "freekey_add",
      target: license,
      ip: getIp(req),
      success: true,
      details: { ttlSeconds, exp }
    });

    return res.status(200).json({ ok: true, license, ttlSeconds, exp, build: BUILD });
  }

  if (action === "freekey_remove") {
    if (!canWriteFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });

    await redis.del(freeKeyRedisKey(license));
    await audit(redis, {
      type: "freekey",
      actor: admin.username,
      role: admin.role,
      action: "freekey_remove",
      target: license,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "freekeys_expire_all") {
    if (!canWriteFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listFreeKeys(redis);
    for (const row of rows) {
      await redis.del(freeKeyRedisKey(row.license));
    }

    await audit(redis, {
      type: "freekey",
      actor: admin.username,
      role: admin.role,
      action: "freekeys_expire_all",
      target: "all",
      ip: getIp(req),
      success: true,
      details: { count: rows.length }
    });

    return res.status(200).json({ ok: true, expired: rows.length, build: BUILD });
  }

  // ========= LAUNCHER CONTROL =========
  if (action === "launcher_status") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const g = await getGlobalState(redis);
    return res.status(200).json({ ok: true, launcher: g, build: BUILD });
  }

  if (action === "launcher_pause") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const reason = String(q.reason || "").trim();
    await redis.set(globalKey("paused"), "1");
    if (reason) await redis.set(globalKey("paused_reason"), reason);

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_pause",
      target: "global",
      ip: getIp(req),
      success: true,
      details: { reason }
    });

    return res.status(200).json({ ok: true, paused: true, reason, build: BUILD });
  }

  if (action === "launcher_unpause") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("paused"));
    await redis.del(globalKey("paused_reason"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_unpause",
      target: "global",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, paused: false, build: BUILD });
  }

  if (action === "launcher_set_min_version") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const version = String(q.version || "").trim();
    if (!version) return res.status(400).json({ ok: false, error: "missing_version", build: BUILD });

    await redis.set(globalKey("min_version"), version);
    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_set_min_version",
      target: "min_version",
      ip: getIp(req),
      success: true,
      newValue: version
    });

    return res.status(200).json({ ok: true, version, build: BUILD });
  }

  if (action === "launcher_set_maintenance_message") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const message = String(q.message || "").trim();
    await redis.set(globalKey("maintenance_message"), message);
    await redis.set(globalKey("maintenance_mode"), message ? "1" : "");
    if (!message) await redis.del(globalKey("maintenance_mode"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_set_maintenance_message",
      target: "maintenance_message",
      ip: getIp(req),
      success: true,
      newValue: message
    });

    return res.status(200).json({ ok: true, message, build: BUILD });
  }

  // ========= HWID / DEVICE =========
  if (action === "hwid_search") {
    if (!canReadHWID(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const hw = String(q.hwidHash || q.hwid || "").trim();
    const out = {
      byLicense: [],
      byHwid: {
        hwidHash: hw || "",
        banned: false,
        suspicious: false,
        banInfo: null,
        suspiciousInfo: null,
        licenses: [],
        sessions: []
      }
    };

    if (license) {
      let hwids = [];
      try { hwids = await redis.smembers(hwidSetKey(license)); } catch { hwids = []; }

      const sessions = await listActiveSessionRecords(redis, license);
      out.byLicense.push({
        license,
        hwids: hwids || [],
        sessions
      });
    }

    if (hw) {
      const banRaw = await redis.get(bannedHwidKey(hw));
      const suspRaw = await redis.get(suspiciousHwidKey(hw));
      out.byHwid.banned = !!banRaw;
      out.byHwid.suspicious = !!suspRaw;
      out.byHwid.banInfo = safeJsonParse(banRaw, null);
      out.byHwid.suspiciousInfo = safeJsonParse(suspRaw, null);

      const sessions = await listActiveSessionRecords(redis);
      out.byHwid.sessions = sessions.filter((s) => s.hwidHash === hw);

      const licenses = new Set();
      for (const s of out.byHwid.sessions) licenses.add(s.license);

      const envLic = getLicenseList();
      const customLicRows = await listCustomKeys(redis);
      const freeRows = await listFreeKeys(redis);
      const candidates = Array.from(new Set([
        ...envLic,
        ...customLicRows.map((x) => x.license),
        ...freeRows.map((x) => x.license)
      ]));

      for (const lic of candidates) {
        let hwids = [];
        try { hwids = await redis.smembers(hwidSetKey(lic)); } catch { hwids = []; }
        if ((hwids || []).includes(hw)) licenses.add(lic);
      }

      out.byHwid.licenses = Array.from(licenses);
    }

    return res.status(200).json({ ok: true, result: out, build: BUILD });
  }

  if (action === "hwid_ban") {
    if (!canWriteHWID(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const hw = String(q.hwidHash || q.hwid || "").trim();
    const reason = String(q.reason || "").trim();
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });

    const row = {
      hwidHash: hw,
      reason,
      bannedAt: nowSec(),
      bannedBy: admin.username
    };

    await redis.set(bannedHwidKey(hw), JSON.stringify(row));
    await audit(redis, {
      type: "hwid",
      actor: admin.username,
      role: admin.role,
      action: "hwid_ban",
      target: hw,
      ip: getIp(req),
      success: true,
      details: row
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "hwid_unban") {
    if (!canWriteHWID(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const hw = String(q.hwidHash || q.hwid || "").trim();
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });

    await redis.del(bannedHwidKey(hw));
    await audit(redis, {
      type: "hwid",
      actor: admin.username,
      role: admin.role,
      action: "hwid_unban",
      target: hw,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "hwid_mark_suspicious") {
    if (!canWriteHWID(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const hw = String(q.hwidHash || q.hwid || "").trim();
    const reason = String(q.reason || "").trim();
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });

    const row = {
      hwidHash: hw,
      reason,
      markedAt: nowSec(),
      markedBy: admin.username
    };

    await redis.set(suspiciousHwidKey(hw), JSON.stringify(row));
    await audit(redis, {
      type: "hwid",
      actor: admin.username,
      role: admin.role,
      action: "hwid_mark_suspicious",
      target: hw,
      ip: getIp(req),
      success: true,
      details: row
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  // ========= ADMIN ACCOUNTS =========
  if (action === "admin_accounts_list") {
    if (!canReadAdminAccounts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = Object.keys(ADMIN_USERS).map((k) => ({
      username: ADMIN_USERS[k].username,
      role: ADMIN_USERS[k].role,
      disabled: !!ADMIN_USERS[k].disabled
    }));

    let active = [];
    try {
      const keys = await redis.keys("sn:admin:session:*");
      for (const k of keys || []) {
        const raw = await redis.get(k);
        const obj = safeJsonParse(raw, null);
        if (!obj) continue;
        active.push({
          tokenTail: String(k).slice(-8),
          username: String(obj.username || ""),
          role: String(obj.role || ""),
          exp: toInt(obj.exp, 0),
          ip: String(obj.ip || ""),
          createdAt: toInt(obj.createdAt, 0)
        });
      }
    } catch {
      active = [];
    }

    return res.status(200).json({
      ok: true,
      accounts: rows,
      activeSessions: active,
      build: BUILD
    });
  }

  if (action === "admin_force_logout_all") {
    if (!canWriteAdminAccounts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let n = 0;
    try {
      const keys = await redis.keys("sn:admin:session:*");
      for (const k of keys || []) {
        await redis.del(k);
        n++;
      }
    } catch {}

    await audit(redis, {
      type: "admin",
      actor: admin.username,
      role: admin.role,
      action: "admin_force_logout_all",
      target: "all_admin_sessions",
      ip: getIp(req),
      success: true,
      details: { count: n }
    });

    return res.status(200).json({ ok: true, count: n, build: BUILD });
  }

  // ========= SYSTEM CONFIG =========
  if (action === "config_get") {
    if (!canReadConfig(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const g = await getGlobalState(redis);

    return res.status(200).json({
      ok: true,
      config: {
        currentPlanDefaults: {
          free: {
            ttlSeconds: 900,
            sessionLimit: 1,
            maxDevices: 1
          },
          basic: {
            ttlSeconds: 32 * 60,
            sessionLimit: 2,
            maxDevices: 2
          },
          pro: {
            ttlSeconds: 118 * 60 * 60,
            sessionLimit: 4,
            maxDevices: 2
          }
        },
        launcherForceVersionValue: g.minVersion || "v13.13.14",
        maintenanceMessageText: g.maintenanceMessage || "",
        featureToggles: {
          paused: g.paused,
          maintenanceMode: g.maintenanceMode,
          disableAllKeys: g.disableAll
        }
      },
      build: BUILD
    });
  }

  // ========= ANALYTICS =========
  if (action === "analytics_summary") {
    if (!canReadAnalytics(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let visitors = 0;
    let trusted = 0;
    let downloads = 0;
    try { visitors = toInt(await redis.get("sn:count:visitors"), 0); } catch {}
    try { trusted = toInt(await redis.get("sn:count:trusted"), 0); } catch {}
    try { downloads = toInt(await redis.get("sn:count:downloads"), 0); } catch {}

    let metrics = {};
    try {
      metrics = await redis.hgetall(metricsKey(todayKeyDate()));
      if (!metrics || typeof metrics !== "object") metrics = {};
    } catch {
      metrics = {};
    }

    return res.status(200).json({
      ok: true,
      analytics: {
        totalVisitors: visitors,
        trustedVisitors: trusted,
        totalDownloads: downloads,
        keyChecksToday: toInt(metrics.keyChecks, 0),
        verifyAttemptsToday: toInt(metrics.verifyAttempts, 0),
        launchAttemptsToday: toInt(metrics.launchAttempts, 0),
        launchFailuresToday: toInt(metrics.launchFailures, 0),
        freeKeysGeneratedToday: toInt(metrics.freeKeysGenerated, 0),
        sessionsEndedToday: toInt(metrics.sessionsEnded, 0),
        adminLoginFailuresToday: toInt(metrics.adminLoginFailures, 0)
      },
      build: BUILD
    });
  }

  // ========= ALERTS =========
  if (action === "alerts_list") {
    if (!canReadAlerts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const limit = clamp(toInt(q.limit, 50), 1, 200);
    let rows = [];
    try {
      rows = await redis.lrange(alertsListKey(), 0, limit - 1);
    } catch {
      rows = [];
    }

    return res.status(200).json({
      ok: true,
      items: (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean),
      build: BUILD
    });
  }

  // ========= AUDIT =========
  if (action === "audit_list") {
    if (!canReadAudit(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const limit = clamp(toInt(q.limit, 50), 1, 200);
    let rows = [];
    try {
      rows = await redis.lrange(auditListKey(), 0, limit - 1);
    } catch {
      rows = [];
    }

    return res.status(200).json({
      ok: true,
      items: (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean),
      build: BUILD
    });
  }

  // ========= EMERGENCY =========
  if (action === "emergency_disable_all_keys") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.set(globalKey("disable_all"), "1");
    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_disable_all_keys",
      target: "global",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, disabled: true, build: BUILD });
  }

  if (action === "emergency_enable_all_keys") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("disable_all"));
    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_enable_all_keys",
      target: "global",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, disabled: false, build: BUILD });
  }

  if (action === "emergency_pause_all_launches") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.set(globalKey("paused"), "1");
    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_pause_all_launches",
      target: "global",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, paused: true, build: BUILD });
  }

  if (action === "emergency_end_all_sessions") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listActiveSessionRecords(redis);
    for (const r of rows) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
    }

    await metricIncr(redis, "sessionsEnded", rows.length);
    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_end_all_sessions",
      target: "all",
      ip: getIp(req),
      success: true,
      details: { count: rows.length }
    });

    return res.status(200).json({ ok: true, ended: rows.length, build: BUILD });
  }

  if (action === "emergency_clear_launch_nonces") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let count = 0;
    try {
      const keys = await redis.keys("sn:launchnonce:*");
      for (const k of keys || []) {
        await redis.del(k);
        count++;
      }
    } catch {}

    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_clear_launch_nonces",
      target: "all",
      ip: getIp(req),
      success: true,
      details: { count }
    });

    return res.status(200).json({ ok: true, cleared: count, build: BUILD });
  }

  if (action === "emergency_set_banner") {
    if (!canEmergency(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const message = String(q.message || "").trim();
    await redis.set(globalKey("maintenance_message"), message);
    await redis.set(globalKey("maintenance_mode"), message ? "1" : "");
    if (!message) await redis.del(globalKey("maintenance_mode"));

    await audit(redis, {
      type: "emergency",
      actor: admin.username,
      role: admin.role,
      action: "emergency_set_banner",
      target: "maintenance_message",
      ip: getIp(req),
      success: true,
      newValue: message
    });

    return res.status(200).json({ ok: true, message, build: BUILD });
  }

  return res.status(400).json({
    ok: false,
    error: "unknown_action",
    build: BUILD
  });
};