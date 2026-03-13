const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-admin-2026-03-13-adminplus";

// ===== admin credentials =====
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

const ADMIN_SESSION_TTL = 12 * 60 * 60;
const AUDIT_KEEP = 800;
const ALERT_KEEP = 300;
const PUBLIC_EVENT_KEEP_DEFAULT = 120;

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Token");
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
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

function cleanStr(v, maxLen) {
  v = String(v == null ? "" : v).trim();
  if (!maxLen) return v;
  return v.length > maxLen ? v.slice(0, maxLen) : v;
}

function cleanUrl(v, maxLen) {
  const s = cleanStr(v, maxLen || 500);
  if (!s) return "";
  if (/^https?:\/\//i.test(s) || s.indexOf("/api/") === 0 || s.indexOf("/") === 0) return s;
  return "";
}

function uniqArrayStrings(arr, maxItems, maxLen) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  const seen = new Set();
  for (const v of arr) {
    const s = cleanStr(v, maxLen || 200);
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= (maxItems || 50)) break;
  }
  return out;
}

function sanitizeQuickLinks(arr) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const item of arr) {
    if (!item || typeof item !== "object") continue;
    const label = cleanStr(item.label, 80);
    const url = cleanUrl(item.url, 400);
    if (!label || !url) continue;
    out.push({
      label,
      url,
      icon: cleanStr(item.icon, 40),
      mode: cleanStr(item.mode, 20) || "external"
    });
    if (out.length >= 20) break;
  }
  return out;
}

function sanitizeModalButtons(arr) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const item of arr) {
    if (!item || typeof item !== "object") continue;
    const label = cleanStr(item.label, 60);
    const action = cleanStr(item.action, 40);
    const url = cleanUrl(item.url, 400);
    if (!label) continue;
    out.push({
      label,
      action: action || (url ? "open" : "close"),
      url,
      style: cleanStr(item.style, 20) || "normal"
    });
    if (out.length >= 8) break;
  }
  return out;
}

function sanitizePollOptions(arr) {
  let src = arr;
  if (typeof src === "string") {
    try {
      src = JSON.parse(src);
    } catch {
      src = String(src).split(/\r?\n|[,|]/g);
    }
  }
  if (!Array.isArray(src)) return [];
  const flat = [];
  for (const item of src) {
    if (typeof item === "string") {
      const parts = String(item).split(/\r?\n|[,|]/g).map((x) => cleanStr(x, 120)).filter(Boolean);
      for (const p of parts) flat.push(p);
      continue;
    }
    if (item && typeof item === "object") {
      const s = cleanStr(item.label || item.value || item.text || "", 120);
      if (s) flat.push(s);
    }
  }
  return uniqArrayStrings(flat, 12, 120);
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
  return 2;
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

function clientBlockKey(clientId) {
  return "sn:client:block:" + String(clientId);
}

function clientNoteKey(clientId) {
  return "sn:client:note:" + String(clientId);
}

function clientSuspiciousKey(clientId) {
  return "sn:client:suspicious:" + String(clientId);
}

function clientCommandKey(clientId) {
  return "sn:admin:cmd:client:" + String(clientId);
}

function hwidCommandKey(hwHash) {
  return "sn:admin:cmd:hwid:" + String(hwHash);
}

function keyCommandKey(license) {
  return "sn:admin:cmd:key:" + String(license);
}

function globalCommandKey() {
  return "sn:admin:cmd:global";
}

function hwidNoteKey(hwHash) {
  return "sn:hwid:note:" + String(hwHash);
}

function hwidCooldownKey(hwHash) {
  return "sn:hwid:cooldown:" + String(hwHash);
}

function hwidDenyMessageKey(hwHash) {
  return "sn:hwid:denymsg:" + String(hwHash);
}

function keyMetaKey(license) {
  return "sn:keymeta:" + String(license);
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

function eventsListKey() {
  return "sn:public:events";
}

function pollVotesKey(pollId) {
  return "sn:public:poll:" + String(pollId) + ":votes";
}

function isSafeClientId(clientId) {
  return /^SN\-[A-Za-z0-9_-]{2,80}$/.test(String(clientId || "").trim());
}

function normalizeClientId(v) {
  const s = String(v || "").trim();
  return isSafeClientId(s) ? s : "";
}

function normalizeCommandType(v) {
  const allowed = new Set([
    "close_chrome_soft",
    "close_chrome_hard",
    "refresh_ui",
    "refresh_bootstrap",
    "show_message",
    "show_banner",
    "force_reverify",
    "require_relaunch",
    "open_support",
    "open_download",
    "open_url",
    "cleanup_prompt",
    "update_check",
    "disconnect"
  ]);
  const s = cleanStr(v, 80);
  return allowed.has(s) ? s : "show_message";
}

function normalizeTargetType(v) {
  const s = cleanStr(v, 30);
  return ["global","client","hwid","key"].includes(s) ? s : "global";
}

function remoteCommandBucketKey(targetType, targetValue) {
  if (targetType === "client") return clientCommandKey(targetValue);
  if (targetType === "hwid") return hwidCommandKey(targetValue);
  if (targetType === "key") return keyCommandKey(targetValue);
  return globalCommandKey();
}

async function pushRemoteCommand(redis, actor, role, req, targetType, targetValue, commandType, payload) {
  const row = {
    id: randHex(10),
    createdAt: nowSec(),
    createdBy: actor,
    createdRole: role,
    targetType,
    targetValue: targetValue || "",
    commandType,
    payload: payload || {},
    expiresAt: nowSec() + 60 * 60 * 24,
    received: false,
    executed: false
  };
  const key = remoteCommandBucketKey(targetType, targetValue || "");
  await redis.lpush(key, JSON.stringify(row));
  await redis.ltrim(key, 0, 49);
  await redis.expire(key, 60 * 60 * 24 * 7);
  await audit(redis, {
    type: "remote_command",
    actor,
    role,
    action: "remote_command_push",
    target: (targetType || "global") + ":" + (targetValue || "all"),
    ip: getIp(req),
    success: true,
    details: row
  });
  return row;
}

async function readRemoteCommands(redis, targetType, targetValue, limit) {
  const key = remoteCommandBucketKey(targetType, targetValue || "");
  let rows = [];
  try { rows = await redis.lrange(key, 0, Math.max(0, (limit || 25) - 1)); } catch { rows = []; }
  return (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean);
}

async function readKeyMeta(redis, license) {
  return safeJsonParse(await redis.get(keyMetaKey(license)), {});
}

async function writeKeyMeta(redis, license, patch) {
  const prev = await readKeyMeta(redis, license);
  const next = { ...prev, ...patch, license: String(license || "").trim(), updatedAt: nowSec() };
  await redis.set(keyMetaKey(license), JSON.stringify(next));
  return next;
}

async function buildClientLookup(redis, clientId) {
  const rows = await listActiveSessionRecords(redis);
  const sessions = rows.filter((r) => r.clientId === clientId);
  const licenses = Array.from(new Set(sessions.map((x) => x.license).filter(Boolean)));
  const hwids = Array.from(new Set(sessions.map((x) => x.hwidHash).filter(Boolean)));
  const note = safeJsonParse(await redis.get(clientNoteKey(clientId)), null);
  const block = safeJsonParse(await redis.get(clientBlockKey(clientId)), null);
  const suspicious = safeJsonParse(await redis.get(clientSuspiciousKey(clientId)), null);
  const commands = await readRemoteCommands(redis, "client", clientId, 10);
  let launcherVersion = "";
  let startUrl = "";
  let lastSeen = 0;
  let plan = "";
  let license = "";
  let sessionId = "";
  if (sessions.length) {
    const best = sessions.slice().sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))[0];
    lastSeen = best.lastSeen || 0;
    plan = best.plan || "";
    license = best.license || "";
    sessionId = best.sessionId || "";
    const raw = safeJsonParse(await redis.get(sessionKey(best.license, best.sessionId)), {});
    launcherVersion = String(raw.launcherVersion || raw.ver || raw.version || "");
    startUrl = String(raw.lastStartUrl || raw.startUrl || "");
  }
  return {
    clientId,
    live: sessions.some((x) => x.active),
    linkedHWIDs: hwids,
    linkedLicenses: licenses,
    currentSession: sessionId,
    lastPing: lastSeen,
    launcherVersion,
    plan,
    startUrl,
    note,
    block,
    suspicious,
    sessions,
    recentCommands: commands
  };
}

async function endSessionRecords(redis, rows) {
  let ended = 0;
  for (const r of rows || []) {
    try {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
      await maybeDeleteFreeKeyForLicense(redis, r.license);
      ended++;
    } catch {}
  }
  if (ended) await metricIncr(redis, "sessionsEnded", ended);
  return ended;
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

async function maybeDeleteFreeKeyForLicense(redis, license) {
  license = String(license || "").trim();
  if (!license || license.indexOf("FREE-") !== 0) return false;

  try {
    await redis.del(freeKeyRedisKey(license));
    return true;
  } catch {
    return false;
  }
}

async function resolveLicenseInfo(redis, license) {
  license = String(license || "").trim();
  if (!license) return { exists: false };

  const isEnv = getLicenseList().includes(license);
  const custom = await getCustomKey(redis, license);

  let free = null;
  try {
    free = safeJsonParse(await redis.get(freeKeyRedisKey(license)), null);
  } catch {}

  if (!isEnv && !custom && !free) return { exists: false };

  const disabled = !!(await redis.get(disabledKeyKey(license)));
  const meta = await readKeyMeta(redis, license);
  let ttlSeconds = 0;
  let sessionLimit = defaultLimitForPlan(planForLicense(license));
  let maxDevices = defaultMaxDevicesForPlan(planForLicense(license));
  let exp = 0;
  let source = isEnv ? "env" : (custom ? "custom" : "free");
  let tier = "";

  if (custom) {
    ttlSeconds = toInt(custom.ttlSeconds, defaultTtlForPlan(custom.plan || planForLicense(license)));
    sessionLimit = toInt(custom.sessionLimit, defaultLimitForPlan(custom.plan || planForLicense(license)));
    maxDevices = toInt(custom.maxDevices, defaultMaxDevicesForPlan(custom.plan || planForLicense(license)));
    exp = toInt(custom.exp, 0);
  } else if (free) {
    ttlSeconds = toInt(free.ttlSeconds, defaultTtlForPlan("free"));
    sessionLimit = 1;
    maxDevices = 1;
    exp = toInt(free.exp, 0);
    tier = String(free.tier || "");
  } else {
    ttlSeconds = defaultTtlForPlan(planForLicense(license));
    sessionLimit = defaultLimitForPlan(planForLicense(license));
    maxDevices = defaultMaxDevicesForPlan(planForLicense(license));
  }

  let hwids = [];
  try {
    hwids = await redis.smembers(hwidSetKey(license));
  } catch {}

  let activeSessions = [];
  try {
    activeSessions = await redis.smembers(activeSetKey(license));
  } catch {}

  const info = {
    exists: true,
    key: {
      license,
      source,
      plan: custom?.plan || planForLicense(license),
      disabled,
      ttlSeconds,
      sessionLimit,
      maxDevices,
      exp,
      activeSessions: (activeSessions || []).length,
      hwids: hwids || [],
      tier,
      note: String(custom?.note || free?.note || ""),
      meta
    }
  };

  return info;
}

async function listCustomKeys(redis) {
  let keys = [];
  try {
    keys = await redis.keys("sn:custom:*");
  } catch {
    keys = [];
  }

  const out = [];
  for (const keyName of keys || []) {
    const raw = await redis.get(keyName);
    const obj = safeJsonParse(raw, null);
    if (!obj) continue;
    out.push({
      license: String(keyName).replace(/^sn:custom:/, ""),
      plan: String(obj.plan || ""),
      ttlSeconds: toInt(obj.ttlSeconds, 0),
      sessionLimit: toInt(obj.sessionLimit, 0),
      maxDevices: toInt(obj.maxDevices, 0),
      exp: toInt(obj.exp, 0),
      createdAt: toInt(obj.createdAt, 0),
      createdBy: String(obj.createdBy || ""),
      note: String(obj.note || "")
    });
  }

  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
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
  for (const keyName of keys || []) {
    const raw = await redis.get(keyName);
    const obj = safeJsonParse(raw, null);
    if (!obj) continue;
    out.push({
      license: String(keyName).replace(/^sn:freekey:/, ""),
      ttlSeconds: toInt(obj.ttlSeconds, 0),
      exp: toInt(obj.exp, 0),
      createdAt: toInt(obj.createdAt, 0),
      createdBy: String(obj.createdBy || ""),
      tier: String(obj.tier || "15m")
    });
  }

  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return out;
}

async function countDownloads(redis) {
  try {
    const raw = await redis.get("sn:downloads");
    return toInt(raw, 0);
  } catch {
    return 0;
  }
}

async function countVisitors(redis) {
  try {
    const raw = await redis.get("sn:visitors");
    return toInt(raw, 0);
  } catch {
    return 0;
  }
}

async function countTrusted(redis) {
  try {
    const raw = await redis.get("sn:trusted");
    return toInt(raw, 0);
  } catch {
    return 0;
  }
}

async function countKeysByPrefix(redis, prefix) {
  try {
    const keys = await redis.keys(prefix);
    return (keys || []).length;
  } catch {
    return 0;
  }
}

async function countPublicEvents(redis) {
  try {
    return await redis.llen(eventsListKey());
  } catch {
    return 0;
  }
}

async function getTodayMetrics(redis) {
  try {
    const raw = await redis.hgetall(metricsKey(todayKeyDate()));
    return raw || {};
  } catch {
    return {};
  }
}

async function getAnalyticsSummary(redis) {
  const sessions = await listActiveSessionRecords(redis);
  const freeKeys = await listFreeKeys(redis);
  const customKeys = await listCustomKeys(redis);

  const counts = {
    activeSessions: sessions.length,
    freeKeys: freeKeys.length,
    customKeys: customKeys.length,
    downloads: await countDownloads(redis),
    visitors: await countVisitors(redis),
    trusted: await countTrusted(redis),
    bannedHwids: await countKeysByPrefix(redis, "sn:banned:hwid:*"),
    suspiciousHwids: await countKeysByPrefix(redis, "sn:suspicious:hwid:*"),
    activeByPlan: {
      free: sessions.filter((x) => x.plan === "free").length,
      basic: sessions.filter((x) => x.plan === "basic").length,
      pro: sessions.filter((x) => x.plan === "pro").length
    }
  };

  const launcherStatus = {
    paused: !!(await redis.get(globalKey("paused"))),
    pausedReason: String((await redis.get(globalKey("paused_reason"))) || ""),
    maintenanceMode: !!(await redis.get(globalKey("maintenance_mode"))),
    maintenanceMessage: String((await redis.get(globalKey("maintenance_message"))) || ""),
    minVersion: String((await redis.get(globalKey("min_version"))) || ""),
    supportEmail: String((await redis.get(globalKey("launcher_support_email"))) || ""),
    discordUrl: String((await redis.get(globalKey("launcher_discord_url"))) || ""),
    defaultStartUrl: String((await redis.get(globalKey("launcher_default_start_url"))) || ""),
    submitUrl: String((await redis.get(globalKey("launcher_submit_url"))) || ""),
    cleanupOldPromptEnabled: !!(await redis.get(globalKey("cleanup_old_prompt_enabled"))),
    publicBannerEnabled: !!(await redis.get(globalKey("public_banner_enabled"))),
    publicModalEnabled: !!(await redis.get(globalKey("public_modal_enabled"))),
    publicPollEnabled: !!(await redis.get(globalKey("public_poll_enabled"))),
    quickLinksCount: safeJsonParse(await redis.get(globalKey("launcher_quick_links_json")), []).length,
    disableAllKeys: !!(await redis.get(globalKey("disable_all")))
  };

  const today = await getTodayMetrics(redis);
  const publicEvents = await countPublicEvents(redis);

  return {
    counts,
    launcherStatus,
    today: {
      keyChecks: toInt(today.keyChecks, 0),
      verifyAttempts: toInt(today.verifyAttempts, 0),
      launchAttempts: toInt(today.launchAttempts, 0),
      launchFailures: toInt(today.launchFailures, 0),
      uiChallenges: toInt(today.uiChallenges, 0),
      freeKeysGenerated: toInt(today.freeKeysGenerated, 0),
      sessionsEnded: toInt(today.sessionsEnded, 0),
      adminLoginFailures: toInt(today.adminLoginFailures, 0),
      publicEvents: toInt(today.publicEvents, publicEvents),
      pollVotes: toInt(today.pollVotes, 0),
      bannerDismissals: toInt(today.bannerDismissals, 0),
      cleanupRuns: toInt(today.cleanupRuns, 0)
    }
  };
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  const body = await getJsonBody(req);
  const q = req.method === "GET" ? req.query || {} : body || {};
  const action = lower(q.action);

  if (!action) {
    return res.status(400).json({ ok: false, error: "missing_action", build: BUILD });
  }

  const rl = await rateLimit(req, "admin:" + action, 180, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({
      ok: false,
      error: "rate_limited",
      retryAfter: rl.retryAfter,
      build: BUILD
    });
  }

  if (action === "login") {
    const username = cleanStr(q.username, 80);
    const password = String(q.password || "");
    const userKey = userKeyForLogin(username);
    const user = userKey ? ADMIN_USERS[userKey] : null;

    if (!user || user.disabled || user.password !== password) {
      await metricIncr(redis, "adminLoginFailures", 1);
      await addAlert(redis, {
        type: "admin_login_failure",
        actor: username || "unknown",
        level: "medium",
        ip: getIp(req)
      });
      return res.status(401).json({ ok: false, error: "bad_login", build: BUILD });
    }

    const token = randHex(24);
    const now = nowSec();
    const sess = {
      username: user.username,
      role: user.role,
      createdAt: now,
      exp: now + ADMIN_SESSION_TTL,
      ip: getIp(req),
      disabled: false
    };

    await redis.set(adminSessionKey(token), JSON.stringify(sess), { ex: ADMIN_SESSION_TTL });

    await audit(redis, {
      type: "admin_login",
      actor: user.username,
      role: user.role,
      action: "login",
      target: "admin_panel",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({
      ok: true,
      token,
      me: {
        username: user.username,
        role: user.role,
        exp: sess.exp
      },
      build: BUILD
    });
  }

  const auth = await requireAdmin(req, res, redis, body);
  if (!auth.ok) {
    return res.status(auth.status).json({ ok: false, error: auth.error, build: BUILD });
  }
  const admin = auth.session;

  if (action === "logout") {
    await redis.del(adminSessionKey(auth.token));
    await audit(redis, {
      type: "admin_logout",
      actor: admin.username,
      role: admin.role,
      action: "logout",
      target: "admin_panel",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "me") {
    return res.status(200).json({
      ok: true,
      me: {
        username: admin.username,
        role: admin.role,
        exp: admin.exp,
        createdAt: admin.createdAt,
        ip: admin.ip
      },
      build: BUILD
    });
  }

  if (action === "dashboard") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const summary = await getAnalyticsSummary(redis);
    return res.status(200).json({
      ok: true,
      summary,
      build: BUILD
    });
  }

  if (action === "sessions_list") {
    if (!canReadSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const search = lower(q.search);
    const license = String(q.license || "").trim();
    const plan = lower(q.plan);
    const clientId = String(q.clientId || "").trim();
    const hwidHash = String(q.hwidHash || q.hwid || "").trim();

    let rows = await listActiveSessionRecords(redis, license || "");
    rows = rows.filter((r) => {
      if (plan && r.plan !== plan) return false;
      if (clientId && r.clientId !== clientId) return false;
      if (hwidHash && r.hwidHash !== hwidHash) return false;
      if (search) {
        const hay = lower([
          r.license, r.plan, r.clientId, r.hwidHash, r.sessionId, r.ip, r.hwidRawPreview
        ].join(" "));
        if (hay.indexOf(search) === -1) return false;
      }
      return true;
    });

    return res.status(200).json({ ok: true, items: rows, build: BUILD });
  }

  if (action === "session_end_one") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    const sessionId = String(q.sessionId || "").trim();
    if (!license || !sessionId) {
      return res.status(400).json({ ok: false, error: "missing_license_or_session", build: BUILD });
    }

    await redis.del(sessionKey(license, sessionId));
    await redis.srem(activeSetKey(license), sessionId);
    await maybeDeleteFreeKeyForLicense(redis, license);
    await metricIncr(redis, "sessionsEnded", 1);

    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "session_end_one",
      target: license + ":" + sessionId,
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
      await maybeDeleteFreeKeyForLicense(redis, r.license);
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

    const hwid = String(q.hwidHash || q.hwid || "").trim();
    if (!hwid) {
      return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });
    }

    const rows = (await listActiveSessionRecords(redis)).filter((r) => r.hwidHash === hwid);
    for (const r of rows) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
      await maybeDeleteFreeKeyForLicense(redis, r.license);
    }

    await metricIncr(redis, "sessionsEnded", rows.length);
    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "sessions_end_by_hwid",
      target: hwid,
      ip: getIp(req),
      success: true,
      details: { count: rows.length }
    });

    return res.status(200).json({ ok: true, ended: rows.length, build: BUILD });
  }

  if (action === "key_search") {
    if (!canReadKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

    const info = await resolveLicenseInfo(redis, license);
    return res.status(200).json({
      ok: true,
      ...info,
      build: BUILD
    });
  }

  if (action === "key_disable") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

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

    return res.status(200).json({ ok: true, disabled: true, build: BUILD });
  }

  if (action === "key_enable") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = String(q.license || "").trim();
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

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

    return res.status(200).json({ ok: true, disabled: false, build: BUILD });
  }

  if (action === "key_create_custom") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = cleanStr(q.license, 160);
    const plan = lower(q.plan || "basic");
    const ttlSeconds = clamp(toInt(q.ttlSeconds, defaultTtlForPlan(plan)), 60, 60 * 60 * 24 * 365);
    const sessionLimit = clamp(toInt(q.sessionLimit, defaultLimitForPlan(plan)), 1, 50);
    const maxDevices = clamp(toInt(q.maxDevices, defaultMaxDevicesForPlan(plan)), 1, 20);
    const exp = toInt(q.exp, 0);
    const note = cleanStr(q.note, 300);

    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

    const row = {
      license,
      plan: ["free", "basic", "pro"].includes(plan) ? plan : "basic",
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

    return res.status(200).json({ ok: true, key: row, build: BUILD });
  }

  if (action === "key_delete_custom") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = cleanStr(q.license, 160);
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

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

    const license = cleanStr(q.license, 160);
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

    const prev = await getCustomKey(redis, license);
    if (!prev) {
      return res.status(404).json({ ok: false, error: "custom_key_not_found", build: BUILD });
    }

    const plan = lower(q.plan || prev.plan || "basic");
    const row = {
      ...prev,
      license,
      plan: ["free", "basic", "pro"].includes(plan) ? plan : "basic",
      ttlSeconds: clamp(toInt(q.ttlSeconds, prev.ttlSeconds), 60, 60 * 60 * 24 * 365),
      sessionLimit: clamp(toInt(q.sessionLimit, prev.sessionLimit), 1, 50),
      maxDevices: clamp(toInt(q.maxDevices, prev.maxDevices), 1, 20),
      exp: toInt(q.exp, prev.exp || 0),
      note: cleanStr(q.note, 300),
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
      details: row
    });

    return res.status(200).json({ ok: true, key: row, build: BUILD });
  }

  if (action === "key_reset_hwid_bindings") {
    if (!canWriteKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = cleanStr(q.license, 160);
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

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

    return res.status(200).json({ ok: true, items: await listCustomKeys(redis), build: BUILD });
  }

  if (action === "freekeys_list") {
    if (!canReadFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    return res.status(200).json({ ok: true, items: await listFreeKeys(redis), build: BUILD });
  }

  if (action === "freekey_add") {
    if (!canWriteFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = cleanStr(q.license, 160) || ("FREE-" + randHex(6).toUpperCase());
    const tier = cleanStr(q.tier, 20) || "15m";
    const ttlSeconds = clamp(toInt(q.ttlSeconds, tier === "2h" ? 7200 : (tier === "35m" ? 2100 : 900)), 60, 60 * 60 * 24);
    const row = {
      license,
      tier,
      ttlSeconds,
      exp: nowSec() + ttlSeconds,
      createdAt: nowSec(),
      createdBy: admin.username
    };

    await redis.set(freeKeyRedisKey(license), JSON.stringify(row), { ex: ttlSeconds });
    await audit(redis, {
      type: "freekey",
      actor: admin.username,
      role: admin.role,
      action: "freekey_add",
      target: license,
      ip: getIp(req),
      success: true,
      details: row
    });

    return res.status(200).json({ ok: true, license, freeKey: row, build: BUILD });
  }

  if (action === "freekey_remove") {
    if (!canWriteFreeKeys(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const license = cleanStr(q.license, 160);
    if (!license) {
      return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    }

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
    for (const r of rows) {
      await redis.del(freeKeyRedisKey(r.license));
    }

    await audit(redis, {
      type: "freekey",
      actor: admin.username,
      role: admin.role,
      action: "freekeys_expire_all",
      target: "all_free_keys",
      ip: getIp(req),
      success: true,
      details: { count: rows.length }
    });

    return res.status(200).json({ ok: true, expired: rows.length, build: BUILD });
  }

  if (action === "launcher_status") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    return res.status(200).json({ ok: true, summary: await getAnalyticsSummary(redis), build: BUILD });
  }

  if (action === "launcher_pause") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const reason = cleanStr(q.reason, 300);
    await redis.set(globalKey("paused"), "1");
    if (reason) await redis.set(globalKey("paused_reason"), reason);
    else await redis.del(globalKey("paused_reason"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_pause",
      target: "paused",
      ip: getIp(req),
      success: true,
      newValue: reason
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
      target: "paused",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, paused: false, build: BUILD });
  }

  if (action === "launcher_set_min_version") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const version = cleanStr(q.version || q.minVersion, 80);
    if (!version) {
      return res.status(400).json({ ok: false, error: "missing_version", build: BUILD });
    }

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

    return res.status(200).json({ ok: true, minVersion: version, build: BUILD });
  }

  if (action === "launcher_set_maintenance_message") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const message = cleanStr(q.message, 500);
    if (message) {
      await redis.set(globalKey("maintenance_mode"), "1");
      await redis.set(globalKey("maintenance_message"), message);
    } else {
      await redis.del(globalKey("maintenance_mode"));
      await redis.del(globalKey("maintenance_message"));
    }

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

    return res.status(200).json({ ok: true, maintenanceMode: !!message, message, build: BUILD });
  }

  if (action === "launcher_set_runtime_config") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const supportEmail = cleanStr(q.supportEmail, 200);
    const discordUrl = cleanUrl(q.discordUrl, 400);
    const defaultStartUrl = cleanUrl(q.defaultStartUrl, 400);
    const submitUrl = cleanUrl(q.submitUrl, 400);

    if (supportEmail) await redis.set(globalKey("launcher_support_email"), supportEmail);
    else await redis.del(globalKey("launcher_support_email"));

    if (discordUrl) await redis.set(globalKey("launcher_discord_url"), discordUrl);
    else await redis.del(globalKey("launcher_discord_url"));

    if (defaultStartUrl) await redis.set(globalKey("launcher_default_start_url"), defaultStartUrl);
    else await redis.del(globalKey("launcher_default_start_url"));

    if (submitUrl) await redis.set(globalKey("launcher_submit_url"), submitUrl);
    else await redis.del(globalKey("launcher_submit_url"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_set_runtime_config",
      target: "runtime_config",
      ip: getIp(req),
      success: true,
      details: { supportEmail, discordUrl, defaultStartUrl, submitUrl }
    });

    return res.status(200).json({
      ok: true,
      runtime: { supportEmail, discordUrl, defaultStartUrl, submitUrl },
      build: BUILD
    });
  }

  if (action === "launcher_cleanup_prompt_get") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const prompt = {
      enabled: !!(await redis.get(globalKey("cleanup_old_prompt_enabled"))),
      message: String((await redis.get(globalKey("cleanup_old_prompt_message"))) || ""),
      forceOnce: toInt(await redis.get(globalKey("cleanup_old_prompt_force_once")), 0),
      scanPaths: safeJsonParse(await redis.get(globalKey("cleanup_old_scan_paths_json")), []),
      nameHints: safeJsonParse(await redis.get(globalKey("cleanup_old_name_hints_json")), [])
    };

    return res.status(200).json({ ok: true, prompt, build: BUILD });
  }

  if (action === "launcher_cleanup_prompt_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled = !!(
      q.enabled === true || q.enabled === 1 || q.enabled === "1" ||
      lower(q.enabled) === "true" || lower(q.enabled) === "yes"
    );
    const message = cleanStr(q.message, 500);
    const scanPaths = uniqArrayStrings(
      typeof q.scanPaths === "string" ? safeJsonParse(q.scanPaths, q.scanPaths.split(/\r?\n|,/g)) : q.scanPaths,
      30,
      260
    );
    const nameHints = uniqArrayStrings(
      typeof q.nameHints === "string" ? safeJsonParse(q.nameHints, q.nameHints.split(/\r?\n|,/g)) : q.nameHints,
      30,
      120
    );

    if (enabled) await redis.set(globalKey("cleanup_old_prompt_enabled"), "1");
    else await redis.del(globalKey("cleanup_old_prompt_enabled"));

    if (message) await redis.set(globalKey("cleanup_old_prompt_message"), message);
    else await redis.del(globalKey("cleanup_old_prompt_message"));

    await redis.set(globalKey("cleanup_old_scan_paths_json"), JSON.stringify(scanPaths));
    await redis.set(globalKey("cleanup_old_name_hints_json"), JSON.stringify(nameHints));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_cleanup_prompt_set",
      target: "cleanup_prompt",
      ip: getIp(req),
      success: true,
      details: { enabled, message, scanPaths, nameHints }
    });

    return res.status(200).json({
      ok: true,
      prompt: { enabled, message, scanPaths, nameHints },
      build: BUILD
    });
  }

  if (action === "launcher_cleanup_prompt_bump") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const forceOnce = nowSec();
    await redis.set(globalKey("cleanup_old_prompt_force_once"), String(forceOnce));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_cleanup_prompt_bump",
      target: "cleanup_prompt_force_once",
      ip: getIp(req),
      success: true,
      newValue: forceOnce
    });

    return res.status(200).json({ ok: true, forceOnce, build: BUILD });
  }

  if (action === "launcher_public_banner_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled =
      q.enabled === true || q.enabled === 1 || q.enabled === "1" || lower(q.enabled) === "true" || lower(q.enabled) === "yes";
    const id = cleanStr(q.id, 120) || ("banner_" + randHex(6));
    const title = cleanStr(q.title, 120);
    const text = cleanStr(q.text, 500);
    const mode = cleanStr(q.mode, 20) || "info";
    const dismissable =
      q.dismissable === true || q.dismissable === 1 || q.dismissable === "1" || lower(q.dismissable) === "true" || lower(q.dismissable) === "yes";

    if (enabled) await redis.set(globalKey("public_banner_enabled"), "1");
    else await redis.del(globalKey("public_banner_enabled"));

    if (id) await redis.set(globalKey("public_banner_id"), id); else await redis.del(globalKey("public_banner_id"));
    if (title) await redis.set(globalKey("public_banner_title"), title); else await redis.del(globalKey("public_banner_title"));
    if (text) await redis.set(globalKey("public_banner_text"), text); else await redis.del(globalKey("public_banner_text"));
    if (mode) await redis.set(globalKey("public_banner_mode"), mode); else await redis.del(globalKey("public_banner_mode"));
    if (dismissable) await redis.set(globalKey("public_banner_dismissable"), "1"); else await redis.del(globalKey("public_banner_dismissable"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_banner_set",
      target: id,
      ip: getIp(req),
      success: true,
      details: { enabled, title, textLen: text.length, mode, dismissable }
    });

    return res.status(200).json({
      ok: true,
      banner: { enabled, id, title, text, mode, dismissable },
      build: BUILD
    });
  }

  if (action === "launcher_public_banner_clear") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("public_banner_enabled"));
    await redis.del(globalKey("public_banner_id"));
    await redis.del(globalKey("public_banner_title"));
    await redis.del(globalKey("public_banner_text"));
    await redis.del(globalKey("public_banner_mode"));
    await redis.del(globalKey("public_banner_dismissable"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_banner_clear",
      target: "public_banner",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "launcher_public_modal_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled =
      q.enabled === true || q.enabled === 1 || q.enabled === "1" || lower(q.enabled) === "true" || lower(q.enabled) === "yes";
    const id = cleanStr(q.id, 120) || ("modal_" + randHex(6));
    const title = cleanStr(q.title, 120);
    const text = cleanStr(q.text, 800);

    let buttons = q.buttons;
    if (typeof buttons === "string") buttons = safeJsonParse(buttons, []);
    buttons = sanitizeModalButtons(buttons);

    if (enabled) await redis.set(globalKey("public_modal_enabled"), "1");
    else await redis.del(globalKey("public_modal_enabled"));

    if (id) await redis.set(globalKey("public_modal_id"), id); else await redis.del(globalKey("public_modal_id"));
    if (title) await redis.set(globalKey("public_modal_title"), title); else await redis.del(globalKey("public_modal_title"));
    if (text) await redis.set(globalKey("public_modal_text"), text); else await redis.del(globalKey("public_modal_text"));
    await redis.set(globalKey("public_modal_buttons_json"), JSON.stringify(buttons));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_modal_set",
      target: id,
      ip: getIp(req),
      success: true,
      details: { enabled, title, textLen: text.length, buttonCount: buttons.length }
    });

    return res.status(200).json({
      ok: true,
      modal: { enabled, id, title, text, buttons },
      build: BUILD
    });
  }

  if (action === "launcher_public_modal_clear") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("public_modal_enabled"));
    await redis.del(globalKey("public_modal_id"));
    await redis.del(globalKey("public_modal_title"));
    await redis.del(globalKey("public_modal_text"));
    await redis.del(globalKey("public_modal_buttons_json"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_modal_clear",
      target: "public_modal",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "launcher_public_poll_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled =
      q.enabled === true || q.enabled === 1 || q.enabled === "1" || lower(q.enabled) === "true" || lower(q.enabled) === "yes";
    const id = cleanStr(q.id, 120) || ("poll_" + randHex(6));
    const question = cleanStr(q.question, 400);

    let options = q.options;
    if (typeof options === "string") options = safeJsonParse(options, options.split(/\r?\n|,/g));
    options = sanitizePollOptions(options);

    if (options.length < 2) {
      return res.status(400).json({ ok: false, error: "poll_needs_two_options", build: BUILD });
    }

    if (enabled) await redis.set(globalKey("public_poll_enabled"), "1");
    else await redis.del(globalKey("public_poll_enabled"));

    if (id) await redis.set(globalKey("public_poll_id"), id); else await redis.del(globalKey("public_poll_id"));
    if (question) await redis.set(globalKey("public_poll_question"), question); else await redis.del(globalKey("public_poll_question"));
    await redis.set(globalKey("public_poll_options_json"), JSON.stringify(options));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_poll_set",
      target: id,
      ip: getIp(req),
      success: true,
      details: { enabled, question, options }
    });

    return res.status(200).json({
      ok: true,
      poll: { enabled, id, question, options },
      build: BUILD
    });
  }

  if (action === "launcher_public_poll_clear") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("public_poll_enabled"));
    await redis.del(globalKey("public_poll_id"));
    await redis.del(globalKey("public_poll_question"));
    await redis.del(globalKey("public_poll_options_json"));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_poll_clear",
      target: "public_poll",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "launcher_public_poll_results") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let pollId = cleanStr(q.pollId, 120);
    if (!pollId) pollId = String((await redis.get(globalKey("public_poll_id"))) || "");

    const question = String((await redis.get(globalKey("public_poll_question"))) || "");
    const options = safeJsonParse(await redis.get(globalKey("public_poll_options_json")), []);

    const raw = safeJsonParse(await redis.hgetall(pollVotesKey(pollId)), {});
    const votes = {};
    let totalVotes = 0;
    for (const k of Object.keys(raw || {})) {
      votes[k] = toInt(raw[k], 0);
      totalVotes += votes[k];
    }

    return res.status(200).json({
      ok: true,
      poll: { pollId, question, options, votes, totalVotes },
      build: BUILD
    });
  }

  if (action === "launcher_public_poll_reset") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let pollId = cleanStr(q.pollId, 120);
    if (!pollId) pollId = String((await redis.get(globalKey("public_poll_id"))) || "");

    if (!pollId) {
      return res.status(400).json({ ok: false, error: "missing_poll_id", build: BUILD });
    }

    await redis.del(pollVotesKey(pollId));
    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_poll_reset",
      target: pollId,
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, pollId, build: BUILD });
  }

  if (action === "launcher_quick_links_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let links = q.links;
    if (typeof links === "string") links = safeJsonParse(links, []);
    links = sanitizeQuickLinks(links);

    await redis.set(globalKey("launcher_quick_links_json"), JSON.stringify(links));

    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_quick_links_set",
      target: "quick_links",
      ip: getIp(req),
      success: true,
      details: { count: links.length }
    });

    return res.status(200).json({ ok: true, links, build: BUILD });
  }

  if (action === "launcher_quick_links_clear") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(globalKey("launcher_quick_links_json"));
    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_quick_links_clear",
      target: "quick_links",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "launcher_public_events_list") {
    if (!canReadDashboard(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const limit = clamp(toInt(q.limit, 50), 1, 200);
    let rows = [];
    try { rows = await redis.lrange(eventsListKey(), 0, limit - 1); } catch { rows = []; }
    rows = (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean);

    return res.status(200).json({ ok: true, items: rows, build: BUILD });
  }

  if (action === "launcher_public_events_clear") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    await redis.del(eventsListKey());
    await audit(redis, {
      type: "launcher",
      actor: admin.username,
      role: admin.role,
      action: "launcher_public_events_clear",
      target: "public_events",
      ip: getIp(req),
      success: true
    });

    return res.status(200).json({ ok: true, build: BUILD });
  }

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
        noteInfo: null,
        cooldownInfo: null,
        denyInfo: null,
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
      const noteRaw = await redis.get(hwidNoteKey(hw));
      const cooldownRaw = await redis.get(hwidCooldownKey(hw));
      const denyRaw = await redis.get(hwidDenyMessageKey(hw));
      out.byHwid.banned = !!banRaw;
      out.byHwid.suspicious = !!suspRaw;
      out.byHwid.banInfo = safeJsonParse(banRaw, null);
      out.byHwid.suspiciousInfo = safeJsonParse(suspRaw, null);
      out.byHwid.noteInfo = safeJsonParse(noteRaw, null);
      out.byHwid.cooldownInfo = safeJsonParse(cooldownRaw, null);
      out.byHwid.denyInfo = safeJsonParse(denyRaw, null);

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

  if (action === "admin_accounts_list") {
    if (!canReadAdminAccounts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const accounts = Object.values(ADMIN_USERS).map((u) => ({
      username: u.username,
      role: u.role,
      disabled: !!u.disabled
    }));

    let sessions = [];
    try {
      const keys = await redis.keys("sn:admin:session:*");
      for (const k of keys || []) {
        const raw = await redis.get(k);
        const obj = safeJsonParse(raw, null);
        if (!obj) continue;
        sessions.push({
          tokenTail: String(k).slice(-8),
          username: String(obj.username || ""),
          role: String(obj.role || ""),
          createdAt: toInt(obj.createdAt, 0),
          exp: toInt(obj.exp, 0),
          ip: String(obj.ip || "")
        });
      }
    } catch {
      sessions = [];
    }

    sessions.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    return res.status(200).json({
      ok: true,
      accounts,
      sessions,
      build: BUILD
    });
  }

  if (action === "admin_force_logout_all") {
    if (!canWriteAdminAccounts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    let count = 0;
    try {
      const keys = await redis.keys("sn:admin:session:*");
      for (const k of keys || []) {
        await redis.del(k);
        count++;
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
      details: { count }
    });

    return res.status(200).json({ ok: true, count, build: BUILD });
  }

  if (action === "config_get") {
    if (!canReadConfig(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const quickLinks = safeJsonParse(await redis.get(globalKey("launcher_quick_links_json")), []);
    const modalButtons = safeJsonParse(await redis.get(globalKey("public_modal_buttons_json")), []);
    const pollOptions = safeJsonParse(await redis.get(globalKey("public_poll_options_json")), []);
    const cleanupScanPaths = safeJsonParse(await redis.get(globalKey("cleanup_old_scan_paths_json")), []);
    const cleanupNameHints = safeJsonParse(await redis.get(globalKey("cleanup_old_name_hints_json")), []);

    return res.status(200).json({
      ok: true,
      config: {
        launcher: {
          paused: !!(await redis.get(globalKey("paused"))),
          pausedReason: String((await redis.get(globalKey("paused_reason"))) || ""),
          maintenanceMode: !!(await redis.get(globalKey("maintenance_mode"))),
          maintenanceMessage: String((await redis.get(globalKey("maintenance_message"))) || ""),
          minVersion: String((await redis.get(globalKey("min_version"))) || ""),
          disableAllKeys: !!(await redis.get(globalKey("disable_all"))),
          supportEmail: String((await redis.get(globalKey("launcher_support_email"))) || ""),
          discordUrl: String((await redis.get(globalKey("launcher_discord_url"))) || ""),
          defaultStartUrl: String((await redis.get(globalKey("launcher_default_start_url"))) || ""),
          submitUrl: String((await redis.get(globalKey("launcher_submit_url"))) || ""),
          cleanupOldPromptEnabled: !!(await redis.get(globalKey("cleanup_old_prompt_enabled"))),
          cleanupOldPromptMessage: String((await redis.get(globalKey("cleanup_old_prompt_message"))) || ""),
          cleanupOldPromptForceOnce: toInt(await redis.get(globalKey("cleanup_old_prompt_force_once")), 0),
          cleanupOldScanPaths: cleanupScanPaths,
          cleanupOldNameHints: cleanupNameHints,
          publicBannerEnabled: !!(await redis.get(globalKey("public_banner_enabled"))),
          publicBannerId: String((await redis.get(globalKey("public_banner_id"))) || ""),
          publicBannerTitle: String((await redis.get(globalKey("public_banner_title"))) || ""),
          publicBannerText: String((await redis.get(globalKey("public_banner_text"))) || ""),
          publicBannerMode: String((await redis.get(globalKey("public_banner_mode"))) || ""),
          publicBannerDismissable: !!(await redis.get(globalKey("public_banner_dismissable"))),
          publicModalEnabled: !!(await redis.get(globalKey("public_modal_enabled"))),
          publicModalId: String((await redis.get(globalKey("public_modal_id"))) || ""),
          publicModalTitle: String((await redis.get(globalKey("public_modal_title"))) || ""),
          publicModalText: String((await redis.get(globalKey("public_modal_text"))) || ""),
          publicModalButtons: modalButtons,
          publicPollEnabled: !!(await redis.get(globalKey("public_poll_enabled"))),
          publicPollId: String((await redis.get(globalKey("public_poll_id"))) || ""),
          publicPollQuestion: String((await redis.get(globalKey("public_poll_question"))) || ""),
          publicPollOptions: pollOptions,
          quickLinks: quickLinks,
          quickLinksCount: Array.isArray(quickLinks) ? quickLinks.length : 0,
          allowlistMode: !!(await redis.get(globalKey("allowlist_mode"))),
          rotatingAnnouncement: String((await redis.get(globalKey("rotating_announcement"))) || ""),
          oneTimeAnnouncement: String((await redis.get(globalKey("one_time_announcement"))) || "")
        }
      },
      build: BUILD
    });
  }

  if (action === "analytics_summary") {
    if (!canReadAnalytics(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const summary = await getAnalyticsSummary(redis);
    const eventCount = await countPublicEvents(redis);

    return res.status(200).json({
      ok: true,
      analytics: {
        ...summary,
        eventCount,
        pollVotesToday: toInt(summary.today.pollVotes, 0),
        cleanupRunsToday: toInt(summary.today.cleanupRuns, 0),
        bannerDismissalsToday: toInt(summary.today.bannerDismissals, 0)
      },
      build: BUILD
    });
  }

  if (action === "alerts_list") {
    if (!canReadAlerts(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const limit = clamp(toInt(q.limit, 50), 1, 200);
    let rows = [];
    try { rows = await redis.lrange(alertsListKey(), 0, limit - 1); } catch { rows = []; }
    rows = (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean);

    return res.status(200).json({ ok: true, items: rows, build: BUILD });
  }

  if (action === "audit_list") {
    if (!canReadAudit(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const limit = clamp(toInt(q.limit, 100), 1, 300);
    let rows = [];
    try { rows = await redis.lrange(auditListKey(), 0, limit - 1); } catch { rows = []; }
    rows = (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean);

    const filterType = cleanStr(q.type, 50);
    const filterAction = cleanStr(q.filterAction, 80);
    if (filterType) rows = rows.filter((x) => String(x.type || "") === filterType);
    if (filterAction) rows = rows.filter((x) => String(x.action || "") === filterAction);

    return res.status(200).json({ ok: true, items: rows, build: BUILD });
  }

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
      await maybeDeleteFreeKeyForLicense(redis, r.license);
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

  if (action === "client_lookup") {
    if (!canReadSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const result = await buildClientLookup(redis, clientId);
    return res.status(200).json({ ok: true, result, build: BUILD });
  }

  if (action === "client_note_set") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    const note = cleanStr(q.note, 500);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const row = { clientId, note, updatedAt: nowSec(), updatedBy: admin.username };
    await redis.set(clientNoteKey(clientId), JSON.stringify(row));
    await audit(redis, { type: "client", actor: admin.username, role: admin.role, action: "client_note_set", target: clientId, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, note: row, build: BUILD });
  }

  if (action === "client_block") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const minutes = clamp(toInt(q.minutes || q.durationMinutes, 60), 1, 60 * 24 * 30);
    const row = { clientId, reason: cleanStr(q.reason, 300), until: nowSec() + minutes * 60, blockedAt: nowSec(), blockedBy: admin.username };
    await redis.set(clientBlockKey(clientId), JSON.stringify(row), { ex: minutes * 60 });
    await audit(redis, { type: "client", actor: admin.username, role: admin.role, action: "client_block", target: clientId, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, block: row, build: BUILD });
  }

  if (action === "client_unblock") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    await redis.del(clientBlockKey(clientId));
    await audit(redis, { type: "client", actor: admin.username, role: admin.role, action: "client_unblock", target: clientId, ip: getIp(req), success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === "client_mark_suspicious") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const row = { clientId, reason: cleanStr(q.reason, 300), markedAt: nowSec(), markedBy: admin.username };
    await redis.set(clientSuspiciousKey(clientId), JSON.stringify(row));
    await audit(redis, { type: "client", actor: admin.username, role: admin.role, action: "client_mark_suspicious", target: clientId, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, suspicious: row, build: BUILD });
  }

  if (action === "client_clear_binding") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const rows = (await listActiveSessionRecords(redis)).filter((x) => x.clientId === clientId);
    let changed = 0;
    for (const r of rows) {
      const sk = sessionKey(r.license, r.sessionId);
      const raw = safeJsonParse(await redis.get(sk), null);
      if (!raw) continue;
      raw.cid = "";
      await redis.set(sk, JSON.stringify(raw), { ex: Math.max(60, (toInt(raw.exp, nowSec()+60)-nowSec()) + 180) });
      changed++;
    }
    await audit(redis, { type: "client", actor: admin.username, role: admin.role, action: "client_clear_binding", target: clientId, ip: getIp(req), success: true, details: { changed } });
    return res.status(200).json({ ok: true, changed, build: BUILD });
  }

  if (action === "sessions_end_by_client") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const clientId = normalizeClientId(q.clientId || q.id);
    if (!clientId) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    const rows = (await listActiveSessionRecords(redis)).filter((x) => x.clientId === clientId);
    const ended = await endSessionRecords(redis, rows);
    await audit(redis, { type: "session", actor: admin.username, role: admin.role, action: "sessions_end_by_client", target: clientId, ip: getIp(req), success: true, details: { ended } });
    return res.status(200).json({ ok: true, ended, build: BUILD });
  }

  if (action === "sessions_end_by_license") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const license = cleanStr(q.license, 160);
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    const rows = await listActiveSessionRecords(redis, license);
    const ended = await endSessionRecords(redis, rows);
    await audit(redis, { type: "session", actor: admin.username, role: admin.role, action: "sessions_end_by_license", target: license, ip: getIp(req), success: true, details: { ended } });
    return res.status(200).json({ ok: true, ended, build: BUILD });
  }

  if (action === "sessions_end_selected") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    let items = Array.isArray(q.items) ? q.items : safeJsonParse(q.items, []);
    items = Array.isArray(items) ? items : [];
    const rows = [];
    for (const it of items) {
      if (!it || typeof it !== "object") continue;
      const license = cleanStr(it.license, 160);
      const sessionId = cleanStr(it.sessionId, 160);
      if (!license || !sessionId) continue;
      rows.push({ license, sessionId });
    }
    let ended = 0;
    for (const r of rows) {
      const found = safeJsonParse(await redis.get(sessionKey(r.license, r.sessionId)), null);
      if (!found) continue;
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
      await maybeDeleteFreeKeyForLicense(redis, r.license);
      ended++;
    }
    if (ended) await metricIncr(redis, "sessionsEnded", ended);
    await audit(redis, { type: "session", actor: admin.username, role: admin.role, action: "sessions_end_selected", target: "selected", ip: getIp(req), success: true, details: { count: ended } });
    return res.status(200).json({ ok: true, ended, build: BUILD });
  }

  if (action === "sessions_list_stale") {
    if (!canReadSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const olderThanMinutes = clamp(toInt(q.olderThanMinutes, 20), 1, 24 * 60);
    const cutoff = nowSec() - olderThanMinutes * 60;
    const items = (await listActiveSessionRecords(redis)).filter((x) => (x.lastSeen || 0) < cutoff).map((x) => ({
      ...x,
      pingAgeSec: Math.max(0, nowSec() - (x.lastSeen || 0)),
      sessionAgeSec: Math.max(0, nowSec() - (x.createdAt || x.lastSeen || nowSec()))
    }));
    return res.status(200).json({ ok: true, items, olderThanMinutes, build: BUILD });
  }

  if (action === "sessions_cleanup_stale") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const olderThanMinutes = clamp(toInt(q.olderThanMinutes, 20), 1, 24 * 60);
    const cutoff = nowSec() - olderThanMinutes * 60;
    const rows = (await listActiveSessionRecords(redis)).filter((x) => (x.lastSeen || 0) < cutoff);
    const ended = await endSessionRecords(redis, rows);
    await audit(redis, { type: "session", actor: admin.username, role: admin.role, action: "sessions_cleanup_stale", target: "stale", ip: getIp(req), success: true, details: { ended, olderThanMinutes } });
    return res.status(200).json({ ok: true, ended, build: BUILD });
  }

  if (action === "hwid_note_set") {
    if (!canWriteHWID(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const hw = cleanStr(q.hwidHash || q.hwid, 200);
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });
    const row = { hwidHash: hw, note: cleanStr(q.note, 500), updatedAt: nowSec(), updatedBy: admin.username };
    await redis.set(hwidNoteKey(hw), JSON.stringify(row));
    await audit(redis, { type: "hwid", actor: admin.username, role: admin.role, action: "hwid_note_set", target: hw, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, note: row, build: BUILD });
  }

  if (action === "hwid_cooldown_set") {
    if (!canWriteHWID(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const hw = cleanStr(q.hwidHash || q.hwid, 200);
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });
    const minutes = clamp(toInt(q.minutes, 60), 1, 60 * 24 * 30);
    const row = { hwidHash: hw, reason: cleanStr(q.reason, 300), until: nowSec() + minutes * 60, updatedAt: nowSec(), updatedBy: admin.username };
    await redis.set(hwidCooldownKey(hw), JSON.stringify(row), { ex: minutes * 60 });
    await audit(redis, { type: "hwid", actor: admin.username, role: admin.role, action: "hwid_cooldown_set", target: hw, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, cooldown: row, build: BUILD });
  }

  if (action === "hwid_deny_message_set") {
    if (!canWriteHWID(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const hw = cleanStr(q.hwidHash || q.hwid, 200);
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });
    const minutes = clamp(toInt(q.minutes, 60), 1, 60 * 24 * 30);
    const row = { hwidHash: hw, message: cleanStr(q.message, 300), until: nowSec() + minutes * 60, updatedAt: nowSec(), updatedBy: admin.username };
    await redis.set(hwidDenyMessageKey(hw), JSON.stringify(row), { ex: minutes * 60 });
    await audit(redis, { type: "hwid", actor: admin.username, role: admin.role, action: "hwid_deny_message_set", target: hw, ip: getIp(req), success: true, details: row });
    return res.status(200).json({ ok: true, deny: row, build: BUILD });
  }

  if (action === "key_meta_set") {
    if (!canWriteKeys(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const license = cleanStr(q.license, 160);
    if (!license) return res.status(400).json({ ok: false, error: "missing_license", build: BUILD });
    const patch = {
      paused: !!(q.paused === true || q.paused === 1 || q.paused === "1" || lower(q.paused) === "true" || lower(q.paused) === "yes"),
      suspendMessage: cleanStr(q.suspendMessage, 300),
      tag: cleanStr(q.tag, 80),
      risk: cleanStr(q.risk, 40),
      note: cleanStr(q.note, 500),
      planOverride: cleanStr(q.planOverride, 30),
      ttlOverride: toInt(q.ttlOverride, 0),
      updatedBy: admin.username
    };
    const meta = await writeKeyMeta(redis, license, patch);
    await audit(redis, { type: "key", actor: admin.username, role: admin.role, action: "key_meta_set", target: license, ip: getIp(req), success: true, details: meta });
    return res.status(200).json({ ok: true, meta, build: BUILD });
  }

  if (action === "lookup_any") {
    if (!canReadDashboard(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const query = cleanStr(q.query, 200);
    const all = await listActiveSessionRecords(redis);
    const out = { query, byClient: null, byHWID: null, byLicense: null, bySession: null };
    const clientId = normalizeClientId(query);
    if (clientId) out.byClient = await buildClientLookup(redis, clientId);
    if (query) {
      const hwSessions = all.filter((x) => x.hwidHash === query);
      if (hwSessions.length) out.byHWID = { hwidHash: query, sessions: hwSessions, note: safeJsonParse(await redis.get(hwidNoteKey(query)), null), cooldown: safeJsonParse(await redis.get(hwidCooldownKey(query)), null), deny: safeJsonParse(await redis.get(hwidDenyMessageKey(query)), null) };
      const licInfo = await resolveLicenseInfo(redis, query);
      if (licInfo && licInfo.exists) out.byLicense = licInfo;
      const sess = all.find((x) => x.sessionId === query);
      if (sess) out.bySession = sess;
    }
    return res.status(200).json({ ok: true, result: out, build: BUILD });
  }

  if (action === "remote_command_push") {
    if (!canEndSessions(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const targetType = normalizeTargetType(q.targetType);
    const targetValue = cleanStr(q.targetValue, 200);
    if (targetType === "client" && !normalizeClientId(targetValue)) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
    if ((targetType === "hwid" || targetType === "key") && !targetValue) return res.status(400).json({ ok: false, error: "missing_target_value", build: BUILD });
    const commandType = normalizeCommandType(q.commandType);
    const payload = {
      reason: cleanStr(q.reason, 300),
      message: cleanStr(q.message, 500),
      url: cleanUrl(q.url, 400),
      mode: cleanStr(q.mode, 30),
      closeAndEndSession: !!(q.closeAndEndSession === true || q.closeAndEndSession === 1 || q.closeAndEndSession === "1"),
      blockUntilRefresh: !!(q.blockUntilRefresh === true || q.blockUntilRefresh === 1 || q.blockUntilRefresh === "1")
    };
    const row = await pushRemoteCommand(redis, admin.username, admin.role, req, targetType, targetValue, commandType, payload);
    let ended = 0;
    if (payload.closeAndEndSession || commandType === "disconnect") {
      const all = await listActiveSessionRecords(redis);
      let rows = [];
      if (targetType === "global") rows = all;
      if (targetType === "client") rows = all.filter((x) => x.clientId === targetValue);
      if (targetType === "hwid") rows = all.filter((x) => x.hwidHash === targetValue);
      if (targetType === "key") rows = all.filter((x) => x.license === targetValue);
      ended = await endSessionRecords(redis, rows);
    }
    return res.status(200).json({ ok: true, command: row, ended, build: BUILD });
  }

  if (action === "remote_commands_list") {
    if (!canReadDashboard(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const targetType = normalizeTargetType(q.targetType);
    const targetValue = cleanStr(q.targetValue, 200);
    const items = await readRemoteCommands(redis, targetType, targetValue, clamp(toInt(q.limit, 25), 1, 100));
    return res.status(200).json({ ok: true, items, build: BUILD });
  }

  if (action === "launcher_global_extras_set") {
    if (!canWriteLauncher(admin.role)) return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    const allowlistMode = !!(q.allowlistMode === true || q.allowlistMode === 1 || q.allowlistMode === "1" || lower(q.allowlistMode) === "true");
    const rotatingAnnouncement = cleanStr(q.rotatingAnnouncement, 500);
    const oneTimeAnnouncement = cleanStr(q.oneTimeAnnouncement, 500);
    if (allowlistMode) await redis.set(globalKey("allowlist_mode"), "1"); else await redis.del(globalKey("allowlist_mode"));
    if (rotatingAnnouncement) await redis.set(globalKey("rotating_announcement"), rotatingAnnouncement); else await redis.del(globalKey("rotating_announcement"));
    if (oneTimeAnnouncement) await redis.set(globalKey("one_time_announcement"), oneTimeAnnouncement); else await redis.del(globalKey("one_time_announcement"));
    await audit(redis, { type: "launcher", actor: admin.username, role: admin.role, action: "launcher_global_extras_set", target: "global_extras", ip: getIp(req), success: true, details: { allowlistMode, rotatingAnnouncement, oneTimeAnnouncement } });
    return res.status(200).json({ ok: true, extras: { allowlistMode, rotatingAnnouncement, oneTimeAnnouncement }, build: BUILD });
  }

  return res.status(400).json({
    ok: false,
    error: "unknown_action",
    build: BUILD
  });
};