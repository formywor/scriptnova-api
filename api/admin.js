const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-admin-2026-03-10c";

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
  return uniqArrayStrings(arr, 12, 120);
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
      createdBy: String(custom.createdBy || ""),
      updatedAt: toInt(custom.updatedAt, 0),
      updatedBy: String(custom.updatedBy || "")
    };
  }

  if (license.indexOf("FREE-") === 0) {
    const free = await redis.get(freeKeyRedisKey(license));
    if (!free) return { exists: false };

    const freeObj = safeJsonParse(free, {});
    return {
      exists: true,
      source: "free",
      disabled,
      license,
      plan: "free",
      ttlSeconds: toInt(freeObj.ttlSeconds, 900),
      sessionLimit: 1,
      maxDevices: 1,
      exp: 0,
      tier: String(freeObj.tier || "15m")
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
      createdBy: String(obj.createdBy || ""),
      tier: String(obj.tier || "")
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

async function getGlobalString(redis, name, fallback) {
  try {
    const v = await redis.get(globalKey(name));
    if (v == null || String(v).trim() === "") return fallback;
    return String(v);
  } catch {
    return fallback;
  }
}

async function getGlobalBool(redis, name) {
  try {
    const v = await redis.get(globalKey(name));
    return !!v && String(v).trim() !== "";
  } catch {
    return false;
  }
}

async function getGlobalInt(redis, name, fallback) {
  try {
    const v = await redis.get(globalKey(name));
    return toInt(v, fallback);
  } catch {
    return fallback;
  }
}

async function getGlobalJson(redis, name, fallback) {
  try {
    const v = await redis.get(globalKey(name));
    return safeJsonParse(v, fallback);
  } catch {
    return fallback;
  }
}

async function getGlobalState(redis) {
  const paused = await getGlobalBool(redis, "paused");
  const disableAll = await getGlobalBool(redis, "disable_all");
  const maintenanceMode = await getGlobalBool(redis, "maintenance_mode");
  const maintenanceMessage = await getGlobalString(redis, "maintenance_message", "");
  const minVersion = await getGlobalString(redis, "min_version", "");
  const htaPausedReason = await getGlobalString(redis, "paused_reason", "");

  const cleanupOldPromptEnabled = await getGlobalBool(redis, "cleanup_old_prompt_enabled");
  const cleanupOldPromptMessage = await getGlobalString(redis, "cleanup_old_prompt_message", "");
  const cleanupOldPromptForceOnce = await getGlobalInt(redis, "cleanup_old_prompt_force_once", 0);
  const cleanupOldScanPaths = getGlobalJson(redis, "cleanup_old_scan_paths_json", []);
  const cleanupOldNameHints = getGlobalJson(redis, "cleanup_old_name_hints_json", []);

  const launcherSupportEmail = await getGlobalString(redis, "launcher_support_email", "gomegaassist@gmail.com");
  const launcherDiscordUrl = await getGlobalString(redis, "launcher_discord_url", "https://discord.gg/gscGTMVsWE");
  const launcherDefaultStartUrl = await getGlobalString(redis, "launcher_default_start_url", "https://www.guns.lol/iii_dev");
  const launcherSubmitUrl = await getGlobalString(redis, "launcher_submit_url", "/api/ui");

  const publicBannerEnabled = await getGlobalBool(redis, "public_banner_enabled");
  const publicBannerId = await getGlobalString(redis, "public_banner_id", "");
  const publicBannerTitle = await getGlobalString(redis, "public_banner_title", "");
  const publicBannerText = await getGlobalString(redis, "public_banner_text", "");
  const publicBannerMode = await getGlobalString(redis, "public_banner_mode", "info");
  const publicBannerDismissable = await getGlobalBool(redis, "public_banner_dismissable");

  const publicModalEnabled = await getGlobalBool(redis, "public_modal_enabled");
  const publicModalId = await getGlobalString(redis, "public_modal_id", "");
  const publicModalTitle = await getGlobalString(redis, "public_modal_title", "");
  const publicModalText = await getGlobalString(redis, "public_modal_text", "");
  const publicModalButtons = await getGlobalJson(redis, "public_modal_buttons_json", []);

  const publicPollEnabled = await getGlobalBool(redis, "public_poll_enabled");
  const publicPollId = await getGlobalString(redis, "public_poll_id", "");
  const publicPollQuestion = await getGlobalString(redis, "public_poll_question", "");
  const publicPollOptions = await getGlobalJson(redis, "public_poll_options_json", []);

  const launcherQuickLinks = await getGlobalJson(redis, "launcher_quick_links_json", []);

  return {
    paused,
    disableAll,
    maintenanceMode,
    maintenanceMessage,
    minVersion,
    pausedReason: htaPausedReason,

    cleanupOldPromptEnabled,
    cleanupOldPromptMessage,
    cleanupOldPromptForceOnce,
    cleanupOldScanPaths: await cleanupOldScanPaths,
    cleanupOldNameHints: await cleanupOldNameHints,

    launcherSupportEmail,
    launcherDiscordUrl,
    launcherDefaultStartUrl,
    launcherSubmitUrl,

    publicBannerEnabled,
    publicBannerId,
    publicBannerTitle,
    publicBannerText,
    publicBannerMode,
    publicBannerDismissable,

    publicModalEnabled,
    publicModalId,
    publicModalTitle,
    publicModalText,
    publicModalButtons,

    publicPollEnabled,
    publicPollId,
    publicPollQuestion,
    publicPollOptions,

    launcherQuickLinks
  };
}

async function serviceStatusFromUrl(url) {
  return { url, status: "unknown" };
}

async function getPollVotes(redis, pollId) {
  if (!pollId) return {};
  try {
    const rows = await redis.hgetall(pollVotesKey(pollId));
    return rows && typeof rows === "object" ? rows : {};
  } catch {
    return {};
  }
}

async function listPublicEvents(redis, limit) {
  const n = clamp(toInt(limit, 50), 1, 200);
  let rows = [];
  try {
    rows = await redis.lrange(eventsListKey(), 0, n - 1);
  } catch {
    rows = [];
  }
  return (rows || []).map((x) => safeJsonParse(x, null)).filter(Boolean);
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
        requiredMinVersion: global.minVersion || "v13.13.15",
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
      disableAllKeys: global.disableAll,
      cleanupOldPromptEnabled: global.cleanupOldPromptEnabled,
      cleanupOldPromptMessage: global.cleanupOldPromptMessage,
      cleanupOldPromptForceOnce: global.cleanupOldPromptForceOnce,
      cleanupOldScanPaths: Array.isArray(global.cleanupOldScanPaths) ? global.cleanupOldScanPaths : [],
      cleanupOldNameHints: Array.isArray(global.cleanupOldNameHints) ? global.cleanupOldNameHints : [],
      supportEmail: global.launcherSupportEmail,
      discordUrl: global.launcherDiscordUrl,
      defaultStartUrl: global.launcherDefaultStartUrl,
      submitUrl: global.launcherSubmitUrl,
      publicBannerEnabled: global.publicBannerEnabled,
      publicModalEnabled: global.publicModalEnabled,
      publicPollEnabled: global.publicPollEnabled,
      quickLinksCount: Array.isArray(global.launcherQuickLinks) ? global.launcherQuickLinks.length : 0
    },
    analyticsToday: {
      keyChecks: toInt(metrics.keyChecks, 0),
      verifyAttempts: toInt(metrics.verifyAttempts, 0),
      launchAttempts: toInt(metrics.launchAttempts, 0),
      launchFailures: toInt(metrics.launchFailures, 0),
      freeKeysGenerated: toInt(metrics.freeKeysGenerated, 0),
      sessionsEnded: toInt(metrics.sessionsEnded, 0),
      adminLoginFailures: toInt(metrics.adminLoginFailures, 0),
      uiChallenges: toInt(metrics.uiChallenges, 0),
      publicEvents: toInt(metrics.publicEvents, 0),
      pollVotes: toInt(metrics.pollVotes, 0),
      bannerDismissals: toInt(metrics.bannerDismissals, 0),
      cleanupRuns: toInt(metrics.cleanupRuns, 0)
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
    const freeKeyDeleted = await maybeDeleteFreeKeyForLicense(redis, license);
    await metricIncr(redis, "sessionsEnded", 1);

    await audit(redis, {
      type: "session",
      actor: admin.username,
      role: admin.role,
      action: "session_end_one",
      target: license + ":" + sid,
      ip: getIp(req),
      success: true,
      details: { freeKeyDeleted }
    });

    return res.status(200).json({ ok: true, freeKeyDeleted, build: BUILD });
  }

  if (action === "sessions_end_all") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const rows = await listActiveSessionRecords(redis);
    let freeKeyDeletedCount = 0;
    for (const r of rows) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
      if (await maybeDeleteFreeKeyForLicense(redis, r.license)) freeKeyDeletedCount += 1;
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
      details: { count: rows.length, freeKeyDeletedCount }
    });

    return res.status(200).json({ ok: true, ended: rows.length, freeKeyDeletedCount, build: BUILD });
  }

  if (action === "sessions_end_by_hwid") {
    if (!canEndSessions(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const hw = String(q.hwidHash || q.hwid || "").trim();
    if (!hw) return res.status(400).json({ ok: false, error: "missing_hwid_hash", build: BUILD });

    const rows = await listActiveSessionRecords(redis);
    const hit = rows.filter((r) => r.hwidHash === hw);

    let freeKeyDeletedCount = 0;
    for (const r of hit) {
      await redis.del(sessionKey(r.license, r.sessionId));
      await redis.srem(activeSetKey(r.license), r.sessionId);
      if (await maybeDeleteFreeKeyForLicense(redis, r.license)) freeKeyDeletedCount += 1;
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
      details: { count: hit.length, freeKeyDeletedCount }
    });

    return res.status(200).json({ ok: true, ended: hit.length, freeKeyDeletedCount, build: BUILD });
  }

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
    const tier = String(q.tier || "").trim();

    await redis.set(
      freeKeyRedisKey(license),
      JSON.stringify({
        exp,
        createdAt: nowSec(),
        createdBy: admin.username,
        ttlSeconds,
        tier
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
      details: { ttlSeconds, exp, tier }
    });

    return res.status(200).json({ ok: true, license, ttlSeconds, exp, tier, build: BUILD });
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

  if (action === "launcher_set_runtime_config") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const supportEmail = cleanStr(q.supportEmail, 200);
    const discordUrl = cleanUrl(q.discordUrl, 400);
    const defaultStartUrl = cleanUrl(q.defaultStartUrl, 500);
    const submitUrl = cleanUrl(q.submitUrl, 400) || "/api/ui";

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

    const g = await getGlobalState(redis);
    return res.status(200).json({
      ok: true,
      cleanupPrompt: {
        enabled: g.cleanupOldPromptEnabled,
        message: g.cleanupOldPromptMessage,
        forceOnce: g.cleanupOldPromptForceOnce,
        scanPaths: Array.isArray(g.cleanupOldScanPaths) ? g.cleanupOldScanPaths : [],
        nameHints: Array.isArray(g.cleanupOldNameHints) ? g.cleanupOldNameHints : []
      },
      build: BUILD
    });
  }

  if (action === "launcher_cleanup_prompt_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled =
      q.enabled === true ||
      q.enabled === 1 ||
      q.enabled === "1" ||
      lower(q.enabled) === "true" ||
      lower(q.enabled) === "yes" ||
      lower(q.enabled) === "on";

    const message = String(q.message || "").trim();

    let scanPaths = q.scanPaths;
    let nameHints = q.nameHints;

    if (typeof scanPaths === "string") scanPaths = safeJsonParse(scanPaths, scanPaths.split(/\r?\n|,/g));
    if (typeof nameHints === "string") nameHints = safeJsonParse(nameHints, nameHints.split(/\r?\n|,/g));

    scanPaths = uniqArrayStrings(scanPaths, 20, 260);
    nameHints = uniqArrayStrings(nameHints, 20, 120);

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
      target: "cleanup_old_prompt",
      ip: getIp(req),
      success: true,
      details: { enabled, message, scanPaths, nameHints }
    });

    return res.status(200).json({
      ok: true,
      enabled,
      message,
      scanPaths,
      nameHints,
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
      target: "cleanup_old_prompt_force_once",
      ip: getIp(req),
      success: true,
      newValue: forceOnce
    });

    return res.status(200).json({
      ok: true,
      forceOnce,
      build: BUILD
    });
  }

  if (action === "launcher_public_banner_set") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const enabled =
      q.enabled === true || q.enabled === 1 || q.enabled === "1" || lower(q.enabled) === "true" || lower(q.enabled) === "yes";
    const id = cleanStr(q.id, 120) || ("banner_" + randHex(6));
    const title = cleanStr(q.title, 120);
    const text = cleanStr(q.text, 1200);
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
      details: { enabled, title, text, mode, dismissable }
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
    const text = cleanStr(q.text, 4000);

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

    const pollId = cleanStr(q.pollId, 120) || await getGlobalString(redis, "public_poll_id", "");
    const question = await getGlobalString(redis, "public_poll_question", "");
    const options = await getGlobalJson(redis, "public_poll_options_json", []);
    const votes = await getPollVotes(redis, pollId);

    return res.status(200).json({
      ok: true,
      poll: {
        pollId,
        question,
        options: Array.isArray(options) ? options : [],
        votes
      },
      build: BUILD
    });
  }

  if (action === "launcher_public_poll_reset") {
    if (!canWriteLauncher(admin.role)) {
      return res.status(403).json({ ok: false, error: "forbidden", build: BUILD });
    }

    const pollId = cleanStr(q.pollId, 120) || await getGlobalString(redis, "public_poll_id", "");
    if (!pollId) return res.status(400).json({ ok: false, error: "missing_poll_id", build: BUILD });

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

    const limit = clamp(toInt(q.limit, PUBLIC_EVENT_KEEP_DEFAULT), 1, 200);
    const items = await listPublicEvents(redis, limit);

    return res.status(200).json({
      ok: true,
      items,
      count: items.length,
      build: BUILD
    });
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
        launcherForceVersionValue: g.minVersion || "v13.13.15",
        maintenanceMessageText: g.maintenanceMessage || "",
        cleanupOldPrompt: {
          enabled: g.cleanupOldPromptEnabled,
          message: g.cleanupOldPromptMessage || "",
          forceOnce: g.cleanupOldPromptForceOnce || 0,
          scanPaths: Array.isArray(g.cleanupOldScanPaths) ? g.cleanupOldScanPaths : [],
          nameHints: Array.isArray(g.cleanupOldNameHints) ? g.cleanupOldNameHints : []
        },
        runtimeConfig: {
          supportEmail: g.launcherSupportEmail || "",
          discordUrl: g.launcherDiscordUrl || "",
          defaultStartUrl: g.launcherDefaultStartUrl || "",
          submitUrl: g.launcherSubmitUrl || "/api/ui"
        },
        publicBanner: {
          enabled: g.publicBannerEnabled,
          id: g.publicBannerId,
          title: g.publicBannerTitle,
          text: g.publicBannerText,
          mode: g.publicBannerMode,
          dismissable: g.publicBannerDismissable
        },
        publicModal: {
          enabled: g.publicModalEnabled,
          id: g.publicModalId,
          title: g.publicModalTitle,
          text: g.publicModalText,
          buttons: Array.isArray(g.publicModalButtons) ? g.publicModalButtons : []
        },
        publicPoll: {
          enabled: g.publicPollEnabled,
          id: g.publicPollId,
          question: g.publicPollQuestion,
          options: Array.isArray(g.publicPollOptions) ? g.publicPollOptions : []
        },
        quickLinks: Array.isArray(g.launcherQuickLinks) ? g.launcherQuickLinks : [],
        featureToggles: {
          paused: g.paused,
          maintenanceMode: g.maintenanceMode,
          disableAllKeys: g.disableAll
        }
      },
      build: BUILD
    });
  }

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
        adminLoginFailuresToday: toInt(metrics.adminLoginFailures, 0),
        uiChallengesToday: toInt(metrics.uiChallenges, 0),
        publicEventsToday: toInt(metrics.publicEvents, 0),
        pollVotesToday: toInt(metrics.pollVotes, 0),
        bannerDismissalsToday: toInt(metrics.bannerDismissals, 0),
        cleanupRunsToday: toInt(metrics.cleanupRuns, 0)
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

  return res.status(400).json({
    ok: false,
    error: "unknown_action",
    build: BUILD
  });
};