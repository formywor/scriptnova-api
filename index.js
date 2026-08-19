"use strict";

const crypto = require("crypto");
const express = require("express");
const {initializeApp, cert, getApps} = require("firebase-admin/app");
const {getDatabase, ServerValue} = require("firebase-admin/database");
const {
  TOKEN_OPTIONS,
  ECONOMY,
  REDIRECT_WAIT_CHANCES,
  redirectWaitPlan,
  normalizeUsername,
  validateUsername,
  validatePin,
} =
  require("./lib/policy");

function firebaseOptions() {
  const options = {
    projectId: process.env.FIREBASE_PROJECT_ID || "share-browser-7091c",
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  };
  if (process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    options.credential = cert({
      projectId: options.projectId,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    });
  }
  return options;
}

if (!getApps().length) initializeApp(firebaseOptions());
const database = getDatabase();
const root = database.ref();
let rootCacheWarmed = false;
const CURRENT_LAUNCHER_VERSION = "1.2.0";
const LAUNCHER_DOWNLOAD_URL = "https://scriptnovaa.com/downloads/ShareBrowser.hta";
const DEVICE_SETUP_BONUS = 2;
const ONLINE_DEMO_MINUTES = 10;
const ONLINE_DEMO_COOLDOWN_HOURS = 24;
const ONLINE_DEMO_IP_DAILY_LIMIT = 20;
const app = express();
app.disable("x-powered-by");
app.disable("etag");
app.set("trust proxy", true);
app.use(express.json({limit: "32kb"}));
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");
  res.setHeader("Vary", "Origin, Authorization");
  next();
});

const ALLOWED_ORIGINS = new Set([
  "https://scriptnovaa.com",
  "https://www.scriptnovaa.com",
  ...(process.env.EXTRA_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean),
]);
app.use((req, res, next) => {
  const origin = String(req.headers.origin || "");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Admin-Secret, X-Launcher-Version");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") {
    return origin && ALLOWED_ORIGINS.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
  }
  next();
});

const PRESETS = {
  balanced: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications", "--disable-background-mode"],
  privacy: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications", "--disable-extensions",
    "--disable-background-mode",
    "--disable-features=AutofillServerCommunication", "--incognito"],
  minimal: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-background-mode"],
  protected: [
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-component-extensions-with-background-pages",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-background-mode",
    "--disable-component-update",
    "--dns-prefetch-disable",
    "--enable-features=DnsOverHttps",
    "--dns-over-https-mode=secure",
    "--dns-over-https-templates=https://cloudflare-dns.com/dns-query",
    "--disable-notifications",
    "--incognito",
  ],
};
const USER_AGENTS = {
  default: "",
  shareDesktop: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 " +
    "Safari/537.36 ShareBrowser/1.0",
  chromeOs120: "Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
};
const LAUNCHER_CONFIGURATION = Object.freeze({
  defaultMode: "protected",
  defaultIdentity: "chromeOs120",
  modes: [
    {id: "balanced", label: "Balanced"},
    {id: "privacy", label: "Private"},
    {id: "minimal", label: "Lightweight"},
    {id: "protected", label: "Protected"},
  ],
  identities: [
    {id: "default", label: "Standard"},
    {id: "chromeOs120", label: "ScriptNovaa compatibility"},
  ],
  appearance: {
    background: "#090c14",
    panel: "#121724",
    border: "#343c51",
    accentStart: "#735cff",
    accentEnd: "#23ceb9",
  },
});
function browserLaunchFlags(browser, presetId) {
  const flags = [...PRESETS[presetId]];
  if (browser === "edge") {
    flags.push("--disable-features=msEdgeStartupBoost");
  }
  return flags;
}
const SUPPORT_CATEGORIES = new Set([
  "CONNECTION_CODE_REPLACEMENT",
  "BROWSER_PROBLEM",
  "ACCOUNT_ACCESS",
  "POINTS_OR_REWARDS",
  "REFERRAL_PROBLEM",
  "DEVELOPER_PROGRAM",
  "OTHER",
]);
const DEFAULT_REDIRECT_URL = "https://omg10.com/4/11435374";
const LIMITED_FREE_TOKEN = Object.freeze({
  id: "free-4m-2026",
  minutes: 4,
  points: 0,
  label: "4 minutes — FREE limited token",
  endsAt: Date.parse("2026-08-28T03:59:59.000Z"),
});

function availableTokenOptions() {
  const standard = TOKEN_OPTIONS.map((option) => ({
    id: `${option.hours}h`,
    hours: option.hours,
    minutes: option.hours * 60,
    points: option.points,
    label: `${option.hours} hour${option.hours === 1 ? "" : "s"} — ${option.points} points`,
  }));
  if (Date.now() < LIMITED_FREE_TOKEN.endsAt) {
    standard.unshift({...LIMITED_FREE_TOKEN, limited: true});
  }
  return standard;
}

function requestedTokenOption(body) {
  const options = availableTokenOptions();
  const optionId = String(body.optionId || "");
  return options.find((option) => option.id === optionId) ||
    options.find((option) => option.hours === Number(body.hours));
}

function fail(message, statusCode = 400, code = "") {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.apiCode = code;
  throw error;
}
function envSecret(name) {
  const value = process.env[name];
  if (!value || value.length < 24) fail(`${name} is not configured.`, 500);
  return value;
}
function hmac(value, pepper = "SESSION_PEPPER") {
  return crypto.createHmac("sha256", envSecret(pepper)).update(String(value)).digest("hex");
}
function credential(value, pepper) {
  const salt = crypto.randomBytes(16).toString("hex");
  return {salt, hash: crypto.scryptSync(String(value) + envSecret(pepper), salt, 64).toString("hex")};
}
function verifies(value, stored, pepper) {
  if (!stored?.salt || !stored?.hash) return false;
  const actual = crypto.scryptSync(String(value) + envSecret(pepper), stored.salt, 64);
  const expected = Buffer.from(stored.hash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function code(prefix, bytes = 18) {
  const text = crypto.randomBytes(bytes).toString("base64url").toUpperCase();
  return `${prefix}-${text.match(/.{1,4}/g).join("-")}`;
}
function id(path) { return root.child(path).push().key; }
function bearer(req) {
  return String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i)?.[1] || "";
}
function ipPrefix(req) {
  const ip = String(req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
  return ip.includes(":") ? ip.split(":").slice(0, 4).join(":") : ip.split(".").slice(0, 3).join(".");
}
function publicAccount(a) {
  return {username: a.username, pointBalance: Number(a.pointBalance || 0),
    pendingPointBalance: Number(a.pendingPointBalance || 0), referralCode: a.username,
    registeredComputer: Boolean(a.registeredDeviceId),
    unusedTokenCount: Number(a.unusedTokenCount || 0),
    limitedFreeTokenClaimed: Boolean(a.limitedFreeTokenClaimedAt),
    deviceSetupBonusAwarded: Boolean(a.deviceSetupBonusAwardedAt),
    deviceSetupNoticePending: Boolean(a.deviceSetupNoticePending),
    fraudStatus: a.fraudStatus || "CLEAR", activeSessionId: a.activeSessionId || null};
}
function publicSupportTicket(ticketId, ticket) {
  return {
    ticketId,
    category: ticket.category,
    subject: ticket.subject,
    message: ticket.message,
    status: ticket.status || "PENDING",
    adminResponse: ticket.adminResponse || "",
    createdAt: Number(ticket.createdAt || 0),
    updatedAt: Number(ticket.updatedAt || ticket.createdAt || 0),
    replacementConsumedAt: Number(ticket.replacementConsumedAt || 0) || null,
  };
}
async function accountSupportTickets(accountId) {
  return Object.entries(await read("supportTickets") || {})
      .filter(([, ticket]) => ticket.accountId === accountId)
      .sort((a, b) => Number(b[1].createdAt || 0) - Number(a[1].createdAt || 0));
}
async function pairingContext(accountId, account) {
  const [activeHash, pairings, tickets] = await Promise.all([
    read(`activeDevicePairings/${accountId}`),
    read("devicePairings"),
    accountSupportTickets(accountId),
  ]);
  const activePairing = activeHash ? pairings?.[activeHash] : null;
  const hasPairingHistory = Object.values(pairings || {})
      .some((pairing) => pairing.accountId === accountId);
  const replacementEntry = tickets.find(([, ticket]) =>
    ticket.category === "CONNECTION_CODE_REPLACEMENT" &&
    ["PENDING", "APPROVED", "DECLINED", "FULFILLED"].includes(ticket.status));
  const approvedEntry = tickets.find(([, ticket]) =>
    ticket.category === "CONNECTION_CODE_REPLACEMENT" &&
    ticket.status === "APPROVED" && !ticket.replacementConsumedAt);
  return {
    activeHash,
    activePairing,
    hasIssued: Boolean(account.pairingCodeIssuedAt ||
      account.registeredDeviceId || activeHash || hasPairingHistory),
    migrationAvailable: Boolean(account.registeredDeviceId &&
      !account.persistentLauncherPairedAt &&
      !account.persistentMigrationCodeIssuedAt),
    replacementEntry,
    approvedEntry,
  };
}
function route(handler) {
  return async (req, res) => {
    try { await handler(req, res); } catch (error) {
      const statusCode = error.statusCode || 400;
      if (statusCode >= 500) console.error(error);
      if (req.path === "/api/device/pairing/complete" && statusCode < 500) {
        console.warn("Pairing request rejected:", statusCode,
            error.message || "Request failed.");
      }
      const response = {ok: false, error: error.message || "Request failed."};
      if (error.apiCode) response.code = error.apiCode;
      if (error.apiCode === "LAUNCHER_UPDATE_REQUIRED") {
        response.currentVersion = CURRENT_LAUNCHER_VERSION;
        response.updateUrl = LAUNCHER_DOWNLOAD_URL;
      }
      res.status(statusCode).json(response);
    }
  };
}
function ensure(data, key) { if (!data[key]) data[key] = {}; return data[key]; }
async function read(path) { return (await root.child(path).get()).val(); }
async function pendingReferralPoints(accountId) {
  return Object.values(await read("referrals") || {})
      .filter((referral) =>
        referral.referrerAccountId === accountId &&
        ["WAITING_FOR_DEVICE", "RISK_REVIEW"].includes(referral.status))
      .reduce((total, referral) =>
        total + Number(referral.pendingReward || 0), 0);
}
function requireCurrentLauncherVersion(req) {
  const supplied = String(req.headers["x-launcher-version"] || "");
  if (supplied !== CURRENT_LAUNCHER_VERSION) {
    fail(
        `Share Browser ${CURRENT_LAUNCHER_VERSION} is required. Download the latest version from scriptnovaa.com.`,
        426,
        "LAUNCHER_UPDATE_REQUIRED",
    );
  }
}
async function ensureDeviceSetupBonus(accountId, account) {
  if (!account.registeredDeviceId || account.deviceSetupBonusAwardedAt ||
      account.fraudStatus !== "CLEAR") {
    return account;
  }
  const registeredDevice = await read(`devices/${account.registeredDeviceId}`);
  if (!registeredDevice || registeredDevice.status !== "ACTIVE" ||
      registeredDevice.accountId !== accountId) {
    return account;
  }
  const updated = await atomic((data) => {
    const fresh = data.accounts?.[accountId];
    if (!fresh || !fresh.registeredDeviceId || fresh.deviceSetupBonusAwardedAt ||
        fresh.fraudStatus !== "CLEAR") {
      return data;
    }
    const now = Date.now();
    const referredBonusAlreadyPaid = Boolean(fresh.referredByAccountId) &&
      Number(fresh.pendingPointBalance || 0) < DEVICE_SETUP_BONUS;
    fresh.deviceSetupBonusAwardedAt = now;
    fresh.deviceSetupNoticePending = true;
    fresh.updatedAt = now;
    if (!referredBonusAlreadyPaid) {
      fresh.pointBalance = Number(fresh.pointBalance || 0) + DEVICE_SETUP_BONUS;
      if (fresh.referredByAccountId) {
        fresh.pendingPointBalance = Math.max(
            0,
            Number(fresh.pendingPointBalance || 0) - DEVICE_SETUP_BONUS,
        );
      }
      const transactionId = id("pointTransactions");
      ensure(data, "pointTransactions")[transactionId] = {
        accountId,
        amount: DEVICE_SETUP_BONUS,
        type: "DEVICE_SETUP_BONUS",
        sourceId: fresh.registeredDeviceId,
        createdAt: now,
      };
    } else {
      fresh.deviceSetupBonusMigratedAt = now;
    }
    return data;
  });
  return updated.accounts?.[accountId] || account;
}
async function registerDeviceForAccount(accountId, proof) {
  const rawProof = String(proof || "");
  if (rawProof.length < 20) fail("Computer identity is missing.");
  const account = await read(`accounts/${accountId}`);
  if (!account || account.accountStatus !== "ACTIVE") {
    fail("Account restricted.", 403);
  }
  const deviceHash = hmac(rawProof);
  const allDevices = await read("devices") || {};
  const usedByAnother = Object.values(allDevices)
      .some((device) =>
        device.deviceHash === deviceHash && device.accountId !== accountId);
  if (account.registeredDeviceId) {
    const existing = allDevices[account.registeredDeviceId];
    if (existing?.deviceHash === deviceHash) {
      return {
        alreadyRegistered: true,
        deviceId: account.registeredDeviceId,
        riskStatus: existing.status === "ACTIVE" ? "PASSED" : "REVIEW",
      };
    }
    fail("This account already has a different registered computer.");
  }

  const deviceId = id("devices");
  const registeredDeviceReference =
    root.child(`accounts/${accountId}/registeredDeviceId`);
  const claim = await registeredDeviceReference.transaction((current) => {
    if (current) return;
    return deviceId;
  }, undefined, false);
  if (!claim.committed) {
    const currentDeviceId = claim.snapshot.val();
    const currentDevice = currentDeviceId ?
      await read(`devices/${currentDeviceId}`) : null;
    if (currentDevice?.deviceHash === deviceHash) {
      return {
        alreadyRegistered: true,
        deviceId: currentDeviceId,
        riskStatus: currentDevice.status === "ACTIVE" ? "PASSED" : "REVIEW",
      };
    }
    fail("This account already has a different registered computer.", 409);
  }

  const now = Date.now();
  const updates = {
    [`devices/${deviceId}`]: {
      accountId,
      deviceHash,
      status: usedByAnother ? "REVIEW" : "ACTIVE",
      riskScore: usedByAnother ? 100 : 0,
      registeredAt: now,
    },
    [`accounts/${accountId}/fraudStatus`]: usedByAnother ? "REVIEW" : "CLEAR",
    [`accounts/${accountId}/updatedAt`]: now,
  };
  if (!usedByAnother && account.referredByAccountId) {
    updates[`accounts/${accountId}/pointBalance`] =
      ServerValue.increment(DEVICE_SETUP_BONUS);
    updates[`accounts/${accountId}/pendingPointBalance`] =
      Math.max(0, Number(account.pendingPointBalance || 0) - DEVICE_SETUP_BONUS);
    const referralId = await read(`referralsByReferred/${accountId}`);
    const referral = referralId ? await read(`referrals/${referralId}`) : null;
    if (referral?.status === "WAITING_FOR_DEVICE") {
      updates[`referrals/${referralId}/status`] = "DEVICE_PASSED";
      updates[`referrals/${referralId}/signupRewardAwarded`] = 3;
      updates[`referrals/${referralId}/devicePassedAt`] = now;
      updates[`accounts/${referral.referrerAccountId}/pointBalance`] =
        ServerValue.increment(3);
    }
  } else if (!usedByAnother) {
    updates[`accounts/${accountId}/pointBalance`] =
      ServerValue.increment(DEVICE_SETUP_BONUS);
  }
  if (!usedByAnother) {
    updates[`accounts/${accountId}/deviceSetupBonusAwardedAt`] = now;
    updates[`accounts/${accountId}/deviceSetupNoticePending`] = true;
    updates[`pointTransactions/${id("pointTransactions")}`] = {
      accountId,
      amount: DEVICE_SETUP_BONUS,
      type: "DEVICE_SETUP_BONUS",
      sourceId: deviceId,
      createdAt: now,
    };
  }
  try {
    await root.update(updates);
  } catch (error) {
    await registeredDeviceReference.transaction((current) =>
      current === deviceId ? null : current);
    throw error;
  }
  return {
    alreadyRegistered: false,
    deviceId,
    riskStatus: usedByAnother ? "REVIEW" : "PASSED",
  };
}

async function rewardWaitPolicy(accountId, account) {
  const referrals = await read("referrals");
  const referralHistory = Object.values(referrals || {}).filter((referral) =>
    referral.referrerAccountId === accountId ||
    referral.referredAccountId === accountId);
  const wasFraudReversed = referralHistory.some((referral) =>
    referral.status === "FRAUD_REVERSED");
  const wasFlagged =
    !["CLEAR", undefined, null].includes(account.fraudStatus) ||
    wasFraudReversed;
  const accountAge = Date.now() - Number(account.createdAt || Date.now());
  const plan = redirectWaitPlan(
      accountAge / 86400000,
      crypto.randomInt(0, 100),
      wasFlagged,
  );
  if (plan.zeroWait) return {...plan, minutes: 0};
  if (wasFlagged) return {...plan, minutes: crypto.randomInt(12, 15)};
  return {...plan, minutes: crypto.randomInt(1, plan.maximumMinutes + 1)};
}
async function atomic(mutator) {
  // Warm the Admin SDK cache before a root transaction. On a cold Vercel
  // instance the first transaction callback can otherwise receive null and
  // incorrectly report that an existing account is missing.
  if (!rootCacheWarmed) {
    await root.get();
    rootCacheWarmed = true;
  }
  let thrown = null;
  const result = await root.transaction((current) => {
    try { return mutator(current || {}); } catch (error) { thrown = error; return; }
  }, undefined, false);
  if (thrown) throw thrown;
  if (!result.committed) fail("The request conflicted with another update. Try again.", 409);
  return result.snapshot.val();
}
async function rateLimit(key, action, maximum, windowSeconds) {
  const keyHash = crypto.createHash("sha256").update(`${action}:${key}`).digest("hex");
  const now = Date.now();
  await root.child(`rateLimits/${keyHash}`).transaction((value) => {
    if (!value || now - Number(value.windowStartedAt || 0) >= windowSeconds * 1000) {
      return {action, count: 1, windowStartedAt: now, updatedAt: now};
    }
    if (Number(value.count || 0) >= maximum) return;
    return {...value, count: Number(value.count || 0) + 1, updatedAt: now};
  }).then((result) => {
    if (!result.committed) {
      const minutes = Math.max(1, Math.ceil(windowSeconds / 60));
      fail(`Too many attempts. Try again in up to ${minutes} minutes.`, 429,
          "RATE_LIMITED");
    }
  });
  return root.child(`rateLimits/${keyHash}`);
}
async function newLogin(accountId, clientDescription) {
  const raw = crypto.randomBytes(32).toString("base64url");
  await root.child(`loginSessions/${hmac(raw)}`).set({
    accountId, clientDescription: String(clientDescription || "").slice(0, 250),
    revoked: false, createdAt: Date.now(), lastUsedAt: Date.now(),
  });
  return raw;
}
async function requireAccount(req) {
  const raw = bearer(req); if (!raw) fail("Authentication required.", 401);
  const loginId = hmac(raw);
  const login = await read(`loginSessions/${loginId}`);
  if (!login || login.revoked) fail("Authentication required.", 401);
  const account = await read(`accounts/${login.accountId}`);
  if (!account || account.accountStatus !== "ACTIVE") fail("Account restricted.", 403);
  root.child(`loginSessions/${loginId}/lastUsedAt`).set(Date.now()).catch(console.error);
  return {id: login.accountId, data: account, loginId};
}
async function requireBrowserSession(req) {
  const sessionId = String(req.body.sessionId || "");
  const raw = String(req.body.sessionSecret || "");
  const session = await read(`sessions/${sessionId}`);
  if (!session || session.sessionSecretHash !== hmac(raw)) {
    fail("Browser session authentication failed.", 401);
  }
  return {id: sessionId, data: session};
}
async function finishSession(sessionId, session, reason) {
  const clean = String(reason || "UNKNOWN").replace(/[^A-Z0-9_-]/gi, "").slice(0, 50);
  const finishId = crypto.randomBytes(12).toString("hex");
  const lockedAt = Date.now();
  const lockReference = root.child(`sessionFinishLocks/${sessionId}`);
  const lock = await lockReference.transaction((current) => {
    if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
    return {finishId, lockedAt};
  }, undefined, false);
  if (!lock.committed) return;
  try {
    const current = await read(`sessions/${sessionId}`);
    if (!current || current.status !== "ACTIVE") return;
    const [token, account] = await Promise.all([
      read(`tokens/${current.tokenId}`),
      read(`accounts/${current.accountId}`),
    ]);
    const endedAt = Date.now();
    const launchFailedQuickly = clean === "LAUNCH_FAILED" &&
      endedAt - Number(current.startedAt || 0) <= 60000 &&
      !current.launchConfirmedAt &&
      token?.status === "ACTIVE" && token.sessionId === sessionId &&
      Boolean(account);
    const updates = {
      [`sessions/${sessionId}/status`]: "FINISHED",
      [`sessions/${sessionId}/endReason`]: clean,
      [`sessions/${sessionId}/endedAt`]: endedAt,
    };
    if (account?.activeSessionId === sessionId) {
      updates[`accounts/${current.accountId}/activeSessionId`] = null;
      updates[`accounts/${current.accountId}/updatedAt`] = endedAt;
    }
    if (launchFailedQuickly) {
      updates[`sessions/${sessionId}/tokenRestored`] = true;
      updates[`tokens/${current.tokenId}/status`] = "UNUSED";
      updates[`tokens/${current.tokenId}/sessionId`] = null;
      updates[`tokens/${current.tokenId}/deviceId`] = null;
      updates[`tokens/${current.tokenId}/activatedAt`] = null;
      updates[`tokens/${current.tokenId}/expiresAt`] = null;
      updates[`tokens/${current.tokenId}/endReason`] = null;
      updates[`tokens/${current.tokenId}/endedAt`] = null;
      updates[`accounts/${current.accountId}/unusedTokenCount`] =
        ServerValue.increment(1);
    } else if (token) {
      updates[`tokens/${current.tokenId}/status`] =
        clean === "TIME_EXPIRED" ? "EXPIRED" : "COMPLETED";
      updates[`tokens/${current.tokenId}/endReason`] = clean;
      updates[`tokens/${current.tokenId}/endedAt`] = endedAt;
      updates[`tokens/${current.tokenId}/displayToken`] = null;
    }
    await root.update(updates);
  } finally {
    const activeLock = await read(`sessionFinishLocks/${sessionId}`);
    if (activeLock?.finishId === finishId) await lockReference.remove();
  }
}

app.get("/api/health", (req, res) => res.json({
  ok: true, product: "Share Browser API", database: "Firebase Realtime Database",
  launcherVersion: CURRENT_LAUNCHER_VERSION,
}));
app.get("/", (req, res) => res.json({
  ok: true,
  product: "Share Browser API",
  health: "https://api.scriptnovaa.com/api/health",
}));
app.get(["/favicon.ico", "/favicon.png"], (req, res) => res.status(204).end());
app.get("/api/public-config", (req, res) => res.json({
  ok: true, tokenOptions: availableTokenOptions(),
  economy: {...ECONOMY, maximumRedirectPoints: 22},
  redirectWaitChances: REDIRECT_WAIT_CHANCES,
  launcher: {
    currentVersion: CURRENT_LAUNCHER_VERSION,
    downloadUrl: LAUNCHER_DOWNLOAD_URL,
  },
  limitedOffer: {
    active: Date.now() < LIMITED_FREE_TOKEN.endsAt,
    id: LIMITED_FREE_TOKEN.id,
    endsAt: new Date(LIMITED_FREE_TOKEN.endsAt).toISOString(),
    onePerAccount: true,
  },
  browsers: [{id: "chrome", name: "Google Chrome"}, {id: "edge", name: "Microsoft Edge"}],
  onlineDemo: {
    minutes: ONLINE_DEMO_MINUTES,
    cooldownHours: ONLINE_DEMO_COOLDOWN_HOURS,
    schoolFriendlyIpCapacity: ONLINE_DEMO_IP_DAILY_LIMIT,
  },
}));

app.post("/api/demo/start", route(async (req, res) => {
  const browserId = String(req.body.browserId || "").trim();
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(browserId)) {
    fail("The online demo could not identify this browser. Refresh and try again.");
  }
  const network = ipPrefix(req);
  await rateLimit(network, "ONLINE_DEMO_START", 60, 3600);
  const now = Date.now();
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const browserKey = hmac(`online-demo-browser:${browserId}`);
  const ipKey = hmac(`online-demo-ip:${network}`);
  const existingBrowserTrial = await read(`onlineDemoBrowsers/${browserKey}`);
  if (existingBrowserTrial && Number(existingBrowserTrial.cooldownUntil || 0) > now) {
    fail("This browser has already used its online demo. Try again after the 24-hour reset.",
        429, "DEMO_COOLDOWN");
  }
  const ipUsage = Object.values(await read(`onlineDemoIpUsage/${ipKey}`) || {})
      .filter((usage) => Number(usage.startedAt || 0) >= dayAgo);
  if (ipUsage.length >= ONLINE_DEMO_IP_DAILY_LIMIT) {
    fail("This network has reached today's online-demo capacity. Try again later.",
        429, "DEMO_NETWORK_CAPACITY");
  }

  const trialId = id("onlineDemoTrials");
  const trialSecret = crypto.randomBytes(24).toString("base64url");
  const expiresAt = now + ONLINE_DEMO_MINUTES * 60 * 1000;
  const cooldownUntil = now + ONLINE_DEMO_COOLDOWN_HOURS * 60 * 60 * 1000;
  await root.update({
    [`onlineDemoTrials/${trialId}`]: {
      browserKey,
      ipKey,
      secretHash: hmac(trialSecret),
      status: "ACTIVE",
      startedAt: now,
      expiresAt,
    },
    [`onlineDemoBrowsers/${browserKey}`]: {
      trialId,
      startedAt: now,
      expiresAt,
      cooldownUntil,
    },
    [`onlineDemoIpUsage/${ipKey}/${trialId}`]: {startedAt: now, expiresAt},
  });
  res.status(201).json({
    ok: true,
    trialId,
    trialSecret,
    expiresAt: new Date(expiresAt).toISOString(),
    minutes: ONLINE_DEMO_MINUTES,
  });
}));

app.post("/api/demo/status", route(async (req, res) => {
  const trialId = String(req.body.trialId || "");
  const trialSecret = String(req.body.trialSecret || "");
  const trial = await read(`onlineDemoTrials/${trialId}`);
  if (!trial || !trialSecret || trial.secretHash !== hmac(trialSecret)) {
    fail("Online demo session not found.", 401);
  }
  const active = trial.status === "ACTIVE" && Number(trial.expiresAt || 0) > Date.now();
  if (!active && trial.status === "ACTIVE") {
    await root.child(`onlineDemoTrials/${trialId}`).update({
      status: "EXPIRED",
      endedAt: Date.now(),
    });
  }
  res.json({
    ok: true,
    active,
    status: active ? "ACTIVE" : "EXPIRED",
    expiresAt: new Date(Number(trial.expiresAt || 0)).toISOString(),
  });
}));

app.post("/api/signup", route(async (req, res) => {
  await rateLimit(ipPrefix(req), "SIGNUP", 6, 3600);
  const username = validateUsername(req.body.username);
  const pin = validatePin(req.body.pin);
  const referralUsername = normalizeUsername(req.body.referralUsername);
  const accountId = id("accounts"); const recoveryCode = code("RCVY", 12);
  await atomic((data) => {
    const usernames = ensure(data, "usernames");
    const accounts = ensure(data, "accounts");
    if (usernames[username]) fail("That username is already taken.");
    const referrerAccountId = referralUsername && referralUsername !== username ?
      usernames[referralUsername]?.accountId || null : null;
    usernames[username] = {accountId, createdAt: Date.now()};
    accounts[accountId] = {
      username, pinCredential: credential(pin, "PIN_PEPPER"),
      recoveryCredential: credential(recoveryCode, "RECOVERY_PEPPER"),
      pointBalance: 0, pendingPointBalance: referrerAccountId ? 2 : 0,
      registeredDeviceId: null, activeSessionId: null, unusedTokenCount: 0,
      accountStatus: "ACTIVE", fraudStatus: "CLEAR", referredByAccountId: referrerAccountId,
      createdAt: Date.now(), updatedAt: Date.now(),
    };
    if (referrerAccountId) {
      const referralId = id("referrals");
      ensure(data, "referrals")[referralId] = {
        referrerAccountId, referredAccountId: accountId, status: "WAITING_FOR_DEVICE",
        pendingReward: 3, createdAt: Date.now(),
      };
      ensure(data, "referralsByReferred")[accountId] = referralId;
    }
    return data;
  });
  res.status(201).json({ok: true,
    loginToken: await newLogin(accountId, req.body.clientDescription), recoveryCode,
    warning: "Save this recovery code now. It will not be shown again."});
}));

app.post("/api/login", route(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const loginLimit = await rateLimit(`${ipPrefix(req)}:${username}`, "LOGIN", 12, 900);
  const usernameRecord = await read(`usernames/${username}`);
  const account = usernameRecord ? await read(`accounts/${usernameRecord.accountId}`) : null;
  if (!account || !verifies(req.body.pin, account.pinCredential, "PIN_PEPPER")) {
    fail("Incorrect username or PIN.", 401);
  }
  if (account.accountStatus !== "ACTIVE") fail("This account is restricted.", 403);
  await loginLimit.remove();
  res.json({ok: true,
    loginToken: await newLogin(usernameRecord.accountId, req.body.clientDescription),
    account: publicAccount(account)});
}));

app.post("/api/recover", route(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  await rateLimit(`${ipPrefix(req)}:${username}`, "RECOVER", 6, 3600);
  const usernameRecord = await read(`usernames/${username}`);
  const account = usernameRecord ? await read(`accounts/${usernameRecord.accountId}`) : null;
  if (!account || !verifies(req.body.recoveryCode, account.recoveryCredential, "RECOVERY_PEPPER")) {
    fail("Recovery failed.", 401);
  }
  const pin = validatePin(req.body.newPin); const replacement = code("RCVY", 12);
  await atomic((data) => {
    const fresh = data.accounts?.[usernameRecord.accountId];
    if (!fresh) fail("Recovery failed.", 401);
    fresh.pinCredential = credential(pin, "PIN_PEPPER");
    fresh.recoveryCredential = credential(replacement, "RECOVERY_PEPPER");
    fresh.updatedAt = Date.now();
    Object.values(data.loginSessions || {}).forEach((session) => {
      if (session.accountId === usernameRecord.accountId) session.revoked = true;
    });
    return data;
  });
  res.json({ok: true, newRecoveryCode: replacement});
}));

app.get("/api/account", route(async (req, res) => {
  const account = await requireAccount(req);
  const currentAccount = await ensureDeviceSetupBonus(account.id, account.data);
  const pendingReferrals = await pendingReferralPoints(account.id);
  const summary = publicAccount(currentAccount);
  summary.pendingPointBalance += pendingReferrals;
  res.json({ok: true, account: summary});
}));

app.post("/api/account/device-welcome/acknowledge", route(async (req, res) => {
  const account = await requireAccount(req);
  await root.child(`accounts/${account.id}`).update({
    deviceSetupNoticePending: false,
    deviceSetupNoticeAcknowledgedAt: Date.now(),
  });
  res.json({ok: true});
}));

app.post("/api/logout", route(async (req, res) => {
  const account = await requireAccount(req);
  await root.child(`loginSessions/${account.loginId}`).update({
    revoked: true,
    revokedAt: Date.now(),
  });
  res.json({ok: true});
}));

app.post("/api/device/register", route(async (req, res) => {
  const account = await requireAccount(req);
  const result = await registerDeviceForAccount(
      account.id, req.body.deviceProof);
  res.json({ok: true, ...result});
}));

app.post("/api/device/pairing/start", route(async (req, res) => {
  const account = await requireAccount(req);
  const context = await pairingContext(account.id, account.data);
  if (context.activePairing?.pairingCode &&
      context.activePairing.status === "OPEN" &&
      Number(context.activePairing.expiresAt || 0) > Date.now()) {
    res.json({
      ok: true,
      pairingCode: context.activePairing.pairingCode,
      expiresAt: new Date(context.activePairing.expiresAt).toISOString(),
      restored: true,
    });
    return;
  }
  if (context.hasIssued && !context.approvedEntry && !context.migrationAvailable) {
    fail("Your connection code cannot be replaced automatically. Submit a connection-code request on the Support page.", 403);
  }

  const pairingCode = crypto.randomBytes(5).toString("hex").toUpperCase();
  const pairingHash = hmac(pairingCode);
  const expiresAt = Date.now() + 10 * 60000;
  const createdAt = Date.now();
  const updates = {
    [`devicePairings/${pairingHash}`]: {
      accountId: account.id,
      pairingCode,
      status: "OPEN",
      createdAt,
      expiresAt,
    },
    [`activeDevicePairings/${account.id}`]: pairingHash,
    [`accounts/${account.id}/pairingCodeIssuedAt`]: createdAt,
    [`accounts/${account.id}/updatedAt`]: createdAt,
  };
  if (context.migrationAvailable) {
    updates[`accounts/${account.id}/persistentMigrationCodeIssuedAt`] = createdAt;
  }
  if (context.activeHash && context.activeHash !== pairingHash) {
    updates[`devicePairings/${context.activeHash}/status`] = "REPLACED";
    updates[`devicePairings/${context.activeHash}/replacedAt`] = createdAt;
  }
  if (context.approvedEntry) {
    const [ticketId] = context.approvedEntry;
    updates[`supportTickets/${ticketId}/status`] = "FULFILLED";
    updates[`supportTickets/${ticketId}/replacementConsumedAt`] = createdAt;
    updates[`supportTickets/${ticketId}/updatedAt`] = createdAt;
    updates[`supportTickets/${ticketId}/generatedPairingHash`] = pairingHash;
  }
  await root.update(updates);
  res.json({ok: true, pairingCode, expiresAt: new Date(expiresAt).toISOString()});
}));

app.get("/api/device/pairing/current", route(async (req, res) => {
  const account = await requireAccount(req);
  const context = await pairingContext(account.id, account.data);
  const pairingHash = context.activeHash;
  const pairing = context.activePairing;
  if (!pairing || !pairing.pairingCode || pairing.status !== "OPEN" ||
      Number(pairing.expiresAt || 0) <= Date.now()) {
    if (pairingHash) {
      await root.update({
        [`activeDevicePairings/${account.id}`]: null,
        [`devicePairings/${pairingHash}/status`]:
          pairing?.status === "OPEN" ? "EXPIRED" : pairing?.status || "EXPIRED",
      });
    }
    res.json({
      ok: true,
      pairing: null,
      registeredComputer: Boolean(account.data.registeredDeviceId),
      canGenerate: !context.hasIssued || context.migrationAvailable ||
        Boolean(context.approvedEntry),
      migrationAvailable: context.migrationAvailable,
      requiresSupportApproval: context.hasIssued &&
        !context.migrationAvailable && !context.approvedEntry,
      replacementRequest: context.replacementEntry ?
        publicSupportTicket(...context.replacementEntry) : null,
    });
    return;
  }
  res.json({
    ok: true,
    pairing: {
      pairingCode: pairing.pairingCode,
      expiresAt: new Date(pairing.expiresAt).toISOString(),
    },
    registeredComputer: Boolean(account.data.registeredDeviceId),
    canGenerate: false,
    migrationAvailable: false,
    requiresSupportApproval: false,
    replacementRequest: context.replacementEntry ?
      publicSupportTicket(...context.replacementEntry) : null,
  });
}));

app.post("/api/device/pairing/complete", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  const pairingCode = String(req.body.pairingCode || "")
      .replace(/[^A-F0-9]/gi, "").toUpperCase();
  if (pairingCode.length !== 10) fail("Connection code is invalid.");
  await rateLimit(ipPrefix(req), "DEVICE_PAIRING", 30, 900);
  const pairingHash = hmac(pairingCode);
  const pairing = await read(`devicePairings/${pairingHash}`);
  if (!pairing || pairing.status !== "OPEN" ||
      Number(pairing.expiresAt || 0) <= Date.now()) {
    fail("Connection code is invalid or expired.");
  }
  const result = await registerDeviceForAccount(
      pairing.accountId, req.body.deviceProof);
  await root.update({
    [`devicePairings/${pairingHash}/status`]: "USED",
    [`devicePairings/${pairingHash}/usedAt`]: Date.now(),
    [`activeDevicePairings/${pairing.accountId}`]: null,
    [`accounts/${pairing.accountId}/persistentLauncherPairedAt`]: Date.now(),
  });
  const launcherToken = await newLogin(
      pairing.accountId, "Share Browser launcher");
  res.json({ok: true, ...result, launcherToken});
}));

app.post("/api/device/launcher/status", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  const account = await requireAccount(req);
  const deviceId = account.data.registeredDeviceId;
  const device = deviceId ? await read(`devices/${deviceId}`) : null;
  if (!device || device.status !== "ACTIVE" ||
      device.deviceHash !== hmac(req.body.deviceProof)) {
    fail("Saved computer connection is no longer valid.", 403);
  }
  res.json({
    ok: true,
    connected: true,
    username: account.data.username,
    deviceId,
  });
}));

app.post("/api/launcher/config", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  await requireAccount(req);
  res.json({
    ok: true,
    configuration: LAUNCHER_CONFIGURATION,
  });
}));

app.post("/api/launcher/diagnostic", route(async (req, res) => {
  const account = await requireAccount(req);
  const event = String(req.body.event || "UNKNOWN")
      .replace(/[^A-Z0-9_-]/gi, "").slice(0, 50).toUpperCase();
  const detail = String(req.body.detail || "").slice(0, 500);
  const browser = String(req.body.browser || "").replace(/[^a-z]/gi, "").slice(0, 20);
  const launcherVersion = String(
      req.body.launcherVersion || req.headers["x-launcher-version"] || "unknown",
  ).slice(0, 30);
  const processCountValue = Number(req.body.processCount);
  const processCount = Number.isFinite(processCountValue) ? processCountValue : null;
  const diagnosticId = id("launcherDiagnostics");
  const diagnostic = {
    accountId: account.id,
    username: account.data.username,
    event,
    detail,
    browser,
    launcherVersion,
    processCount,
    createdAt: Date.now(),
  };
  await root.child(`launcherDiagnostics/${diagnosticId}`).set(diagnostic);
  console.warn("Launcher diagnostic", diagnostic);
  res.json({ok: true, diagnosticId});
}));

app.get("/api/support/tickets", route(async (req, res) => {
  const account = await requireAccount(req);
  const tickets = await accountSupportTickets(account.id);
  res.json({
    ok: true,
    tickets: tickets.slice(0, 50)
        .map(([ticketId, ticket]) => publicSupportTicket(ticketId, ticket)),
  });
}));

app.post("/api/support/tickets", route(async (req, res) => {
  const account = await requireAccount(req);
  await rateLimit(account.id, "SUPPORT_TICKET", 12, 24 * 60 * 60);
  const category = String(req.body.category || "").trim().toUpperCase();
  const subject = String(req.body.subject || "").trim().replace(/\s+/g, " ");
  const ticketMessage = String(req.body.message || "").trim();
  if (!SUPPORT_CATEGORIES.has(category)) fail("Choose a valid support category.");
  if (subject.length < 5 || subject.length > 80) {
    fail("Subject must contain between 5 and 80 characters.");
  }
  if (ticketMessage.length < 20 || ticketMessage.length > 2000) {
    fail("Explanation must contain between 20 and 2,000 characters.");
  }

  const existing = await accountSupportTickets(account.id);
  if (category === "CONNECTION_CODE_REPLACEMENT") {
    const activeRequest = existing.find(([, ticket]) =>
      ticket.category === category &&
      ["PENDING", "APPROVED"].includes(ticket.status) &&
      !ticket.replacementConsumedAt);
    if (activeRequest) {
      fail("You already have an active connection-code request.", 409);
    }
  }

  const ticketId = id("supportTickets");
  const createdAt = Date.now();
  const ticket = {
    accountId: account.id,
    username: account.data.username,
    category,
    subject,
    message: ticketMessage,
    status: "PENDING",
    createdAt,
    updatedAt: createdAt,
    submittedIpPrefix: ipPrefix(req),
  };
  await root.child(`supportTickets/${ticketId}`).set(ticket);
  res.status(201).json({
    ok: true,
    ticket: publicSupportTicket(ticketId, ticket),
  });
}));

app.get("/api/tokens", route(async (req, res) => {
  const account = await requireAccount(req);
  const tokens = Object.entries(await read("tokens") || {})
      .filter(([, token]) => token.ownerAccountId === account.id)
      .map(([tokenId, token]) => ({id: tokenId, ...token, tokenHash: undefined}))
      .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0)).slice(0, 50);
  res.json({ok: true, tokens});
}));

app.post("/api/tokens/create", route(async (req, res) => {
  const account = await requireAccount(req);
  const option = requestedTokenOption(req.body);
  if (!option) fail("Invalid token duration.");
  const rawToken = code("SHARE"); const tokenHash = hmac(rawToken); const tokenId = id("tokens");
  const lockId = crypto.randomBytes(12).toString("hex");
  const lockReference = root.child(`tokenCreationLocks/${account.id}`);
  const lockedAt = Date.now();
  const lock = await lockReference.transaction((current) => {
    if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
    return {lockId, lockedAt};
  }, undefined, false);
  if (!lock.committed) fail("A token is already being created. Try again.", 409);

  try {
    const fresh = await read(`accounts/${account.id}`);
    if (!fresh) fail("Authentication required. Sign in again.", 401);
    if (Number(fresh.pointBalance || 0) < option.points) {
      fail("Not enough points for this token.");
    }
    if (!fresh.registeredDeviceId) {
      fail("Register your computer first.");
    }
    if (fresh.fraudStatus !== "CLEAR") {
      fail("Your account is under review.", 403);
    }
    if (Number(fresh.unusedTokenCount || 0) >= ECONOMY.maximumUnusedTokens) {
      fail("Maximum two unused tokens.");
    }
    if (option.id === LIMITED_FREE_TOKEN.id && fresh.limitedFreeTokenClaimedAt) {
      fail("Your free limited token was already claimed.");
    }

    const createdAt = Date.now();
    const updates = {
      [`tokens/${tokenId}`]: {
        tokenHash,
        displayToken: rawToken,
        ownerAccountId: account.id,
        durationHours: option.hours || null,
        durationMinutes: option.minutes,
        durationLabel: option.minutes < 60 ? `${option.minutes} minutes` :
          `${option.hours} hour${option.hours === 1 ? "" : "s"}`,
        durationSeconds: option.minutes * 60,
        pointCost: option.points,
        limitedOfferId: option.limited ? option.id : null,
        status: "UNUSED",
        createdAt,
      },
      [`tokenHashes/${tokenHash}`]: tokenId,
      [`accounts/${account.id}/pointBalance`]: ServerValue.increment(-option.points),
      [`accounts/${account.id}/unusedTokenCount`]: ServerValue.increment(1),
      [`accounts/${account.id}/updatedAt`]: createdAt,
      [`pointTransactions/${id("pointTransactions")}`]: {
        accountId: account.id,
        amount: -option.points,
        type: option.limited ? "LIMITED_FREE_TOKEN" : "TOKEN_PURCHASE",
        sourceId: tokenId,
        createdAt,
      },
    };
    if (option.id === LIMITED_FREE_TOKEN.id) {
      updates[`accounts/${account.id}/limitedFreeTokenClaimedAt`] = createdAt;
    }
    await root.update({
      ...updates,
    });
    res.status(201).json({
      ok: true,
      token: rawToken,
      durationMinutes: option.minutes,
      durationLabel: option.minutes < 60 ? `${option.minutes} minutes` :
        `${option.hours} hour${option.hours === 1 ? "" : "s"}`,
      pointCost: option.points,
    });
  } finally {
    const activeLock = await read(`tokenCreationLocks/${account.id}`);
    if (activeLock?.lockId === lockId) await lockReference.remove();
  }
}));

app.post("/api/session/activate", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  const account = await requireAccount(req);
  const browser = String(req.body.browser || "");
  const presetId = String(req.body.presetId || "balanced");
  const userAgentId = String(req.body.userAgentId || "default");
  if (!["chrome", "edge"].includes(browser) || !PRESETS[presetId] ||
    !Object.prototype.hasOwnProperty.call(USER_AGENTS, userAgentId)) {
    fail("Unsupported browser setting.");
  }
  const tokenHash = hmac(req.body.token); const tokenId = await read(`tokenHashes/${tokenHash}`);
  if (!tokenId) fail("Token is invalid.");
  const sessionId = id("sessions"); const rawSecret = crypto.randomBytes(32).toString("base64url");
  const activationId = crypto.randomBytes(12).toString("hex");
  const lockedAt = Date.now();
  const lockReference = root.child(`sessionActivationLocks/${account.id}`);
  const lock = await lockReference.transaction((current) => {
    if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
    return {activationId, lockedAt};
  }, undefined, false);
  if (!lock.committed) fail("A browser session is already starting. Try again.", 409);
  let expiresAt = 0;
  try {
    const freshAccount = await read(`accounts/${account.id}`);
    if (!freshAccount || freshAccount.accountStatus !== "ACTIVE") {
      fail("Account not found or restricted.", 401);
    }
    const [token, device] = await Promise.all([
      read(`tokens/${tokenId}`),
      freshAccount.registeredDeviceId ?
        read(`devices/${freshAccount.registeredDeviceId}`) : Promise.resolve(null),
    ]);
    if (!token || token.status !== "UNUSED" || token.ownerAccountId !== account.id) {
      fail("Token cannot be used.");
    }
    if (!device || device.status !== "ACTIVE" ||
      device.deviceHash !== hmac(req.body.deviceProof)) {
      fail("Computer is not authorized. Reconnect this computer from the Tokens page.", 403);
    }

    const updates = {};
    if (freshAccount.activeSessionId) {
      const previousSessionId = freshAccount.activeSessionId;
      const previous = await read(`sessions/${previousSessionId}`);
      const stale = !previous || previous.status !== "ACTIVE" ||
        Number(previous.lastHeartbeatAt || 0) < Date.now() - 30000;
      if (!stale) fail("An active session already exists.");
      if (previous && previous.status === "ACTIVE") {
        const endedAt = Date.now();
        updates[`sessions/${previousSessionId}/status`] = "FINISHED";
        updates[`sessions/${previousSessionId}/endReason`] = "HEARTBEAT_TIMEOUT";
        updates[`sessions/${previousSessionId}/endedAt`] = endedAt;
        const previousToken = previous.tokenId ? await read(`tokens/${previous.tokenId}`) : null;
        if (previousToken) {
          updates[`tokens/${previous.tokenId}/status`] = "COMPLETED";
          updates[`tokens/${previous.tokenId}/endReason`] = "HEARTBEAT_TIMEOUT";
          updates[`tokens/${previous.tokenId}/endedAt`] = endedAt;
          updates[`tokens/${previous.tokenId}/displayToken`] = null;
        }
      }
    }

    const startedAt = Date.now();
    expiresAt = startedAt + Number(token.durationSeconds) * 1000;
    if (!Number.isFinite(expiresAt) || expiresAt <= startedAt) {
      fail("Token duration is invalid.");
    }
    Object.assign(updates, {
      [`tokens/${tokenId}/status`]: "ACTIVE",
      [`tokens/${tokenId}/sessionId`]: sessionId,
      [`tokens/${tokenId}/deviceId`]: freshAccount.registeredDeviceId,
      [`tokens/${tokenId}/activatedAt`]: startedAt,
      [`tokens/${tokenId}/expiresAt`]: expiresAt,
      [`accounts/${account.id}/activeSessionId`]: sessionId,
      [`accounts/${account.id}/unusedTokenCount`]: ServerValue.increment(-1),
      [`accounts/${account.id}/updatedAt`]: startedAt,
    });
    updates[`sessions/${sessionId}`] = {
      accountId: account.id, tokenId, deviceId: freshAccount.registeredDeviceId,
      browser, presetId, userAgentId, status: "ACTIVE", sessionSecretHash: hmac(rawSecret),
      startedAt, expiresAt, lastHeartbeatAt: startedAt,
    };

    const referralId = await read(`referralsByReferred/${account.id}`);
    const referral = referralId ? await read(`referrals/${referralId}`) : null;
    if (referral && referral.status === "DEVICE_PASSED" && referral.referrerAccountId) {
      updates[`referrals/${referralId}/status`] = "COMPLETED";
      updates[`referrals/${referralId}/firstSessionRewardAwarded`] = 4;
      updates[`referrals/${referralId}/reviewBonusAwarded`] = 1;
      updates[`referrals/${referralId}/totalRewardAwarded`] = 8;
      updates[`referrals/${referralId}/completedAt`] = startedAt;
      updates[`accounts/${referral.referrerAccountId}/pointBalance`] =
        ServerValue.increment(5);
      updates[`accounts/${referral.referrerAccountId}/updatedAt`] = startedAt;
      updates[`rewards/${id("rewards")}`] = {
        accountId: referral.referrerAccountId,
        referralId,
        amount: 5,
        type: "REFERRAL_FIRST_SESSION_AND_REVIEW",
        status: "AVAILABLE",
        createdAt: startedAt,
      };
    }
    await root.update(updates);
  } finally {
    const activeLock = await read(`sessionActivationLocks/${account.id}`);
    if (activeLock?.activationId === activationId) await lockReference.remove();
  }
  res.json({ok: true, sessionId, sessionSecret: rawSecret,
    expiresAt: new Date(expiresAt).toISOString(), heartbeatSeconds: 10,
    launch: {browser, startupOptions: browserLaunchFlags(browser, presetId),
      userAgent: USER_AGENTS[userAgentId]}});
}));

app.post("/api/session/heartbeat", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  const session = await requireBrowserSession(req);
  if (session.data.status !== "ACTIVE") {
    return res.status(409).json({ok: false, action: "CLOSE_BROWSER",
      reason: session.data.endReason || "SESSION_FINISHED"});
  }
  if (session.data.expiresAt <= Date.now()) {
    await finishSession(session.id, session.data, "TIME_EXPIRED");
    return res.status(409).json({ok: false, action: "CLOSE_BROWSER", reason: "TIME_EXPIRED"});
  }
  const [account, device] = await Promise.all([
    read(`accounts/${session.data.accountId}`), read(`devices/${session.data.deviceId}`),
  ]);
  if (!account || account.accountStatus !== "ACTIVE" || !device || device.status !== "ACTIVE") {
    await finishSession(session.id, session.data, "AUTHORIZATION_REVOKED");
    return res.status(409).json({ok: false, action: "CLOSE_BROWSER",
      reason: "AUTHORIZATION_REVOKED"});
  }
  await root.child(`sessions/${session.id}/lastHeartbeatAt`).set(Date.now());
  res.json({ok: true, action: "CONTINUE",
    expiresAt: new Date(session.data.expiresAt).toISOString()});
}));

app.post("/api/session/launched", route(async (req, res) => {
  requireCurrentLauncherVersion(req);
  const session = await requireBrowserSession(req);
  if (session.data.status !== "ACTIVE") {
    fail("Browser session is no longer active.", 409);
  }
  const confirmedAt = Date.now();
  await root.child(`sessions/${session.id}`).update({
    launchConfirmedAt: session.data.launchConfirmedAt || confirmedAt,
    lastHeartbeatAt: confirmedAt,
  });
  res.json({ok: true, confirmedAt});
}));

app.post("/api/session/end", route(async (req, res) => {
  const session = await requireBrowserSession(req);
  await finishSession(session.id, session.data, req.body.reason);
  res.json({ok: true});
}));

app.post("/api/redirect/start", route(async (req, res) => {
  const account = await requireAccount(req);
  const attempts = Object.values(await read("redirectAttempts") || {});
  const cutoff = Date.now() - 14 * 3600000;
  const count = attempts.filter((attempt) =>
    attempt.accountId === account.id &&
    attempt.createdAt >= cutoff &&
    attempt.status !== "AD_BLOCKED").length;
  if (count >= 44) fail("44-redirect limit reached for this rolling 14-hour window.");
  const attemptId = id("redirectAttempts");
  const claimCode = crypto.randomBytes(24).toString("base64url");
  const waitPolicy = await rewardWaitPolicy(account.id, account.data);
  const claimableAt = Date.now() + waitPolicy.minutes * 60000;
  const adBlockDetected = req.body.adBlockDetected === true;
  await root.child(`redirectAttempts/${attemptId}`).set({
    accountId: account.id, campaignId: String(req.body.campaignId || "default").slice(0, 80),
    claimHash: hmac(claimCode),
    status: adBlockDetected ? "AD_BLOCKED" : "OPENED",
    rewardAmount: adBlockDetected ? 0 : 0.5,
    rewardEligible: !adBlockDetected,
    adBlockDetected,
    ipPrefix: ipPrefix(req), createdAt: Date.now(), claimableAt,
    waitTier: waitPolicy.tier, waitMinutes: waitPolicy.minutes,
    zeroWaitChance: waitPolicy.zeroWaitChance,
  });
  res.status(201).json({ok: true, attemptId, claimCode,
    claimableAt: new Date(claimableAt).toISOString(),
    waitTier: waitPolicy.tier,
    zeroWaitChance: waitPolicy.zeroWaitChance,
    rewardEligible: !adBlockDetected,
    notice: adBlockDetected ?
      "Redirect didn't count because an ad blocker was detected." : null,
    redirectUrl: !process.env.REDIRECT_TARGET_URL ||
      process.env.REDIRECT_TARGET_URL === "https://example.com/" ?
      DEFAULT_REDIRECT_URL : process.env.REDIRECT_TARGET_URL});
}));

app.get("/api/redirect/status", route(async (req, res) => {
  const account = await requireAccount(req);
  const cutoff = Date.now() - 14 * 3600000;
  const recoveryUpdates = {};
  const attempts = Object.entries(await read("redirectAttempts") || {})
      .filter(([, attempt]) =>
        attempt.accountId === account.id && attempt.createdAt >= cutoff)
      .map(([attemptId, attempt]) => {
        const staleClaim = attempt.status === "CLAIMING" &&
          (!attempt.claimingAt || Number(attempt.claimingAt) < Date.now() - 60000);
        if (staleClaim) {
          attempt.status = "OPENED";
          recoveryUpdates[`redirectAttempts/${attemptId}/status`] = "OPENED";
          recoveryUpdates[`redirectAttempts/${attemptId}/claimingAt`] = null;
          recoveryUpdates[`redirectAttempts/${attemptId}/claimId`] = null;
        }
        return {
          attemptId,
          status: attempt.status,
          rewardAmount: Number(attempt.rewardAmount || 0),
          createdAt: Number(attempt.createdAt || 0),
          claimableAt: Number(attempt.claimableAt || 0),
          waitTier: attempt.waitTier || "NEW",
          zeroWaitChance: Number(attempt.zeroWaitChance || 0),
        };
      })
      .sort((a, b) => b.createdAt - a.createdAt);
  if (Object.keys(recoveryUpdates).length) await root.update(recoveryUpdates);
  const rewardedCount = attempts.filter((attempt) =>
    attempt.status === "REWARDED").length;
  const eligibleCount = attempts.filter((attempt) =>
    attempt.status !== "AD_BLOCKED").length;
  const blockedCount = attempts.filter((attempt) =>
    attempt.status === "AD_BLOCKED").length;
  res.json({
    ok: true,
    openedCount: eligibleCount,
    blockedCount,
    rewardedCount,
    earnedPoints: rewardedCount * ECONOMY.redirectReward,
    maximumCount: ECONOMY.redirectMaximumCount,
    rollingHours: ECONOMY.redirectRollingHours,
    attempts,
  });
}));

app.post("/api/redirect/claim", route(async (req, res) => {
  const account = await requireAccount(req);
  const attemptId = String(req.body.attemptId || "");
  if (!attemptId) fail("Reward attempt is missing.");
  const claimId = crypto.randomBytes(12).toString("hex");
  const lockReference = root.child(`rewardClaimLocks/${attemptId}`);
  const lockedAt = Date.now();
  const lock = await lockReference.transaction((current) => {
    if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
    return {claimId, lockedAt};
  }, undefined, false);
  if (!lock.committed) fail("Reward is being processed. Try again shortly.", 409);
  try {
    const attempt = await read(`redirectAttempts/${attemptId}`);
    if (!attempt || attempt.accountId !== account.id) {
      fail("This reward does not belong to the signed-in account.");
    }
    if (attempt.status === "AD_BLOCKED" || attempt.adBlockDetected === true) {
      fail("Redirect didn't count because an ad blocker was detected.", 409);
    }
    if (attempt.status === "CLAIMING" &&
        (!attempt.claimingAt || Number(attempt.claimingAt) < Date.now() - 60000)) {
      attempt.status = "OPENED";
    }
    if (attempt.status !== "OPENED") fail("Reward already claimed.");
    if (Number(attempt.claimableAt || 0) > Date.now()) {
      fail("Reward is still pending.");
    }

    const transactionId = id("pointTransactions");
    const rewardedAt = Date.now();
    await root.update({
      [`redirectAttempts/${attemptId}/status`]: "REWARDED",
      [`redirectAttempts/${attemptId}/rewardedAt`]: rewardedAt,
      [`redirectAttempts/${attemptId}/claimId`]: null,
      [`redirectAttempts/${attemptId}/claimingAt`]: null,
      [`rewardClaimLocks/${attemptId}`]: null,
      [`accounts/${account.id}/pointBalance`]: ServerValue.increment(0.5),
      [`accounts/${account.id}/updatedAt`]: rewardedAt,
      [`pointTransactions/${transactionId}`]: {
        accountId: account.id,
        amount: 0.5,
        type: "REDIRECT_REWARD",
        sourceId: attemptId,
        createdAt: rewardedAt,
      },
    });
    res.json({ok: true, awardedPoints: 0.5});
  } finally {
    const activeLock = await read(`rewardClaimLocks/${attemptId}`);
    if (activeLock?.claimId === claimId) await lockReference.remove();
  }
}));

app.post("/api/admin/referrals/reverse", route(async (req, res) => {
  const supplied = String(req.headers["x-admin-secret"] || "");
  const expected = envSecret("ADMIN_SECRET");
  if (!supplied || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    fail("Administrator authorization required.", 401);
  }
  const referralId = String(req.body.referralId || "");
  let result = {};
  await atomic((data) => {
    const referral = data.referrals?.[referralId];
    if (!referral) fail("Referral not found.", 404);
    if (referral.status === "FRAUD_REVERSED") fail("Referral was already reversed.");
    const awarded = Number(referral.totalRewardAwarded || referral.signupRewardAwarded || 0);
    let revoked = 0;
    Object.values(data.tokens || {}).forEach((token) => {
      if (token.ownerAccountId === referral.referrerAccountId && token.status === "UNUSED") {
        token.status = "FRAUD_REVERSED"; delete token.displayToken; token.endedAt = Date.now();
        revoked++;
      }
    });
    const referrer = data.accounts?.[referral.referrerAccountId];
    if (referrer) {
      referrer.pointBalance = Number(referrer.pointBalance || 0) - awarded - 2;
      referrer.fraudStatus = "RESTRICTED";
      referrer.unusedTokenCount = Math.max(0, Number(referrer.unusedTokenCount || 0) - revoked);
    }
    Object.assign(referral, {status: "FRAUD_REVERSED", reversedReward: awarded,
      fraudPenalty: 2, reversedAt: Date.now()});
    result = {awarded, revoked};
    return data;
  });
  res.json({ok: true, reversedPoints: result.awarded, penalty: 2,
    revokedUnusedTokens: result.revoked});
}));

app.use((req, res) => res.status(404).json({ok: false, error: "Endpoint not found."}));

if (require.main === module) {
  const port = Number(process.env.PORT || 8787);
  app.listen(port, () => console.log(`Share Browser API listening on port ${port}`));
}
module.exports = app;
