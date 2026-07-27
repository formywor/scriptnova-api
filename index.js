"use strict";

const crypto = require("crypto");
const express = require("express");
const {initializeApp, cert, getApps} = require("firebase-admin/app");
const {getDatabase, ServerValue} = require("firebase-admin/database");
const {TOKEN_OPTIONS, ECONOMY, normalizeUsername, validateUsername, validatePin} =
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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Secret");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") {
    return origin && ALLOWED_ORIGINS.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
  }
  next();
});

const PRESETS = {
  balanced: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications"],
  privacy: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications", "--disable-extensions",
    "--disable-features=AutofillServerCommunication"],
  minimal: ["--no-first-run", "--no-default-browser-check", "--disable-sync"],
};
const USER_AGENTS = {
  default: "",
  shareDesktop: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 " +
    "Safari/537.36 ShareBrowser/1.0",
};
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

function fail(message, statusCode = 400) {
  const error = new Error(message); error.statusCode = statusCode; throw error;
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
    fraudStatus: a.fraudStatus || "CLEAR", activeSessionId: a.activeSessionId || null};
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
      res.status(statusCode)
          .json({ok: false, error: error.message || "Request failed."});
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
    updates[`accounts/${accountId}/pointBalance`] = ServerValue.increment(2);
    updates[`accounts/${accountId}/pendingPointBalance`] =
      Math.max(0, Number(account.pendingPointBalance || 0) - 2);
    const referralId = await read(`referralsByReferred/${accountId}`);
    const referral = referralId ? await read(`referrals/${referralId}`) : null;
    if (referral?.status === "WAITING_FOR_DEVICE") {
      updates[`referrals/${referralId}/status`] = "DEVICE_PASSED";
      updates[`referrals/${referralId}/signupRewardAwarded`] = 3;
      updates[`referrals/${referralId}/devicePassedAt`] = now;
      updates[`accounts/${referral.referrerAccountId}/pointBalance`] =
        ServerValue.increment(3);
    }
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
  const [referrals, sessions] = await Promise.all([
    read("referrals"),
    read("sessions"),
  ]);
  const referralHistory = Object.values(referrals || {}).filter((referral) =>
    referral.referrerAccountId === accountId ||
    referral.referredAccountId === accountId);
  const wasFraudReversed = referralHistory.some((referral) =>
    referral.status === "FRAUD_REVERSED");
  const wasFlagged =
    !["CLEAR", undefined, null].includes(account.fraudStatus) ||
    wasFraudReversed;
  const hasRealSession = Object.values(sessions || {}).some((session) =>
    session.accountId === accountId &&
    ["ACTIVE", "FINISHED"].includes(session.status));
  const accountAge = Date.now() - Number(account.createdAt || Date.now());
  const isNew = accountAge < 7 * 86400000 || !hasRealSession;

  if (wasFlagged) {
    return {tier: "REVIEW", minutes: crypto.randomInt(12, 15)};
  }
  if (isNew) {
    return {tier: "NEW", minutes: crypto.randomInt(5, 15)};
  }
  return {tier: "ESTABLISHED", minutes: crypto.randomInt(0, 5)};
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
    if (!result.committed) fail("Too many attempts. Try again later.", 429);
  });
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
  await atomic((data) => {
    const current = data.sessions?.[sessionId];
    if (!current || current.status !== "ACTIVE") return data;
    current.status = "FINISHED"; current.endReason = clean; current.endedAt = Date.now();
    const token = data.tokens?.[session.tokenId];
    if (token) {
      token.status = clean === "TIME_EXPIRED" ? "EXPIRED" : "COMPLETED";
      token.endReason = clean; token.endedAt = Date.now(); delete token.displayToken;
    }
    const account = data.accounts?.[session.accountId];
    if (account) { account.activeSessionId = null; account.updatedAt = Date.now(); }
    return data;
  });
}

app.get("/api/health", (req, res) => res.json({
  ok: true, product: "Share Browser API", database: "Firebase Realtime Database",
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
  limitedOffer: {
    active: Date.now() < LIMITED_FREE_TOKEN.endsAt,
    id: LIMITED_FREE_TOKEN.id,
    endsAt: new Date(LIMITED_FREE_TOKEN.endsAt).toISOString(),
    onePerAccount: true,
  },
  browsers: [{id: "chrome", name: "Google Chrome"}, {id: "edge", name: "Microsoft Edge"}],
}));

app.post("/api/signup", route(async (req, res) => {
  await rateLimit(ipPrefix(req), "SIGNUP", 3, 3600);
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
  await rateLimit(`${ipPrefix(req)}:${username}`, "LOGIN", 5, 900);
  const usernameRecord = await read(`usernames/${username}`);
  const account = usernameRecord ? await read(`accounts/${usernameRecord.accountId}`) : null;
  if (!account || !verifies(req.body.pin, account.pinCredential, "PIN_PEPPER")) {
    fail("Incorrect username or PIN.", 401);
  }
  if (account.accountStatus !== "ACTIVE") fail("This account is restricted.", 403);
  res.json({ok: true,
    loginToken: await newLogin(usernameRecord.accountId, req.body.clientDescription),
    account: publicAccount(account)});
}));

app.post("/api/recover", route(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  await rateLimit(`${ipPrefix(req)}:${username}`, "RECOVER", 3, 3600);
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
  const pendingReferrals = await pendingReferralPoints(account.id);
  const summary = publicAccount(account.data);
  summary.pendingPointBalance += pendingReferrals;
  res.json({ok: true, account: summary});
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
  const pairingCode = crypto.randomBytes(5).toString("hex").toUpperCase();
  const pairingHash = hmac(pairingCode);
  const expiresAt = Date.now() + 10 * 60000;
  const previousHash = await read(`activeDevicePairings/${account.id}`);
  const updates = {
    [`devicePairings/${pairingHash}`]: {
      accountId: account.id,
      pairingCode,
      status: "OPEN",
      createdAt: Date.now(),
      expiresAt,
    },
    [`activeDevicePairings/${account.id}`]: pairingHash,
  };
  if (previousHash && previousHash !== pairingHash) {
    updates[`devicePairings/${previousHash}/status`] = "REPLACED";
    updates[`devicePairings/${previousHash}/replacedAt`] = Date.now();
  }
  await root.update(updates);
  res.json({ok: true, pairingCode, expiresAt: new Date(expiresAt).toISOString()});
}));

app.get("/api/device/pairing/current", route(async (req, res) => {
  const account = await requireAccount(req);
  const pairingHash = await read(`activeDevicePairings/${account.id}`);
  const pairing = pairingHash ? await read(`devicePairings/${pairingHash}`) : null;
  if (!pairing || !pairing.pairingCode || pairing.status !== "OPEN" ||
      Number(pairing.expiresAt || 0) <= Date.now()) {
    if (pairingHash) {
      await root.update({
        [`activeDevicePairings/${account.id}`]: null,
        [`devicePairings/${pairingHash}/status`]:
          pairing?.status === "OPEN" ? "EXPIRED" : pairing?.status || "EXPIRED",
      });
    }
    res.json({ok: true, pairing: null});
    return;
  }
  res.json({
    ok: true,
    pairing: {
      pairingCode: pairing.pairingCode,
      expiresAt: new Date(pairing.expiresAt).toISOString(),
    },
  });
}));

app.post("/api/device/pairing/complete", route(async (req, res) => {
  const pairingCode = String(req.body.pairingCode || "")
      .replace(/[^A-F0-9]/gi, "").toUpperCase();
  if (pairingCode.length !== 10) fail("Connection code is invalid.");
  await rateLimit(ipPrefix(req), "DEVICE_PAIRING", 10, 900);
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
  });
  const launcherToken = await newLogin(
      pairing.accountId, "Share Browser launcher");
  res.json({ok: true, ...result, launcherToken});
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
    launch: {browser, flags: PRESETS[presetId], userAgent: USER_AGENTS[userAgentId]}});
}));

app.post("/api/session/heartbeat", route(async (req, res) => {
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
    attempt.accountId === account.id && attempt.createdAt >= cutoff).length;
  if (count >= 44) fail("44-redirect limit reached for this rolling 14-hour window.");
  const attemptId = id("redirectAttempts");
  const claimCode = crypto.randomBytes(24).toString("base64url");
  const waitPolicy = await rewardWaitPolicy(account.id, account.data);
  const claimableAt = Date.now() + waitPolicy.minutes * 60000;
  await root.child(`redirectAttempts/${attemptId}`).set({
    accountId: account.id, campaignId: String(req.body.campaignId || "default").slice(0, 80),
    claimHash: hmac(claimCode), status: "OPENED", rewardAmount: 0.5,
    ipPrefix: ipPrefix(req), createdAt: Date.now(), claimableAt,
    waitTier: waitPolicy.tier, waitMinutes: waitPolicy.minutes,
  });
  res.status(201).json({ok: true, attemptId, claimCode,
    claimableAt: new Date(claimableAt).toISOString(),
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
        };
      })
      .sort((a, b) => b.createdAt - a.createdAt);
  if (Object.keys(recoveryUpdates).length) await root.update(recoveryUpdates);
  const rewardedCount = attempts.filter((attempt) =>
    attempt.status === "REWARDED").length;
  res.json({
    ok: true,
    openedCount: attempts.length,
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
