"use strict";

const crypto = require("crypto");
const express = require("express");
const {initializeApp, cert, getApps} = require("firebase-admin/app");
const {getDatabase} = require("firebase-admin/database");
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
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);
app.use(express.json({limit: "32kb"}));

const ALLOWED_ORIGINS = new Set([
  "https://scriptnovaa.com",
  "https://www.scriptnovaa.com",
  ...(process.env.EXTRA_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean),
]);
app.use((req, res, next) => {
  const origin = String(req.headers.origin || "");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
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
const DEFAULT_REDIRECT_URL = "https://omg10.com/4/11435374";

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
    fraudStatus: a.fraudStatus || "CLEAR", activeSessionId: a.activeSessionId || null};
}
function route(handler) {
  return async (req, res) => {
    try { await handler(req, res); } catch (error) {
      console.error(error); res.status(error.statusCode || 400)
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
async function atomic(mutator) {
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
app.get("/api/public-config", (req, res) => res.json({
  ok: true, tokenOptions: TOKEN_OPTIONS,
  economy: {...ECONOMY, maximumRedirectPoints: 22},
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
  const proof = String(req.body.deviceProof || ""); if (proof.length < 20) fail("Device proof missing.");
  const deviceHash = hmac(proof); const allDevices = await read("devices") || {};
  const usedByAnother = Object.values(allDevices)
      .some((device) => device.deviceHash === deviceHash && device.accountId !== account.id);
  if (account.data.registeredDeviceId) {
    const existing = allDevices[account.data.registeredDeviceId];
    if (existing?.deviceHash === deviceHash) {
      return res.json({ok: true, alreadyRegistered: true, deviceId: account.data.registeredDeviceId});
    }
    fail("This account already has a different registered computer.");
  }
  const deviceId = id("devices");
  await atomic((data) => {
    const fresh = data.accounts?.[account.id];
    if (!fresh) fail("Account not found.", 404);
    if (fresh.registeredDeviceId) fail("A computer is already registered.");
    ensure(data, "devices")[deviceId] = {
      accountId: account.id, deviceHash, status: usedByAnother ? "REVIEW" : "ACTIVE",
      riskScore: usedByAnother ? 100 : 0, registeredAt: Date.now(),
    };
    fresh.registeredDeviceId = deviceId;
    fresh.fraudStatus = usedByAnother ? "REVIEW" : "CLEAR";
    fresh.updatedAt = Date.now();
    if (!usedByAnother && fresh.referredByAccountId) {
      fresh.pointBalance = Number(fresh.pointBalance || 0) + 2;
      fresh.pendingPointBalance = Math.max(0, Number(fresh.pendingPointBalance || 0) - 2);
      const referralId = data.referralsByReferred?.[account.id];
      const referral = data.referrals?.[referralId];
      if (referral?.status === "WAITING_FOR_DEVICE") {
        referral.status = "DEVICE_PASSED"; referral.signupRewardAwarded = 3;
        referral.devicePassedAt = Date.now();
        const referrer = data.accounts?.[referral.referrerAccountId];
        if (referrer) referrer.pointBalance = Number(referrer.pointBalance || 0) + 3;
      }
    }
    return data;
  });
  res.json({ok: true, deviceId, riskStatus: usedByAnother ? "REVIEW" : "PASSED"});
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
  const option = TOKEN_OPTIONS.find((item) => item.hours === Number(req.body.hours));
  if (!option) fail("Invalid token duration.");
  const rawToken = code("SHARE"); const tokenHash = hmac(rawToken); const tokenId = id("tokens");
  await atomic((data) => {
    const fresh = data.accounts?.[account.id];
    if (!fresh?.registeredDeviceId) fail("Register your computer first.");
    if (fresh.fraudStatus !== "CLEAR") fail("Your account is under review.");
    if (Number(fresh.unusedTokenCount || 0) >= 2) fail("Maximum two unused tokens.");
    if (Number(fresh.pointBalance || 0) < option.points) fail("You do not have enough points.");
    ensure(data, "tokens")[tokenId] = {
      tokenHash, displayToken: rawToken, ownerAccountId: account.id,
      durationHours: option.hours, durationSeconds: option.hours * 3600,
      pointCost: option.points, status: "UNUSED", createdAt: Date.now(),
    };
    ensure(data, "tokenHashes")[tokenHash] = tokenId;
    fresh.pointBalance -= option.points; fresh.unusedTokenCount += 1; fresh.updatedAt = Date.now();
    return data;
  });
  res.status(201).json({ok: true, token: rawToken, hours: option.hours, pointCost: option.points});
}));

app.post("/api/session/activate", route(async (req, res) => {
  const account = await requireAccount(req);
  const browser = String(req.body.browser || ""); const presetId = String(req.body.presetId || "balanced");
  if (!["chrome", "edge"].includes(browser) || !PRESETS[presetId]) fail("Unsupported browser setting.");
  const tokenHash = hmac(req.body.token); const tokenId = await read(`tokenHashes/${tokenHash}`);
  if (!tokenId) fail("Token is invalid.");
  const sessionId = id("sessions"); const rawSecret = crypto.randomBytes(32).toString("base64url");
  let expiresAt = 0;
  await atomic((data) => {
    const freshAccount = data.accounts?.[account.id];
    const token = data.tokens?.[tokenId];
    const device = data.devices?.[freshAccount?.registeredDeviceId];
    if (!token || token.status !== "UNUSED" || token.ownerAccountId !== account.id) {
      fail("Token cannot be used.");
    }
    if (freshAccount.activeSessionId) {
      const previous = data.sessions?.[freshAccount.activeSessionId];
      const stale = !previous || previous.status !== "ACTIVE" ||
        Number(previous.lastHeartbeatAt || 0) < Date.now() - 30000;
      if (!stale) fail("An active session already exists.");
      if (previous?.status === "ACTIVE") {
        previous.status = "FINISHED"; previous.endReason = "HEARTBEAT_TIMEOUT";
        previous.endedAt = Date.now();
        const previousToken = data.tokens?.[previous.tokenId];
        if (previousToken) {
          previousToken.status = "COMPLETED"; previousToken.endReason = "HEARTBEAT_TIMEOUT";
          previousToken.endedAt = Date.now(); delete previousToken.displayToken;
        }
      }
      freshAccount.activeSessionId = null;
    }
    if (!device || device.status !== "ACTIVE" || device.deviceHash !== hmac(req.body.deviceProof)) {
      fail("Computer is not authorized.");
    }
    const startedAt = Date.now(); expiresAt = startedAt + token.durationSeconds * 1000;
    Object.assign(token, {status: "ACTIVE", sessionId, deviceId: freshAccount.registeredDeviceId,
      activatedAt: startedAt, expiresAt});
    freshAccount.activeSessionId = sessionId;
    freshAccount.unusedTokenCount = Math.max(0, freshAccount.unusedTokenCount - 1);
    freshAccount.updatedAt = startedAt;
    ensure(data, "sessions")[sessionId] = {
      accountId: account.id, tokenId, deviceId: freshAccount.registeredDeviceId,
      browser, presetId, status: "ACTIVE", sessionSecretHash: hmac(rawSecret),
      startedAt, expiresAt, lastHeartbeatAt: startedAt,
    };
    const referralId = data.referralsByReferred?.[account.id];
    const referral = data.referrals?.[referralId];
    if (referral?.status === "DEVICE_PASSED") {
      referral.status = "COMPLETED"; referral.firstSessionRewardAwarded = 4;
      referral.reviewBonusAwarded = 1; referral.totalRewardAwarded = 8;
      referral.completedAt = startedAt;
      const referrer = data.accounts?.[referral.referrerAccountId];
      if (referrer) referrer.pointBalance = Number(referrer.pointBalance || 0) + 5;
    }
    return data;
  });
  res.json({ok: true, sessionId, sessionSecret: rawSecret,
    expiresAt: new Date(expiresAt).toISOString(), heartbeatSeconds: 10,
    launch: {browser, flags: PRESETS[presetId]}});
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
  const claimableAt = Date.now() + crypto.randomInt(4, 31) * 60000;
  await root.child(`redirectAttempts/${attemptId}`).set({
    accountId: account.id, campaignId: String(req.body.campaignId || "default").slice(0, 80),
    claimHash: hmac(claimCode), status: "OPENED", rewardAmount: 0.5,
    ipPrefix: ipPrefix(req), createdAt: Date.now(), claimableAt,
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
  const attempts = Object.entries(await read("redirectAttempts") || {})
      .filter(([, attempt]) =>
        attempt.accountId === account.id && attempt.createdAt >= cutoff)
      .map(([attemptId, attempt]) => ({
        attemptId,
        status: attempt.status,
        rewardAmount: Number(attempt.rewardAmount || 0),
        createdAt: Number(attempt.createdAt || 0),
        claimableAt: Number(attempt.claimableAt || 0),
      }))
      .sort((a, b) => b.createdAt - a.createdAt);
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
  await atomic((data) => {
    const attempt = data.redirectAttempts?.[attemptId];
    if (!attempt || attempt.accountId !== account.id) {
      fail("This reward does not belong to the signed-in account.");
    }
    if (attempt.status !== "OPENED") fail("Reward already claimed.");
    if (attempt.claimableAt > Date.now()) fail("Reward is still pending.");
    attempt.status = "REWARDED"; attempt.rewardedAt = Date.now();
    data.accounts[account.id].pointBalance =
      Number(data.accounts[account.id].pointBalance || 0) + 0.5;
    return data;
  });
  res.json({ok: true, awardedPoints: 0.5});
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
