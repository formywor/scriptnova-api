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
const {
  supportAssistantReply,
  redactSupportSecrets,
  suggestKnowledgeKeywords,
} = require("./lib/support-assistant");
const projectZ = require("./lib/project-z");
const mountProjectZ = require("./lib/project-z-routes");
const devicePairing = require("./lib/device-pairing");
const {mountSnovaWeb} = require("./lib/snova-web");

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
const CURRENT_LAUNCHER_VERSION = "1.2.7";
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
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
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
        "Content-Type, Authorization, X-Admin-Secret, X-Launcher-Version, X-Project-Z-Version");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") {
    return origin && ALLOWED_ORIGINS.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
  }
  next();
});

const PRESETS = {
  t44: [],
  t55: [],
  t77: ["--disable-extensions"],
  balanced: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications", "--disable-background-mode"],
  privacy: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-notifications", "--disable-extensions",
    "--disable-background-mode",
    "--disable-features=AutofillServerCommunication"],
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
  ],
};
const MODE_IDENTITY_OVERRIDES = Object.freeze({
  t44: "default",
  t55: "chromeOs120",
  t77: "default",
});
const DISALLOWED_BROWSER_OPTIONS = new Set(["--incognito", "--guest"]);
const USER_AGENTS = {
  default: "",
  shareDesktop: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 " +
    "Safari/537.36 ShareBrowser/1.0",
  chromeOs120: "Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
};
const LAUNCHER_CONFIGURATION = Object.freeze({
  defaultMode: "balanced",
  defaultIdentity: "default",
  modes: [
    {id: "t44", label: "T44 — Standard identity"},
    {id: "t55", label: "T55 — Compatibility identity"},
    {id: "t77", label: "T77 — Private local trace"},
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
  const flags = PRESETS[presetId].filter((option) =>
    !DISALLOWED_BROWSER_OPTIONS.has(String(option).toLowerCase()));
  if (browser === "edge" && !["t44", "t55", "t77"].includes(presetId)) {
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
const ACCOUNT_STATUSES = new Set(["ACTIVE", "SUSPENDED", "BANNED", "TERMINATED"]);
const APPEAL_STATUSES = new Set(["PENDING", "APPROVED", "DENIED"]);
const ADMIN_ROLES = new Set(["ADMIN", "SUPPORT"]);
const CHAT_MESSAGE_LIMIT = 800;
const DEFAULT_REDIRECT_URL = "https://omg10.com/4/11435374";
const LIMITED_FREE_TOKEN = Object.freeze({
  id: "free-4m-2026",
  minutes: 4,
  points: 0,
  label: "4 minutes — FREE limited token",
  endsAt: Date.parse("2026-08-28T03:59:59.000Z"),
});

function availableTokenOptions(product = "share") {
  const standard = TOKEN_OPTIONS.map((option) => ({
    id: `${option.hours}h`,
    hours: option.hours,
    minutes: option.hours * 60,
    points: option.points,
    label: `${option.hours} hour${option.hours === 1 ? "" : "s"} — ${option.points} points`,
  }));
  if (product === "share" && Date.now() < LIMITED_FREE_TOKEN.endsAt) {
    standard.unshift({...LIMITED_FREE_TOKEN, limited: true});
  }
  return standard;
}

function requestedTokenOption(body) {
  const options = availableTokenOptions(projectZ.productChoice(body.product));
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
function recoveryConfirmationRequired(account) {
  // Existing accounts are grandfathered. Only records explicitly marked as
  // requiring confirmation are held at the backup-code screen.
  return account.recoveryPromptRequired === true && !account.recoveryAcknowledgedAt;
}
function publicRestriction(account) {
  return {
    status: ACCOUNT_STATUSES.has(account.accountStatus) ? account.accountStatus : "ACTIVE",
    reason: String(account.statusReason || "").slice(0, 500),
    startsAt: Number(account.statusChangedAt || 0) || null,
    endsAt: Number(account.statusEndsAt || 0) || null,
    appealAllowed: account.accountStatus !== "ACTIVE",
  };
}
function publicAccount(a) {
  return {username: a.username, pointBalance: Number(a.pointBalance || 0),
    pendingPointBalance: Number(a.pendingPointBalance || 0), referralCode: a.username,
    registeredComputer: Boolean(a.registeredDeviceId),
    unusedTokenCount: Number(a.unusedTokenCount || 0),
    limitedFreeTokenClaimed: Boolean(a.limitedFreeTokenClaimedAt),
    deviceSetupBonusAwarded: Boolean(a.deviceSetupBonusAwardedAt),
    deviceSetupNoticePending: Boolean(a.deviceSetupNoticePending),
    recoveryConfirmationRequired: recoveryConfirmationRequired(a),
    accountStatus: a.accountStatus || "ACTIVE",
    restriction: publicRestriction(a),
    fraudStatus: a.fraudStatus || "CLEAR", activeSessionId: a.activeSessionId || null};
}
function publicSupportTicket(ticketId, ticket) {
  return {
    ticketId,
    username: String(ticket.username || ""),
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
function publicAppeal(appealId, appeal) {
  return {
    appealId,
    accountId: appeal.accountId,
    username: appeal.username,
    restrictionStatus: appeal.restrictionStatus,
    subject: appeal.subject,
    message: appeal.message,
    status: APPEAL_STATUSES.has(appeal.status) ? appeal.status : "PENDING",
    adminResponse: String(appeal.adminResponse || ""),
    createdAt: Number(appeal.createdAt || 0),
    updatedAt: Number(appeal.updatedAt || appeal.createdAt || 0),
  };
}
function publicChat(chatId, chat) {
  const messages = Object.entries(chat.messages || {})
      .map(([messageId, item]) => ({
        messageId,
        sender: ["AGENT", "ASSISTANT", "SYSTEM"].includes(item.sender) ? item.sender : "USER",
        senderName: String(item.senderName || "").slice(0, 40),
        message: String(item.message || "").slice(0, CHAT_MESSAGE_LIMIT),
        createdAt: Number(item.createdAt || 0),
      }))
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(-100);
  return {
    chatId,
    accountId: chat.accountId,
    username: chat.username,
    status: ["ASSISTANT", "WAITING", "ACTIVE", "CLOSED"].includes(chat.status) ? chat.status : "ASSISTANT",
    assignedAgentName: String(chat.assignedAgentName || ""),
    createdAt: Number(chat.createdAt || 0),
    updatedAt: Number(chat.updatedAt || chat.createdAt || 0),
    messages,
  };
}

async function recentLauncherDiagnostics(accountId) {
  const snapshot = await root.child("launcherDiagnostics")
      .orderByChild("accountId").equalTo(accountId).limitToLast(12).get();
  return Object.values(snapshot.val() || {})
      .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
}

async function assistantContext(account, chat = null) {
  const [diagnostics, knowledgeData] = await Promise.all([
    recentLauncherDiagnostics(account.id),
    read("supportKnowledge"),
  ]);
  const previousUserMessages = Object.values(chat?.messages || {})
      .filter((item) => item.sender === "USER")
      .sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0))
      .slice(-5)
      .map((item) => String(item.message || ""));
  return {
    account: {
      accountStatus: account.data.accountStatus || "ACTIVE",
      statusReason: String(account.data.statusReason || "").slice(0, 500),
      statusEndsAt: Number(account.data.statusEndsAt || 0) || null,
      registeredDeviceId: account.data.registeredDeviceId || null,
      pointBalance: Number(account.data.pointBalance || 0),
      pendingPointBalance: Number(account.data.pendingPointBalance || 0),
    },
    diagnostics,
    previousUserMessages,
    knowledge: Object.entries(knowledgeData || {})
        .map(([knowledgeId, entry]) => ({knowledgeId, ...entry}))
        .filter((entry) => entry.active === true)
        .slice(0, 100),
  };
}

async function createLearningCandidate(chatId, chat, administrator) {
  const messages = Object.values(chat.messages || {})
      .sort((a, b) => Number(a.createdAt || 0) - Number(b.createdAt || 0));
  const userMessages = messages.filter((item) => item.sender === "USER");
  const agentMessages = messages.filter((item) => item.sender === "AGENT");
  if (!userMessages.length || !agentMessages.length) return false;
  const existing = await read(`supportLearningCandidates/${chatId}`);
  if (existing) return false;
  const question = userMessages.slice(-3).map((item) => item.message).join("\n").slice(0, 800);
  const answer = String(agentMessages[agentMessages.length - 1].message || "").slice(0, 800);
  if (answer.length < 10) return false;
  await root.child(`supportLearningCandidates/${chatId}`).set({
    chatId,
    question,
    suggestedAnswer: answer,
    suggestedKeywords: suggestKnowledgeKeywords(question),
    status: "PENDING",
    createdByClosingAdministratorId: administrator.id,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });
  return true;
}
function cleanLine(value, maximum) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, maximum);
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
      if (error.gate) response.gate = error.gate;
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
function requireProjectZVersion(req) {
  if (req.headers["x-project-z-version"] !== projectZ.VERSION) {
    fail(`Update Project Z at scriptnovaa.com/project-z. Required version: ${projectZ.VERSION}.`, 426, "Z_UPDATE_REQUIRED");
  }
}
function requirePairingClientVersion(req) {
  if (req.headers["x-project-z-version"]) requireProjectZVersion(req);
  else requireCurrentLauncherVersion(req);
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

async function releasePairingClaim(pairingRef, claimId, now) {
  try {
    const pairing = (await pairingRef.get()).val();
    if (pairing && pairing.status === "CLAIMING" && pairing.claimId === claimId) {
      const released = {...pairing};
      delete released.claimId;
      delete released.claimingAt;
      if (Number(released.expiresAt || 0) <= now) {
        released.status = "EXPIRED";
        released.expiredAt = now;
      } else {
        released.status = "OPEN";
      }
      await pairingRef.set(released);
    }
  } catch (error) {
    console.error("Could not release pairing claim:", error.message);
  }
}

async function claimPairingWithEtag(pairingHash, claimId, now) {
  const configuredUrl = String(getApps()[0].options.databaseURL || "")
      .replace(/\/$/, "");
  const credentialProvider = getApps()[0].options.credential;
  if (!configuredUrl || !credentialProvider?.getAccessToken) {
    fail("Firebase pairing service is not configured.", 500);
  }
  const access = await credentialProvider.getAccessToken();
  const url = `${configuredUrl}/devicePairings/${pairingHash}.json`;
  for (let attempt = 0; attempt < 2; attempt++) {
    const currentResponse = await fetch(url, {
      headers: {
        Authorization: `Bearer ${access.access_token}`,
        "X-Firebase-ETag": "true",
      },
    });
    if (!currentResponse.ok) fail("Firebase pairing lookup failed.", 502);
    const pairing = await currentResponse.json();
    const etag = currentResponse.headers.get("etag");
    const staleClaim = pairing?.status === "CLAIMING" &&
      now - Number(pairing.claimingAt || 0) > 30000;
    if (!pairing || Number(pairing.expiresAt || 0) <= now ||
        (pairing.status !== "OPEN" && !staleClaim)) {
      fail("Connection code is invalid or expired.");
    }
    const claimed = {...pairing, status: "CLAIMING", claimId, claimingAt: now};
    const claimResponse = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${access.access_token}`,
        "Content-Type": "application/json",
        "if-match": etag,
      },
      body: JSON.stringify(claimed),
    });
    if (claimResponse.status === 412) continue;
    if (!claimResponse.ok) fail("Firebase pairing update failed.", 502);
    return claimed;
  }
  fail("The connection code was used by another request. Try once more.", 409);
}

async function completeTargetedPairing(pairingHash, rawProof) {
  const now = Date.now();
  const claimId = crypto.randomBytes(16).toString("hex");
  const pairingRef = root.child(`devicePairings/${pairingHash}`);
  const pairing = await claimPairingWithEtag(pairingHash, claimId, now);
  try {
    const accountId = pairing.accountId;
    const [account, devices] = await Promise.all([
      read(`accounts/${accountId}`),
      read("devices"),
    ]);
    if (!account || account.accountStatus !== "ACTIVE") {
      fail("Account restricted.", 403);
    }
    if (account.recoveryPromptRequired === true &&
        !account.recoveryAcknowledgedAt) {
      fail("Save and confirm your recovery code on the website first.", 428);
    }

    const deviceHash = hmac(rawProof);
    const candidateDeviceId = id("devices");
    const deviceId = account.registeredDeviceId || candidateDeviceId;
    const alreadyRegistered = Boolean(account.registeredDeviceId);
    const currentDevices = devices || {};
    if (alreadyRegistered) {
      const device = currentDevices[deviceId];
      if (!device || device.accountId !== accountId ||
          device.deviceHash !== deviceHash || device.status === "REVOKED") {
        fail("This account already has a different or revoked computer.", 403);
      }
    }

    const reused = !alreadyRegistered && Object.values(currentDevices)
        .some((device) => device.deviceHash === deviceHash &&
          device.accountId !== accountId);
    const launcherToken = crypto.randomBytes(32).toString("base64url");
    const loginHash = hmac(launcherToken);
    const ledgerId = id("pointTransactions");
    const updates = {
      [`devicePairings/${pairingHash}/status`]: "USED",
      [`devicePairings/${pairingHash}/usedAt`]: now,
      [`devicePairings/${pairingHash}/alreadyRegistered`]: alreadyRegistered,
      [`devicePairings/${pairingHash}/claimId`]: null,
      [`devicePairings/${pairingHash}/claimingAt`]: null,
      [`activeDevicePairings/${accountId}`]: null,
      [`accounts/${accountId}/persistentLauncherPairedAt`]: now,
      [`accounts/${accountId}/updatedAt`]: now,
      [`loginSessions/${loginHash}`]: {
        accountId,
        clientDescription: "ScriptNovaa paired launcher",
        revoked: false,
        createdAt: now,
        lastUsedAt: now,
      },
    };

    let riskStatus = "PASSED";
    if (!alreadyRegistered) {
      riskStatus = reused ? "REVIEW" : "PASSED";
      updates[`devices/${deviceId}`] = {
        accountId,
        deviceHash,
        status: reused ? "REVIEW" : "ACTIVE",
        riskScore: reused ? 100 : 0,
        registeredAt: now,
      };
      updates[`accounts/${accountId}/registeredDeviceId`] = deviceId;
      if (reused) updates[`accounts/${accountId}/fraudStatus`] = "REVIEW";

      const awardSetup = !reused && account.fraudStatus === "CLEAR" &&
        !account.deviceSetupBonusAwardedAt;
      if (awardSetup) {
        updates[`accounts/${accountId}/pointBalance`] = ServerValue.increment(2);
        updates[`accounts/${accountId}/pendingPointBalance`] =
          Math.max(0, Number(account.pendingPointBalance || 0) - 2);
        updates[`accounts/${accountId}/deviceSetupBonusAwardedAt`] = now;
        updates[`accounts/${accountId}/deviceSetupNoticePending`] = true;
        updates[`pointTransactions/${ledgerId}`] = {
          accountId,
          amount: 2,
          type: "DEVICE_SETUP_BONUS",
          sourceId: deviceId,
          createdAt: now,
        };

        const referralId = await read(`referralsByReferred/${accountId}`);
        const referral = referralId ? await read(`referrals/${referralId}`) : null;
        const referrer = referral?.referrerAccountId ?
          await read(`accounts/${referral.referrerAccountId}`) : null;
        if (referral?.status === "WAITING_FOR_DEVICE" && referrer) {
          updates[`referrals/${referralId}/status`] = "DEVICE_PASSED";
          updates[`referrals/${referralId}/signupRewardAwarded`] = 3;
          updates[`referrals/${referralId}/devicePassedAt`] = now;
          updates[`accounts/${referral.referrerAccountId}/pointBalance`] =
            ServerValue.increment(3);
          updates[`pointTransactions/${ledgerId}_referral`] = {
            accountId: referral.referrerAccountId,
            amount: 3,
            type: "REFERRAL_SIGNUP",
            sourceId: referralId,
            createdAt: now,
          };
        }
      }
    } else {
      riskStatus = currentDevices[deviceId].status === "ACTIVE" ? "PASSED" : "REVIEW";
    }

    await root.update(updates);
    return {alreadyRegistered, deviceId, riskStatus, launcherToken};
  } catch (error) {
    await releasePairingClaim(pairingRef, claimId, Date.now());
    throw error;
  }
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
  if (wasFlagged) return {...plan, minutes: crypto.randomInt(12, 15)};
  const trustScore = Math.max(0, Math.min(100, Number(account.trustScore ?? 50)));
  const trustAdjustment = Math.round((trustScore - 50) * 0.4);
  const zeroWaitChance = Math.max(5, Math.min(99,
      Number(plan.zeroWaitChance || 0) + trustAdjustment));
  const trustRoll = crypto.randomInt(0, 100);
  if (trustRoll < zeroWaitChance) {
    return {...plan, trustScore, zeroWaitChance, zeroWait: true, minutes: 0};
  }
  const maximumMinutes = Math.max(1,
      Math.min(14, plan.maximumMinutes + Math.ceil((50 - trustScore) / 20)));
  return {...plan, trustScore, zeroWaitChance, zeroWait: false,
    maximumMinutes, minutes: crypto.randomInt(1, maximumMinutes + 1)};
}
async function etagTransaction(path, mutator, maximumAttempts = 5) {
  const configuredUrl = String(getApps()[0].options.databaseURL || "")
      .replace(/\/$/, "");
  const credentialProvider = getApps()[0].options.credential;
  if (!configuredUrl || !credentialProvider?.getAccessToken) {
    fail("Firebase transaction service is not configured.", 500);
  }
  const access = await credentialProvider.getAccessToken();
  const suffix = path ? `/${path}` : "/";
  const url = `${configuredUrl}${suffix}.json`;
  for (let attempt = 0; attempt < maximumAttempts; attempt++) {
    const currentResponse = await fetch(url, {
      headers: {
        Authorization: `Bearer ${access.access_token}`,
        "X-Firebase-ETag": "true",
      },
    });
    if (!currentResponse.ok) fail("Firebase transaction lookup failed.", 502);
    const current = await currentResponse.json();
    const etag = currentResponse.headers.get("etag");
    const next = mutator(current);
    if (next === undefined) {
      return {committed: false, value: current};
    }
    const updateResponse = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${access.access_token}`,
        "Content-Type": "application/json",
        "if-match": etag,
      },
      body: JSON.stringify(next),
    });
    if (updateResponse.status === 412) continue;
    if (!updateResponse.ok) fail("Firebase transaction update failed.", 502);
    return {committed: true, value: next};
  }
  fail("The request conflicted with another update. Try again.", 409);
}

async function atomic(mutator) {
  const result = await etagTransaction("", (current) => mutator(current || {}));
  if (!result.committed) {
    fail("The request conflicted with another update. Try again.", 409);
  }
  return result.value;
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
async function newLogin(accountId, clientDescription, networkPrefix = "unknown") {
  const raw = crypto.randomBytes(32).toString("base64url");
  await root.child(`loginSessions/${hmac(raw)}`).set({
    accountId, clientDescription: String(clientDescription || "").slice(0, 250),
    networkPrefix: String(networkPrefix || "unknown").slice(0, 80),
    revoked: false, createdAt: Date.now(), lastUsedAt: Date.now(),
  });
  return raw;
}
async function resolveExpiredSuspension(accountId, account) {
  if (account.accountStatus === "SUSPENDED" && Number(account.statusEndsAt || 0) > 0 &&
      Number(account.statusEndsAt) <= Date.now()) {
    const now = Date.now();
    await root.child(`accounts/${accountId}`).update({
      accountStatus: "ACTIVE",
      statusReason: null,
      statusEndsAt: null,
      statusChangedAt: now,
      statusAutomaticallyRestoredAt: now,
      updatedAt: now,
    });
    return {...account, accountStatus: "ACTIVE", statusReason: null, statusEndsAt: null};
  }
  return account;
}
function accountGateError(account) {
  const status = account.accountStatus || "ACTIVE";
  const error = new Error(status === "SUSPENDED" ? "This account is suspended." :
    status === "BANNED" ? "This account is banned." : "This account is terminated.");
  error.statusCode = 403;
  error.apiCode = `ACCOUNT_${status}`;
  error.gate = {type: "RESTRICTION", ...publicRestriction(account)};
  return error;
}
async function requireAccount(req, options = {}) {
  const raw = bearer(req); if (!raw) fail("Authentication required.", 401);
  const loginId = hmac(raw);
  const login = await read(`loginSessions/${loginId}`);
  if (!login || login.revoked) fail("Authentication required.", 401);
  let account = await read(`accounts/${login.accountId}`);
  if (!account) fail("Authentication required.", 401);
  account = await resolveExpiredSuspension(login.accountId, account);
  account.accountStatus = account.accountStatus || "ACTIVE";
  if (account.accountStatus !== "ACTIVE" && !options.allowRestricted) {
    throw accountGateError(account);
  }
  if (recoveryConfirmationRequired(account) && !options.allowRecoveryPending) {
    const error = new Error("Save and confirm your backup recovery code before continuing.");
    error.statusCode = 428;
    error.apiCode = "RECOVERY_CONFIRMATION_REQUIRED";
    error.gate = {type: "RECOVERY_CONFIRMATION"};
    throw error;
  }
  root.child(`loginSessions/${loginId}/lastUsedAt`).set(Date.now()).catch(console.error);
  return {id: login.accountId, data: account, loginId};
}
async function requireAdmin(req, capability = "SUPPORT") {
  const account = await requireAccount(req);
  const administrator = await read(`administrators/${account.id}`);
  if (!administrator || administrator.active !== true ||
      !ADMIN_ROLES.has(String(administrator.role || "").toUpperCase())) {
    fail("Administrator authorization required.", 403, "ADMIN_REQUIRED");
  }
  const role = String(administrator.role).toUpperCase();
  if (capability === "ADMIN" && role !== "ADMIN") {
    fail("This administrator role cannot perform that action.", 403, "ADMIN_PERMISSION_REQUIRED");
  }
  return {...account, administrator: {...administrator, role}};
}
async function adminAudit(admin, action, targetAccountId, detail = {}) {
  const auditId = id("adminAuditLog");
  await root.child(`adminAuditLog/${auditId}`).set({
    administratorAccountId: admin.id,
    administratorUsername: admin.data.username,
    action,
    targetAccountId: targetAccountId || null,
    detail,
    createdAt: Date.now(),
  });
  return auditId;
}
async function requireBrowserSession(req) {
  const sessionId = String(req.body.sessionId || "");
  const raw = String(req.body.sessionSecret || "");
  const session = await read(`sessions/${sessionId}`);
  if (!session || session.sessionSecretHash !== hmac(raw)) {
    fail("Browser session authentication failed.", 401);
  }
  if (session.product === "z") fail("Use the Project Z session API.", 403);
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
      endedAt - Number(current.startedAt || 0) <= 120000 &&
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
    console.info("Browser session finished", {
      sessionId,
      accountId: current.accountId,
      browser: current.browser || "unknown",
      reason: clean,
      tokenRestored: launchFailedQuickly,
      launchConfirmed: Boolean(current.launchConfirmedAt),
    });
  } finally {
    const activeLock = await read(`sessionFinishLocks/${sessionId}`);
    if (activeLock?.finishId === finishId) await lockReference.remove();
  }
}

mountSnovaWeb(app, {route, rateLimit, ipPrefix, read, hmac});

app.get("/api/health", (req, res) => res.json({
  ok: true, product: "Share Browser API", database: "Firebase Realtime Database",
  launcherVersion: CURRENT_LAUNCHER_VERSION,
  projectZVersion: projectZ.VERSION,
  pairingProtocol: "etag-transactions-v5",
}));
app.get("/", (req, res) => res.json({
  ok: true,
  product: "Share Browser API",
  health: "https://api.scriptnovaa.com/api/health",
}));
app.get(["/favicon.ico", "/favicon.png"], (req, res) => res.status(204).end());
app.get("/api/public-config", (req, res) => res.json({
  ok: true, pairingProtocol: "etag-transactions-v5",
  tokenOptions: availableTokenOptions(),
  projectZ: {...projectZ.configuration(), tokenOptions: availableTokenOptions("z")},
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
    if (referralUsername === username) {
      fail("You cannot refer your own new account.");
    }
    if (referralUsername && !usernames[referralUsername]) {
      fail("That referral username was not found. Check the spelling or leave it blank.");
    }
    const referrerAccountId = referralUsername && referralUsername !== username ?
      usernames[referralUsername]?.accountId || null : null;
    usernames[username] = {accountId, createdAt: Date.now()};
    accounts[accountId] = {
      username, pinCredential: credential(pin, "PIN_PEPPER"),
      recoveryCredential: credential(recoveryCode, "RECOVERY_PEPPER"),
      recoveryPromptRequired: true,
      recoveryAcknowledgedAt: null,
      pointBalance: 0, pendingPointBalance: referrerAccountId ? 2 : 0,
      registeredDeviceId: null, activeSessionId: null, unusedTokenCount: 0,
      accountStatus: "ACTIVE", fraudStatus: "CLEAR", referredByAccountId: referrerAccountId,
      trustScore: 50,
      createdNetworkPrefix: ipPrefix(req),
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
    loginToken: await newLogin(accountId, req.body.clientDescription, ipPrefix(req)), recoveryCode,
    warning: "Save this recovery code now. It will not be shown again."});
}));

app.post("/api/login", route(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const loginLimit = await rateLimit(`${ipPrefix(req)}:${username}`, "LOGIN", 12, 900);
  const accountLoginLimit = await rateLimit(username || "missing", "LOGIN_ACCOUNT", 20, 3600);
  await rateLimit(ipPrefix(req), "LOGIN_NETWORK", 120, 3600);
  const usernameRecord = await read(`usernames/${username}`);
  const account = usernameRecord ? await read(`accounts/${usernameRecord.accountId}`) : null;
  if (!account || !verifies(req.body.pin, account.pinCredential, "PIN_PEPPER")) {
    fail("Incorrect username or PIN.", 401);
  }
  await loginLimit.remove();
  await accountLoginLimit.remove();
  res.json({ok: true,
    loginToken: await newLogin(usernameRecord.accountId, req.body.clientDescription, ipPrefix(req)),
    account: publicAccount(account),
    gate: account.accountStatus !== "ACTIVE" ?
      {type: "RESTRICTION", ...publicRestriction(account)} :
      recoveryConfirmationRequired(account) ? {type: "RECOVERY_CONFIRMATION"} : null});
}));

app.post("/api/recover", route(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  await rateLimit(`${ipPrefix(req)}:${username}`, "RECOVER", 6, 3600);
  await rateLimit(username || "missing", "RECOVER_ACCOUNT", 8, 24 * 60 * 60);
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
    fresh.recoveryPromptRequired = true;
    fresh.recoveryAcknowledgedAt = null;
    fresh.updatedAt = Date.now();
    Object.values(data.loginSessions || {}).forEach((session) => {
      if (session.accountId === usernameRecord.accountId) session.revoked = true;
    });
    return data;
  });
  res.json({ok: true,
    loginToken: await newLogin(usernameRecord.accountId,
        req.body.clientDescription, ipPrefix(req)),
    newRecoveryCode: replacement,
    warning: "Save the replacement recovery code before leaving this page."});
}));

app.get("/api/account/gate", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  res.json({
    ok: true,
    gate: account.data.accountStatus !== "ACTIVE" ?
      {type: "RESTRICTION", ...publicRestriction(account.data)} :
      recoveryConfirmationRequired(account.data) ?
        {type: "RECOVERY_CONFIRMATION"} : {type: "CLEAR"},
    account: publicAccount(account.data),
  });
}));

app.post("/api/account/recovery/acknowledge", route(async (req, res) => {
  const account = await requireAccount(req, {allowRecoveryPending: true});
  if (req.body.saved !== true) fail("Confirm that you saved the backup code.");
  if (!recoveryConfirmationRequired(account.data)) {
    return res.json({ok: true, alreadyAcknowledged: true});
  }
  const now = Date.now();
  await root.child(`accounts/${account.id}`).update({
    recoveryAcknowledgedAt: now,
    recoveryPromptRequired: false,
    updatedAt: now,
  });
  res.json({ok: true, acknowledgedAt: now});
}));

app.post("/api/account/recovery/regenerate", route(async (req, res) => {
  const account = await requireAccount(req, {allowRecoveryPending: true});
  await rateLimit(account.id, "RECOVERY_REGENERATE", 3, 24 * 60 * 60);
  if (!recoveryConfirmationRequired(account.data)) {
    fail("A backup code can only be regenerated during required confirmation.", 409);
  }
  if (!verifies(req.body.pin, account.data.pinCredential, "PIN_PEPPER")) {
    fail("Incorrect PIN.", 401);
  }
  const replacement = code("RCVY", 12);
  await root.child(`accounts/${account.id}`).update({
    recoveryCredential: credential(replacement, "RECOVERY_PEPPER"),
    recoveryRegeneratedAt: Date.now(),
    updatedAt: Date.now(),
  });
  res.json({ok: true, recoveryCode: replacement,
    warning: "The previous backup code no longer works. Save this replacement."});
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
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
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
  requirePairingClientVersion(req);
  const pairingCode = String(req.body.pairingCode || "")
      .replace(/[^A-F0-9]/gi, "").toUpperCase();
  if (pairingCode.length !== 10) fail("Connection code is invalid.");
  await rateLimit(ipPrefix(req), "DEVICE_PAIRING", 30, 900);
  const calculatedPairingHash = hmac(pairingCode);
  let pairingHash = calculatedPairingHash;
  const calculatedPairing = await read(`devicePairings/${calculatedPairingHash}`);
  if (!calculatedPairing || calculatedPairing.pairingCode !== pairingCode) {
    pairingHash = devicePairing.resolveHash(
        await read("devicePairings") || {}, calculatedPairingHash,
        pairingCode, Date.now(),
    );
    if (!pairingHash) fail("Connection code is invalid or expired.");
    console.warn("Pairing lookup recovered an open code after a hash-key mismatch.");
  }
  const rawProof = String(req.body.deviceProof || "");
  if (rawProof.length < 20 || rawProof.length > 2048) fail("Computer identity is missing or invalid.");
  const result = await completeTargetedPairing(pairingHash, rawProof);
  res.json({ok: true, ...result});
}));

app.post("/api/device/launcher/status", route(async (req, res) => {
  requirePairingClientVersion(req);
  const account = await requireAccount(req);
  const deviceId = account.data.registeredDeviceId;
  const device = deviceId ? await read(`devices/${deviceId}`) : null;
  if (!device || device.deviceHash !== hmac(req.body.deviceProof) ||
      !["ACTIVE", "REVIEW"].includes(device.status)) {
    fail("Saved computer connection is no longer valid.", 403);
  }
  if (device.status === "REVIEW") {
    res.json({ok: true, connected: false, review: true,
      username: account.data.username, deviceId});
    return;
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
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  const tickets = await accountSupportTickets(account.id);
  res.json({
    ok: true,
    tickets: tickets.slice(0, 50)
        .map(([ticketId, ticket]) => publicSupportTicket(ticketId, ticket)),
  });
}));

app.post("/api/support/tickets", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  await rateLimit(account.id, "SUPPORT_TICKET", 12, 24 * 60 * 60);
  const category = String(req.body.category || "").trim().toUpperCase();
  const subject = String(req.body.subject || "").trim().replace(/\s+/g, " ");
  const rawTicketMessage = String(req.body.message || "").trim();
  if (!SUPPORT_CATEGORIES.has(category)) fail("Choose a valid support category.");
  if (subject.length < 5 || subject.length > 80) {
    fail("Subject must contain between 5 and 80 characters.");
  }
  if (rawTicketMessage.length < 20 || rawTicketMessage.length > 2000) {
    fail("Explanation must contain between 20 and 2,000 characters.");
  }
  const ticketMessage = redactSupportSecrets(rawTicketMessage);

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

app.get("/api/support/chat", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  const chats = Object.entries(await read("supportChats") || {})
      .filter(([, chat]) => chat.accountId === account.id)
      .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0));
  res.json({ok: true, chats: chats.slice(0, 10)
      .map(([chatId, chat]) => publicChat(chatId, chat))});
}));

app.post("/api/support/chat/start", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  await rateLimit(account.id, "SUPPORT_CHAT_START", 12, 24 * 60 * 60);
  if (req.body.acceptedPolicy !== true) {
    fail("Accept the support-chat notice before starting a chat.");
  }
  const rawInitialMessage = String(req.body.message || "").trim();
  if (rawInitialMessage.length < 20 || rawInitialMessage.length > CHAT_MESSAGE_LIMIT) {
    fail(`Message must contain between 20 and ${CHAT_MESSAGE_LIMIT} characters.`);
  }
  const initialMessage = redactSupportSecrets(rawInitialMessage);
  const existing = Object.entries(await read("supportChats") || {})
      .find(([, chat]) => chat.accountId === account.id &&
        ["ASSISTANT", "WAITING", "ACTIVE"].includes(chat.status));
  if (existing) {
    return res.json({ok: true, existing: true,
      chat: publicChat(existing[0], existing[1])});
  }
  const chatId = id("supportChats");
  const messageId = id(`supportChats/${chatId}/messages`);
  const assistantMessageId = id(`supportChats/${chatId}/messages`);
  const now = Date.now();
  const assistantReply = supportAssistantReply(
      initialMessage,
      await assistantContext(account),
  );
  const chat = {
    accountId: account.id,
    username: account.data.username,
    status: assistantReply.transfer ? "WAITING" : "ASSISTANT",
    createdAt: now,
    updatedAt: now,
    submittedNetworkPrefix: ipPrefix(req),
    messages: {
      [messageId]: {
        sender: "USER",
        senderName: account.data.username,
        message: initialMessage,
        createdAt: now,
      },
      [assistantMessageId]: {
        sender: "ASSISTANT",
        senderName: "ScriptNovaa Assistant",
        message: assistantReply.message,
        createdAt: now + 1,
      },
    },
  };
  await root.child(`supportChats/${chatId}`).set(chat);
  res.status(201).json({ok: true, chat: publicChat(chatId, chat)});
}));

app.post("/api/support/chat/:chatId/messages", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  await rateLimit(account.id, "SUPPORT_CHAT_MESSAGE", 40, 60 * 60);
  const chatId = String(req.params.chatId || "");
  const chat = await read(`supportChats/${chatId}`);
  if (!chat || chat.accountId !== account.id) fail("Support chat not found.", 404);
  if (chat.status === "CLOSED") fail("This support chat is closed.", 409);
  const rawChatMessage = String(req.body.message || "").trim();
  if (rawChatMessage.length < 1 || rawChatMessage.length > CHAT_MESSAGE_LIMIT) {
    fail(`Message must contain between 1 and ${CHAT_MESSAGE_LIMIT} characters.`);
  }
  const chatMessage = redactSupportSecrets(rawChatMessage);
  const messageId = id(`supportChats/${chatId}/messages`);
  const now = Date.now();
  const updates = {
    [`supportChats/${chatId}/messages/${messageId}`]: {
      sender: "USER",
      senderName: account.data.username,
      message: chatMessage,
      createdAt: now,
    },
    [`supportChats/${chatId}/updatedAt`]: now,
  };
  if (chat.status === "ASSISTANT") {
    const assistantMessageId = id(`supportChats/${chatId}/messages`);
    const assistantReply = supportAssistantReply(
        chatMessage,
        await assistantContext(account, chat),
    );
    updates[`supportChats/${chatId}/messages/${assistantMessageId}`] = {
      sender: "ASSISTANT",
      senderName: "ScriptNovaa Assistant",
      message: assistantReply.message,
      createdAt: now + 1,
    };
    updates[`supportChats/${chatId}/status`] = assistantReply.transfer ?
      "WAITING" : "ASSISTANT";
  }
  await root.update(updates);
  res.status(201).json({ok: true, messageId});
}));

app.post("/api/support/chat/:chatId/transfer", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  await rateLimit(account.id, "SUPPORT_CHAT_TRANSFER", 6, 24 * 60 * 60);
  const chatId = String(req.params.chatId || "");
  const chat = await read(`supportChats/${chatId}`);
  if (!chat || chat.accountId !== account.id) fail("Support chat not found.", 404);
  if (chat.status === "CLOSED") fail("This support chat is closed.", 409);
  if (["WAITING", "ACTIVE"].includes(chat.status)) {
    return res.json({ok: true, status: chat.status});
  }
  const now = Date.now();
  const messageId = id(`supportChats/${chatId}/messages`);
  await root.update({
    [`supportChats/${chatId}/status`]: "WAITING",
    [`supportChats/${chatId}/updatedAt`]: now,
    [`supportChats/${chatId}/messages/${messageId}`]: {
      sender: "SYSTEM",
      senderName: "ScriptNovaa",
      message: "Transfer requested. This chat is waiting for a representative. Response time is not guaranteed.",
      createdAt: now,
    },
  });
  res.json({ok: true, status: "WAITING"});
}));

app.post("/api/support/chat/:chatId/close", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  const chatId = String(req.params.chatId || "");
  const chat = await read(`supportChats/${chatId}`);
  if (!chat || chat.accountId !== account.id) fail("Support chat not found.", 404);
  if (chat.status !== "CLOSED") {
    const now = Date.now();
    const messageId = id(`supportChats/${chatId}/messages`);
    await root.update({
      [`supportChats/${chatId}/status`]: "CLOSED",
      [`supportChats/${chatId}/closedBy`]: "USER",
      [`supportChats/${chatId}/closedAt`]: now,
      [`supportChats/${chatId}/updatedAt`]: now,
      [`supportChats/${chatId}/messages/${messageId}`]: {
        sender: "SYSTEM",
        senderName: "ScriptNovaa",
        message: "Chat closed. You can start a new conversation whenever you need help.",
        createdAt: now,
      },
    });
  }
  res.json({ok: true, status: "CLOSED"});
}));

app.get("/api/appeals", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  const appeals = Object.entries(await read("appeals") || {})
      .filter(([, appeal]) => appeal.accountId === account.id)
      .sort((a, b) => Number(b[1].createdAt || 0) - Number(a[1].createdAt || 0));
  res.json({ok: true, appeals: appeals.slice(0, 10)
      .map(([appealId, appeal]) => publicAppeal(appealId, appeal))});
}));

app.post("/api/appeals", route(async (req, res) => {
  const account = await requireAccount(req, {
    allowRestricted: true,
    allowRecoveryPending: true,
  });
  if (account.data.accountStatus === "ACTIVE") {
    fail("This account does not currently have a restriction to appeal.", 409);
  }
  await rateLimit(account.id, "ACCOUNT_APPEAL", 2, 30 * 24 * 60 * 60);
  const existing = Object.values(await read("appeals") || {})
      .find((appeal) => appeal.accountId === account.id && appeal.status === "PENDING");
  if (existing) fail("You already have a pending appeal.", 409);
  const subject = cleanLine(req.body.subject, 100);
  const appealMessage = String(req.body.message || "").trim();
  if (subject.length < 5) fail("Appeal subject must contain at least 5 characters.");
  if (appealMessage.length < 50 || appealMessage.length > 2500) {
    fail("Appeal explanation must contain between 50 and 2,500 characters.");
  }
  const appealId = id("appeals");
  const now = Date.now();
  const appeal = {
    accountId: account.id,
    username: account.data.username,
    restrictionStatus: account.data.accountStatus,
    subject,
    message: appealMessage,
    status: "PENDING",
    submittedNetworkPrefix: ipPrefix(req),
    createdAt: now,
    updatedAt: now,
  };
  await root.child(`appeals/${appealId}`).set(appeal);
  res.status(201).json({ok: true, appeal: publicAppeal(appealId, appeal)});
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
  const product = projectZ.productChoice(req.body.product);
  const rawToken = code(product === "z" ? "Z" : "SHARE"); const tokenHash = hmac(rawToken); const tokenId = id("tokens");
  const lockId = crypto.randomBytes(12).toString("hex");
  const lockReference = root.child(`tokenCreationLocks/${account.id}`);
  const lockedAt = Date.now();
  const lock = await lockReference.transaction((current) => {
    if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
    return {lockId, lockedAt};
  }, undefined, false);
  if (!lock.committed) fail("A token is already being created. Try again.", 409);

  try {
    const createdAt = Date.now();
    const ledgerId = id("pointTransactions");
    await atomic((data) => projectZ.purchase(data, {
      accountId: account.id, tokenId, tokenHash, rawToken, option,
      product, now: createdAt, ledgerId,
    }));
    res.status(201).json({
      ok: true,
      token: rawToken,
      product,
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
  const effectiveUserAgentId = MODE_IDENTITY_OVERRIDES[presetId] || userAgentId;
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
    let [token, device] = await Promise.all([
      read(`tokens/${tokenId}`),
      freshAccount.registeredDeviceId ?
        read(`devices/${freshAccount.registeredDeviceId}`) : Promise.resolve(null),
    ]);
    if (!device || device.status !== "ACTIVE" ||
      device.deviceHash !== hmac(req.body.deviceProof)) {
      fail("Computer is not authorized. Reconnect this computer from the Tokens page.", 403);
    }

    const updates = {};
    let restoredUnconfirmedToken = false;
    if (freshAccount.activeSessionId) {
      const previousSessionId = freshAccount.activeSessionId;
      const previous = await read(`sessions/${previousSessionId}`);
      const staleWindow = previous?.launchConfirmedAt ? 30000 : 120000;
      const stale = !previous || previous.status !== "ACTIVE" ||
        Number(previous.lastHeartbeatAt || 0) < Date.now() - staleWindow;
      if (!stale) fail("An active session already exists.");
      if (previous && previous.status === "ACTIVE") {
        const endedAt = Date.now();
        updates[`sessions/${previousSessionId}/status`] = "FINISHED";
        updates[`sessions/${previousSessionId}/endedAt`] = endedAt;
        const previousToken = previous.tokenId ? await read(`tokens/${previous.tokenId}`) : null;
        const launchWasNeverConfirmed = !previous.launchConfirmedAt &&
          previousToken?.status === "ACTIVE" &&
          previousToken.sessionId === previousSessionId;
        if (launchWasNeverConfirmed) {
          restoredUnconfirmedToken = true;
          updates[`sessions/${previousSessionId}/endReason`] = "LAUNCH_CONFIRMATION_TIMEOUT";
          updates[`sessions/${previousSessionId}/tokenRestored`] = true;
          updates[`tokens/${previous.tokenId}/status`] = "UNUSED";
          updates[`tokens/${previous.tokenId}/sessionId`] = null;
          updates[`tokens/${previous.tokenId}/deviceId`] = null;
          updates[`tokens/${previous.tokenId}/activatedAt`] = null;
          updates[`tokens/${previous.tokenId}/expiresAt`] = null;
          updates[`tokens/${previous.tokenId}/endReason`] = null;
          updates[`tokens/${previous.tokenId}/endedAt`] = null;
          if (previous.tokenId === tokenId) token = {...token, status: "UNUSED"};
        } else if (previousToken) {
          updates[`sessions/${previousSessionId}/endReason`] = "HEARTBEAT_TIMEOUT";
          updates[`tokens/${previous.tokenId}/status`] = "COMPLETED";
          updates[`tokens/${previous.tokenId}/endReason`] = "HEARTBEAT_TIMEOUT";
          updates[`tokens/${previous.tokenId}/endedAt`] = endedAt;
          updates[`tokens/${previous.tokenId}/displayToken`] = null;
        } else {
          updates[`sessions/${previousSessionId}/endReason`] = "HEARTBEAT_TIMEOUT";
        }
      }
    }

    if (!token || token.ownerAccountId !== account.id) fail("Token cannot be used.");
    if (projectZ.productOf(token) !== "share") fail("This is a Project Z token. Open it in Project Z.");
    if (token.status === "ACTIVE") fail("This token already has an active session.", 409);
    if (token.status !== "UNUSED") fail("This token has already been used and cannot be reused.");

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
      [`accounts/${account.id}/unusedTokenCount`]:
        ServerValue.increment(restoredUnconfirmedToken ? 0 : -1),
      [`accounts/${account.id}/updatedAt`]: startedAt,
    });
    updates[`sessions/${sessionId}`] = {
      accountId: account.id, tokenId, deviceId: freshAccount.registeredDeviceId,
      browser, presetId, userAgentId: effectiveUserAgentId,
      status: "ACTIVE", sessionSecretHash: hmac(rawSecret),
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
      userAgent: USER_AGENTS[effectiveUserAgentId],
      fallbackStartupOptions: browserLaunchFlags(browser,
          ["t44", "t55", "t77"].includes(presetId) ? presetId : "minimal"),
      fallbackUserAgent: ["t44", "t55", "t77"].includes(presetId) ?
        USER_AGENTS[effectiveUserAgentId] : ""}});
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

mountProjectZ(app, {route, requireAccount, root, read, atomic, hmac, rateLimit, fail,
  requireVersion: requireProjectZVersion});

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

app.get("/api/admin/me", route(async (req, res) => {
  const administrator = await requireAdmin(req, "SUPPORT");
  res.json({ok: true, administrator: {
    username: administrator.data.username,
    role: administrator.administrator.role,
    displayName: cleanLine(administrator.administrator.displayName ||
      administrator.data.username, 40),
  }});
}));

app.post("/api/admin/accounts/search", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const username = normalizeUsername(req.body.username);
  if (!username) fail("Enter an exact username.");
  const usernameRecord = await read(`usernames/${username}`);
  const account = usernameRecord ? await read(`accounts/${usernameRecord.accountId}`) : null;
  if (!account) fail("Account not found.", 404);
  res.json({ok: true, account: {
    accountId: usernameRecord.accountId,
    ...publicAccount(account),
    trustScore: Math.max(0, Math.min(100, Number(account.trustScore ?? 50))),
    createdAt: Number(account.createdAt || 0),
    updatedAt: Number(account.updatedAt || 0),
  }});
}));

app.get("/api/admin/accounts/:accountId", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const accountId = String(req.params.accountId || "");
  const account = await read(`accounts/${accountId}`);
  if (!account) fail("Account not found.", 404);
  const [loginSessions, devices, tickets, appeals, referrals, pointTransactions] =
    await Promise.all([
      read("loginSessions"), read("devices"), read("supportTickets"),
      read("appeals"), read("referrals"), read("pointTransactions"),
    ]);
  const networkHistory = Object.values(loginSessions || {})
      .filter((session) => session.accountId === accountId)
      .map((session) => ({
        networkPrefix: String(session.networkPrefix || "unknown"),
        client: cleanLine(session.clientDescription || "Unknown client", 180),
        createdAt: Number(session.createdAt || 0),
        lastUsedAt: Number(session.lastUsedAt || 0),
        revoked: Boolean(session.revoked),
      }))
      .sort((a, b) => b.lastUsedAt - a.lastUsedAt)
      .slice(0, 30);
  const deviceHistory = Object.entries(devices || {})
      .filter(([, device]) => device.accountId === accountId)
      .map(([deviceId, device]) => ({
        deviceId,
        status: device.status || "UNKNOWN",
        riskScore: Number(device.riskScore || 0),
        registeredAt: Number(device.registeredAt || 0),
      }));
  res.json({ok: true, account: {
    accountId,
    ...publicAccount(account),
    trustScore: Math.max(0, Math.min(100, Number(account.trustScore ?? 50))),
    createdAt: Number(account.createdAt || 0),
    updatedAt: Number(account.updatedAt || 0),
    createdNetworkPrefix: String(account.createdNetworkPrefix || "unknown"),
    statusReason: String(account.statusReason || ""),
    statusEndsAt: Number(account.statusEndsAt || 0) || null,
    networkHistory,
    deviceHistory,
    ticketCount: Object.values(tickets || {}).filter((item) => item.accountId === accountId).length,
    appealCount: Object.values(appeals || {}).filter((item) => item.accountId === accountId).length,
    referralCount: Object.values(referrals || {}).filter((item) =>
      item.referrerAccountId === accountId).length,
    recentPointTransactions: Object.entries(pointTransactions || {})
        .filter(([, item]) => item.accountId === accountId)
        .map(([transactionId, item]) => ({transactionId, amount: Number(item.amount || 0),
          type: item.type || "UNKNOWN", reason: String(item.reason || ""),
          createdAt: Number(item.createdAt || 0)}))
        .sort((a, b) => b.createdAt - a.createdAt).slice(0, 25),
  }});
}));

app.post("/api/admin/accounts/:accountId/status", route(async (req, res) => {
  const administrator = await requireAdmin(req, "ADMIN");
  const accountId = String(req.params.accountId || "");
  if (accountId === administrator.id) fail("You cannot restrict your own administrator account.");
  const target = await read(`accounts/${accountId}`);
  if (!target) fail("Account not found.", 404);
  const status = String(req.body.status || "").toUpperCase();
  if (!ACCOUNT_STATUSES.has(status)) fail("Choose a valid account status.");
  const reason = cleanLine(req.body.reason, 500);
  if (status !== "ACTIVE" && reason.length < 8) {
    fail("Give a clear reason containing at least 8 characters.");
  }
  let endsAt = null;
  if (status === "SUSPENDED") {
    endsAt = Number(req.body.endsAt || 0);
    if (!Number.isFinite(endsAt) || endsAt <= Date.now() ||
        endsAt > Date.now() + 366 * 24 * 60 * 60 * 1000) {
      fail("Suspension end must be in the future and no more than one year away.");
    }
  }
  if (target.activeSessionId) {
    const session = await read(`sessions/${target.activeSessionId}`);
    if (session?.status === "ACTIVE") {
      await finishSession(target.activeSessionId, session, `ACCOUNT_${status}`);
    }
  }
  const now = Date.now();
  await root.child(`accounts/${accountId}`).update({
    accountStatus: status,
    statusReason: status === "ACTIVE" ? null : reason,
    statusEndsAt: endsAt,
    statusChangedAt: now,
    statusChangedBy: administrator.id,
    updatedAt: now,
  });
  await adminAudit(administrator, "ACCOUNT_STATUS_CHANGED", accountId,
      {status, reason: status === "ACTIVE" ? "" : reason, endsAt});
  res.json({ok: true, status, endsAt});
}));

app.post("/api/admin/accounts/:accountId/trust", route(async (req, res) => {
  const administrator = await requireAdmin(req, "ADMIN");
  const accountId = String(req.params.accountId || "");
  const target = await read(`accounts/${accountId}`);
  if (!target) fail("Account not found.", 404);
  const trustScore = Number(req.body.trustScore);
  const reason = cleanLine(req.body.reason, 300);
  if (!Number.isInteger(trustScore) || trustScore < 0 || trustScore > 100) {
    fail("Trust score must be a whole number from 0 to 100.");
  }
  if (reason.length < 8) fail("Give a reason for changing trust.");
  await root.child(`accounts/${accountId}`).update({
    trustScore,
    trustChangedAt: Date.now(),
    trustChangedBy: administrator.id,
    updatedAt: Date.now(),
  });
  await adminAudit(administrator, "ACCOUNT_TRUST_CHANGED", accountId,
      {from: Number(target.trustScore ?? 50), to: trustScore, reason});
  res.json({ok: true, trustScore});
}));

app.post("/api/admin/accounts/:accountId/points", route(async (req, res) => {
  const administrator = await requireAdmin(req, "ADMIN");
  const accountId = String(req.params.accountId || "");
  const target = await read(`accounts/${accountId}`);
  if (!target) fail("Account not found.", 404);
  const amount = Number(req.body.amount);
  const reason = cleanLine(req.body.reason, 300);
  if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 1000 ||
      Math.round(amount * 2) !== amount * 2) {
    fail("Point change must be in 0.5-point steps between -1,000 and 1,000.");
  }
  if (reason.length < 8) fail("Give a reason for changing points.");
  const transactionId = id("pointTransactions");
  const now = Date.now();
  await root.update({
    [`accounts/${accountId}/pointBalance`]: ServerValue.increment(amount),
    [`accounts/${accountId}/updatedAt`]: now,
    [`pointTransactions/${transactionId}`]: {
      accountId,
      amount,
      type: "ADMIN_ADJUSTMENT",
      reason,
      administratorAccountId: administrator.id,
      createdAt: now,
    },
  });
  await adminAudit(administrator, "ACCOUNT_POINTS_CHANGED", accountId, {amount, reason});
  res.json({ok: true, amount, pointBalance: Number(target.pointBalance || 0) + amount});
}));

app.get("/api/admin/support/tickets", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const status = String(req.query.status || "").toUpperCase();
  const tickets = Object.entries(await read("supportTickets") || {})
      .filter(([, ticket]) => !status || ticket.status === status)
      .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0))
      .slice(0, 100)
      .map(([ticketId, ticket]) => publicSupportTicket(ticketId, ticket));
  res.json({ok: true, tickets});
}));

app.post("/api/admin/support/tickets/:ticketId/respond", route(async (req, res) => {
  const administrator = await requireAdmin(req, "SUPPORT");
  const ticketId = String(req.params.ticketId || "");
  const ticket = await read(`supportTickets/${ticketId}`);
  if (!ticket) fail("Support ticket not found.", 404);
  const adminResponse = String(req.body.response || "").trim();
  const status = String(req.body.status || "PENDING").toUpperCase();
  const allowedStatuses = ticket.category === "CONNECTION_CODE_REPLACEMENT" ?
    new Set(["PENDING", "APPROVED", "DECLINED"]) :
    new Set(["PENDING", "ANSWERED", "CLOSED"]);
  if (!allowedStatuses.has(status)) fail("Choose a valid ticket status.");
  if (adminResponse.length < 2 || adminResponse.length > 2000) {
    fail("Response must contain between 2 and 2,000 characters.");
  }
  const now = Date.now();
  await root.child(`supportTickets/${ticketId}`).update({
    adminResponse,
    status,
    respondedByAccountId: administrator.id,
    respondedByName: cleanLine(administrator.administrator.displayName ||
      administrator.data.username, 40),
    respondedAt: now,
    updatedAt: now,
  });
  await adminAudit(administrator, "SUPPORT_TICKET_RESPONDED", ticket.accountId,
      {ticketId, status});
  res.json({ok: true, status});
}));

app.get("/api/admin/support/chats", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const chats = Object.entries(await read("supportChats") || {})
      .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0))
      .slice(0, 50)
      .map(([chatId, chat]) => publicChat(chatId, chat));
  res.json({ok: true, chats});
}));

app.post("/api/admin/support/chats/:chatId/messages", route(async (req, res) => {
  const administrator = await requireAdmin(req, "SUPPORT");
  const chatId = String(req.params.chatId || "");
  const chat = await read(`supportChats/${chatId}`);
  if (!chat) fail("Support chat not found.", 404);
  if (chat.status === "CLOSED") fail("This support chat is closed.", 409);
  const chatMessage = String(req.body.message || "").trim();
  if (chatMessage.length < 1 || chatMessage.length > CHAT_MESSAGE_LIMIT) {
    fail(`Message must contain between 1 and ${CHAT_MESSAGE_LIMIT} characters.`);
  }
  const messageId = id(`supportChats/${chatId}/messages`);
  const now = Date.now();
  const displayName = cleanLine(administrator.administrator.displayName ||
    administrator.data.username, 40);
  await root.update({
    [`supportChats/${chatId}/messages/${messageId}`]: {
      sender: "AGENT", senderName: displayName, message: chatMessage, createdAt: now,
    },
    [`supportChats/${chatId}/status`]: "ACTIVE",
    [`supportChats/${chatId}/assignedAgentAccountId`]: administrator.id,
    [`supportChats/${chatId}/assignedAgentName`]: displayName,
    [`supportChats/${chatId}/updatedAt`]: now,
  });
  await adminAudit(administrator, "SUPPORT_CHAT_MESSAGE", chat.accountId, {chatId});
  res.status(201).json({ok: true, messageId});
}));

app.post("/api/admin/support/chats/:chatId/status", route(async (req, res) => {
  const administrator = await requireAdmin(req, "SUPPORT");
  const chatId = String(req.params.chatId || "");
  const chat = await read(`supportChats/${chatId}`);
  if (!chat) fail("Support chat not found.", 404);
  const status = String(req.body.status || "").toUpperCase();
  if (!["ASSISTANT", "WAITING", "ACTIVE", "CLOSED"].includes(status)) fail("Invalid chat status.");
  const now = Date.now();
  const updates = {
    [`supportChats/${chatId}/status`]: status,
    [`supportChats/${chatId}/updatedAt`]: now,
  };
  if (status === "CLOSED") {
    const messageId = id(`supportChats/${chatId}/messages`);
    updates[`supportChats/${chatId}/closedBy`] = "ADMIN";
    updates[`supportChats/${chatId}/closedAt`] = now;
    updates[`supportChats/${chatId}/messages/${messageId}`] = {
      sender: "SYSTEM",
      senderName: "ScriptNovaa",
      message: "A representative closed this chat. You can start a new conversation whenever you need help.",
      createdAt: now,
    };
  }
  await root.update(updates);
  if (status === "CLOSED") {
    await createLearningCandidate(chatId, chat, administrator);
  }
  await adminAudit(administrator, "SUPPORT_CHAT_STATUS", chat.accountId, {chatId, status});
  res.json({ok: true, status});
}));

app.get("/api/admin/support/learning", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const candidates = Object.entries(await read("supportLearningCandidates") || {})
      .map(([candidateId, candidate]) => ({candidateId, ...candidate}))
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))
      .slice(0, 100);
  res.json({ok: true, candidates});
}));

app.post("/api/admin/support/learning/:candidateId/review", route(async (req, res) => {
  const administrator = await requireAdmin(req, "ADMIN");
  const candidateId = String(req.params.candidateId || "");
  const candidate = await read(`supportLearningCandidates/${candidateId}`);
  if (!candidate) fail("Learning suggestion not found.", 404);
  const status = String(req.body.status || "").toUpperCase();
  if (!["APPROVED", "REJECTED"].includes(status)) fail("Choose approved or rejected.");
  const answer = redactSupportSecrets(String(req.body.answer || "").trim()).slice(0, 800);
  const suppliedKeywords = Array.isArray(req.body.keywords) ? req.body.keywords :
    String(req.body.keywords || "").split(",");
  const keywords = [...new Set(suppliedKeywords.map((item) =>
    String(item || "").trim().toLowerCase().replace(/[^a-z0-9 -]/g, "").slice(0, 40))
      .filter((item) => item.length >= 2))].slice(0, 12);
  if (status === "APPROVED" && (answer.length < 10 || !keywords.length)) {
    fail("Approved guidance needs an answer and at least one matching keyword.");
  }
  const now = Date.now();
  const updates = {
    [`supportLearningCandidates/${candidateId}/status`]: status,
    [`supportLearningCandidates/${candidateId}/reviewedAnswer`]: answer,
    [`supportLearningCandidates/${candidateId}/reviewedKeywords`]: keywords,
    [`supportLearningCandidates/${candidateId}/reviewedByAccountId`]: administrator.id,
    [`supportLearningCandidates/${candidateId}/reviewedAt`]: now,
    [`supportLearningCandidates/${candidateId}/updatedAt`]: now,
  };
  if (status === "APPROVED") {
    updates[`supportKnowledge/${candidateId}`] = {
      active: true,
      answer,
      keywords,
      sourceChatId: candidate.chatId || candidateId,
      approvedByAccountId: administrator.id,
      approvedAt: now,
      updatedAt: now,
    };
  } else {
    updates[`supportKnowledge/${candidateId}`] = null;
  }
  await root.update(updates);
  await adminAudit(administrator, "SUPPORT_LEARNING_REVIEWED", null,
      {candidateId, status, keywords});
  res.json({ok: true, status});
}));

app.get("/api/admin/appeals", route(async (req, res) => {
  await requireAdmin(req, "SUPPORT");
  const appeals = Object.entries(await read("appeals") || {})
      .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0))
      .slice(0, 100)
      .map(([appealId, appeal]) => publicAppeal(appealId, appeal));
  res.json({ok: true, appeals});
}));

app.post("/api/admin/appeals/:appealId/review", route(async (req, res) => {
  const administrator = await requireAdmin(req, "ADMIN");
  const appealId = String(req.params.appealId || "");
  const appeal = await read(`appeals/${appealId}`);
  if (!appeal) fail("Appeal not found.", 404);
  if (appeal.status !== "PENDING") fail("This appeal has already been reviewed.", 409);
  const status = String(req.body.status || "").toUpperCase();
  if (!["APPROVED", "DENIED"].includes(status)) fail("Choose approved or denied.");
  const adminResponse = String(req.body.response || "").trim();
  if (adminResponse.length < 10 || adminResponse.length > 2000) {
    fail("Appeal response must contain between 10 and 2,000 characters.");
  }
  const now = Date.now();
  const updates = {
    [`appeals/${appealId}/status`]: status,
    [`appeals/${appealId}/adminResponse`]: adminResponse,
    [`appeals/${appealId}/reviewedByAccountId`]: administrator.id,
    [`appeals/${appealId}/reviewedAt`]: now,
    [`appeals/${appealId}/updatedAt`]: now,
  };
  if (status === "APPROVED" && req.body.restoreAccount === true) {
    updates[`accounts/${appeal.accountId}/accountStatus`] = "ACTIVE";
    updates[`accounts/${appeal.accountId}/statusReason`] = null;
    updates[`accounts/${appeal.accountId}/statusEndsAt`] = null;
    updates[`accounts/${appeal.accountId}/statusChangedAt`] = now;
    updates[`accounts/${appeal.accountId}/statusChangedBy`] = administrator.id;
    updates[`accounts/${appeal.accountId}/updatedAt`] = now;
  }
  await root.update(updates);
  await adminAudit(administrator, "ACCOUNT_APPEAL_REVIEWED", appeal.accountId,
      {appealId, status, restored: status === "APPROVED" && req.body.restoreAccount === true});
  res.json({ok: true, status});
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
