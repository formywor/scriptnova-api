"use strict";
const crypto = require("crypto");
const PUBLIC_RETENTION_MS = 48 * 60 * 60 * 1000;
const EDIT_WINDOW_MS = 2 * 60 * 1000;
const CHAT_BAN_MS = 2 * 24 * 60 * 60 * 1000;
const CHAT_UNBAN_FEE = 8;
const TYPING_TTL_MS = 9000;
const PRESENCE_TTL_MS = 90000;
const BETA_AVATAR_MAX_BYTES = 96 * 1024;
const ACCENTS = new Set(["violet", "mint", "blue", "rose", "amber"]);
const BETA_ACCENTS = new Set(["cosmic", "electric"]);
const AVATARS = new Set(["nova", "orbit", "pixel", "bolt", "wave", "game"]);
const BETA_AVATARS = new Set(["prism", "comet", "signal"]);
const BETA_FRAMES = new Set(["none", "aurora", "starlight", "pulse"]);
const BAD_WORDS = ["fuck", "shit", "bitch", "nigger", "faggot", "cunt", "kike", "spic", "chink",
  "retard", "tranny", "whore", "slut"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "grabify.link", "iplogger.org"];

function cleanText(value, maximum) {
  return String(value || "").trim().replace(/\r\n?/g, "\n").replace(/\n{3,}/g, "\n\n").slice(0, maximum);
}
function cleanDisplayName(value, fallback) {
  const name = String(value || "").trim().replace(/\s+/g, " ").slice(0, 32);
  return name || String(fallback || "User").slice(0, 32);
}
function conversationKey(a, b) {
  return crypto.createHash("sha256").update([String(a), String(b)].sort().join(":")).digest("hex").slice(0, 32);
}
function activeTyping(entries, now = Date.now(), except = "") {
  return Object.entries(entries || {}).filter(([key, item]) => key !== except && Number(item.expiresAt || 0) > now)
      .map(([accountId, item]) => ({accountId, displayName: cleanDisplayName(item.displayName, item.username)}));
}
function typingLabel(people) {
  if (!people.length) return "";
  if (people.length >= 4) return "Several people are typing…";
  if (people.length === 1) return `${people[0].displayName} is typing…`;
  return `${people.map((p) => p.displayName).join(", ")} are typing…`;
}
function normalizedMessage(text) {
  return cleanText(text, 1000).toLowerCase().replace(/https?:\/\/\S+/g, "[link]").replace(/[^a-z0-9]+/g, " ").trim();
}
function moderationText(value) {
  return cleanText(value, 1000).normalize("NFKC").toLowerCase()
      .replace(/[@4]/g, "a").replace(/[3]/g, "e").replace(/[1!|]/g, "i")
      .replace(/[0]/g, "o").replace(/[$5]/g, "s").replace(/[7]/g, "t");
}
function abusiveWordPattern(word) {
  const letters = String(word).replace(/[^a-z0-9]/gi, "").split("")
      .map((letter) => letter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`(?:^|[^a-z0-9])${letters.join("[^a-z0-9]*")}(?:s|es|ed|ing)?(?:$|[^a-z0-9])`, "i");
}
function assessMessage(text) {
  const value = cleanText(text, 1000); const lower = moderationText(value);
  if (/\b(?:javascript|data|file|vbscript):/i.test(value)) return {ok: false, reason: "Dangerous links are not allowed."};
  if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i.test(value)) return {ok: false, reason: "Direct-IP links are not allowed in chat."};
  if (SHORTENERS.some((host) => lower.includes(host))) return {ok: false, reason: "Shortened or tracking links are not allowed."};
  if (BAD_WORDS.some((word) => abusiveWordPattern(word).test(lower))) return {ok: false, reason: "That message contains prohibited abusive language."};
  if (/\b(?:kill|hurt|attack|doxx?)\s+(?:you|yourself|them|him|her)\b/i.test(lower) ||
      /\b(?:go\s+)?kill\s+yourself\b/i.test(lower)) return {ok: false, reason: "Threats and targeted harm are not allowed."};
  if (/(.)\1{14,}/.test(value) || /(.{3,30})\1{4,}/i.test(value)) return {ok: false, reason: "Repeated spam is not allowed."};
  return {ok: true};
}

function nextWarningState(current, now = Date.now()) {
  const windowStartedAt = Number(current.chatWarningWindowStartedAt || 0);
  const warningCount = now - windowStartedAt < 30 * 86400000 ? Number(current.chatWarningCount || 0) : 0;
  const nextCount = Math.min(2, warningCount + 1);
  return {
    chatWarningCount: nextCount,
    chatWarningWindowStartedAt: warningCount ? windowStartedAt : now,
    chatBannedUntil: nextCount >= 2 ? now + CHAT_BAN_MS : Number(current.chatBannedUntil || 0),
  };
}
function warningStateWithHistory(current, notifications, now = Date.now()) {
  const fresh = {...current};
  const oldBan = Number(fresh.chatBannedUntil || 0);
  if (oldBan && oldBan <= now) {
    fresh.chatWarningCount = 0; fresh.chatWarningWindowStartedAt = 0; fresh.chatBannedUntil = 0;
    return nextWarningState(fresh, now);
  }
  const recent = (notifications || []).filter((item) =>
    item?.type === "CHAT_WARNING" && Number(item.createdAt || 0) > now - 30 * 86400000);
  if (!Number(fresh.chatWarningCount || 0) && recent.length) {
    fresh.chatWarningCount = 1;
    fresh.chatWarningWindowStartedAt = Math.min(...recent.map((item) => Number(item.createdAt)));
  }
  return nextWarningState(fresh, now);
}

function chatUnbanEligibility(account, now = Date.now()) {
  const bannedUntil = Number(account?.chatBannedUntil || 0);
  if (bannedUntil <= now) return {allowed: false, reason: "Chat is not currently paused."};
  if (String(account?.chatBanSource || "AUTOMATIC").toUpperCase() === "ADMIN") {
    return {allowed: false, reason: "Administrator chat bans must be appealed through Support."};
  }
  if (Number(account?.pointBalance || 0) < CHAT_UNBAN_FEE) {
    return {allowed: false, reason: `You need ${CHAT_UNBAN_FEE} points to restore chat access.`};
  }
  return {allowed: true, fee: CHAT_UNBAN_FEE};
}

function cleanAvatarDataUrl(value) {
  const text = String(value || "");
  if (!text) return "";
  const match = text.match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/i);
  if (!match) throw new Error("Beta profile pictures must be PNG, JPEG, or WebP images.");
  const bytes = Math.floor(match[2].replace(/=/g, "").length * 3 / 4);
  if (bytes > BETA_AVATAR_MAX_BYTES) throw new Error("Beta profile pictures must be smaller than 96 KB.");
  return `data:image/${match[1].toLowerCase()};base64,${match[2]}`;
}
function safeAvatarDataUrl(value) {
  try { return cleanAvatarDataUrl(value); } catch (_) { return ""; }
}

function betaAccess(account, administrator) {
  return Boolean(administrator?.active || account?.developerProgramStatus === "APPROVED" ||
    account?.developer || account?.betaProgramStatus === "ACTIVE");
}

function pointRecognition(value) {
  const points = Math.max(0, Number(value || 0));
  if (points >= 5000) return {points, tier: "supernova", label: "SUPERNOVA", badges: ["CENTURY", "NOVA500", "POINTSTAR", "SUPERNOVA"]};
  if (points >= 1000) return {points, tier: "legendary", label: "POINTSTAR", badges: ["CENTURY", "NOVA500", "POINTSTAR"]};
  if (points >= 500) return {points, tier: "rare", label: "NOVA500", badges: ["CENTURY", "NOVA500"]};
  if (points >= 100) return {points, tier: "century", label: "CENTURY", badges: ["CENTURY"]};
  return {points, tier: "standard", label: "MEMBER", badges: []};
}

async function translateWithGemini(texts, targetLanguage, fetcher = fetch,
    apiKey = process.env.GEMINI_API_KEY) {
  if (!apiKey) return null;
  const model = process.env.GEMINI_MODEL || "gemini-3.5-flash-lite";
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 9000);
  try {
    const response = await fetcher(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
      method: "POST", signal: controller.signal, headers: {"Content-Type": "application/json", "x-goog-api-key": apiKey},
      body: JSON.stringify({contents: [{parts: [{text: `Translate each JSON string into ${targetLanguage}. Preserve meaning, tone, usernames, URLs and emoji. Return only a JSON array of translated strings in the same order. Input: ${JSON.stringify(texts)}`}]}],
        generationConfig: {temperature: 0.1, responseMimeType: "application/json"}}),
    });
    if (!response.ok) return null;
    const body = await response.json(); const raw = body?.candidates?.[0]?.content?.parts?.[0]?.text;
    const parsed = JSON.parse(String(raw || "[]"));
    return Array.isArray(parsed) && parsed.length === texts.length ? parsed.map((item) => cleanText(item, 1000)) : null;
  } catch (_) { return null; } finally { clearTimeout(timer); }
}

function mountCommunity(app, d) {
  const {route, root, read, id, rateLimit, requireAccount, requireAdmin, adminAudit, fail, etagTransaction, atomic} = d;
  async function profileFor(accountId, accountData) {
    const account = accountData || await read(`accounts/${accountId}`); if (!account) return null;
    const stored = await read(`profiles/${accountId}`) || {}; const admin = await read(`administrators/${accountId}`); const badges = [];
    if (admin?.active) badges.push(String(admin.role).toUpperCase() === "ADMIN" ? "ADMIN" : "STAFF");
    if (account.developerProgramStatus === "APPROVED" || account.developer) badges.push("DEVELOPER");
    const isBeta = betaAccess(account, admin); if (isBeta) badges.push("BETA");
    if (Date.now() - Number(account.createdAt || 0) < 7 * 86400000) badges.push("NEW");
    const recognition = pointRecognition(account.pointBalance);
    recognition.badges.forEach((badge) => badges.push(badge));
    return {accountId, username: String(account.username || ""), displayName: cleanDisplayName(stored.displayName, account.username),
      bio: cleanText(stored.bio, 160), accent: (ACCENTS.has(stored.accent) || (isBeta && BETA_ACCENTS.has(stored.accent))) ? stored.accent : "violet",
      avatarId: (AVATARS.has(stored.avatarId) || (isBeta && BETA_AVATARS.has(stored.avatarId))) ? stored.avatarId : "nova",
      avatarImage: isBeta ? safeAvatarDataUrl(stored.avatarImage || "") : "", betaAccess: isBeta,
      betaStatus: isBeta ? cleanText(stored.betaStatus, 60) : "",
      betaFrame: isBeta && BETA_FRAMES.has(stored.betaFrame) ? stored.betaFrame : "none",
      pointBalance: recognition.points, pointTier: recognition.tier, pointTierLabel: recognition.label,
      privacyMode: stored.privacyMode !== false,
      allowDirectMessages: stored.allowDirectMessages !== false, showLastActive: stored.showLastActive === true,
      browserNotifications: stored.browserNotifications === true, autoTranslateChat: stored.autoTranslateChat !== false,
      chatLanguage: String(stored.chatLanguage || "AUTO").slice(0, 20), badges, createdAt: Number(account.createdAt || 0),
      accountStatus: ["BANNED", "SUSPENDED", "TERMINATED"].includes(String(account.status || "").toUpperCase()) ? "RESTRICTED" : "ACTIVE",
      chatWarnings: Number(account.chatWarningCount || 0), chatBannedUntil: Number(account.chatBannedUntil || 0),
      chatBanReason: cleanText(account.chatBanReason || account.lastChatWarningReason, 300),
      chatBanSource: String(account.chatBanSource || "AUTOMATIC").toUpperCase(),
      chatUnbanFee: CHAT_UNBAN_FEE,
      paidChatUnbanAllowed: Number(account.chatBannedUntil || 0) > Date.now() &&
        String(account.chatBanSource || "AUTOMATIC").toUpperCase() !== "ADMIN",
      paidChatUnbanAffordable: Number(account.pointBalance || 0) >= CHAT_UNBAN_FEE};
  }
  const visibleProfile = (p) => p && ({accountId: p.accountId, username: p.username, displayName: p.displayName,
    bio: p.bio, accent: p.accent, avatarId: p.avatarId, avatarImage: p.avatarImage, badges: p.badges,
    betaStatus: p.betaStatus, betaFrame: p.betaFrame, pointBalance: p.pointBalance,
    pointTier: p.pointTier, pointTierLabel: p.pointTierLabel, createdAt: p.createdAt});
  async function presenceFor(accountId, profile) {
    const item = await read(`communityPresence/${accountId}`) || {}; const active = Number(item.expiresAt || 0) > Date.now();
    return {state: active ? (item.state === "IDLE" ? "IDLE" : "ONLINE") : "OFFLINE",
      lastActiveAt: profile?.showLastActive ? Number(item.lastActiveAt || 0) : null};
  }
  async function requireChat(account) {
    if (Number(account.data.chatBannedUntil || 0) > Date.now()) fail(`Chat is paused until ${new Date(account.data.chatBannedUntil).toISOString()}.`, 403, "CHAT_BANNED");
  }
  async function warn(account, reason) {
    const now = Date.now(); const notificationId = id(`notifications/${account.id}`);
    const existingWarnings = Object.values(await read(`notifications/${account.id}`) || {});
    const transaction = await etagTransaction(`accounts/${account.id}`, (fresh) => {
      if (!fresh) fail("Account not found.", 404);
      const state = Number(fresh.chatBannedUntil || 0) > now ? {
        chatWarningCount: Math.max(2, Number(fresh.chatWarningCount || 0)),
        chatWarningWindowStartedAt: Number(fresh.chatWarningWindowStartedAt || now),
        chatBannedUntil: Number(fresh.chatBannedUntil),
      } : warningStateWithHistory(fresh, existingWarnings, now);
      Object.assign(fresh, state, {lastChatWarningReason: reason,
        chatBanReason: state.chatBannedUntil > now ? reason : String(fresh.chatBanReason || ""),
        chatBanSource: state.chatBannedUntil > now ? "AUTOMATIC" : String(fresh.chatBanSource || "AUTOMATIC"),
        updatedAt: now});
      return fresh;
    });
    if (!transaction.committed) fail("The warning could not be recorded. Try again.", 409);
    const updated = transaction.value || {};
    const outcome = {warningCount: Number(updated.chatWarningCount || 0), bannedUntil: Number(updated.chatBannedUntil || 0)};
    await root.child(`notifications/${account.id}/${notificationId}`).set({type: "CHAT_WARNING",
      title: outcome.bannedUntil > now ? "Chat paused for two days" : "Chat safety warning",
      message: reason, createdAt: now, readAt: null});
    return outcome;
  }
  async function validatePost(account, text, channel) {
    await requireChat(account); const check = assessMessage(text); const state = await read(`communityPostState/${account.id}`) || {};
    const repeated = normalizedMessage(text) && normalizedMessage(text) === state.lastNormalizedText && Date.now() - Number(state.lastMessageAt || 0) < 120000;
    if (!check.ok || repeated) { const reason = repeated ? "Repeated-message spam is not allowed." : check.reason; const result = await warn(account, reason);
      fail(`${reason} Warning recorded.${result.bannedUntil ? " Chat is paused for two days." : " One more active warning will pause chat for two days."}`, 403, result.bannedUntil ? "CHAT_BANNED" : "CHAT_WARNING"); }
    await root.child(`communityPostState/${account.id}`).update({lastNormalizedText: normalizedMessage(text), lastMessageAt: Date.now(), channel});
  }
  async function threadMember(req, threadId) {
    const account = await requireAccount(req); await requireChat(account); const thread = await read(`communityPrivateThreads/${threadId}`);
    if (!thread || thread.members?.[account.id] !== true) fail("Private conversation not found.", 404); return {account, thread};
  }
  const publicMessage = (messageId, m) => ({messageId, accountId: m.accountId, username: String(m.username || "Unknown"),
    displayName: String(m.displayName || m.username || "Unknown"), avatarId: m.avatarId || "nova",
    avatarImage: safeAvatarDataUrl(m.avatarImage || ""), badges: Array.isArray(m.badges) ? m.badges.slice(0, 10) : [],
    pointTier: String(m.pointTier || "standard"), betaFrame: String(m.betaFrame || "none"),
    text: cleanText(m.text, 500), createdAt: Number(m.createdAt || 0), editedAt: Number(m.editedAt || 0) || null, deleted: m.deleted === true});
  async function cleanupPublicMessages() {
    const now = Date.now(); const lock = await root.child("communityMaintenance/publicCleanup").transaction((value) => {
      if (Number(value?.checkedAt || 0) > now - 5 * 60 * 1000) return; return {checkedAt: now};
    }, undefined, false); if (!lock.committed) return;
    const snapshot = await root.child("communityPublicMessages").orderByChild("createdAt").endAt(now - PUBLIC_RETENTION_MS).limitToFirst(250).get();
    const updates = {}; Object.keys(snapshot.val() || {}).forEach((key) => { updates[`communityPublicMessages/${key}`] = null; });
    if (Object.keys(updates).length) await root.update(updates);
  }

  app.get("/api/community/summary", route(async (req, res) => {
    const a = await requireAccount(req); const profile = await profileFor(a.id, a.data); const threads = await read("communityPrivateThreads") || {};
    const unreadCount = Object.values(threads).filter((t) => t.members?.[a.id] && t.lastSenderAccountId !== a.id && Number(t.updatedAt || 0) > Number(t.lastReadAt?.[a.id] || 0)).length;
    const notes = await read(`notifications/${a.id}`) || {}; res.json({ok: true, profile, unreadCount, notificationCount: Object.values(notes).filter((n) => !n.readAt).length});
  }));
  app.post("/api/community/unban-purchase", route(async (req, res) => {
    const a = await requireAccount(req); await rateLimit(a.id, "CHAT_UNBAN_PURCHASE", 4, 24 * 60 * 60);
    const now = Date.now(); const transactionId = id("pointTransactions"); const notificationId = id(`notifications/${a.id}`);
    let balance = 0;
    await atomic((data) => {
      const account = data.accounts?.[a.id]; if (!account) fail("Account not found.", 404);
      const eligibility = chatUnbanEligibility(account, now); if (!eligibility.allowed) fail(eligibility.reason, 403, "CHAT_UNBAN_UNAVAILABLE");
      balance = Number(account.pointBalance || 0) - CHAT_UNBAN_FEE;
      Object.assign(account, {pointBalance: balance, chatWarningCount: 0, chatWarningWindowStartedAt: 0,
        chatBannedUntil: 0, chatBanReason: "", chatBanSource: "", lastPaidChatUnbanAt: now, updatedAt: now});
      data.pointTransactions ||= {}; data.pointTransactions[transactionId] = {accountId: a.id,
        amount: -CHAT_UNBAN_FEE, type: "CHAT_UNBAN_FEE", reason: "Self-service chat access restoration", createdAt: now};
      data.notifications ||= {}; data.notifications[a.id] ||= {}; data.notifications[a.id][notificationId] = {
        type: "CHAT_RESTORED", title: "Chat access restored", message: `${CHAT_UNBAN_FEE} points were used to restore chat access. Future safety violations can pause chat again.`, createdAt: now, readAt: null};
      return data;
    });
    res.json({ok: true, fee: CHAT_UNBAN_FEE, pointBalance: balance});
  }));
  app.get("/api/profile/me", route(async (req, res) => { const a = await requireAccount(req); res.json({ok: true, profile: await profileFor(a.id, a.data)}); }));
  app.get("/api/profiles/:username", route(async (req, res) => {
    const viewer = await requireAccount(req); const record = await read(`usernames/${String(req.params.username || "").toLowerCase()}`);
    if (!record?.accountId) fail("User not found.", 404);
    const [p, blocked, muted] = await Promise.all([profileFor(record.accountId),
      read(`communityBlocks/${viewer.id}/${record.accountId}`), read(`communityMutes/${viewer.id}/${record.accountId}`)]);
    if (!p) fail("User not found.", 404);
    res.json({ok: true, profile: {...visibleProfile(p), presence: await presenceFor(record.accountId, p),
      isSelf: record.accountId === viewer.id, accountStatus: p.accountStatus,
      chatStatus: Number(p.chatBannedUntil || 0) > Date.now() ? "PAUSED" : "ACTIVE",
      relationship: {blocked: Boolean(blocked), muted: Boolean(muted)},
      referralUrl: `https://scriptnovaa.com/signup?ref=${encodeURIComponent(p.username)}`}});
  }));
  app.patch("/api/profile/me", route(async (req, res) => {
    const a = await requireAccount(req); await rateLimit(a.id, "PROFILE_UPDATE", 20, 3600); const old = await profileFor(a.id, a.data);
    const displayName = cleanDisplayName(req.body.displayName, a.data.username); const accent = String(req.body.accent || old.accent); const avatarId = String(req.body.avatarId || old.avatarId);
    if (displayName.length < 2 || !(ACCENTS.has(accent) || (old.betaAccess && BETA_ACCENTS.has(accent))) ||
        !(AVATARS.has(avatarId) || (old.betaAccess && BETA_AVATARS.has(avatarId)))) fail("Choose an available profile style.");
    let avatarImage = old.avatarImage || "";
    if (Object.hasOwn(req.body, "avatarImage")) {
      if (!old.betaAccess && req.body.avatarImage) fail("Custom profile pictures are a Beta feature.", 403);
      try { avatarImage = cleanAvatarDataUrl(req.body.avatarImage); } catch (error) { fail(error.message); }
    }
    const chatLanguage = String(req.body.chatLanguage || "AUTO").toUpperCase();
    if (!/^(AUTO|[A-Z]{2,3}(?:-[A-Z]{2})?)$/.test(chatLanguage)) fail("Choose a valid chat language.");
    const betaStatus = cleanText(req.body.betaStatus, 60);
    if (betaStatus && !old.betaAccess) fail("Beta profile status is a Beta feature.", 403);
    const betaFrame = String(req.body.betaFrame || "none").toLowerCase();
    if (!BETA_FRAMES.has(betaFrame) || (!old.betaAccess && betaFrame !== "none")) fail("Choose an available Beta profile frame.", 403);
    await root.child(`profiles/${a.id}`).update({displayName, bio: cleanText(req.body.bio, 160), accent, avatarId, avatarImage,
      betaStatus: old.betaAccess ? betaStatus : "", betaFrame: old.betaAccess ? betaFrame : "none",
      privacyMode: req.body.privacyMode !== false, allowDirectMessages: req.body.allowDirectMessages !== false,
      showLastActive: req.body.showLastActive === true, browserNotifications: req.body.browserNotifications === true,
      autoTranslateChat: req.body.autoTranslateChat !== false, chatLanguage, updatedAt: Date.now()});
    res.json({ok: true, profile: await profileFor(a.id, a.data)});
  }));
  app.get("/api/community/users", route(async (req, res) => {
    const a = await requireAccount(req); const q = String(req.query.query || "").toLowerCase(); if (q.length < 2) return res.json({ok: true, users: []});
    const names = await read("usernames") || {}; const found = Object.entries(names).filter(([name, v]) => name.includes(q) && v.accountId !== a.id).slice(0, 10);
    const users = await Promise.all(found.map(async ([, v]) => { const p = await profileFor(v.accountId); return {...visibleProfile(p), presence: await presenceFor(v.accountId, p)}; })); res.json({ok: true, users});
  }));
  app.post("/api/community/presence", route(async (req, res) => {
    const a = await requireAccount(req); const wanted = String(req.body.state || "ONLINE").toUpperCase(); const state = ["ONLINE", "IDLE", "OFFLINE"].includes(wanted) ? wanted : "ONLINE"; const now = Date.now();
    await root.child(`communityPresence/${a.id}`).set({state, lastActiveAt: now, expiresAt: state === "OFFLINE" ? now : now + PRESENCE_TTL_MS}); res.json({ok: true, state});
  }));

  app.get("/api/community/public", route(async (req, res) => {
    const a = await requireAccount(req); await requireChat(a); await cleanupPublicMessages(); const [blocks, mutes] = await Promise.all([read(`communityBlocks/${a.id}`), read(`communityMutes/${a.id}`)]);
    const snap = await root.child("communityPublicMessages").orderByChild("createdAt").limitToLast(100).get(); const now = Date.now(); const presence = await read("communityPresence") || {};
    const messages = Object.entries(snap.val() || {}).filter(([, m]) => Number(m.createdAt || 0) > now - PUBLIC_RETENTION_MS && !blocks?.[m.accountId] && !mutes?.[m.accountId]).map(([key, m]) => ({...publicMessage(key, m), presence: Number(presence[m.accountId]?.expiresAt || 0) > now ? (presence[m.accountId].state === "IDLE" ? "IDLE" : "ONLINE") : "OFFLINE"}));
    const people = activeTyping(await read("communityTyping/public"), now, a.id); const config = await read("communityConfig") || {};
    res.json({ok: true, messages, typingLabel: typingLabel(people), retentionHours: 48, slowModeSeconds: Number(config.publicSlowModeSeconds || 0)});
  }));
  app.post("/api/community/public/messages", route(async (req, res) => {
    const a = await requireAccount(req); await rateLimit(a.id, "COMMUNITY_PUBLIC_MESSAGE", 30, 60); const text = cleanText(req.body.text, 500); if (!text) fail("Write a message first.");
    const [config, post] = await Promise.all([read("communityConfig"), read(`communityPostState/${a.id}`)]); const wait = Number(config?.publicSlowModeSeconds || 0) * 1000 - (Date.now() - Number(post?.lastPublicAt || 0));
    if (wait > 0) fail(`Slow mode is on. Wait ${Math.ceil(wait / 1000)} seconds.`, 429); await validatePost(a, text, "PUBLIC"); const p = await profileFor(a.id, a.data); const messageId = id("communityPublicMessages"); const now = Date.now();
    const stored = {accountId: a.id, username: a.data.username, displayName: p.displayName, avatarId: p.avatarId, avatarImage: p.avatarImage, badges: p.badges, pointTier: p.pointTier, betaFrame: p.betaFrame, text, createdAt: now, deleteAfter: now + PUBLIC_RETENTION_MS};
    await root.update({[`communityPublicMessages/${messageId}`]: stored, [`communityPostState/${a.id}/lastPublicAt`]: now, [`communityTyping/public/${a.id}`]: null}); res.status(201).json({ok: true, message: publicMessage(messageId, stored)});
  }));
  app.patch("/api/community/public/messages/:messageId", route(async (req, res) => {
    const a = await requireAccount(req); const path = `communityPublicMessages/${req.params.messageId}`; const item = await read(path); if (!item || item.accountId !== a.id) fail("Message not found.", 404);
    if (Date.now() - Number(item.createdAt) > EDIT_WINDOW_MS) fail("Messages can only be edited for two minutes.", 409); const text = cleanText(req.body.text, 500); if (!text) fail("Write a message first."); await validatePost(a, text, "PUBLIC_EDIT"); await root.child(path).update({text, editedAt: Date.now()}); res.json({ok: true});
  }));
  app.delete("/api/community/public/messages/:messageId", route(async (req, res) => { const a = await requireAccount(req); const path = `communityPublicMessages/${req.params.messageId}`; const item = await read(path); if (!item || item.accountId !== a.id) fail("Message not found.", 404); await root.child(path).update({text: "", deleted: true, deletedAt: Date.now()}); res.json({ok: true}); }));
  app.post("/api/community/public/typing", route(async (req, res) => { const a = await requireAccount(req); const path = `communityTyping/public/${a.id}`; if (req.body.typing !== true) await root.child(path).remove(); else { const p = await profileFor(a.id, a.data); await root.child(path).set({displayName: p.displayName, expiresAt: Date.now() + TYPING_TTL_MS}); } res.json({ok: true}); }));

  app.get("/api/community/private", route(async (req, res) => {
    const a = await requireAccount(req); await requireChat(a); const all = await read("communityPrivateThreads") || {}; const rows = Object.entries(all).filter(([, t]) => t.members?.[a.id]).sort((x, y) => Number(y[1].updatedAt || 0) - Number(x[1].updatedAt || 0)).slice(0, 50);
    const threads = await Promise.all(rows.map(async ([threadId, t]) => { const otherId = Object.keys(t.members).find((key) => key !== a.id); const p = await profileFor(otherId); return {threadId, other: {...visibleProfile(p), presence: await presenceFor(otherId, p)}, preview: String(t.lastMessagePreview || ""), unread: t.lastSenderAccountId !== a.id && Number(t.updatedAt || 0) > Number(t.lastReadAt?.[a.id] || 0)}; })); res.json({ok: true, threads});
  }));
  app.post("/api/community/private/start", route(async (req, res) => {
    const a = await requireAccount(req); await requireChat(a); const record = await read(`usernames/${String(req.body.username || "").toLowerCase()}`); if (!record?.accountId || record.accountId === a.id) fail("Choose another user."); const target = await profileFor(record.accountId); if (!target.allowDirectMessages) fail("This user has disabled private messages.", 403);
    if (await read(`communityBlocks/${a.id}/${record.accountId}`) || await read(`communityBlocks/${record.accountId}/${a.id}`)) fail("Private messaging is unavailable between these accounts.", 403);
    const threadId = conversationKey(a.id, record.accountId); if (!await read(`communityPrivateThreads/${threadId}`)) { const now = Date.now(); await root.child(`communityPrivateThreads/${threadId}`).set({members: {[a.id]: true, [record.accountId]: true}, createdAt: now, updatedAt: now, lastReadAt: {[a.id]: now, [record.accountId]: 0}}); }
    res.json({ok: true, threadId, other: visibleProfile(target)});
  }));
  app.get("/api/community/private/:threadId/messages", route(async (req, res) => { const {account, thread} = await threadMember(req, req.params.threadId); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const messages = Object.entries(values).sort((x, y) => Number(x[1].createdAt) - Number(y[1].createdAt)).slice(-100).map(([messageId, m]) => ({messageId, ...m, senderAvatarImage: safeAvatarDataUrl(m.senderAvatarImage || ""), text: cleanText(m.text, 1000)})); const people = activeTyping(await read(`communityTyping/private/${req.params.threadId}`), Date.now(), account.id); res.json({ok: true, messages, typingLabel: typingLabel(people), lastReadAt: thread.lastReadAt || {}}); }));
  app.post("/api/community/private/:threadId/messages", route(async (req, res) => {
    const {account, thread} = await threadMember(req, req.params.threadId); await rateLimit(account.id, "COMMUNITY_PRIVATE_MESSAGE", 40, 60); const otherId = Object.keys(thread.members).find((key) => key !== account.id); const target = await profileFor(otherId); if (!target.allowDirectMessages || await read(`communityBlocks/${otherId}/${account.id}`)) fail("This user is not accepting private messages.", 403);
    const text = cleanText(req.body.text, 1000); if (!text) fail("Write a message first."); await validatePost(account, text, "PRIVATE"); const p = await profileFor(account.id, account.data); const messageId = id(`communityPrivateMessages/${req.params.threadId}`); const noteId = id(`notifications/${otherId}`); const now = Date.now();
    const stored = {senderAccountId: account.id, senderUsername: account.data.username, senderDisplayName: p.displayName, senderAvatarId: p.avatarId, senderAvatarImage: p.avatarImage, senderBadges: p.badges, senderPointTier: p.pointTier, senderBetaFrame: p.betaFrame, text, createdAt: now, readBy: {[account.id]: now}};
    await root.update({[`communityPrivateMessages/${req.params.threadId}/${messageId}`]: stored, [`communityPrivateThreads/${req.params.threadId}/updatedAt`]: now, [`communityPrivateThreads/${req.params.threadId}/lastSenderAccountId`]: account.id, [`communityPrivateThreads/${req.params.threadId}/lastMessagePreview`]: text.slice(0, 90), [`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: now, [`communityTyping/private/${req.params.threadId}/${account.id}`]: null, [`notifications/${otherId}/${noteId}`]: {type: "PRIVATE_MESSAGE", title: `Message from ${p.displayName}`, message: text.slice(0, 120), createdAt: now, readAt: null}}); res.status(201).json({ok: true, message: {messageId, ...stored}});
  }));
  app.patch("/api/community/private/:threadId/messages/:messageId", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityPrivateMessages/${req.params.threadId}/${req.params.messageId}`; const item = await read(path); if (!item || item.senderAccountId !== account.id) fail("Message not found.", 404); if (Date.now() - Number(item.createdAt) > EDIT_WINDOW_MS) fail("Messages can only be edited for two minutes.", 409); const text = cleanText(req.body.text, 1000); await validatePost(account, text, "PRIVATE_EDIT"); await root.child(path).update({text, editedAt: Date.now()}); res.json({ok: true}); }));
  app.delete("/api/community/private/:threadId/messages/:messageId", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityPrivateMessages/${req.params.threadId}/${req.params.messageId}`; const item = await read(path); if (!item || item.senderAccountId !== account.id) fail("Message not found.", 404); await root.child(path).update({text: "", deleted: true, deletedAt: Date.now()}); res.json({ok: true}); }));
  app.post("/api/community/private/:threadId/read", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const now = Date.now(); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const updates = {[`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: now}; Object.entries(values).forEach(([key, m]) => { if (m.senderAccountId !== account.id) updates[`communityPrivateMessages/${req.params.threadId}/${key}/readBy/${account.id}`] = now; }); await root.update(updates); res.json({ok: true}); }));
  app.post("/api/community/private/:threadId/typing", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityTyping/private/${req.params.threadId}/${account.id}`; if (req.body.typing !== true) await root.child(path).remove(); else { const p = await profileFor(account.id, account.data); await root.child(path).set({displayName: p.displayName, expiresAt: Date.now() + TYPING_TTL_MS}); } res.json({ok: true}); }));

  app.post("/api/community/relationships/:username", route(async (req, res) => { const a = await requireAccount(req); const record = await read(`usernames/${String(req.params.username || "").toLowerCase()}`); if (!record?.accountId || record.accountId === a.id) fail("User not found.", 404); const action = String(req.body.action || "").toUpperCase(); const base = action.includes("BLOCK") ? "communityBlocks" : action.includes("MUTE") ? "communityMutes" : ""; if (!base) fail("Choose block, unblock, mute, or unmute."); const ref = root.child(`${base}/${a.id}/${record.accountId}`); if (action.startsWith("UN")) await ref.remove(); else await ref.set({createdAt: Date.now()}); res.json({ok: true, action}); }));
  app.get("/api/community/relationships", route(async (req, res) => { const a = await requireAccount(req); const [blocks, mutes] = await Promise.all([read(`communityBlocks/${a.id}`), read(`communityMutes/${a.id}`)]); const make = async (values, kind) => Promise.all(Object.keys(values || {}).map(async (accountId) => ({kind, profile: visibleProfile(await profileFor(accountId))}))); res.json({ok: true, relationships: [...await make(blocks, "BLOCKED"), ...await make(mutes, "MUTED")]}); }));
  app.post("/api/community/translate", route(async (req, res) => {
    const a = await requireAccount(req); await rateLimit(a.id, "COMMUNITY_TRANSLATE", 30, 60 * 60);
    const targetLanguage = String(req.body.targetLanguage || "").trim().slice(0, 40);
    const texts = Array.isArray(req.body.texts) ? req.body.texts.slice(0, 12).map((item) => cleanText(item, 1000)) : [];
    if (!/^[A-Za-z]{2,3}(?:-[A-Za-z]{2})?$/.test(targetLanguage) || !texts.length || texts.some((item) => !item)) {
      fail("Choose a valid language and messages to translate.");
    }
    const translated = await translateWithGemini(texts, targetLanguage);
    res.json({ok: true, available: Boolean(translated), translations: translated || texts});
  }));
  app.post("/api/community/messages/report", route(async (req, res) => { const a = await requireAccount(req); await rateLimit(a.id, "COMMUNITY_REPORT", 10, 3600); const scope = String(req.body.scope || "PUBLIC").toUpperCase(); const threadId = String(req.body.threadId || ""); const messageId = String(req.body.messageId || ""); let item; if (scope === "PRIVATE") { await threadMember(req, threadId); item = await read(`communityPrivateMessages/${threadId}/${messageId}`); } else item = await read(`communityPublicMessages/${messageId}`); if (!item) fail("Message not found.", 404); const reportId = id("communityReports"); await root.child(`communityReports/${reportId}`).set({reporterAccountId: a.id, reportedAccountId: item.accountId || item.senderAccountId, scope, threadId: threadId || null, messageId, reason: cleanText(req.body.reason, 300) || "Safety concern", status: "OPEN", createdAt: Date.now()}); res.status(201).json({ok: true, reportId}); }));
  app.get("/api/notifications", route(async (req, res) => { const a = await requireAccount(req); const values = await read(`notifications/${a.id}`) || {}; res.json({ok: true, notifications: Object.entries(values).map(([notificationId, n]) => ({notificationId, ...n})).sort((x, y) => Number(y.createdAt) - Number(x.createdAt)).slice(0, 50)}); }));
  app.post("/api/notifications/read", route(async (req, res) => { const a = await requireAccount(req); const values = await read(`notifications/${a.id}`) || {}; const updates = {}; Object.keys(values).forEach((key) => { updates[`notifications/${a.id}/${key}/readAt`] = Date.now(); }); if (Object.keys(updates).length) await root.update(updates); res.json({ok: true}); }));
  async function changeChatStatus(admin, usernameValue, actionValue, reasonValue, durationValue) {
    const username = String(usernameValue || "").trim().replace(/^@/, "").toLowerCase();
    const record = await read(`usernames/${username}`); if (!record?.accountId) fail("User not found.", 404);
    if (record.accountId === admin.id) fail("You cannot change your own chat access here.");
    const action = String(actionValue || "").toUpperCase(); const reason = cleanText(reasonValue, 300);
    if (!["BAN", "UNBAN", "CLEAR_WARNINGS"].includes(action)) fail("Choose ban, unban, or clear warnings.");
    if (reason.length < 8) fail("Give a clear moderation reason containing at least 8 characters.");
    const now = Date.now(); let bannedUntil = 0; let durationHours = 0;
    if (action === "BAN") { durationHours = Math.max(1, Math.min(720, Number(durationValue || 48))); bannedUntil = now + durationHours * 60 * 60 * 1000; }
    const transaction = await etagTransaction(`accounts/${record.accountId}`, (account) => {
      if (!account) fail("Account not found.", 404);
      if (action === "BAN") Object.assign(account, {chatWarningCount: 2, chatWarningWindowStartedAt: now,
        chatBannedUntil: bannedUntil, chatBanReason: reason, chatBanSource: "ADMIN", chatBannedBy: admin.id});
      else if (action === "UNBAN") Object.assign(account, {chatWarningCount: 0, chatWarningWindowStartedAt: 0,
        chatBannedUntil: 0, chatBanReason: "", chatBanSource: "", chatBannedBy: ""});
      else {
        if (Number(account.chatBannedUntil || 0) > now) fail("Unban the user before clearing active warnings.");
        Object.assign(account, {chatWarningCount: 0, chatWarningWindowStartedAt: 0});
      }
      account.updatedAt = now; return account;
    });
    if (!transaction.committed) fail("Chat access could not be updated. Try again.", 409);
    const notificationId = id(`notifications/${record.accountId}`);
    await root.child(`notifications/${record.accountId}/${notificationId}`).set({type: "CHAT_MODERATION",
      title: action === "BAN" ? "Chat access paused" : action === "UNBAN" ? "Chat access restored" : "Chat warnings cleared",
      message: reason, createdAt: now, readAt: null});
    await adminAudit(admin, `COMMUNITY_CHAT_${action}`, record.accountId, {username, reason, durationHours, bannedUntil});
    return {action, username, accountId: record.accountId, bannedUntil};
  }

  app.get("/api/admin/community/reports", route(async (req, res) => { await requireAdmin(req, "SUPPORT"); const values = await read("communityReports") || {}; res.json({ok: true, reports: Object.entries(values).map(([reportId, r]) => ({reportId, ...r})).sort((x, y) => Number(y.createdAt) - Number(x.createdAt)).slice(0, 100)}); }));
  app.get("/api/admin/community/private", route(async (req, res) => { await requireAdmin(req, "SUPPORT"); const values = await read("communityPrivateThreads") || {};
    const threads = await Promise.all(Object.entries(values).sort((x, y) => Number(y[1].updatedAt || 0) - Number(x[1].updatedAt || 0)).slice(0, 100).map(async ([threadId, thread]) => ({threadId, ...thread,
      participants: (await Promise.all(Object.keys(thread.members || {}).map((accountId) => profileFor(accountId)))).filter(Boolean).map(visibleProfile)}))); res.json({ok: true, threads}); }));
  app.get("/api/admin/community/private/:threadId/messages", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const thread = await read(`communityPrivateThreads/${req.params.threadId}`); if (!thread) fail("Private conversation not found.", 404); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const messages = Object.entries(values).sort((x, y) => Number(x[1].createdAt) - Number(y[1].createdAt)).slice(-100).map(([messageId, message]) => ({messageId, ...message})); await adminAudit(admin, "COMMUNITY_PRIVATE_MESSAGES_VIEWED", null, {threadId: req.params.threadId, messageCount: messages.length}); res.json({ok: true, thread, messages}); }));
  app.post("/api/admin/community/slow-mode", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const seconds = Math.max(0, Math.min(300, Number(req.body.seconds || 0))); await root.child("communityConfig").update({publicSlowModeSeconds: seconds, updatedAt: Date.now(), updatedBy: admin.id}); await adminAudit(admin, "COMMUNITY_SLOW_MODE", null, {seconds}); res.json({ok: true, seconds}); }));
  app.post("/api/admin/community/remove", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const scope = String(req.body.scope || "PUBLIC").toUpperCase(); const messageId = String(req.body.messageId || ""); const threadId = String(req.body.threadId || ""); const reason = cleanText(req.body.reason, 300); if (!reason) fail("A moderation reason is required."); const path = scope === "PRIVATE" ? `communityPrivateMessages/${threadId}/${messageId}` : `communityPublicMessages/${messageId}`; const item = await read(path); if (!item) fail("Message not found.", 404); const now = Date.now(); const updates = {[`${path}/text`]: "", [`${path}/deleted`]: true, [`${path}/removedByAdmin`]: admin.id, [`${path}/moderationReason`]: reason, [`${path}/deletedAt`]: now}; const reports = await read("communityReports") || {}; Object.entries(reports).forEach(([reportId, report]) => { if (report.messageId === messageId && report.status === "OPEN") { updates[`communityReports/${reportId}/status`] = "RESOLVED"; updates[`communityReports/${reportId}/resolvedAt`] = now; updates[`communityReports/${reportId}/resolutionReason`] = reason; } }); await root.update(updates); await adminAudit(admin, "COMMUNITY_MESSAGE_REMOVED", item.accountId || item.senderAccountId, {scope, messageId, threadId, reason}); res.json({ok: true}); }));
  app.post("/api/admin/community/warn", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const record = await read(`usernames/${String(req.body.username || "").toLowerCase()}`); if (!record?.accountId) fail("User not found.", 404); const data = await read(`accounts/${record.accountId}`); const reason = cleanText(req.body.reason, 300); if (!reason) fail("A warning reason is required."); const result = await warn({id: record.accountId, data}, reason); await adminAudit(admin, "COMMUNITY_WARNING", record.accountId, {reason, ...result}); res.json({ok: true, ...result}); }));
  app.post("/api/admin/community/chat-status", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN");
    res.json({ok: true, ...await changeChatStatus(admin, req.body.username, req.body.action, req.body.reason, req.body.durationHours)});
  }));
  app.post("/api/admin/community/command", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN"); const command = cleanText(req.body.command, 500);
    let match = command.match(/^\/chatban\s+@?([a-z0-9_]{3,20})(?:\s+(\d{1,3}))?\s+(.{8,300})$/i);
    if (match) return res.json({ok: true, message: `@${match[1]} was chat-banned.`,
      result: await changeChatStatus(admin, match[1], "BAN", match[3], Number(match[2] || 48))});
    match = command.match(/^\/chatunban\s+@?([a-z0-9_]{3,20})\s+(.{8,300})$/i);
    if (match) return res.json({ok: true, message: `@${match[1]} can use chat again.`,
      result: await changeChatStatus(admin, match[1], "UNBAN", match[2], 0)});
    match = command.match(/^\/warn\s+@?([a-z0-9_]{3,20})\s+(.{8,300})$/i);
    if (match) {
      const record = await read(`usernames/${match[1].toLowerCase()}`); if (!record?.accountId) fail("User not found.", 404);
      const data = await read(`accounts/${record.accountId}`); const result = await warn({id: record.accountId, data}, match[2]);
      await adminAudit(admin, "COMMUNITY_WARNING_COMMAND", record.accountId, {reason: match[2], ...result});
      return res.json({ok: true, message: `Warning recorded for @${match[1]}.`, result});
    }
    match = command.match(/^\/clear\s+(.{8,300})$/i);
    if (match) { const messages = await read("communityPublicMessages") || {}; await root.child("communityPublicMessages").remove();
      await adminAudit(admin, "COMMUNITY_PUBLIC_CLEARED", null, {reason: match[1], messageCount: Object.keys(messages).length});
      return res.json({ok: true, message: `Public chat cleared (${Object.keys(messages).length} messages).`}); }
    fail("Unknown command. Use /chatban @user [hours] reason, /chatunban @user reason, /warn @user reason, or /clear reason.");
  }));

  app.post("/api/admin/accounts/:accountId/beta", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN"); const accountId = String(req.params.accountId || "");
    const target = await read(`accounts/${accountId}`); if (!target) fail("Account not found.", 404);
    const action = String(req.body.action || "").toUpperCase(); if (!["GRANT", "REMOVE"].includes(action)) fail("Choose grant or remove.");
    const reason = cleanText(req.body.reason, 300); if (reason.length < 8) fail("Give a reason containing at least 8 characters.");
    const now = Date.now(); await root.child(`accounts/${accountId}`).update({betaProgramStatus: action === "GRANT" ? "ACTIVE" : "REMOVED",
      betaChangedAt: now, betaChangedBy: admin.id, updatedAt: now});
    const notificationId = id(`notifications/${accountId}`); await root.child(`notifications/${accountId}/${notificationId}`).set({
      type: "BETA_PROGRAM", title: action === "GRANT" ? "Welcome to ScriptNovaa Beta" : "Beta access changed",
      message: reason, createdAt: now, readAt: null});
    await adminAudit(admin, `BETA_${action}`, accountId, {reason}); res.json({ok: true, status: action === "GRANT" ? "ACTIVE" : "REMOVED"});
  }));

  app.get("/api/admin/announcements", route(async (req, res) => {
    await requireAdmin(req, "SUPPORT"); const values = await read("announcements") || {};
    res.json({ok: true, announcements: Object.entries(values).map(([announcementId, item]) => ({announcementId, ...item}))
        .sort((a, b) => Number(b.createdAt) - Number(a.createdAt)).slice(0, 50)});
  }));
  app.post("/api/admin/announcements", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN"); const title = cleanText(req.body.title, 80); const message = cleanText(req.body.message, 1000);
    const audience = String(req.body.audience || "ALL").toUpperCase();
    const allowed = new Set(["ALL", "NEW_USERS", "ESTABLISHED_USERS", "BETA", "DEVELOPERS", "ADMINS", "SPECIFIC"]);
    if (!allowed.has(audience)) fail("Choose a valid announcement audience.");
    if (title.length < 3 || message.length < 10) fail("Add a clear title and announcement message.");
    const accounts = await read("accounts") || {}; const administrators = await read("administrators") || {};
    const requestedNames = Array.isArray(req.body.usernames) ? req.body.usernames : String(req.body.usernames || "").split(/[\s,]+/);
    const names = new Set(requestedNames.map((value) => String(value).trim().replace(/^@/, "").toLowerCase()).filter(Boolean));
    const now = Date.now(); const recipients = Object.entries(accounts).filter(([accountId, account]) => {
      if (account.accountStatus === "TERMINATED") return false;
      if (audience === "ALL") return true;
      if (audience === "NEW_USERS") return now - Number(account.createdAt || 0) <= 7 * 86400000;
      if (audience === "ESTABLISHED_USERS") return now - Number(account.createdAt || 0) >= 30 * 86400000;
      if (audience === "BETA") return betaAccess(account, administrators[accountId]);
      if (audience === "DEVELOPERS") return account.developerProgramStatus === "APPROVED" || account.developer;
      if (audience === "ADMINS") return administrators[accountId]?.active === true;
      return names.has(String(account.username || "").toLowerCase());
    });
    if (!recipients.length) fail("No accounts matched that audience.", 404); if (recipients.length > 5000) fail("That audience is too large for one send. Use a smaller group.", 409);
    const announcementId = id("announcements"); const notificationKey = `announcement_${announcementId.replace(/[^A-Za-z0-9_-]/g, "")}`;
    const updates = {[`announcements/${announcementId}`]: {title, message, audience, recipientCount: recipients.length,
      createdAt: now, createdBy: admin.id, createdByName: admin.data.username}};
    recipients.forEach(([accountId]) => { updates[`notifications/${accountId}/${notificationKey}`] = {type: "ANNOUNCEMENT", title,
      message, audience, announcementId, createdAt: now, readAt: null}; });
    await root.update(updates); await adminAudit(admin, "ANNOUNCEMENT_SENT", null, {announcementId, audience, recipientCount: recipients.length});
    res.status(201).json({ok: true, announcementId, recipientCount: recipients.length});
  }));
}

module.exports = {mountCommunity, cleanText, cleanDisplayName, conversationKey, activeTyping, typingLabel,
  normalizedMessage, moderationText, assessMessage, nextWarningState, warningStateWithHistory,
  chatUnbanEligibility, cleanAvatarDataUrl, safeAvatarDataUrl, betaAccess, pointRecognition, translateWithGemini,
  PUBLIC_RETENTION_MS, EDIT_WINDOW_MS, CHAT_BAN_MS, CHAT_UNBAN_FEE};
