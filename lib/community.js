"use strict";
const crypto = require("crypto");
const PUBLIC_RETENTION_MS = 48 * 60 * 60 * 1000;
const EDIT_WINDOW_MS = 2 * 60 * 1000;
const CHAT_BAN_MS = 2 * 24 * 60 * 60 * 1000;
const TYPING_TTL_MS = 9000;
const PRESENCE_TTL_MS = 90000;
const ACCENTS = new Set(["violet", "mint", "blue", "rose", "amber"]);
const AVATARS = new Set(["nova", "orbit", "pixel", "bolt", "wave", "game"]);
const BAD_WORDS = ["anus", "arse", "arsehole", "ass", "assbag", "assclown", "asses", "asshat", "asshole", "assholes", "asslicker", "asswipe", "balls", "ballsack", "bastard", "bastards", "bitch", "bitches", "bitching", "bitchy", "blowjob", "bollocks", "boob", "boobies", "boobs", "bugger", "bullshit", "butt", "buttfuck", "butthead", "butthole", "buttplug", "choad", "chode", "clit", "clitoris", "clusterfuck", "cock", "cockblock", "cockhead", "cocks", "cocksucker", "cocksucking", "crap", "crappy", "cum", "cumming", "cumshot", "cunt", "cunts", "dammit", "damn", "dick", "dickbag", "dickhead", "dicks", "dickweed", "dildo", "dipshit", "douche", "douchebag", "dumbass", "dumbfuck", "dumbshit", "erection", "freak", "freaking", "fuck", "fuckboy", "fuckface", "fucker", "fuckers", "fucking", "fucknut", "fucks", "fuckup", "fuckwad", "fuckwit", "goddamn", "goddamned", "goddamnit", "hell", "hoe", "hoebag", "hoes", "horny", "jackass", "jackoff", "jerkoff", "jizz", "knob", "knobhead", "labia", "masturbate", "masturbation", "mofo", "motherfucker", "motherfucking", "nutsack", "orgasm", "pecker", "penis", "piss", "pissed", "pissing", "pissoff", "porn", "porno", "pornography", "prick", "pricks", "pussies", "pussy", "rimjob", "schlong", "schmuck", "scrote", "scrotum", "semen", "sex", "shag", "shit", "shitbag", "shitface", "shitfaced", "shithead", "shithole", "shits", "shitter", "shitting", "shitty", "skank", "skanky", "slut", "sluts", "slutty", "smegma", "smut", "snatch", "testicle", "testicles", "tit", "tits", "titties", "turd", "turds", "twat", "twats", "vagina", "vulva", "wank", "wanker", "wankers", "wanking", "wankstain", "weiner", "whore", "whorehouse", "whores"];
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
function assessMessage(text) {
  const value = cleanText(text, 1000); const lower = value.toLowerCase();
  if (/\b(?:javascript|data|file|vbscript):/i.test(value)) return {ok: false, reason: "Dangerous links are not allowed."};
  if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i.test(value)) return {ok: false, reason: "Direct-IP links are not allowed in chat."};
  if (SHORTENERS.some((host) => lower.includes(host))) return {ok: false, reason: "Shortened or tracking links are not allowed."};
  if (BAD_WORDS.some((word) => new RegExp(`\\b${word}\\b`, "i").test(lower))) return {ok: false, reason: "That message contains prohibited abusive language."};
  if (/(.)\1{14,}/.test(value) || /(.{3,30})\1{4,}/i.test(value)) return {ok: false, reason: "Repeated spam is not allowed."};
  return {ok: true};
}

function mountCommunity(app, d) {
  const {route, root, read, id, rateLimit, requireAccount, requireAdmin, adminAudit, fail} = d;
  async function profileFor(accountId, accountData) {
    const account = accountData || await read(`accounts/${accountId}`); if (!account) return null;
    const stored = await read(`profiles/${accountId}`) || {}; const admin = await read(`administrators/${accountId}`); const badges = [];
    if (admin?.active) badges.push(String(admin.role).toUpperCase() === "ADMIN" ? "ADMIN" : "STAFF");
    if (account.developerProgramStatus === "APPROVED" || account.developer) badges.push("DEVELOPER");
    if (Date.now() - Number(account.createdAt || 0) < 7 * 86400000) badges.push("NEW");
    return {accountId, username: String(account.username || ""), displayName: cleanDisplayName(stored.displayName, account.username),
      bio: cleanText(stored.bio, 160), accent: ACCENTS.has(stored.accent) ? stored.accent : "violet",
      avatarId: AVATARS.has(stored.avatarId) ? stored.avatarId : "nova", privacyMode: stored.privacyMode !== false,
      allowDirectMessages: stored.allowDirectMessages !== false, showLastActive: stored.showLastActive === true,
      browserNotifications: stored.browserNotifications === true, badges, createdAt: Number(account.createdAt || 0),
      chatWarnings: Number(account.chatWarningCount || 0), chatBannedUntil: Number(account.chatBannedUntil || 0)};
  }
  const visibleProfile = (p) => p && ({accountId: p.accountId, username: p.username, displayName: p.displayName,
    bio: p.bio, accent: p.accent, avatarId: p.avatarId, badges: p.badges, createdAt: p.createdAt});
  async function presenceFor(accountId, profile) {
    const item = await read(`communityPresence/${accountId}`) || {}; const active = Number(item.expiresAt || 0) > Date.now();
    return {state: active ? (item.state === "IDLE" ? "IDLE" : "ONLINE") : "OFFLINE",
      lastActiveAt: profile?.showLastActive ? Number(item.lastActiveAt || 0) : null};
  }
  async function requireChat(account) {
    if (Number(account.data.chatBannedUntil || 0) > Date.now()) fail(`Chat is paused until ${new Date(account.data.chatBannedUntil).toISOString()}.`, 403, "CHAT_BANNED");
  }
  async function warn(account, reason) {
    const now = Date.now(); const result = await root.child(`accounts/${account.id}`).transaction((fresh) => {
      if (!fresh) return; const current = now - Number(fresh.chatWarningWindowStartedAt || 0) < 30 * 86400000 ? Number(fresh.chatWarningCount || 0) : 0;
      const next = current + 1; fresh.chatWarningCount = next >= 2 ? 0 : next; fresh.chatWarningWindowStartedAt = next >= 2 ? null : now;
      if (next >= 2) fresh.chatBannedUntil = now + CHAT_BAN_MS; fresh.lastChatWarningReason = reason; fresh.updatedAt = now; return fresh;
    }, undefined, false); const data = result.snapshot.val() || {};
    const notificationId = id(`notifications/${account.id}`); await root.child(`notifications/${account.id}/${notificationId}`).set({
      type: "CHAT_WARNING", title: Number(data.chatBannedUntil || 0) > now ? "Chat paused for two days" : "Chat safety warning", message: reason, createdAt: now, readAt: null});
    return {warningCount: Number(data.chatWarningCount || 0), bannedUntil: Number(data.chatBannedUntil || 0)};
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
    displayName: String(m.displayName || m.username || "Unknown"), avatarId: m.avatarId || "nova", badges: Array.isArray(m.badges) ? m.badges.slice(0, 4) : [],
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
  app.get("/api/profile/me", route(async (req, res) => { const a = await requireAccount(req); res.json({ok: true, profile: await profileFor(a.id, a.data)}); }));
  app.get("/api/profiles/:username", route(async (req, res) => { await requireAccount(req); const record = await read(`usernames/${String(req.params.username || "").toLowerCase()}`); if (!record?.accountId) fail("User not found.", 404); const p = await profileFor(record.accountId); res.json({ok: true, profile: {...visibleProfile(p), presence: await presenceFor(record.accountId, p)}}); }));
  app.patch("/api/profile/me", route(async (req, res) => {
    const a = await requireAccount(req); await rateLimit(a.id, "PROFILE_UPDATE", 20, 3600); const old = await profileFor(a.id, a.data);
    const displayName = cleanDisplayName(req.body.displayName, a.data.username); const accent = String(req.body.accent || old.accent); const avatarId = String(req.body.avatarId || old.avatarId);
    if (displayName.length < 2 || !ACCENTS.has(accent) || !AVATARS.has(avatarId)) fail("Choose an available profile style.");
    await root.child(`profiles/${a.id}`).update({displayName, bio: cleanText(req.body.bio, 160), accent, avatarId,
      privacyMode: req.body.privacyMode !== false, allowDirectMessages: req.body.allowDirectMessages !== false,
      showLastActive: req.body.showLastActive === true, browserNotifications: req.body.browserNotifications === true, updatedAt: Date.now()});
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
    const stored = {accountId: a.id, username: a.data.username, displayName: p.displayName, avatarId: p.avatarId, badges: p.badges, text, createdAt: now, deleteAfter: now + PUBLIC_RETENTION_MS};
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
  app.get("/api/community/private/:threadId/messages", route(async (req, res) => { const {account, thread} = await threadMember(req, req.params.threadId); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const messages = Object.entries(values).sort((x, y) => Number(x[1].createdAt) - Number(y[1].createdAt)).slice(-100).map(([messageId, m]) => ({messageId, ...m, text: cleanText(m.text, 1000)})); const people = activeTyping(await read(`communityTyping/private/${req.params.threadId}`), Date.now(), account.id); res.json({ok: true, messages, typingLabel: typingLabel(people), lastReadAt: thread.lastReadAt || {}}); }));
  app.post("/api/community/private/:threadId/messages", route(async (req, res) => {
    const {account, thread} = await threadMember(req, req.params.threadId); await rateLimit(account.id, "COMMUNITY_PRIVATE_MESSAGE", 40, 60); const otherId = Object.keys(thread.members).find((key) => key !== account.id); const target = await profileFor(otherId); if (!target.allowDirectMessages || await read(`communityBlocks/${otherId}/${account.id}`)) fail("This user is not accepting private messages.", 403);
    const text = cleanText(req.body.text, 1000); if (!text) fail("Write a message first."); await validatePost(account, text, "PRIVATE"); const p = await profileFor(account.id, account.data); const messageId = id(`communityPrivateMessages/${req.params.threadId}`); const noteId = id(`notifications/${otherId}`); const now = Date.now();
    const stored = {senderAccountId: account.id, senderUsername: account.data.username, senderDisplayName: p.displayName, senderAvatarId: p.avatarId, senderBadges: p.badges, text, createdAt: now, readBy: {[account.id]: now}};
    await root.update({[`communityPrivateMessages/${req.params.threadId}/${messageId}`]: stored, [`communityPrivateThreads/${req.params.threadId}/updatedAt`]: now, [`communityPrivateThreads/${req.params.threadId}/lastSenderAccountId`]: account.id, [`communityPrivateThreads/${req.params.threadId}/lastMessagePreview`]: text.slice(0, 90), [`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: now, [`communityTyping/private/${req.params.threadId}/${account.id}`]: null, [`notifications/${otherId}/${noteId}`]: {type: "PRIVATE_MESSAGE", title: `Message from ${p.displayName}`, message: text.slice(0, 120), createdAt: now, readAt: null}}); res.status(201).json({ok: true, message: {messageId, ...stored}});
  }));
  app.patch("/api/community/private/:threadId/messages/:messageId", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityPrivateMessages/${req.params.threadId}/${req.params.messageId}`; const item = await read(path); if (!item || item.senderAccountId !== account.id) fail("Message not found.", 404); if (Date.now() - Number(item.createdAt) > EDIT_WINDOW_MS) fail("Messages can only be edited for two minutes.", 409); const text = cleanText(req.body.text, 1000); await validatePost(account, text, "PRIVATE_EDIT"); await root.child(path).update({text, editedAt: Date.now()}); res.json({ok: true}); }));
  app.delete("/api/community/private/:threadId/messages/:messageId", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityPrivateMessages/${req.params.threadId}/${req.params.messageId}`; const item = await read(path); if (!item || item.senderAccountId !== account.id) fail("Message not found.", 404); await root.child(path).update({text: "", deleted: true, deletedAt: Date.now()}); res.json({ok: true}); }));
  app.post("/api/community/private/:threadId/read", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const now = Date.now(); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const updates = {[`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: now}; Object.entries(values).forEach(([key, m]) => { if (m.senderAccountId !== account.id) updates[`communityPrivateMessages/${req.params.threadId}/${key}/readBy/${account.id}`] = now; }); await root.update(updates); res.json({ok: true}); }));
  app.post("/api/community/private/:threadId/typing", route(async (req, res) => { const {account} = await threadMember(req, req.params.threadId); const path = `communityTyping/private/${req.params.threadId}/${account.id}`; if (req.body.typing !== true) await root.child(path).remove(); else { const p = await profileFor(account.id, account.data); await root.child(path).set({displayName: p.displayName, expiresAt: Date.now() + TYPING_TTL_MS}); } res.json({ok: true}); }));

  app.post("/api/community/relationships/:username", route(async (req, res) => { const a = await requireAccount(req); const record = await read(`usernames/${String(req.params.username || "").toLowerCase()}`); if (!record?.accountId || record.accountId === a.id) fail("User not found.", 404); const action = String(req.body.action || "").toUpperCase(); const base = action.includes("BLOCK") ? "communityBlocks" : action.includes("MUTE") ? "communityMutes" : ""; if (!base) fail("Choose block, unblock, mute, or unmute."); const ref = root.child(`${base}/${a.id}/${record.accountId}`); if (action.startsWith("UN")) await ref.remove(); else await ref.set({createdAt: Date.now()}); res.json({ok: true, action}); }));
  app.get("/api/community/relationships", route(async (req, res) => { const a = await requireAccount(req); const [blocks, mutes] = await Promise.all([read(`communityBlocks/${a.id}`), read(`communityMutes/${a.id}`)]); const make = async (values, kind) => Promise.all(Object.keys(values || {}).map(async (accountId) => ({kind, profile: visibleProfile(await profileFor(accountId))}))); res.json({ok: true, relationships: [...await make(blocks, "BLOCKED"), ...await make(mutes, "MUTED")]}); }));
  app.post("/api/community/messages/report", route(async (req, res) => { const a = await requireAccount(req); await rateLimit(a.id, "COMMUNITY_REPORT", 10, 3600); const scope = String(req.body.scope || "PUBLIC").toUpperCase(); const threadId = String(req.body.threadId || ""); const messageId = String(req.body.messageId || ""); let item; if (scope === "PRIVATE") { await threadMember(req, threadId); item = await read(`communityPrivateMessages/${threadId}/${messageId}`); } else item = await read(`communityPublicMessages/${messageId}`); if (!item) fail("Message not found.", 404); const reportId = id("communityReports"); await root.child(`communityReports/${reportId}`).set({reporterAccountId: a.id, reportedAccountId: item.accountId || item.senderAccountId, scope, threadId: threadId || null, messageId, reason: cleanText(req.body.reason, 300) || "Safety concern", status: "OPEN", createdAt: Date.now()}); res.status(201).json({ok: true, reportId}); }));
  app.get("/api/notifications", route(async (req, res) => { const a = await requireAccount(req); const values = await read(`notifications/${a.id}`) || {}; res.json({ok: true, notifications: Object.entries(values).map(([notificationId, n]) => ({notificationId, ...n})).sort((x, y) => Number(y.createdAt) - Number(x.createdAt)).slice(0, 50)}); }));
  app.post("/api/notifications/read", route(async (req, res) => { const a = await requireAccount(req); const values = await read(`notifications/${a.id}`) || {}; const updates = {}; Object.keys(values).forEach((key) => { updates[`notifications/${a.id}/${key}/readAt`] = Date.now(); }); if (Object.keys(updates).length) await root.update(updates); res.json({ok: true}); }));
  app.get("/api/admin/community/reports", route(async (req, res) => { await requireAdmin(req, "SUPPORT"); const values = await read("communityReports") || {}; res.json({ok: true, reports: Object.entries(values).map(([reportId, r]) => ({reportId, ...r})).sort((x, y) => Number(y.createdAt) - Number(x.createdAt)).slice(0, 100)}); }));
  app.get("/api/admin/community/private", route(async (req, res) => { await requireAdmin(req, "SUPPORT"); const values = await read("communityPrivateThreads") || {};
    const threads = await Promise.all(Object.entries(values).sort((x, y) => Number(y[1].updatedAt || 0) - Number(x[1].updatedAt || 0)).slice(0, 100).map(async ([threadId, thread]) => ({threadId, ...thread,
      participants: (await Promise.all(Object.keys(thread.members || {}).map((accountId) => profileFor(accountId)))).filter(Boolean).map(visibleProfile)}))); res.json({ok: true, threads}); }));
  app.get("/api/admin/community/private/:threadId/messages", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const thread = await read(`communityPrivateThreads/${req.params.threadId}`); if (!thread) fail("Private conversation not found.", 404); const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {}; const messages = Object.entries(values).sort((x, y) => Number(x[1].createdAt) - Number(y[1].createdAt)).slice(-100).map(([messageId, message]) => ({messageId, ...message})); await adminAudit(admin, "COMMUNITY_PRIVATE_MESSAGES_VIEWED", null, {threadId: req.params.threadId, messageCount: messages.length}); res.json({ok: true, thread, messages}); }));
  app.post("/api/admin/community/slow-mode", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const seconds = Math.max(0, Math.min(300, Number(req.body.seconds || 0))); await root.child("communityConfig").update({publicSlowModeSeconds: seconds, updatedAt: Date.now(), updatedBy: admin.id}); await adminAudit(admin, "COMMUNITY_SLOW_MODE", null, {seconds}); res.json({ok: true, seconds}); }));
  app.post("/api/admin/community/remove", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const scope = String(req.body.scope || "PUBLIC").toUpperCase(); const messageId = String(req.body.messageId || ""); const threadId = String(req.body.threadId || ""); const reason = cleanText(req.body.reason, 300); if (!reason) fail("A moderation reason is required."); const path = scope === "PRIVATE" ? `communityPrivateMessages/${threadId}/${messageId}` : `communityPublicMessages/${messageId}`; const item = await read(path); if (!item) fail("Message not found.", 404); const now = Date.now(); const updates = {[`${path}/text`]: "", [`${path}/deleted`]: true, [`${path}/removedByAdmin`]: admin.id, [`${path}/moderationReason`]: reason, [`${path}/deletedAt`]: now}; const reports = await read("communityReports") || {}; Object.entries(reports).forEach(([reportId, report]) => { if (report.messageId === messageId && report.status === "OPEN") { updates[`communityReports/${reportId}/status`] = "RESOLVED"; updates[`communityReports/${reportId}/resolvedAt`] = now; updates[`communityReports/${reportId}/resolutionReason`] = reason; } }); await root.update(updates); await adminAudit(admin, "COMMUNITY_MESSAGE_REMOVED", item.accountId || item.senderAccountId, {scope, messageId, threadId, reason}); res.json({ok: true}); }));
  app.post("/api/admin/community/warn", route(async (req, res) => { const admin = await requireAdmin(req, "SUPPORT"); const record = await read(`usernames/${String(req.body.username || "").toLowerCase()}`); if (!record?.accountId) fail("User not found.", 404); const data = await read(`accounts/${record.accountId}`); const reason = cleanText(req.body.reason, 300); if (!reason) fail("A warning reason is required."); const result = await warn({id: record.accountId, data}, reason); await adminAudit(admin, "COMMUNITY_WARNING", record.accountId, {reason, ...result}); res.json({ok: true, ...result}); }));
}

module.exports = {mountCommunity, cleanText, cleanDisplayName, conversationKey, activeTyping, typingLabel,
  normalizedMessage, assessMessage, PUBLIC_RETENTION_MS, EDIT_WINDOW_MS};
