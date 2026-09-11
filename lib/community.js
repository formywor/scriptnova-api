"use strict";

const crypto = require("crypto");

const PUBLIC_RETENTION_MS = 48 * 60 * 60 * 1000;
const TYPING_TTL_MS = 9000;
const PUBLIC_LIMIT = 100;
const PRIVATE_LIMIT = 100;
const ACCENTS = new Set(["violet", "mint", "blue", "rose", "amber"]);

function cleanText(value, maximum) {
  return String(value || "").trim().replace(/\r\n?/g, "\n")
      .replace(/\n{3,}/g, "\n\n").slice(0, maximum);
}

function cleanDisplayName(value, fallback) {
  const name = String(value || "").trim().replace(/\s+/g, " ").slice(0, 32);
  return name || String(fallback || "User").slice(0, 32);
}

function conversationKey(firstId, secondId) {
  return crypto.createHash("sha256")
      .update([String(firstId), String(secondId)].sort().join(":"))
      .digest("hex").slice(0, 32);
}

function activeTyping(entries, now = Date.now(), exceptAccountId = "") {
  return Object.entries(entries || {})
      .filter(([accountId, item]) => accountId !== exceptAccountId &&
        Number(item.expiresAt || 0) > now)
      .map(([accountId, item]) => ({
        accountId,
        displayName: cleanDisplayName(item.displayName, item.username),
      }));
}

function typingLabel(people) {
  if (!people.length) return "";
  if (people.length >= 4) return "Several people are typing…";
  if (people.length === 1) return `${people[0].displayName} is typing…`;
  return `${people.map((person) => person.displayName).join(", ")} are typing…`;
}

function visibleProfile(profile) {
  if (!profile) return null;
  return {
    username: profile.username,
    displayName: profile.displayName,
    bio: profile.bio,
    accent: profile.accent,
    badges: profile.badges,
    createdAt: profile.createdAt,
  };
}

function mountCommunity(app, dependencies) {
  const {route, root, read, id, rateLimit, requireAccount,
    requireAdmin, adminAudit, fail} = dependencies;

  async function profileFor(accountId, accountData = null) {
    const account = accountData || await read(`accounts/${accountId}`);
    if (!account) return null;
    const stored = await read(`profiles/${accountId}`) || {};
    const administrator = await read(`administrators/${accountId}`);
    const badges = [];
    if (administrator?.active === true) {
      badges.push(String(administrator.role || "STAFF").toUpperCase() === "ADMIN" ?
        "ADMIN" : "STAFF");
    }
    if (account.developerProgramStatus === "APPROVED" || account.developer === true) {
      badges.push("DEVELOPER");
    }
    if (Date.now() - Number(account.createdAt || 0) < 7 * 24 * 60 * 60 * 1000) {
      badges.push("NEW");
    }
    return {
      accountId,
      username: String(account.username || ""),
      displayName: cleanDisplayName(stored.displayName, account.username),
      bio: cleanText(stored.bio, 160),
      accent: ACCENTS.has(stored.accent) ? stored.accent : "violet",
      privacyMode: stored.privacyMode !== false,
      badges,
      createdAt: Number(account.createdAt || 0),
    };
  }

  async function requireThreadMember(req, threadId) {
    const account = await requireAccount(req);
    const thread = await read(`communityPrivateThreads/${threadId}`);
    if (!thread || thread.members?.[account.id] !== true) {
      fail("Private conversation not found.", 404);
    }
    return {account, thread};
  }

  async function cleanPublicMessages() {
    const now = Date.now();
    const maintenance = await root.child("communityMaintenance/publicCleanup").transaction((value) => {
      if (Number(value?.checkedAt || 0) > now - 5 * 60 * 1000) return;
      return {checkedAt: now};
    }, undefined, false);
    if (!maintenance.committed) return;
    const snapshot = await root.child("communityPublicMessages")
        .orderByChild("createdAt").endAt(now - PUBLIC_RETENTION_MS)
        .limitToFirst(250).get();
    const values = snapshot.val() || {};
    const updates = {};
    Object.entries(values).forEach(([messageId, message]) => {
      if (Number(message.createdAt || 0) <= now - PUBLIC_RETENTION_MS) {
        updates[`communityPublicMessages/${messageId}`] = null;
      }
    });
    if (Object.keys(updates).length) await root.update(updates);
  }

  async function publicMessage(messageId, message) {
    return {
      messageId,
      accountId: message.accountId,
      username: String(message.username || "Unknown"),
      displayName: String(message.displayName || message.username || "Unknown"),
      badges: Array.isArray(message.badges) ? message.badges.slice(0, 4) : [],
      text: cleanText(message.text, 500),
      createdAt: Number(message.createdAt || 0),
    };
  }

  app.get("/api/community/summary", route(async (req, res) => {
    const account = await requireAccount(req);
    const profile = await profileFor(account.id, account.data);
    const threads = await read("communityPrivateThreads") || {};
    let unreadCount = 0;
    Object.entries(threads).forEach(([threadId, thread]) => {
      if (thread.members?.[account.id] !== true) return;
      const readAt = Number(thread.lastReadAt?.[account.id] || 0);
      if (thread.lastSenderAccountId !== account.id && Number(thread.updatedAt || 0) > readAt) {
        unreadCount++;
      }
    });
    res.json({ok: true, profile, unreadCount});
  }));

  app.get("/api/profile/me", route(async (req, res) => {
    const account = await requireAccount(req);
    res.json({ok: true, profile: await profileFor(account.id, account.data)});
  }));

  app.patch("/api/profile/me", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "PROFILE_UPDATE", 20, 60 * 60);
    const current = await profileFor(account.id, account.data);
    const displayName = cleanDisplayName(req.body.displayName, account.data.username);
    if (displayName.length < 2) fail("Display name must contain at least 2 characters.");
    const bio = cleanText(req.body.bio, 160);
    const accent = String(req.body.accent || current.accent).toLowerCase();
    if (!ACCENTS.has(accent)) fail("Choose an available profile color.");
    const privacyMode = req.body.privacyMode !== false;
    await root.child(`profiles/${account.id}`).update({
      displayName, bio, accent, privacyMode, updatedAt: Date.now(),
    });
    res.json({ok: true, profile: await profileFor(account.id, account.data)});
  }));

  app.get("/api/profiles/:username", route(async (req, res) => {
    await requireAccount(req);
    const username = String(req.params.username || "").trim().toLowerCase();
    const record = await read(`usernames/${username}`);
    if (!record?.accountId) fail("User not found.", 404);
    res.json({ok: true, profile: visibleProfile(await profileFor(record.accountId))});
  }));

  app.get("/api/community/users", route(async (req, res) => {
    const account = await requireAccount(req);
    const query = String(req.query.query || "").trim().toLowerCase();
    if (query.length < 2) return res.json({ok: true, users: []});
    const usernames = await read("usernames") || {};
    const matches = Object.entries(usernames)
        .filter(([username, value]) => username.includes(query) && value.accountId !== account.id)
        .slice(0, 10);
    const users = await Promise.all(matches.map(([, value]) => profileFor(value.accountId)));
    res.json({ok: true, users: users.filter(Boolean).map(visibleProfile)});
  }));

  app.get("/api/community/public", route(async (req, res) => {
    const account = await requireAccount(req);
    await cleanPublicMessages();
    const snapshot = await root.child("communityPublicMessages")
        .orderByChild("createdAt").limitToLast(PUBLIC_LIMIT).get();
    const recent = Object.entries(snapshot.val() || {})
        .filter(([, message]) => Number(message.createdAt || 0) > Date.now() - PUBLIC_RETENTION_MS)
        .sort((a, b) => Number(a[1].createdAt || 0) - Number(b[1].createdAt || 0))
        .slice(-PUBLIC_LIMIT);
    const messages = await Promise.all(recent.map(([messageId, message]) =>
      publicMessage(messageId, message)));
    const people = activeTyping(await read("communityTyping/public"), Date.now(), account.id);
    res.json({ok: true, messages, typing: people, typingLabel: typingLabel(people),
      retentionHours: 48});
  }));

  app.post("/api/community/public/messages", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "COMMUNITY_PUBLIC_MESSAGE", 30, 60);
    const text = cleanText(req.body.text, 500);
    if (!text) fail("Write a message first.");
    const profile = await profileFor(account.id, account.data);
    const messageId = id("communityPublicMessages");
    const createdAt = Date.now();
    await root.child(`communityPublicMessages/${messageId}`).set({
      accountId: account.id,
      username: account.data.username,
      displayName: profile.displayName,
      badges: profile.badges,
      text,
      createdAt,
      deleteAfter: createdAt + PUBLIC_RETENTION_MS,
    });
    await root.child(`communityTyping/public/${account.id}`).remove();
    res.status(201).json({ok: true,
      message: await publicMessage(messageId, {accountId: account.id, text, createdAt})});
  }));

  app.post("/api/community/public/typing", route(async (req, res) => {
    const account = await requireAccount(req);
    if (req.body.typing !== true) {
      await root.child(`communityTyping/public/${account.id}`).remove();
    } else {
      const profile = await profileFor(account.id, account.data);
      await root.child(`communityTyping/public/${account.id}`).set({
        username: account.data.username,
        displayName: profile.displayName,
        expiresAt: Date.now() + TYPING_TTL_MS,
      });
    }
    res.json({ok: true});
  }));

  app.get("/api/community/private", route(async (req, res) => {
    const account = await requireAccount(req);
    const threads = await read("communityPrivateThreads") || {};
    const selected = Object.entries(threads)
        .filter(([, thread]) => thread.members?.[account.id] === true)
        .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0))
        .slice(0, 50);
    const result = await Promise.all(selected.map(async ([threadId, thread]) => {
      const otherId = Object.keys(thread.members || {}).find((memberId) => memberId !== account.id);
      const other = thread.participantProfiles?.[otherId] ||
        visibleProfile(await profileFor(otherId));
      return {
        threadId,
        other: visibleProfile(other),
        updatedAt: Number(thread.updatedAt || 0),
        preview: String(thread.lastMessagePreview || ""),
        unread: thread.lastSenderAccountId !== account.id &&
          Number(thread.updatedAt || 0) > Number(thread.lastReadAt?.[account.id] || 0),
      };
    }));
    res.json({ok: true, threads: result.filter((thread) => thread.other)});
  }));

  app.post("/api/community/private/start", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "COMMUNITY_DM_START", 20, 60 * 60);
    const username = String(req.body.username || "").trim().toLowerCase();
    const target = await read(`usernames/${username}`);
    if (!target?.accountId) fail("User not found.", 404);
    if (target.accountId === account.id) fail("Choose another user.");
    const threadId = conversationKey(account.id, target.accountId);
    const existing = await read(`communityPrivateThreads/${threadId}`);
    if (!existing) {
      const createdAt = Date.now();
      await root.child(`communityPrivateThreads/${threadId}`).set({
        members: {[account.id]: true, [target.accountId]: true},
        participantProfiles: {
          [account.id]: visibleProfile(await profileFor(account.id, account.data)),
          [target.accountId]: visibleProfile(await profileFor(target.accountId)),
        },
        createdAt, updatedAt: createdAt,
        lastReadAt: {[account.id]: createdAt, [target.accountId]: 0},
      });
    }
    res.json({ok: true, threadId,
      other: visibleProfile(await profileFor(target.accountId))});
  }));

  app.get("/api/community/private/:threadId/messages", route(async (req, res) => {
    const {account, thread} = await requireThreadMember(req, req.params.threadId);
    const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {};
    const messages = Object.entries(values)
        .sort((a, b) => Number(a[1].createdAt || 0) - Number(b[1].createdAt || 0))
        .slice(-PRIVATE_LIMIT)
        .map(([messageId, message]) => ({messageId, ...message,
          text: cleanText(message.text, 1000)}));
    const people = activeTyping(
        await read(`communityTyping/private/${req.params.threadId}`), Date.now(), account.id);
    res.json({ok: true, messages, typing: people, typingLabel: typingLabel(people),
      lastReadAt: thread.lastReadAt || {}});
  }));

  app.post("/api/community/private/:threadId/messages", route(async (req, res) => {
    const {account} = await requireThreadMember(req, req.params.threadId);
    await rateLimit(account.id, "COMMUNITY_PRIVATE_MESSAGE", 40, 60);
    const text = cleanText(req.body.text, 1000);
    if (!text) fail("Write a message first.");
    const profile = await profileFor(account.id, account.data);
    const messageId = id(`communityPrivateMessages/${req.params.threadId}`);
    const createdAt = Date.now();
    const message = {
      senderAccountId: account.id,
      senderUsername: account.data.username,
      senderDisplayName: profile.displayName,
      senderBadges: profile.badges,
      text, createdAt,
      readBy: {[account.id]: createdAt},
    };
    await root.update({
      [`communityPrivateMessages/${req.params.threadId}/${messageId}`]: message,
      [`communityPrivateThreads/${req.params.threadId}/updatedAt`]: createdAt,
      [`communityPrivateThreads/${req.params.threadId}/lastSenderAccountId`]: account.id,
      [`communityPrivateThreads/${req.params.threadId}/lastMessagePreview`]: text.slice(0, 90),
      [`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: createdAt,
      [`communityTyping/private/${req.params.threadId}/${account.id}`]: null,
    });
    res.status(201).json({ok: true, message: {messageId, ...message}});
  }));

  app.post("/api/community/private/:threadId/read", route(async (req, res) => {
    const {account} = await requireThreadMember(req, req.params.threadId);
    const now = Date.now();
    const messages = await read(`communityPrivateMessages/${req.params.threadId}`) || {};
    const updates = {
      [`communityPrivateThreads/${req.params.threadId}/lastReadAt/${account.id}`]: now,
    };
    Object.entries(messages).forEach(([messageId, message]) => {
      if (message.senderAccountId !== account.id) {
        updates[`communityPrivateMessages/${req.params.threadId}/${messageId}/readBy/${account.id}`] = now;
      }
    });
    await root.update(updates);
    res.json({ok: true, readAt: now});
  }));

  app.post("/api/community/private/:threadId/typing", route(async (req, res) => {
    const {account} = await requireThreadMember(req, req.params.threadId);
    const path = `communityTyping/private/${req.params.threadId}/${account.id}`;
    if (req.body.typing !== true) await root.child(path).remove();
    else {
      const profile = await profileFor(account.id, account.data);
      await root.child(path).set({username: account.data.username,
        displayName: profile.displayName, expiresAt: Date.now() + TYPING_TTL_MS});
    }
    res.json({ok: true});
  }));

  app.get("/api/admin/community/private", route(async (req, res) => {
    const administrator = await requireAdmin(req, "SUPPORT");
    const threads = await read("communityPrivateThreads") || {};
    const selected = Object.entries(threads)
        .sort((a, b) => Number(b[1].updatedAt || 0) - Number(a[1].updatedAt || 0))
        .slice(0, 100);
    const result = await Promise.all(selected.map(async ([threadId, thread]) => ({
      threadId,
      ...thread,
      participants: Object.values(thread.participantProfiles || {}).length ?
        Object.values(thread.participantProfiles) :
        (await Promise.all(Object.keys(thread.members || {})
            .map((accountId) => profileFor(accountId)))).filter(Boolean),
    })));
    res.json({ok: true, threads: result});
  }));

  app.get("/api/admin/community/private/:threadId/messages", route(async (req, res) => {
    const administrator = await requireAdmin(req, "SUPPORT");
    const thread = await read(`communityPrivateThreads/${req.params.threadId}`);
    if (!thread) fail("Private conversation not found.", 404);
    const values = await read(`communityPrivateMessages/${req.params.threadId}`) || {};
    const messages = Object.entries(values)
        .sort((a, b) => Number(a[1].createdAt || 0) - Number(b[1].createdAt || 0))
        .slice(-PRIVATE_LIMIT)
        .map(([messageId, message]) => ({messageId, ...message}));
    await adminAudit(administrator, "COMMUNITY_PRIVATE_MESSAGES_VIEWED", null,
        {threadId: req.params.threadId, messageCount: messages.length});
    res.json({ok: true, thread, messages});
  }));
}

module.exports = {
  mountCommunity,
  cleanText,
  cleanDisplayName,
  conversationKey,
  activeTyping,
  typingLabel,
  visibleProfile,
  PUBLIC_RETENTION_MS,
};
