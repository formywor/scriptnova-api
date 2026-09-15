"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  cleanText,
  cleanDisplayName,
  conversationKey,
  activeTyping,
  typingLabel,
  normalizedMessage,
  moderationText,
  assessMessage,
  nextWarningState,
  warningStateWithHistory,
  chatUnbanEligibility,
  cleanAvatarDataUrl,
  safeAvatarDataUrl,
  cleanProfileSongUrl,
  betaAccess,
  pointRecognition,
  notificationCategory,
  notificationPreferences,
  notificationAllowed,
  translateWithGemini,
  encryptPrivateText,
  decryptPrivateText,
  scriptNovaEncode,
  scriptNovaDecode,
  CHAT_UNBAN_FEE,
  CHAT_BAN_MS,
  EDIT_WINDOW_MS,
  PUBLIC_RETENTION_MS,
} = require("../lib/community");

test("conversation keys are stable regardless of participant order", () => {
  assert.equal(conversationKey("account-a", "account-b"),
      conversationKey("account-b", "account-a"));
  assert.notEqual(conversationKey("account-a", "account-b"),
      conversationKey("account-a", "account-c"));
});

test("chat text is trimmed, normalized and limited", () => {
  assert.equal(cleanText("  hello\r\n\r\n\r\nworld  ", 20), "hello\n\nworld");
  assert.equal(cleanText("abcdef", 4), "abcd");
});

test("display names fall back to username", () => {
  assert.equal(cleanDisplayName("   ", "sample_user"), "sample_user");
  assert.equal(cleanDisplayName("  Nova   User ", "fallback"), "Nova User");
});

test("typing activity ignores expired entries and the current user", () => {
  const people = activeTyping({
    self: {displayName: "Me", expiresAt: 2000},
    active: {displayName: "Nova", expiresAt: 2000},
    expired: {displayName: "Old", expiresAt: 900},
  }, 1000, "self");
  assert.deepEqual(people.map((person) => person.displayName), ["Nova"]);
});

test("typing labels become compact for four or more people", () => {
  assert.equal(typingLabel([]), "");
  assert.equal(typingLabel([{displayName: "Nova"}]), "Nova is typing…");
  assert.equal(typingLabel([
    {displayName: "A"}, {displayName: "B"},
    {displayName: "C"}, {displayName: "D"},
  ]), "Several people are typing…");
});

test("public retention is exactly forty-eight hours", () => {
  assert.equal(PUBLIC_RETENTION_MS, 48 * 60 * 60 * 1000);
  assert.equal(EDIT_WINDOW_MS, 2 * 60 * 1000);
});

test("chat safety rejects dangerous links and obvious repeated spam", () => {
  assert.equal(assessMessage("hello there").ok, true);
  assert.equal(assessMessage("javascript:alert(1)").ok, false);
  assert.equal(assessMessage("visit https://127.0.0.1/private").ok, false);
  assert.equal(assessMessage("abcabcabcabcabc").ok, false);
});

test("chat safety catches separated and common substituted abusive spelling", () => {
  assert.equal(assessMessage("f.u.c.k").ok, false);
  assert.equal(assessMessage("sh1t").ok, false);
  assert.equal(assessMessage("I disagree with you").ok, true);
  assert.equal(moderationText("H3LL0"), "hello");
});

test("chat safety rejects direct targeted threats", () => {
  assert.equal(assessMessage("I will hurt you").ok, false);
  assert.equal(assessMessage("This exercise might hurt your legs").ok, true);
});

test("message comparison ignores ordinary casing and link details", () => {
  assert.equal(normalizedMessage("Hello https://example.com/a"),
      normalizedMessage("hello https://example.org/b"));
});

test("the second active chat warning creates a two-day pause", () => {
  const now = 2_000_000_000_000;
  const first = nextWarningState({}, now);
  assert.equal(first.chatWarningCount, 1);
  assert.equal(first.chatBannedUntil, 0);
  const second = nextWarningState(first, now + 1000);
  assert.equal(second.chatWarningCount, 2);
  assert.equal(second.chatBannedUntil, now + 1000 + CHAT_BAN_MS);
});

test("expired warning windows restart at warning one", () => {
  const now = 2_000_000_000_000;
  const state = nextWarningState({chatWarningCount: 1, chatWarningWindowStartedAt: now - 31 * 86400000}, now);
  assert.equal(state.chatWarningCount, 1);
  assert.equal(state.chatWarningWindowStartedAt, now);
  assert.equal(state.chatBannedUntil, 0);
});

test("recent legacy warning notifications make the next violation the second warning", () => {
  const now = 2_000_000_000_000;
  const state = warningStateWithHistory({}, [{type: "CHAT_WARNING", createdAt: now - 1000}], now);
  assert.equal(state.chatWarningCount, 2);
  assert.equal(state.chatBannedUntil, now + CHAT_BAN_MS);
});

test("a completed chat pause starts a fresh two-warning cycle", () => {
  const now = 2_000_000_000_000;
  const state = warningStateWithHistory({chatWarningCount: 2, chatBannedUntil: now - 1},
      [{type: "CHAT_WARNING", createdAt: now - 1000}], now);
  assert.equal(state.chatWarningCount, 1);
  assert.equal(state.chatBannedUntil, 0);
});

test("automatic chat bans can be cleared when the account has the fee", () => {
  const now = 2_000_000_000_000;
  assert.deepEqual(chatUnbanEligibility({chatBannedUntil: now + 1000,
    chatBanSource: "AUTOMATIC", pointBalance: CHAT_UNBAN_FEE}, now),
  {allowed: true, fee: CHAT_UNBAN_FEE});
});

test("administrator chat bans require an appeal", () => {
  const now = 2_000_000_000_000;
  const result = chatUnbanEligibility({chatBannedUntil: now + 1000,
    chatBanSource: "ADMIN", pointBalance: 100}, now);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /appealed through Support/);
});

test("paid chat restoration checks the point balance and active pause", () => {
  const now = 2_000_000_000_000;
  assert.match(chatUnbanEligibility({chatBannedUntil: now + 1000, pointBalance: 7}, now).reason,
      /need 8 points/);
  assert.match(chatUnbanEligibility({chatBannedUntil: now - 1, pointBalance: 100}, now).reason,
      /not currently paused/);
});

test("Beta access includes invited users, approved developers, and administrators", () => {
  assert.equal(betaAccess({betaProgramStatus: "ACTIVE"}), true);
  assert.equal(betaAccess({developerProgramStatus: "APPROVED"}), true);
  assert.equal(betaAccess({}, {active: true}), true);
  assert.equal(betaAccess({}, null), false);
});

test("point recognition is derived from the real balance", () => {
  assert.deepEqual(pointRecognition(0), {points: 0, tier: "standard", label: "MEMBER", badges: []});
  assert.deepEqual(pointRecognition(100).badges, ["RISING", "SPARK", "CENTURY"]);
  assert.deepEqual(pointRecognition(500).badges, ["RISING", "SPARK", "CENTURY", "ORBIT", "NOVA500"]);
  assert.equal(pointRecognition(1000).tier, "legendary");
  assert.equal(pointRecognition(5000).tier, "supernova");
  assert.equal(pointRecognition(10000).tier, "galaxy");
  assert.equal(pointRecognition(-50).points, 0);
});

test("custom profile pictures accept small safe image data only", () => {
  const valid = "data:image/png;base64," + Buffer.from("small image").toString("base64");
  assert.equal(cleanAvatarDataUrl(valid), valid);
  assert.throws(() => cleanAvatarDataUrl("data:image/svg+xml;base64,PHN2Zz4="), /PNG, JPEG, or WebP/);
  assert.equal(safeAvatarDataUrl("javascript:alert(1)"), "");
});

test("Beta profile songs require a public direct HTTPS MP3 link", () => {
  assert.equal(cleanProfileSongUrl("https://cdn.example.com/music/theme.mp3"),
      "https://cdn.example.com/music/theme.mp3");
  assert.equal(cleanProfileSongUrl(""), "");
  assert.throws(() => cleanProfileSongUrl("http://example.com/song.mp3"), /public HTTPS/);
  assert.throws(() => cleanProfileSongUrl("https://localhost/song.mp3"), /public HTTPS/);
  assert.throws(() => cleanProfileSongUrl("https://example.com/player"), /direct .mp3/);
});

test("notification levels and custom categories filter the notification center", () => {
  assert.equal(notificationCategory("LOGIN_LOCKED"), "security");
  assert.equal(notificationCategory("CHAT_WARNING"), "chatSafety");
  assert.equal(notificationCategory("PRIVATE_MESSAGE"), "privateMessages");
  assert.equal(notificationAllowed({type: "PRIVATE_MESSAGE"}, {mode: "IMPORTANT", categories: {}}), false);
  assert.equal(notificationAllowed({type: "CHAT_WARNING"}, {mode: "IMPORTANT", categories: {}}), true);
  assert.equal(notificationAllowed({type: "CHAT_WARNING"}, {mode: "NONE", categories: {chatSafety: true}}), false);
  const prefs = notificationPreferences({notificationMode: "CUSTOM", notificationCategories: {privateMessages: false}});
  assert.equal(prefs.categories.privateMessages, false);
  assert.equal(notificationAllowed({type: "PRIVATE_MESSAGE"}, prefs), false);
  assert.equal(notificationAllowed({type: "ANNOUNCEMENT"}, prefs), true);
});

test("chat translation returns constrained translated strings", async () => {
  const fetcher = async () => ({ok: true, json: async () => ({candidates: [{content: {parts: [{text: '["Hola"]'}]}}]})});
  assert.deepEqual(await translateWithGemini(["Hello"], "es", fetcher, "test-key"), ["Hola"]);
  assert.equal(await translateWithGemini(["Hello"], "es", fetcher, ""), null);
});

test("private messages use authenticated encryption and reject the wrong key", () => {
  const encrypted = encryptPrivateText("private hello", "a".repeat(32));
  assert.equal(encrypted.encryptedVersion, 1);
  assert.equal(encrypted.text, undefined);
  assert.equal(decryptPrivateText(encrypted, "a".repeat(32)), "private hello");
  assert.equal(decryptPrivateText(encrypted, "b".repeat(32)), "[This encrypted message could not be opened.]");
});

test("ScriptNova Language is reversible and separate from encryption", () => {
  const coded = scriptNovaEncode("Hello, Nova ✨");
  assert.notEqual(coded, "Hello, Nova ✨");
  assert.equal(scriptNovaDecode(coded), "Hello, Nova ✨");
  assert.throws(() => scriptNovaDecode("ordinary words"), /not valid/);
});
