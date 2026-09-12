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
