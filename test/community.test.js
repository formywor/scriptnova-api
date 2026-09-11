"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  cleanText,
  cleanDisplayName,
  conversationKey,
  activeTyping,
  typingLabel,
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
});
