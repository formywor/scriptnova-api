"use strict";

const TOKEN_OPTIONS = Object.freeze([
  {hours: 1, points: 2}, {hours: 2, points: 4}, {hours: 4, points: 7},
  {hours: 8, points: 13}, {hours: 12, points: 18},
  {hours: 24, points: 34}, {hours: 48, points: 52},
]);

const ECONOMY = Object.freeze({
  referredUserBonus: 2,
  referralSignupReward: 3,
  referralFirstSessionReward: 4,
  referralReviewBonus: 1,
  referralFraudPenalty: 2,
  redirectReward: 0.5,
  redirectMaximumCount: 44,
  redirectRollingHours: 14,
  redirectPendingMinimumMinutes: 0,
  redirectPendingMaximumMinutes: 14,
  maximumUnusedTokens: 2,
  heartbeatSeconds: 10,
});

const RESERVED = new Set([
  "admin", "administrator", "mod", "moderator", "staff", "support",
  "official", "owner", "developer", "dev", "system", "security",
  "billing", "help", "root", "api", "firebase", "scriptnova",
  "scriptnovaa", "share", "sharebrowser", "null", "undefined",
]);

const BLOCKED_WORDS = ["fuck", "shit", "bitch", "nigger", "faggot", "cunt"];

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function safetyUsername(value) {
  return normalizeUsername(value).replace(/[_\-.]/g, "")
      .replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e")
      .replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t");
}

function validateUsername(value) {
  const username = normalizeUsername(value);
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    throw new Error("Username must be 3–20 lowercase letters, numbers, or underscores.");
  }
  const safe = safetyUsername(username);
  if (RESERVED.has(username) || RESERVED.has(safe) ||
      [...RESERVED].some((word) => safe.startsWith(word)) ||
      BLOCKED_WORDS.some((word) => safe.includes(word))) {
    throw new Error("That username is reserved or contains prohibited language.");
  }
  return username;
}

function validatePin(value) {
  const pin = String(value || "");
  if (!/^\d{4,8}$/.test(pin)) throw new Error("PIN must contain 4–8 digits.");
  const sequential = "0123456789 9876543210";
  if (/^(\d)\1+$/.test(pin) || sequential.includes(pin) ||
      ["1212", "2580", "6969"].includes(pin)) {
    throw new Error("Choose a less common PIN.");
  }
  return pin;
}

module.exports = {TOKEN_OPTIONS, ECONOMY, normalizeUsername, validateUsername, validatePin};
