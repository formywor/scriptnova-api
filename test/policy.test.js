"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  TOKEN_OPTIONS,
  ECONOMY,
  redirectWaitPlan,
  validateUsername,
  validatePin,
} = require("../lib/policy");

test("economy matches product decisions", () => {
  assert.deepEqual(TOKEN_OPTIONS.at(-1), {hours: 48, points: 52});
  assert.equal(ECONOMY.redirectMaximumCount * ECONOMY.redirectReward, 22);
  assert.equal(ECONOMY.redirectRollingHours, 14);
});
test("username policy normalizes and blocks impersonation", () => {
  assert.equal(validateUsername("User_24"), "user_24");
  assert.throws(() => validateUsername("adm1n_team"));
  assert.throws(() => validateUsername("support"));
  assert.throws(() => validateUsername("verified_news"));
  assert.throws(() => validateUsername("suuuupport_team"));
});
test("PIN policy accepts 7–14 digits and rejects weak PINs", () => {
  assert.equal(validatePin("4829167"), "4829167");
  assert.equal(validatePin("48291673510482"), "48291673510482");
  assert.throws(() => validatePin("482916"));
  assert.throws(() => validatePin("1234567"));
  assert.throws(() => validatePin("482916735104826"));
});
test("redirect waits reward account age without removing fraud review", () => {
  assert.equal(redirectWaitPlan(0, 19).zeroWait, true);
  assert.equal(redirectWaitPlan(0, 20).zeroWait, false);
  assert.equal(redirectWaitPlan(4, 54).zeroWait, true);
  assert.equal(redirectWaitPlan(7, 83).zeroWait, true);
  assert.equal(redirectWaitPlan(7, 84).zeroWait, false);
  assert.equal(redirectWaitPlan(28, 98).zeroWait, true);
  assert.equal(redirectWaitPlan(28, 99).zeroWait, false);
  assert.deepEqual(redirectWaitPlan(100, 0, true), {
    tier: "REVIEW", zeroWaitChance: 0, zeroWait: false, maximumMinutes: 14,
  });
});
