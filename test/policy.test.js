"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {TOKEN_OPTIONS, ECONOMY, validateUsername, validatePin} = require("../lib/policy");

test("economy matches product decisions", () => {
  assert.deepEqual(TOKEN_OPTIONS.at(-1), {hours: 48, points: 52});
  assert.equal(ECONOMY.redirectMaximumCount * ECONOMY.redirectReward, 22);
  assert.equal(ECONOMY.redirectRollingHours, 14);
});
test("username policy normalizes and blocks impersonation", () => {
  assert.equal(validateUsername("User_24"), "user_24");
  assert.throws(() => validateUsername("adm1n_team"));
  assert.throws(() => validateUsername("support"));
});
test("PIN policy accepts 4–8 digits and rejects weak PINs", () => {
  assert.equal(validatePin("4826"), "4826");
  assert.throws(() => validatePin("1234"));
  assert.throws(() => validatePin("123456789"));
});
