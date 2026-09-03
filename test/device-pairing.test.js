"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {complete} = require("../lib/device-pairing");
const args = {pairingHash: "code", deviceHash: "proof", candidateDeviceId: "pc1", loginHash: "login1", now: 100, ledgerId: "tx1"};
function fixture() { return {accounts: {alice: {accountStatus: "ACTIVE", fraudStatus: "CLEAR", pointBalance: 0}},
  devicePairings: {code: {accountId: "alice", status: "OPEN", expiresAt: 1000}}, activeDevicePairings: {alice: "code"}}; }
test("one pairing atomically registers computer, uses code, creates login and bonus", () => {
  const d = complete(fixture(), args);
  assert.equal(d.accounts.alice.registeredDeviceId, "pc1"); assert.equal(d.accounts.alice.pointBalance, 2);
  assert.equal(d.devicePairings.code.status, "USED"); assert.equal(d.loginSessions.login1.accountId, "alice");
  assert.equal(d.activeDevicePairings.alice, undefined);
  assert.throws(() => complete(d, {...args, loginHash: "login2"}), /invalid or expired/);
  assert.equal(d.loginSessions.login2, undefined); assert.equal(d.accounts.alice.pointBalance, 2);
});
test("existing same computer can pair without duplicate setup bonus", () => {
  const d = fixture(); d.accounts.alice.registeredDeviceId = "old";
  d.devices = {old: {accountId: "alice", status: "ACTIVE", deviceHash: "proof"}};
  complete(d, args); assert.equal(d.accounts.alice.registeredDeviceId, "old"); assert.equal(d.accounts.alice.pointBalance, 0);
});
test("another device cannot replace a registered computer", () => {
  const d = fixture(); d.accounts.alice.registeredDeviceId = "old";
  d.devices = {old: {accountId: "alice", status: "ACTIVE", deviceHash: "different"}};
  assert.throws(() => complete(d, args), /different or revoked/); assert.equal(d.devicePairings.code.status, "OPEN");
});
test("expired code, banned account, unconfirmed recovery do not pair", () => {
  for (const change of [d => d.devicePairings.code.expiresAt = 100, d => d.accounts.alice.accountStatus = "BANNED", d => d.accounts.alice.recoveryPromptRequired = true]) {
    const d = fixture(); change(d); assert.throws(() => complete(d, args)); assert.equal(d.loginSessions, undefined);
  }
});
test("duplicate computer on another account is held for review without points", () => {
  const d = fixture(); d.devices = {other: {accountId: "bob", deviceHash: "proof", status: "ACTIVE"}};
  complete(d, args); assert.equal(d.devices.pc1.status, "REVIEW"); assert.equal(d.accounts.alice.pointBalance, 0);
});
test("existing fraud status cannot be cleared by pairing", () => {
  const d = fixture(); d.accounts.alice.fraudStatus = "RESTRICTED";
  complete(d, args); assert.equal(d.accounts.alice.fraudStatus, "RESTRICTED"); assert.equal(d.accounts.alice.pointBalance, 0);
});
