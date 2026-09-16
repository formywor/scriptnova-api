"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {complete, resolveHash, betaPairingUsage,
  BETA_PAIRING_RECHARGE_MS} = require("../lib/device-pairing");
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
test("open pairing can be recovered when the calculated hash key changed", () => {
  const pairings = {oldHash: {pairingCode: "86D69655D3", status: "OPEN", expiresAt: 200}};
  assert.equal(resolveHash(pairings, "newHash", "86D69655D3", 100), "oldHash");
  assert.equal(resolveHash(pairings, "newHash", "86D69655D3", 200), "");
  pairings.oldHash.status = "USED";
  assert.equal(resolveHash(pairings, "newHash", "86D69655D3", 100), "");
});
test("a missing pairing requests one fresh-root transaction retry", () => {
  assert.throws(
      () => complete({...fixture(), devicePairings: {}}, args),
      (error) => error.retryFreshRoot === true && /invalid or expired/.test(error.message),
  );
});
test("Beta replacement slots recharge independently after four weeks", () => {
  const now = BETA_PAIRING_RECHARGE_MS * 10;
  const expired = now - BETA_PAIRING_RECHARGE_MS;
  const recent = now - 1000;
  let quota = betaPairingUsage({betaConnectionCodeUses: [expired, recent]}, now);
  assert.equal(quota.available, 3);
  assert.deepEqual(quota.usedAt, [recent]);
  assert.equal(quota.nextRechargeAt, recent + BETA_PAIRING_RECHARGE_MS);

  const uses = [now - 4000, now - 3000, now - 2000, now - 1000];
  quota = betaPairingUsage({betaConnectionCodeUses: uses}, now);
  assert.equal(quota.available, 0);
  assert.equal(quota.nextRechargeAt, uses[0] + BETA_PAIRING_RECHARGE_MS);
  assert.equal(betaPairingUsage({betaConnectionCodeUses: uses},
      uses[0] + BETA_PAIRING_RECHARGE_MS).available, 1);
});
test("a successful Beta replacement consumes one slot, not code generation", () => {
  const d = fixture();
  d.accounts.alice.registeredDeviceId = "old";
  d.devices = {old: {accountId: "alice", status: "ACTIVE", deviceHash: "proof"}};
  d.devicePairings.code.betaReplacement = true;
  complete(d, args);
  assert.deepEqual(d.accounts.alice.betaConnectionCodeUses, [args.now]);
  assert.equal(d.devicePairings.code.betaQuotaConsumedAt, args.now);
});
test("an exhausted Beta quota cannot complete another replacement", () => {
  const d = fixture();
  d.accounts.alice.registeredDeviceId = "old";
  d.accounts.alice.betaConnectionCodeUses = [97, 98, 99, 100];
  d.devices = {old: {accountId: "alice", status: "ACTIVE", deviceHash: "proof"}};
  d.devicePairings.code.betaReplacement = true;
  assert.throws(() => complete(d, args), (error) =>
    error.statusCode === 429 && /recharging/.test(error.message));
  assert.equal(d.devicePairings.code.status, "OPEN");
});
