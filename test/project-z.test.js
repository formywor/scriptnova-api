"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const z = require("../lib/project-z");
function fixture() {
  return {accounts: {alice: {accountStatus: "ACTIVE", fraudStatus: "CLEAR", registeredDeviceId: "pc1", pointBalance: 10}},
    devices: {pc1: {accountId: "alice", status: "ACTIVE", deviceHash: "proof"}}};
}
function buy(data, overrides = {}) {
  return z.purchase(data, {accountId: "alice", tokenId: "token1", tokenHash: "hash1", rawToken: "Z-TEST", ledgerId: "tx1",
    option: {hours: 1, minutes: 60, points: 2}, product: "z", now: 1000, ...overrides});
}
function input(overrides = {}) {
  return {accountId: "alice", deviceHash: "proof", tokenHash: "hash1", sessionId: "session1", secretHash: "secret1",
    requestId: "a".repeat(32), now: 2000, mode: "standard", searchEngine: "google", connection: "direct", ...overrides};
}
function running() { return z.activate(buy(fixture()), input()); }
test("Z and legacy Share product identities are separate", () => {
  assert.equal(z.productOf({}), "share"); assert.equal(z.productOf({product: "z"}), "z");
  assert.throws(() => z.productChoice("other"), /Unknown/);
  assert.throws(() => z.activate(buy(fixture(), {product: "share"}), input()), /Z token/);
});
test("purchase debits shared balance exactly once and records product", () => {
  const data = buy(fixture()); assert.equal(data.accounts.alice.pointBalance, 8);
  assert.equal(data.tokens.token1.product, "z"); assert.equal(data.pointTransactions.tx1.amount, -2);
});
test("two unused token cap counts both products, not just cached counter", () => {
  const data = buy(fixture(), {product: "share"});
  buy(data, {tokenId: "token2", tokenHash: "hash2", ledgerId: "tx2"});
  data.accounts.alice.unusedTokenCount = 0;
  assert.throws(() => buy(data, {tokenId: "token3"}), /two unused/);
  assert.equal(data.accounts.alice.pointBalance, 6);
});
test("token purchase requires enough points and active owned device", () => {
  for (const mutate of [d => d.accounts.alice.pointBalance = 0, d => delete d.devices.pc1,
    d => d.devices.pc1.status = "REVOKED", d => d.devices.pc1.accountId = "bob",
    d => d.accounts.alice.fraudStatus = "REVIEW", d => d.accounts.alice.accountStatus = "BANNED",
    d => d.accounts.alice.recoveryPromptRequired = true]) {
    const d = fixture(); mutate(d); assert.throws(() => buy(d)); assert.equal(d.tokens, undefined);
  }
});
test("all search choices and data modes work without Incognito", () => {
  for (const searchEngine of Object.keys(z.SEARCH_ENGINES)) for (const mode of ["standard", "privacy"]) {
    const data = z.activate(buy(fixture()), input({searchEngine, mode}));
    assert.equal(data.sessions.session1.mode, mode); assert.equal(data.sessions.session1.connection, "direct");
  }
});
test("unknown modes, spoofed fast/proxy, invalid request ids fail before consuming", () => {
  for (const override of [{searchEngine: "__proto__"}, {mode: "incognito"}, {connection: "fast"}, {connection: "proxy"}, {requestId: "../../x"}]) {
    const data = buy(fixture()); assert.throws(() => z.activate(data, input(override))); assert.equal(data.tokens.token1.status, "UNUSED");
  }
});
test("wrong account, computer, or owner cannot activate", () => {
  const data = buy(fixture());
  assert.throws(() => z.activate(data, input({deviceHash: "another-pc"})), /computer/);
  assert.throws(() => z.activate(data, input({accountId: "bob"})));
  data.tokens.token1.ownerAccountId = "bob";
  assert.throws(() => z.activate(data, input()), /Z token/);
});
test("Share and Z cannot run simultaneously on an account", () => {
  const data = buy(fixture()); data.sessions = {old: {status: "ACTIVE", browser: "chrome"}};
  data.accounts.alice.activeSessionId = "old";
  assert.throws(() => z.activate(data, input()), /active browser/);
});
test("activation retry returns the same deadlines, never restarts token", () => {
  const data = running(); const expires = data.sessions.session1.expiresAt;
  z.activate(data, input({now: 10000})); assert.equal(data.sessions.session1.expiresAt, expires);
  assert.equal(data.accounts.alice.unusedTokenCount, 0);
  assert.throws(() => z.activate(data, input({sessionId: "other", requestId: "b".repeat(32)})), /active browser/);
});
test("heartbeat maintains lease but does not add purchased time", () => {
  const data = running(); const expires = data.sessions.session1.expiresAt;
  z.heartbeat(data, input({now: 12000})); assert.equal(data.sessions.session1.leaseExpiresAt, 42000);
  assert.equal(data.sessions.session1.expiresAt, expires);
});
test("expired heartbeat authorization cannot revive", () => {
  const data = running(); z.heartbeat(data, input({now: 32000}));
  assert.equal(data.sessions.session1.status, "FINISHED"); assert.equal(data.tokens.token1.status, "COMPLETED");
  z.heartbeat(data, input({now: 32001})); assert.equal(data.sessions.session1.status, "FINISHED");
  assert.throws(() => z.activate(data, input({now: 32002})), /finished/);
});
test("expiry, revoked token/device/account, and account-device mismatch stop browsing", () => {
  for (const mutate of [d => d.sessions.session1.expiresAt = 5000, d => d.tokens.token1.status = "REVOKED",
    d => d.devices.pc1.status = "REVOKED", d => d.accounts.alice.accountStatus = "BANNED",
    d => d.accounts.alice.registeredDeviceId = "pc2", d => d.devices.pc1.accountId = "bob"]) {
    const d = running(); mutate(d); z.heartbeat(d, input({now: 12000}));
    assert.equal(d.sessions.session1.status, "FINISHED"); assert.equal(d.accounts.alice.activeSessionId, undefined);
  }
});
test("forged heartbeat and cross-product session rejected", () => {
  const data = running(); assert.throws(() => z.heartbeat(data, input({secretHash: "wrong"})), /authentication/);
  assert.throws(() => z.heartbeat(data, input({accountId: "bob"})), /authentication/);
  data.sessions.session1.product = "share"; assert.throws(() => z.heartbeat(data, input()), /authentication/);
});
test("end is idempotent, removes display secret, and never refunds finished tokens", () => {
  const data = running(); z.finish(data, "session1", "USER_ENDED", 4000); z.finish(data, "session1", "USER_ENDED", 5000);
  assert.equal(data.tokens.token1.displayToken, undefined); assert.equal(data.sessions.session1.endedAt, 4000);
  assert.equal(data.accounts.alice.pointBalance, 8); assert.equal(data.accounts.alice.unusedTokenCount, 0);
});
test("a fresh Z token can start after a dead Z session without a scheduler", () => {
  const data = running(); buy(data, {tokenId: "token2", tokenHash: "hash2", ledgerId: "tx2"});
  z.activate(data, input({tokenHash: "hash2", sessionId: "session2", requestId: "b".repeat(32), now: 40000}));
  assert.equal(data.sessions.session1.status, "FINISHED"); assert.equal(data.sessions.session2.status, "ACTIVE");
});
test("configuration honestly reports no VPN or FAST tier", () => {
  const config = z.configuration(); assert.equal(config.vpnAvailable, false); assert.equal(config.fastAvailable, false);
  assert.equal(config.connection, "direct");
});
test("a first Z session also qualifies the existing referral once", () => {
  const data = buy(fixture());
  data.accounts.bob = {pointBalance: 3};
  data.referralsByReferred = {alice: "ref1"};
  data.referrals = {ref1: {status: "DEVICE_PASSED", referrerAccountId: "bob"}};
  z.activate(data, input()); z.activate(data, input({now: 3000}));
  assert.equal(data.accounts.bob.pointBalance, 8);
  assert.equal(data.referrals.ref1.status, "COMPLETED");
  assert.equal(Object.keys(data.rewards).length, 1);
});
