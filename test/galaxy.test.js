"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const galaxy = require("../lib/galaxy");

function fixture(accessMode = "single") {
  return {
    accounts: {alice: {accountStatus: "ACTIVE", fraudStatus: "CLEAR",
      registeredDeviceId: "pc1", pointBalance: 20, activeSessionId: null}},
    devices: {pc1: {accountId: "alice", status: "ACTIVE", deviceHash: "proof"}},
    tokens: {token1: {product: "galaxy", tokenHash: "token-hash", ownerAccountId: "alice",
      durationSeconds: 3600, accessMode, status: "UNUSED", displayToken: "GALAXY-TEST"}},
    tokenHashes: {"token-hash": "token1"},
  };
}

function input(overrides = {}) {
  return {accountId: "alice", deviceHash: "proof", tokenHash: "token-hash",
    sessionId: "galaxy_session", secretHash: "secret", webAccessHash: "web",
    requestId: "a".repeat(32), now: 1000, experience: "search", searchEngine: "snova",
    browser: "edge", dataMode: "temporary", ...overrides};
}

test("Galaxy validates its product, computer, experiences, and settings before consumption", () => {
  for (const invalid of [
    {experience: "proxy"}, {searchEngine: "unknown"}, {browser: "firefox"},
    {dataMode: "incognito"}, {requestId: "bad"}, {deviceHash: "foreign"},
  ]) {
    const data = fixture();
    assert.throws(() => galaxy.activate(data, input(invalid)));
    assert.equal(data.tokens.token1.status, "UNUSED");
  }
  const wrong = fixture(); wrong.tokens.token1.product = "z";
  assert.throws(() => galaxy.activate(wrong, input()), /Galaxy token/);
});
test("second computer can start and heartbeat without replacing the first", () => {
  const data = fixture(); data.accounts.alice.secondDeviceId = "pc2";
  data.devices.pc2 = {accountId: "alice", status: "ACTIVE", deviceHash: "second"};
  galaxy.activate(data, input({deviceHash: "second"}));
  assert.equal(data.accounts.alice.registeredDeviceId, "pc1");
  assert.equal(data.sessions.galaxy_session.deviceId, "pc2");
  galaxy.authorize(data, {sessionId: "galaxy_session", accountId: "alice", deviceHash: "second", secretHash: "secret", now: 2000});
  assert.equal(data.sessions.galaxy_session.status, "ACTIVE");
  data.devices.pc2.status = "REVOKED";
  galaxy.authorize(data, {sessionId: "galaxy_session", accountId: "alice", deviceHash: "second", secretHash: "secret", now: 3000});
  assert.equal(data.sessions.galaxy_session.status, "FINISHED");
});

test("Galaxy activation and heartbeats never extend purchased time", () => {
  const data = fixture();
  galaxy.activate(data, input());
  const expiresAt = data.sessions.galaxy_session.expiresAt;
  galaxy.authorize(data, input({now: 12000}));
  assert.equal(data.sessions.galaxy_session.expiresAt, expiresAt);
  assert.equal(data.sessions.galaxy_session.leaseExpiresAt, 42000);
  assert.equal(data.tokens.token1.status, "ACTIVE");
});

test("Multi-use Galaxy sessions remain resumable until their purchased expiry", () => {
  const data = fixture("multi");
  galaxy.activate(data, input());
  assert.equal(data.sessions.galaxy_session.accessMode, "multi");
  assert.equal(data.sessions.galaxy_session.leaseExpiresAt, data.sessions.galaxy_session.expiresAt);
  galaxy.authorize(data, input({now: 600000}));
  assert.equal(data.sessions.galaxy_session.status, "ACTIVE");
});

test("revocation, expiry, and forged session credentials stop Galaxy", () => {
  const forged = fixture(); galaxy.activate(forged, input());
  assert.throws(() => galaxy.authorize(forged, input({secretHash: "wrong"})), /authentication/);
  const expired = fixture(); galaxy.activate(expired, input());
  galaxy.authorize(expired, input({now: expired.sessions.galaxy_session.expiresAt + 1}));
  assert.equal(expired.sessions.galaxy_session.status, "FINISHED");
  assert.equal(expired.tokens.token1.status, "EXPIRED");
  const revoked = fixture(); galaxy.activate(revoked, input()); revoked.devices.pc1.status = "REVOKED";
  galaxy.authorize(revoked, input({now: 12000}));
  assert.equal(revoked.sessions.galaxy_session.status, "FINISHED");
});

test("finishing is idempotent and removes the displayed Galaxy token", () => {
  const data = fixture(); galaxy.activate(data, input());
  galaxy.finish(data, "galaxy_session", "USER_ENDED", 5000);
  galaxy.finish(data, "galaxy_session", "USER_ENDED", 6000);
  assert.equal(data.tokens.token1.status, "COMPLETED");
  assert.equal(data.tokens.token1.displayToken, undefined);
  assert.equal(data.sessions.galaxy_session.endedAt, 5000);
  assert.equal(data.accounts.alice.activeSessionId, undefined);
});

test("Galaxy configuration is explicit about supported first-release capabilities", () => {
  const config = galaxy.configuration();
  assert.equal(config.version, "1.0.5");
  assert.deepEqual(config.experiences, ["search", "partner", "browser"]);
  assert.equal(config.partner.name, "ScriptNovaa");
  assert.match(config.partner.label, /Sponsored/i);
});
test("all managed launch attempts receive extension restrictions and the API identity", () => {
  const launch = galaxy.launchConfiguration("https://www.google.com/");
  assert.ok(launch.flags.includes("--disable-extensions"));
  assert.ok(launch.flags.includes("--disable-component-extensions-with-background-pages"));
  assert.match(launch.userAgent, /CrOS aarch64/);
  assert.equal(launch.startUrl, "https://www.google.com/");
  assert.ok(!launch.flags.includes("--incognito"));
});
