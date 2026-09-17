"use strict";

const VERSION = "1.0.3";
const DOWNLOAD_URL = "https://scriptnovaa.com/galaxy-browser";
const SINGLE_LEASE_MS = 30000;
const EXPERIENCES = new Set(["search", "partner", "browser"]);
const SEARCH_ENGINES = new Set(["snova", "google", "bing"]);
const BROWSERS = new Set(["chrome", "edge"]);
const DATA_MODES = new Set(["standard", "temporary"]);

function reject(message, statusCode = 400, apiCode = "GALAXY_REJECTED") {
  throw Object.assign(new Error(message), {statusCode, apiCode});
}

function productOf(token) { return token?.product || "share"; }

function accountDevice(data, accountId, deviceHash) {
  const account = data.accounts?.[accountId];
  if (!account || (account.accountStatus || "ACTIVE") !== "ACTIVE") {
    reject("Account not available.", 403, "GALAXY_ACCOUNT_UNAVAILABLE");
  }
  if (account.recoveryPromptRequired === true && !account.recoveryAcknowledgedAt) {
    reject("Confirm your recovery code first.", 428);
  }
  const device = data.devices?.[account.registeredDeviceId];
  if (!device || device.accountId !== accountId || device.status !== "ACTIVE" ||
      (deviceHash !== undefined && device.deviceHash !== deviceHash)) {
    reject("Connect this computer to your account on the Tokens page first.", 403,
        "GALAXY_DEVICE_REQUIRED");
  }
  return account;
}

function activate(data, input) {
  const {accountId, deviceHash, tokenHash, sessionId, secretHash, webAccessHash,
    requestId, now, experience, searchEngine, browser, dataMode} = input;
  const account = accountDevice(data, accountId, deviceHash);
  if ((account.fraudStatus || "CLEAR") !== "CLEAR") reject("Your account is under review.", 403);
  if (!EXPERIENCES.has(experience) || !SEARCH_ENGINES.has(searchEngine) ||
      !BROWSERS.has(browser) || !DATA_MODES.has(dataMode)) {
    reject("Unsupported Galaxy setting.");
  }
  if (!/^[a-f0-9]{32}$/.test(requestId)) reject("Invalid start request.");
  const tokenId = data.tokenHashes?.[tokenHash];
  const token = data.tokens?.[tokenId];
  if (!token || token.ownerAccountId !== accountId || productOf(token) !== "galaxy") {
    reject("Use a Galaxy token owned by this account.");
  }
  const prior = data.sessions?.[sessionId];
  if (prior) {
    if (prior.product === "galaxy" && prior.accountId === accountId &&
        prior.tokenId === tokenId && prior.requestId === requestId &&
        prior.sessionSecretHash === secretHash && prior.status === "ACTIVE" &&
        prior.expiresAt > now && prior.leaseExpiresAt > now) return data;
    reject("That start request has finished. Use a new request.", 409);
  }
  const previous = data.sessions?.[account.activeSessionId];
  if (previous?.status === "ACTIVE") {
    if (previous.product === "galaxy" &&
        (previous.expiresAt <= now || previous.leaseExpiresAt <= now)) {
      finish(data, account.activeSessionId, "CONNECTION_EXPIRED", now);
    } else reject("End your active browser session before starting Galaxy.", 409);
  }
  if (token.status !== "UNUSED") reject("This token has already been used.", 409);
  const duration = Number(token.durationSeconds);
  if (!Number.isSafeInteger(duration) || duration <= 0 || duration > 172800) {
    reject("Invalid token duration.");
  }
  const expiresAt = now + duration * 1000;
  const accessMode = token.accessMode === "multi" ? "multi" : "single";
  const leaseExpiresAt = accessMode === "multi" ? expiresAt : Math.min(expiresAt, now + SINGLE_LEASE_MS);
  data.sessions ||= {};
  data.sessions[sessionId] = {
    product: "galaxy", browser, accountId, tokenId,
    deviceId: account.registeredDeviceId, sessionSecretHash: secretHash,
    webAccessHash, requestId, experience, searchEngine, dataMode, accessMode,
    status: "ACTIVE", startedAt: now, launchConfirmedAt: now, expiresAt,
    lastHeartbeatAt: now, leaseExpiresAt,
  };
  Object.assign(token, {status: "ACTIVE", sessionId,
    deviceId: account.registeredDeviceId, activatedAt: now, expiresAt});
  account.activeSessionId = sessionId;
  account.unusedTokenCount = Object.values(data.tokens).filter((item) =>
    item.ownerAccountId === accountId && item.status === "UNUSED").length;
  return data;
}

function finish(data, sessionId, reason, now) {
  const session = data.sessions?.[sessionId];
  if (!session || session.product !== "galaxy" || session.status !== "ACTIVE") return data;
  Object.assign(session, {status: "FINISHED", endReason: reason, endedAt: now});
  const token = data.tokens?.[session.tokenId];
  if (token?.sessionId === sessionId && token.status === "ACTIVE") {
    Object.assign(token, {status: reason === "TIME_EXPIRED" ? "EXPIRED" : "COMPLETED",
      endReason: reason, endedAt: now});
    delete token.displayToken;
  }
  const account = data.accounts?.[session.accountId];
  if (account?.activeSessionId === sessionId) delete account.activeSessionId;
  return data;
}

function authorize(data, input, refreshLease = true) {
  const {sessionId, accountId, deviceHash, secretHash, now} = input;
  const session = data.sessions?.[sessionId];
  if (!session || session.product !== "galaxy" || session.accountId !== accountId ||
      session.sessionSecretHash !== secretHash) reject("Galaxy session authentication failed.", 401);
  if (session.status !== "ACTIVE") return data;
  if (session.expiresAt <= now) return finish(data, sessionId, "TIME_EXPIRED", now);
  if (session.leaseExpiresAt <= now) return finish(data, sessionId, "CONNECTION_EXPIRED", now);
  const account = data.accounts?.[accountId];
  const device = data.devices?.[session.deviceId];
  const token = data.tokens?.[session.tokenId];
  if (!account || (account.accountStatus || "ACTIVE") !== "ACTIVE" ||
      account.activeSessionId !== sessionId || account.registeredDeviceId !== session.deviceId ||
      !device || device.accountId !== accountId || device.status !== "ACTIVE" ||
      device.deviceHash !== deviceHash || token?.status !== "ACTIVE" ||
      token.sessionId !== sessionId || token.ownerAccountId !== accountId) {
    return finish(data, sessionId, "AUTHORIZATION_REVOKED", now);
  }
  session.lastHeartbeatAt = now;
  if (refreshLease && session.accessMode !== "multi") {
    session.leaseExpiresAt = Math.min(session.expiresAt, now + SINGLE_LEASE_MS);
  }
  return data;
}

function launchConfiguration(startUrl) {
  return {flags: ["--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-background-mode", "--disable-extensions",
    "--disable-component-extensions-with-background-pages"],
    userAgent: "Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    startUrl};
}

function configuration() {
  return {
    version: VERSION,
    downloadUrl: DOWNLOAD_URL,
    heartbeatSeconds: 10,
    leaseSeconds: SINGLE_LEASE_MS / 1000,
    experiences: ["search", "partner", "browser"],
    searchEngines: ["snova", "google", "bing"],
    browsers: ["chrome", "edge"],
    dataModes: ["standard", "temporary"],
    partner: {
      id: "scriptnovaa-demo",
      name: "ScriptNovaa",
      label: "Sponsored demonstration",
      url: "https://scriptnovaa.com/",
      disclosure: "ScriptNovaa is demonstrating the partner space until outside partners join Galaxy.",
    },
  };
}

module.exports = {VERSION, DOWNLOAD_URL, SINGLE_LEASE_MS, EXPERIENCES, SEARCH_ENGINES,
  BROWSERS, DATA_MODES, productOf, accountDevice, activate, authorize, finish, configuration, launchConfiguration};
