"use strict";

// Pure transaction rules. The API supplies authenticated identities and server time.
const VERSION = "0.1.2";
const DOWNLOAD_URL = "https://scriptnovaa.com/project-z";
const SEARCH_ENGINES = Object.freeze({
  google: {label: "Google", home: "https://www.google.com/", search: "https://www.google.com/search?q="},
  duckduckgo: {label: "DuckDuckGo", home: "https://duckduckgo.com/", search: "https://duckduckgo.com/?q="},
  bing: {label: "Bing", home: "https://www.bing.com/", search: "https://www.bing.com/search?q="},
});
const LEASE_MS = 30000;
function reject(message, statusCode = 400, apiCode = "Z_REJECTED") {
  throw Object.assign(new Error(message), {statusCode, apiCode});
}
function productOf(token) { return token?.product || "share"; }
function productChoice(value) {
  const product = value === undefined ? "share" : String(value);
  if (!["share", "z"].includes(product)) reject("Unknown browser product.");
  return product;
}
function accountDevice(data, accountId, deviceHash) {
  const account = data.accounts?.[accountId];
  // Accounts made before account restrictions were introduced do not have an
  // accountStatus or fraudStatus field. The rest of the API already treats
  // those missing legacy fields as ACTIVE/CLEAR, so token transactions must do
  // the same instead of incorrectly reporting "Account not available."
  if (!account) {
    const error = new Error("Account not available.");
    Object.assign(error, {statusCode: 403, apiCode: "Z_ACCOUNT_UNAVAILABLE",
      retryFreshRoot: true});
    throw error;
  }
  if ((account.accountStatus || "ACTIVE") !== "ACTIVE") reject("Account not available.", 403);
  if (account.recoveryPromptRequired === true && !account.recoveryAcknowledgedAt) reject("Confirm your recovery code first.", 428);
  const device = data.devices?.[account.registeredDeviceId];
  if (!device || device.accountId !== accountId || device.status !== "ACTIVE" ||
      (deviceHash !== undefined && device.deviceHash !== deviceHash)) {
    reject("Connect this computer to your account on the Tokens page first.", 403, "Z_DEVICE_REQUIRED");
  }
  return account;
}
function purchase(data, input) {
  const {accountId, tokenId, tokenHash, rawToken, option, now, ledgerId} = input;
  const product = productChoice(input.product);
  const account = accountDevice(data, accountId);
  if ((account.fraudStatus || "CLEAR") !== "CLEAR") reject("Your account is under review.", 403);
  if (!Number.isFinite(option.points) || option.points < 0 || !Number.isFinite(option.minutes) || option.minutes <= 0) {
    reject("Invalid token option.");
  }
  if (Number(account.pointBalance || 0) < option.points) reject("Not enough points for this token.");
  const unused = Object.values(data.tokens || {}).filter((t) => t.ownerAccountId === accountId && t.status === "UNUSED").length;
  if (unused >= 2) reject("Maximum two unused tokens across Share Browser and Project Z.");
  if (option.limited && (product !== "share" || account.limitedFreeTokenClaimedAt)) reject("This limited token is unavailable.");
  data.tokens ||= {}; data.tokenHashes ||= {}; data.pointTransactions ||= {};
  data.tokens[tokenId] = {
    product, tokenHash, displayToken: rawToken, ownerAccountId: accountId,
    durationHours: option.hours || null, durationMinutes: option.minutes,
    durationLabel: option.minutes < 60 ? `${option.minutes} minutes` : `${option.hours} hours`,
    durationSeconds: option.minutes * 60, pointCost: option.points,
    limitedOfferId: option.limited ? option.id : null, status: "UNUSED", createdAt: now,
  };
  data.tokenHashes[tokenHash] = tokenId;
  account.pointBalance = Number(account.pointBalance || 0) - option.points;
  account.unusedTokenCount = unused + 1;
  account.updatedAt = now;
  if (option.limited) account.limitedFreeTokenClaimedAt = now;
  data.pointTransactions[ledgerId] = {accountId, amount: -option.points,
    type: option.limited ? "LIMITED_FREE_TOKEN" : "TOKEN_PURCHASE", product, sourceId: tokenId, createdAt: now};
  return data;
}
function activate(data, input) {
  const {accountId, deviceHash, tokenHash, sessionId, secretHash, requestId, now, mode, searchEngine, connection} = input;
  const account = accountDevice(data, accountId, deviceHash);
  if ((account.fraudStatus || "CLEAR") !== "CLEAR") reject("Your account is under review.", 403);
  if (!Object.hasOwn(SEARCH_ENGINES, searchEngine) || !["standard", "privacy"].includes(mode)) reject("Unsupported Project Z setting.");
  if (connection !== "direct") reject("VPN and FAST connections are not available in this release.");
  if (!/^[a-f0-9]{32}$/.test(requestId)) reject("Invalid start request.");
  const tokenId = data.tokenHashes?.[tokenHash];
  const token = data.tokens?.[tokenId];
  if (!token || token.ownerAccountId !== accountId || productOf(token) !== "z") reject("Use a Z token owned by this account.");
  // An HTTP retry may retrieve the same still-active session, never extend it.
  const prior = data.sessions?.[sessionId];
  if (prior) {
    if (prior.product === "z" && prior.accountId === accountId && prior.tokenId === tokenId &&
        prior.requestId === requestId && prior.sessionSecretHash === secretHash &&
        prior.status === "ACTIVE" && prior.expiresAt > now && prior.leaseExpiresAt > now &&
        token.status === "ACTIVE" && token.sessionId === sessionId && account.activeSessionId === sessionId) return data;
    reject("That start request has finished. Use a new request.", 409);
  }
  const previous = data.sessions?.[account.activeSessionId];
  if (previous?.status === "ACTIVE") {
    if (previous.product === "z" && (previous.expiresAt <= now || previous.leaseExpiresAt <= now)) {
      finish(data, account.activeSessionId, "CONNECTION_EXPIRED", now);
    } else reject("End your active browser session before starting Project Z.", 409);
  }
  if (token.status !== "UNUSED") reject("This token has already been used.", 409);
  const duration = Number(token.durationSeconds);
  if (!Number.isSafeInteger(duration) || duration <= 0 || duration > 172800) reject("Invalid token duration.");
  const expiresAt = now + duration * 1000;
  data.sessions ||= {};
  data.sessions[sessionId] = {product: "z", browser: "project-z", accountId, tokenId,
    deviceId: account.registeredDeviceId, sessionSecretHash: secretHash, requestId,
    mode, searchEngine, connection, status: "ACTIVE", startedAt: now, launchConfirmedAt: now, expiresAt,
    lastHeartbeatAt: now, leaseExpiresAt: Math.min(expiresAt, now + LEASE_MS)};
  Object.assign(token, {status: "ACTIVE", sessionId, deviceId: account.registeredDeviceId, activatedAt: now, expiresAt});
  account.activeSessionId = sessionId;
  account.unusedTokenCount = Object.values(data.tokens).filter((t) => t.ownerAccountId === accountId && t.status === "UNUSED").length;
  const referralId = data.referralsByReferred?.[accountId];
  const referral = data.referrals?.[referralId];
  const referrer = data.accounts?.[referral?.referrerAccountId];
  if (referral?.status === "DEVICE_PASSED" && referrer) {
    // Preserve the existing Share qualification: first accepted session + reviewed device.
    Object.assign(referral, {status: "COMPLETED", firstSessionRewardAwarded: 4,
      reviewBonusAwarded: 1, totalRewardAwarded: 8, completedAt: now});
    referrer.pointBalance = Number(referrer.pointBalance || 0) + 5;
    referrer.updatedAt = now;
    data.rewards ||= {};
    data.rewards["z_" + sessionId] = {accountId: referral.referrerAccountId, referralId,
      amount: 5, type: "REFERRAL_FIRST_SESSION_AND_REVIEW", status: "AVAILABLE", createdAt: now};
    data.pointTransactions ||= {};
    data.pointTransactions["z_referral_" + sessionId] = {accountId: referral.referrerAccountId,
      amount: 5, type: "REFERRAL_FIRST_SESSION_AND_REVIEW", sourceId: referralId, createdAt: now};
  }
  return data;
}
function finish(data, sessionId, reason, now) {
  const session = data.sessions?.[sessionId];
  if (!session || session.product !== "z" || session.status !== "ACTIVE") return data;
  Object.assign(session, {status: "FINISHED", endReason: reason, endedAt: now});
  const token = data.tokens?.[session.tokenId];
  if (token?.sessionId === sessionId && token.status === "ACTIVE") {
    Object.assign(token, {status: reason === "TIME_EXPIRED" ? "EXPIRED" : "COMPLETED", endReason: reason, endedAt: now});
    delete token.displayToken;
  }
  const account = data.accounts?.[session.accountId];
  if (account?.activeSessionId === sessionId) delete account.activeSessionId;
  return data;
}
function heartbeat(data, input) {
  const {sessionId, accountId, deviceHash, now} = input;
  const session = data.sessions?.[sessionId];
  if (!session || session.product !== "z" || session.accountId !== accountId || session.sessionSecretHash !== input.secretHash) {
    reject("Project Z session authentication failed.", 401);
  }
  if (session.status !== "ACTIVE") return data;
  const account = data.accounts?.[accountId];
  const device = data.devices?.[session.deviceId];
  const token = data.tokens?.[session.tokenId];
  if (session.expiresAt <= now) return finish(data, sessionId, "TIME_EXPIRED", now);
  if (session.leaseExpiresAt <= now) return finish(data, sessionId, "CONNECTION_EXPIRED", now);
  if (!account || (account.accountStatus || "ACTIVE") !== "ACTIVE" || account.activeSessionId !== sessionId ||
      account.registeredDeviceId !== session.deviceId || !device || device.accountId !== accountId ||
      device.status !== "ACTIVE" || device.deviceHash !== deviceHash || token?.status !== "ACTIVE" ||
      token.sessionId !== sessionId || token.ownerAccountId !== accountId) {
    return finish(data, sessionId, "AUTHORIZATION_REVOKED", now);
  }
  session.lastHeartbeatAt = now;
  session.leaseExpiresAt = Math.min(session.expiresAt, now + LEASE_MS);
  return data;
}
function configuration() {
  return {version: VERSION, downloadUrl: DOWNLOAD_URL, connection: "direct", vpnAvailable: false,
    fastAvailable: false, heartbeatSeconds: 10, leaseSeconds: LEASE_MS / 1000,
    searchEngines: SEARCH_ENGINES, modes: ["standard", "privacy"],
    notice: "Direct connection. Project Z does not hide your IP address or provide a VPN."};
}
module.exports = {VERSION, DOWNLOAD_URL, SEARCH_ENGINES, LEASE_MS, productChoice, productOf,
  accountDevice, purchase, activate, heartbeat, finish, configuration};
