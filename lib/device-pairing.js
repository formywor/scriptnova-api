"use strict";

// Shared one-time pairing transaction for both launchers. No network calls inside it.
function resolveHash(pairings, calculatedHash, pairingCode, now) {
  const direct = pairings?.[calculatedHash];
  if (direct?.pairingCode === pairingCode && direct.status === "OPEN" &&
      Number(direct.expiresAt || 0) > now) return calculatedHash;
  const match = Object.entries(pairings || {}).find(([, pairing]) =>
    pairing?.pairingCode === pairingCode && pairing.status === "OPEN" &&
    Number(pairing.expiresAt || 0) > now);
  return match?.[0] || "";
}

function complete(data, input) {
  const {pairingHash, deviceHash, candidateDeviceId, loginHash, now, ledgerId} = input;
  const fail = (message, statusCode = 400, retryFreshRoot = false) => {
    throw Object.assign(new Error(message), {statusCode, retryFreshRoot});
  };
  const pairing = data.devicePairings?.[pairingHash];
  // A root transaction can initially receive an incomplete local cache after
  // a separate serverless request created the pairing. Ask atomic() for one
  // server-refreshed retry only when the record is absent. Real used or
  // expired records remain terminal and are never retried.
  if (!pairing) fail("Connection code is invalid or expired.", 400, true);
  if (pairing.status !== "OPEN" || Number(pairing.expiresAt || 0) <= now) {
    fail("Connection code is invalid or expired.");
  }
  const accountId = pairing.accountId;
  const account = data.accounts?.[accountId];
  if (!account || account.accountStatus !== "ACTIVE") fail("Account restricted.", 403);
  if (account.recoveryPromptRequired === true && !account.recoveryAcknowledgedAt) fail("Save and confirm your recovery code on the website first.", 428);
  const deviceId = account.registeredDeviceId || candidateDeviceId;
  const alreadyRegistered = Boolean(account.registeredDeviceId);
  data.devices ||= {};
  if (alreadyRegistered) {
    const device = data.devices[deviceId];
    if (!device || device.accountId !== accountId || device.deviceHash !== deviceHash || device.status === "REVOKED") fail("This account already has a different or revoked computer.", 403);
  } else {
    const reused = Object.values(data.devices).some((device) => device.deviceHash === deviceHash && device.accountId !== accountId);
    data.devices[deviceId] = {accountId, deviceHash, status: reused ? "REVIEW" : "ACTIVE", riskScore: reused ? 100 : 0, registeredAt: now};
    account.registeredDeviceId = deviceId;
    // A new connection must not clear an existing fraud restriction.
    if (reused) account.fraudStatus = "REVIEW";
    data.pointTransactions ||= {};
    if (!reused && account.fraudStatus === "CLEAR" && !account.deviceSetupBonusAwardedAt) {
      account.pointBalance = Number(account.pointBalance || 0) + 2;
      if (account.referredByAccountId) account.pendingPointBalance = Math.max(0, Number(account.pendingPointBalance || 0) - 2);
      account.deviceSetupBonusAwardedAt = now; account.deviceSetupNoticePending = true;
      data.pointTransactions[ledgerId] = {accountId, amount: 2, type: "DEVICE_SETUP_BONUS", sourceId: deviceId, createdAt: now};
      const referral = data.referrals?.[data.referralsByReferred?.[accountId]];
      const referrer = data.accounts?.[referral?.referrerAccountId];
      if (referral?.status === "WAITING_FOR_DEVICE" && referrer) {
        Object.assign(referral, {status: "DEVICE_PASSED", signupRewardAwarded: 3, devicePassedAt: now});
        referrer.pointBalance = Number(referrer.pointBalance || 0) + 3;
        data.pointTransactions[ledgerId + "_referral"] = {accountId: referral.referrerAccountId, amount: 3,
          type: "REFERRAL_SIGNUP", sourceId: data.referralsByReferred[accountId], createdAt: now};
      }
    }
  }
  pairing.status = "USED"; pairing.usedAt = now; pairing.alreadyRegistered = alreadyRegistered;
  if (data.activeDevicePairings) delete data.activeDevicePairings[accountId];
  account.persistentLauncherPairedAt = now; account.updatedAt = now;
  data.loginSessions ||= {};
  data.loginSessions[loginHash] = {accountId, clientDescription: "ScriptNovaa paired launcher", revoked: false, createdAt: now, lastUsedAt: now};
  return data;
}
module.exports = {complete, resolveHash};
