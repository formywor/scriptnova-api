"use strict";
const LIMIT = 2;
function ids(account) {
  return [...new Set([account?.registeredDeviceId, account?.secondDeviceId].filter(Boolean))];
}
function find(account, devices, accountId, hash) {
  return ids(account).find(id => devices?.[id]?.accountId === accountId &&
    devices[id].status !== "REVOKED" && (hash === undefined || devices[id].deviceHash === hash)) || null;
}
module.exports = {LIMIT, ids, find};
