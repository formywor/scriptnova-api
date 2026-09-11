"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {safeClient, maskNetwork} = require("../lib/account-security");

test("security summaries reveal only broad device descriptions", () => {
  assert.equal(safeClient("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"), "Google Chrome on Windows");
  assert.equal(safeClient("Mozilla/5.0 (Macintosh) Edg/120.0"), "Microsoft Edge on Mac");
});

test("network summaries remain shortened", () => {
  assert.equal(maskNetwork("192.168.10"), "192.168.10.…");
  assert.equal(maskNetwork("2001:db8:abcd:1"), "2001:db8:abcd:1:…");
});
