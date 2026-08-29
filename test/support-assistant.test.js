"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  supportAssistantReply,
  redactSupportSecrets,
  suggestKnowledgeKeywords,
} = require("../lib/support-assistant");

test("transfers to a representative when requested", () => {
  const reply = supportAssistantReply("Please transfer me to a representative");
  assert.equal(reply.transfer, true);
});

test("uses launcher diagnostics for a launch problem", () => {
  const reply = supportAssistantReply("The browser will not open", {
    diagnostics: [{event: "START_FAILED", browser: "edge", detail: "Browser not found"}],
  });
  assert.match(reply.message, /browser not found/i);
});

test("explains restriction reason without changing the account", () => {
  const reply = supportAssistantReply("Why am I banned?", {
    account: {accountStatus: "BANNED", statusReason: "Automated reward activity"},
  });
  assert.match(reply.message, /automated reward activity/i);
  assert.match(reply.message, /administrator/i);
});

test("does not ask users to disclose recovery secrets", () => {
  const reply = supportAssistantReply("Should I send my recovery code?");
  assert.match(reply.message, /do not send/i);
});

test("redacts common secrets before support stores a message", () => {
  const result = redactSupportSecrets(
      "My PIN is 2244, token SHARE-ABCD-EFGH-IJKL-MNOP, and code ABC12-DEF34",
  );
  assert.doesNotMatch(result, /2244|SHARE-ABCD|ABC12-DEF34/);
  assert.match(result, /removed/);
});

test("keeps restriction context for a short follow-up", () => {
  const reply = supportAssistantReply("please", {
    account: {accountStatus: "BANNED", statusReason: "Repeated abuse"},
    previousUserMessages: ["I want to be unbanned"],
  });
  assert.match(reply.message, /no scheduled automatic end date/i);
});

test("handles point refund requests before ordinary token guidance", () => {
  const reply = supportAssistantReply("I want a refund of 800 points", {
    account: {pointBalance: 89},
  });
  assert.match(reply.message, /cannot refund or restore points through chat/i);
});

test("uses administrator-approved knowledge", () => {
  const reply = supportAssistantReply("The music widget is silent", {
    knowledge: [{active: true, keywords: ["music", "silent"],
      answer: "Check the volume control and confirm music.mp3 exists."}],
  });
  assert.match(reply.message, /approved ScriptNovaa support guide/i);
});

test("suggests useful learning keywords without common filler", () => {
  assert.deepEqual(suggestKnowledgeKeywords("The music widget is silent after loading"),
      ["music", "widget", "silent", "loading"]);
});
