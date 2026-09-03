"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  supportAssistantReply,
  redactSupportSecrets,
  suggestKnowledgeKeywords,
} = require("../lib/support-assistant");

test("redacts Project Z tokens too", () => {
  assert.equal(redactSupportSecrets("My Z-ABCD-EFGH-IJKL-MNOP token"), "My [browser token removed] token");
});

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

test("does not carry an old ban topic into a developer question", () => {
  const reply = supportAssistantReply("What is the Developer portal", {
    account: {accountStatus: "BANNED", statusReason: "Repeated abuse"},
    previousUserMessages: ["I want to be unbanned", "I didnt do it"],
  });
  assert.match(reply.message, /Developer Program is in beta/i);
  assert.doesNotMatch(reply.message, /account is banned/i);
});

test("recognizes connection-code replacement wording", () => {
  const reply = supportAssistantReply("Request another one time activation code", {
    account: {registeredDeviceId: "device-1"},
  });
  assert.match(reply.message, /Connection code replacement ticket/i);
});

test("gives download-specific guidance without requiring launcher logs", () => {
  const reply = supportAssistantReply("I clicked download Share Browser and it didnt work");
  assert.match(reply.message, /Downloads list/i);
  assert.match(reply.message, /scriptnovaa\.com/i);
});

test("recognizes a browser that runs and closes quickly", () => {
  const reply = supportAssistantReply("my browser ran then closed quickly", {
    diagnostics: [{event: "BROWSER_CLOSED", browser: "chrome", detail: "Exited early"}],
  });
  assert.match(reply.message, /exited early/i);
});

test("redacts bare possible PINs and payment numbers", () => {
  assert.equal(redactSupportSecrets("19860347"), "[possible PIN removed]");
  assert.doesNotMatch(redactSupportSecrets("card 1000101010110134312"), /1000101010110134312/);
});

test("flags an unclear numeric restriction reason", () => {
  const reply = supportAssistantReply("how long am I banned", {
    account: {accountStatus: "BANNED", statusReason: "198603471986034719860347"},
  });
  assert.match(reply.message, /not written clearly/i);
});

test("understands a curly-apostrophe ban follow-up", () => {
  const reply = supportAssistantReply("I didn’t do it", {
    account: {accountStatus: "BANNED", statusReason: "Repeated abuse"},
    previousUserMessages: ["Why am I banned?"],
  });
  assert.match(reply.message, /account is banned/i);
});

test("understands how long will it last as a restriction follow-up", () => {
  const reply = supportAssistantReply("How long will it last?", {
    account: {accountStatus: "BANNED", statusReason: "Repeated abuse"},
    previousUserMessages: ["Why am I banned?", "I didn’t do it"],
  });
  assert.match(reply.message, /no scheduled automatic end date/i);
});

test("recognizes nothing happened in past tense", () => {
  const reply = supportAssistantReply("I clicked Start Browser and nothing happened");
  assert.match(reply.message, /could not find a recent launcher diagnostic/i);
});
