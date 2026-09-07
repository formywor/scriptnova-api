"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {scanInvisibleText, analyzeStyle, verdictFor, geminiAnalysis, analyzeWriting} =
  require("../lib/writing-check");

test("finds zero-width, bidi, tag, and private-use characters", () => {
  const result = scanInvisibleText(`safe\u200btext\u202e\u{E0001}\uE123`);
  assert.equal(result.detected, true);
  assert.equal(result.total, 4);
  assert.match(JSON.stringify(result.counts), /zero-width space/);
  assert.match(JSON.stringify(result.counts), /Unicode tag character/);
  assert.match(JSON.stringify(result.counts), /private-use character/);
});

test("ordinary line breaks and tabs are not reported as invisible watermarks", () => {
  assert.deepEqual(scanInvisibleText("A normal line.\n\tAnother line.").samples, []);
});

test("style analysis reports transparent measurements", () => {
  const result = analyzeStyle("First sentence is here. The second sentence is much longer and has several extra words. I can't know who wrote it.");
  assert.ok(result.wordCount > 10);
  assert.ok(result.score >= 0 && result.score <= 100);
  assert.equal(typeof result.vocabularyDiversity, "number");
});

test("short samples never receive an authorship verdict", () => {
  assert.equal(verdictFor(90, 20), "NOT_ENOUGH_TEXT");
});

test("Gemini output is constrained and parsed", async () => {
  const response = await geminiAnalysis("A sufficiently long example", async (_url, options) => {
    assert.equal(options.headers["x-goog-api-key"], "test-key");
    assert.doesNotMatch(options.body, /test-key/);
    return {ok: true, json: async () => ({modelVersion: "test-model", candidates: [{content: {parts: [{text:
      JSON.stringify({score: 71, reasons: ["Uniform structure"], counterSignals: ["Personal detail"], uncertainty: "Uncertain"})}]}}]})};
  }, "test-key");
  assert.equal(response.available, true);
  assert.equal(response.score, 71);
});

test("analysis still works when Gemini is not configured", async () => {
  const result = await analyzeWriting("This is a sample with enough characters to run the local checks only.", {useGemini: false});
  assert.equal(result.gemini.available, false);
  assert.match(result.disclaimer, /not proof/i);
});
