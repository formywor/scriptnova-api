"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {scanInvisibleText, analyzeStyle, sentenceSignals, verdictFor, saplingAnalysis,
  gptZeroAnalysis, copyleaksAnalysis, huggingFaceScore, geminiAnalysis,
  analyzeWriting, improveWriting} =
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

test("polished formulaic essay does not fall back to an unexplained neutral score", () => {
  const paragraph = "At its core, this topic represents the ultimate frontier of knowledge. Beyond its practical value, it acts as a driving engine for innovation and imagination. In a literal sense, it is a tapestry of ideas that shapes daily life. Ultimately, this remains the ultimate catalyst for discovery and progress.";
  const result = analyzeStyle([paragraph, paragraph, paragraph, paragraph].join("\n\n"));
  assert.ok(result.score >= 66);
  assert.ok(result.findings.length >= 2);
});

test("Sapling detector response is normalized without exposing its key", async () => {
  const result = await saplingAnalysis("Long enough detector sample", async (_url, options) => {
    assert.equal(options.headers.Authorization, "Bearer sapling-test-key");
    assert.doesNotMatch(options.body, /sapling-test-key/);
    return {ok: true, json: async () => ({score: 0.92,
      sentence_scores: [{score: 0.95, sentence: "Example sentence."}]})};
  }, "sapling-test-key");
  assert.equal(result.score, 92);
  assert.equal(result.name, "Sapling");
});

test("GPTZero detector response is normalized without exposing its key", async () => {
  const result = await gptZeroAnalysis("Long enough detector sample", async (_url, options) => {
    assert.equal(options.headers["x-api-key"], "gptzero-test-key");
    assert.doesNotMatch(options.body, /gptzero-test-key/);
    return {ok: true, json: async () => ({documents: [{completely_generated_prob: 0.88}]})};
  }, "gptzero-test-key");
  assert.equal(result.score, 88);
  assert.equal(result.name, "GPTZero");
});

test("local sentence highlighting explains stronger passages", () => {
  const signals = sentenceSignals("At its core, this is a tapestry of consistently polished ideas that represents a long and highly structured example sentence, with multiple clauses, transitions, and details.");
  assert.ok(signals[0].score >= 60);
  assert.ok(signals[0].reasons.length >= 1);
});

test("Hugging Face labels are normalized", () => {
  assert.equal(huggingFaceScore([{label: "AI", score: 0.81}, {label: "Human", score: 0.19}]), 81);
  assert.equal(huggingFaceScore([{label: "LABEL_1", score: 0.76}], "LABEL_1"), 76);
});

test("Copyleaks authentication and detector responses are combined", async () => {
  let calls = 0;
  const result = await copyleaksAnalysis("A sufficiently long detector sample", async (url, options) => {
    calls++;
    if (url.includes("/login/api")) {
      assert.doesNotMatch(JSON.stringify(options.headers), /copy-key/);
      return {ok: true, json: async () => ({access_token: "temporary-token"})};
    }
    assert.match(options.headers.Authorization, /temporary-token/);
    return {ok: true, json: async () => ({summary: {ai: 0.91}})};
  }, {email: "test@example.com", apiKey: "copy-key"});
  assert.equal(calls, 2);
  assert.equal(result.score, 91);
});

test("writing improvement preserves a constrained structured response", async () => {
  const result = await improveWriting("A long enough sample that needs clearer writing and more specific details for readers to understand without changing the underlying claims.", async (_url, options) => {
    assert.equal(options.headers["x-goog-api-key"], "gemini-test-key");
    return {ok: true, json: async () => ({candidates: [{content: {parts: [{text: JSON.stringify({
      revisedText: "A clearer revision.", changes: ["Shortened a sentence."], warnings: ["Verify the date."],
    })}]}}]})};
  }, "gemini-test-key");
  assert.equal(result.available, true);
  assert.equal(result.revisedText, "A clearer revision.");
});
