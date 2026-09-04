"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  escapeHtml,
  plainText,
  wikipediaArticleUrl,
  safeReaderUrl,
  searchWikipedia,
  searchResultsHtml,
  requireSnovaAccess,
  sanitizeWikipediaHtml,
  extractArticle,
  readWikipedia,
} = require("../lib/snova-web");

test("Snova output escapes untrusted text and strips result markup", () => {
  assert.equal(escapeHtml("<script>'x'&\"y\"</script>"),
      "&lt;script&gt;&#39;x&#39;&amp;&quot;y&quot;&lt;/script&gt;");
  assert.equal(plainText("A <span class=\"searchmatch\">safe</span> &amp; useful result"),
      "A safe & useful result");
  const html = searchResultsHtml("<test>", [{title: "Safe result", snippet: "<b>Match</b>"}]);
  assert.match(html, /Results for “&lt;test&gt;”/);
  assert.doesNotMatch(html, /<b>Match<\/b>/);
});

test("Snova Reader accepts Wikipedia articles and rejects an open proxy", () => {
  assert.equal(safeReaderUrl("https://en.wikipedia.org/wiki/Browser").hostname,
      "en.wikipedia.org");
  assert.throws(() => safeReaderUrl("http://en.wikipedia.org/wiki/Browser"),
      /supports Wikipedia/);
  assert.throws(() => safeReaderUrl("https://example.com/wiki/Browser"),
      /supports Wikipedia/);
  assert.throws(() => safeReaderUrl("https://en.wikipedia.org/w/api.php"),
      /supports Wikipedia/);
});

test("Snova search uses the public Wikipedia search endpoint", async () => {
  let requested;
  const results = await searchWikipedia("web browser", async (url) => {
    requested = new URL(url);
    return {ok: true, json: async () => ({query: {search: [{title: "Web browser", snippet: "software"}]}})};
  });
  assert.equal(requested.hostname, "en.wikipedia.org");
  assert.equal(requested.searchParams.get("srsearch"), "web browser");
  assert.equal(results[0].title, "Web browser");
  assert.match(wikipediaArticleUrl(results[0].title), /Web_Browser/i);
});

test("Snova Reader removes executable and embedded page content", async () => {
  const article = extractArticle("<html><head><title>Example - Wikipedia</title><style>bad</style></head><body><script>alert(1)</script><h1>Example</h1><p>Readable text.</p><img src='https://upload.wikimedia.org/example.png' onerror='alert(2)'><img src='https://evil.example/tracker.png'><iframe src='bad'></iframe></body></html>");
  assert.equal(article.title, "Example");
  assert.match(article.text, /Readable text/);
  assert.doesNotMatch(article.text, /alert|iframe|bad/);
  assert.match(article.html, /https:\/\/upload\.wikimedia\.org\/example\.png/);
  assert.doesNotMatch(article.html, /onerror|evil\.example|<script|<iframe/i);

  const loaded = await readWikipedia(new URL("https://en.wikipedia.org/wiki/Example"), async () => ({
    ok: true,
    headers: new Headers({"content-type": "text/html", "content-length": "90"}),
    text: async () => "<title>Example - Wikipedia</title><p>Reader content</p>",
  }));
  assert.equal(loaded.title, "Example");
  assert.match(loaded.text, /Reader content/);
});

test("Snova access works only while its Z session and heartbeat lease are active", async () => {
  const sessionId = `z_${"a".repeat(40)}`;
  const secret = "b".repeat(64);
  const hmac = (value) => `hash:${value}`;
  const read = async () => ({product: "z", status: "ACTIVE", accountId: "account-1",
    expiresAt: 20000, leaseExpiresAt: 15000, webAccessHash: hmac(secret)});
  const accepted = await requireSnovaAccess(`${sessionId}.${secret}`, {read, hmac}, 10000);
  assert.equal(accepted.sessionId, sessionId);
  await assert.rejects(() => requireSnovaAccess(`${sessionId}.${secret}`, {read, hmac}, 16000),
      /access has finished/);
  await assert.rejects(() => requireSnovaAccess(`${sessionId}.${"c".repeat(64)}`, {read, hmac}, 10000),
      /access has finished/);
  assert.doesNotMatch(sanitizeWikipediaHtml("<script>alert(1)</script><p>Safe</p>"), /script|alert/);
});
