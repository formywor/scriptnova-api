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
  const article = extractArticle("<html><head><title>Example - Wikipedia</title><style>bad</style></head><body><script>alert(1)</script><h1>Example</h1><p>Readable text.</p><iframe src='bad'></iframe></body></html>");
  assert.equal(article.title, "Example");
  assert.match(article.text, /Readable text/);
  assert.doesNotMatch(article.text, /alert|iframe|bad/);

  const loaded = await readWikipedia(new URL("https://en.wikipedia.org/wiki/Example"), async () => ({
    ok: true,
    headers: new Headers({"content-type": "text/html", "content-length": "90"}),
    text: async () => "<title>Example - Wikipedia</title><p>Reader content</p>",
  }));
  assert.equal(loaded.title, "Example");
  assert.match(loaded.text, /Reader content/);
});
