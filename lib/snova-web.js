"use strict";

const sanitizeHtml = require("sanitize-html");

const WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php";
const MAX_QUERY_LENGTH = 160;
const MAX_READER_BYTES = 1800000;

function escapeHtml(value) {
  return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
}

function plainText(value) {
  return String(value || "")
      .replace(/<[^>]*>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, "\"")
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&#(\d+);/g, (_all, number) => String.fromCharCode(Number(number)))
      .replace(/\s+/g, " ")
      .trim();
}

function wikipediaArticleUrl(title) {
  return `https://en.wikipedia.org/wiki/${encodeURIComponent(String(title).replace(/ /g, "_"))}`;
}

function safeReaderUrl(input) {
  let url;
  try {
    url = new URL(String(input || ""));
  } catch (_error) {
    throw Object.assign(new Error("Enter a valid Wikipedia article address."), {statusCode: 400});
  }
  const hostname = url.hostname.toLowerCase();
  if (url.protocol !== "https:" ||
      !(hostname === "wikipedia.org" || hostname.endsWith(".wikipedia.org")) ||
      !url.pathname.startsWith("/wiki/")) {
    throw Object.assign(new Error("Snova Reader currently supports Wikipedia articles from Snova Search."), {statusCode: 400});
  }
  url.username = "";
  url.password = "";
  url.hash = "";
  return url;
}

function shell(title, content, query = "", access = "") {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=11"><title>${escapeHtml(title)} · Snova</title><style>
  *{box-sizing:border-box}html,body{margin:0;min-height:100%;background:#080b12;color:#f4f6ff;font:16px "Segoe UI",Arial,sans-serif}a{color:#78d8ff}.top{padding:18px 24px;background:#111725;border-bottom:1px solid #2c3549}.brand{font-weight:900;letter-spacing:1.5px}.wrap{max-width:920px;margin:0 auto;padding:30px 22px}.search{display:flex;gap:8px;margin:18px 0 25px}.search input{flex:1;min-width:0;padding:13px;background:#0b101c;color:#fff;border:1px solid #47536e;border-radius:9px;font:inherit}.button{display:inline-block;border:0;border-radius:9px;padding:12px 17px;background:linear-gradient(135deg,#735cff,#22bba9);color:#fff;font-weight:800;text-decoration:none;cursor:pointer}.secondary{background:#273149}.card{margin:13px 0;padding:18px;background:#111725;border:1px solid #34405a;border-radius:14px}.card h2{margin:0 0 7px;font-size:21px}.muted{color:#9da8c2;line-height:1.55}.links{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}.article{line-height:1.68;font-size:17px}.article h1,.article h2,.article h3{line-height:1.2;margin-top:1.4em}.article p{margin:0 0 1em}.article img{display:block;max-width:100%;height:auto;margin:16px auto;border-radius:10px}.article figure{margin:18px 0;padding:12px;background:#0c111d;border:1px solid #2d3850;border-radius:12px}.article figcaption{margin-top:8px;color:#aeb9d0;font-size:13px;text-align:center}.article table{display:block;max-width:100%;overflow:auto;border-collapse:collapse;margin:18px 0}.article th,.article td{border:1px solid #3b4761;padding:8px;vertical-align:top}.article th{background:#192236}.article pre,.article code{white-space:pre-wrap;word-break:break-word;background:#090d16}.article blockquote{margin:16px 0;padding:8px 18px;border-left:4px solid #735cff;color:#cbd3e7}.notice{padding:13px 15px;border-left:4px solid #22bba9;background:#101d25;color:#cbeee7}@media(max-width:640px){.search{display:block}.search input,.search button{width:100%;margin-bottom:8px}}
  </style></head><body><div class="top"><span class="brand">SCRIPTNOVAA / SNOVA</span></div><main class="wrap"><form class="search" method="get" action="/search"><input type="hidden" name="access" value="${escapeHtml(access)}"><input name="q" maxlength="${MAX_QUERY_LENGTH}" value="${escapeHtml(query)}" placeholder="Search with Snova"><button class="button" type="submit">Search</button></form>${content}</main></body></html>`;
}

function sendHtml(res, html, status = 200) {
  res.status(status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Content-Security-Policy", "default-src 'none'; img-src https://upload.wikimedia.org data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'");
  res.send(html);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {...options, signal: controller.signal});
  } finally {
    clearTimeout(timer);
  }
}

async function searchWikipedia(query, fetcher = fetchWithTimeout) {
  const url = new URL(WIKIPEDIA_API);
  url.searchParams.set("action", "query");
  url.searchParams.set("list", "search");
  url.searchParams.set("srsearch", query);
  url.searchParams.set("srlimit", "8");
  url.searchParams.set("utf8", "1");
  url.searchParams.set("format", "json");
  const response = await fetcher(url, {headers: {"User-Agent": "ScriptNovaa-Snova/1.0 (https://scriptnovaa.com/)"}});
  if (!response.ok) throw new Error("Search source is temporarily unavailable.");
  const body = await response.json();
  return Array.isArray(body?.query?.search) ? body.query.search : [];
}

function searchResultsHtml(query, results, access = "") {
  const shortcuts = `<div class="links"><a class="button secondary" href="https://www.google.com/search?q=${encodeURIComponent(query)}">Google</a><a class="button secondary" href="https://duckduckgo.com/?q=${encodeURIComponent(query)}">DuckDuckGo</a><a class="button secondary" href="https://www.bing.com/search?q=${encodeURIComponent(query)}">Bing</a></div>`;
  if (!results.length) return `<h1>Snova Search</h1><p class="muted">No reader results were found. Try another phrase or one of these search providers.</p>${shortcuts}`;
  const cards = results.map((result) => {
    const original = wikipediaArticleUrl(result.title);
    const reader = `/reader?url=${encodeURIComponent(original)}&access=${encodeURIComponent(access)}`;
    return `<article class="card"><h2><a href="${reader}">${escapeHtml(result.title)}</a></h2><p class="muted">${escapeHtml(plainText(result.snippet))}</p><a href="${reader}">Read with Snova</a> · <a href="${escapeHtml(original)}">Open original</a></article>`;
  }).join("");
  return `<h1>Results for “${escapeHtml(query)}”</h1><p class="notice">Snova Reader creates a lightweight version of supported results. Modern games and web applications should be opened with Project Z’s Modern button.</p>${shortcuts}${cards}`;
}

function searchUnavailableHtml(query) {
  return `<h1>Snova Search</h1><p class="notice">Snova Reader results are temporarily unavailable. You can still continue with another search provider.</p><div class="links"><a class="button secondary" href="https://www.google.com/search?q=${encodeURIComponent(query)}">Google</a><a class="button secondary" href="https://duckduckgo.com/?q=${encodeURIComponent(query)}">DuckDuckGo</a><a class="button secondary" href="https://www.bing.com/search?q=${encodeURIComponent(query)}">Bing</a></div>`;
}

async function requireSnovaAccess(rawAccess, dependencies, now = Date.now()) {
  const value = String(rawAccess || "");
  const separator = value.indexOf(".");
  const sessionId = separator > 0 ? value.slice(0, separator) : "";
  const secret = separator > 0 ? value.slice(separator + 1) : "";
  if (!/^z_[a-f0-9]{40}$/.test(sessionId) || !/^[a-f0-9]{64}$/.test(secret)) {
    throw Object.assign(new Error("Start an active Project Z token to use Snova."), {statusCode: 403});
  }
  const session = await dependencies.read(`sessions/${sessionId}`);
  if (!session || session.product !== "z" || session.status !== "ACTIVE" ||
      Number(session.expiresAt || 0) <= now || Number(session.leaseExpiresAt || 0) <= now ||
      session.webAccessHash !== dependencies.hmac(secret)) {
    throw Object.assign(new Error("This Snova access has finished. Start another Project Z token."), {statusCode: 403});
  }
  return {sessionId, session, access: value};
}

function resolveArticleLink(value, articleUrl, access = "") {
  try {
    const url = new URL(String(value || ""), articleUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") return "";
    if (url.hostname.endsWith(".wikipedia.org") && url.pathname.startsWith("/wiki/")) {
      return `/reader?url=${encodeURIComponent(url.href)}&access=${encodeURIComponent(access)}`;
    }
    return url.href;
  } catch (_error) {
    return "";
  }
}

function resolveArticleImage(value, articleUrl) {
  try {
    const url = new URL(String(value || ""), articleUrl);
    if (url.protocol !== "https:" || url.hostname !== "upload.wikimedia.org") return "";
    return url.href;
  } catch (_error) {
    return "";
  }
}

function sanitizeWikipediaHtml(html, articleUrl = "https://en.wikipedia.org/wiki/Main_Page", access = "") {
  return sanitizeHtml(String(html || ""), {
    allowedTags: ["h1", "h2", "h3", "h4", "h5", "h6", "p", "div", "span",
      "a", "img", "figure", "figcaption", "ul", "ol", "li", "table", "thead",
      "tbody", "tfoot", "tr", "th", "td", "blockquote", "pre", "code", "strong",
      "em", "b", "i", "small", "sup", "sub", "hr", "br", "dl", "dt", "dd"],
    allowedAttributes: {
      a: ["href", "title"],
      img: ["src", "alt", "title", "width", "height", "loading"],
      th: ["colspan", "rowspan", "scope"],
      td: ["colspan", "rowspan"],
    },
    allowedSchemes: ["http", "https"],
    transformTags: {
      a: (_tag, attributes) => ({tagName: "a", attribs: {
        href: resolveArticleLink(attributes.href, articleUrl, access),
        title: String(attributes.title || "").slice(0, 240),
      }}),
      img: (_tag, attributes) => ({tagName: "img", attribs: {
        src: resolveArticleImage(attributes.src, articleUrl),
        alt: String(attributes.alt || "Wikipedia image").slice(0, 300),
        title: String(attributes.title || "").slice(0, 240),
        loading: "lazy",
      }}),
    },
    exclusiveFilter: (frame) =>
      (frame.tag === "img" && !frame.attribs.src) ||
      (frame.tag === "a" && !frame.attribs.href),
    nonTextTags: ["script", "style", "textarea", "option", "noscript"],
  });
}

function extractArticle(html, articleUrl, access = "") {
  const titleMatch = String(html).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = plainText(titleMatch?.[1] || "Snova Reader").replace(/\s+-\s+Wikipedia\s*$/i, "");
  let source = String(html)
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|noscript|svg|canvas|iframe|form|nav|header|footer)[^>]*>[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?\s*>/gi, "\n")
      .replace(/<\/p\s*>/gi, "\n\n")
      .replace(/<\/h[1-6]\s*>/gi, "\n\n")
      .replace(/<li[^>]*>/gi, "\n• ");
  source = plainText(source).replace(/\s*•\s*/g, "\n• ").replace(/\n{3,}/g, "\n\n");
  if (source.length > 70000) source = `${source.slice(0, 70000)}\n\n[Reader shortened this long page.]`;
  return {title, text: source, html: sanitizeWikipediaHtml(html, articleUrl, access)};
}

async function readWikipedia(url, fetcher = fetchWithTimeout, access = "") {
  const titleKey = decodeURIComponent(url.pathname.slice("/wiki/".length));
  const response = await fetcher(url, {
    redirect: "follow",
    headers: {"User-Agent": "ScriptNovaa-Snova/1.0 (https://scriptnovaa.com/)"},
  });
  if (!response.ok) throw new Error("The article could not be loaded.");
  if (response.url) safeReaderUrl(response.url);
  const contentType = String(response.headers.get("content-type") || "");
  const length = Number(response.headers.get("content-length") || 0);
  if (!contentType.includes("text/html") || length > MAX_READER_BYTES) {
    throw new Error("This page cannot be displayed in Snova Reader.");
  }
  const html = await response.text();
  if (Buffer.byteLength(html, "utf8") > MAX_READER_BYTES) throw new Error("This article is too large for Snova Reader.");
  const article = extractArticle(html, url, access);
  if (article.title === "Snova Reader") article.title = titleKey.replace(/_/g, " ");
  return article;
}

function mountSnovaWeb(app, dependencies) {
  const {route, rateLimit, ipPrefix} = dependencies;
  app.get("/search", route(async (req, res) => {
    let authorization;
    try {
      authorization = await requireSnovaAccess(req.query.access, dependencies);
    } catch (error) {
      return sendHtml(res, shell("Project Z required", `<h1>Project Z session required</h1><p class="muted">${escapeHtml(error.message)}</p><p>Open Project Z, start a Z token, and choose Snova.</p>`), 403);
    }
    await rateLimit(`${authorization.session.accountId}:${ipPrefix(req)}`, "SNOVA_SEARCH", 90, 60 * 60);
    const query = String(req.query.q || "").trim().slice(0, MAX_QUERY_LENGTH);
    if (!query) {
      return sendHtml(res, shell("Search", "<h1>Snova Search</h1><p class=\"muted\">Search reader-friendly information, or continue with Google, DuckDuckGo, or Bing.</p>", "", authorization.access));
    }
    try {
      const results = await searchWikipedia(query);
      return sendHtml(res, shell("Search", searchResultsHtml(query, results, authorization.access), query, authorization.access));
    } catch (_error) {
      return sendHtml(res, shell("Search", searchUnavailableHtml(query), query, authorization.access));
    }
  }));

  app.get("/reader", route(async (req, res) => {
    let authorization;
    try {
      authorization = await requireSnovaAccess(req.query.access, dependencies);
    } catch (error) {
      return sendHtml(res, shell("Project Z required", `<h1>Project Z session required</h1><p class="muted">${escapeHtml(error.message)}</p>`), 403);
    }
    await rateLimit(`${authorization.session.accountId}:${ipPrefix(req)}`, "SNOVA_READER", 60, 60 * 60);
    const url = safeReaderUrl(req.query.url);
    try {
      const article = await readWikipedia(url, undefined, authorization.access);
      const content = `<div class="links"><a class="button secondary" href="/search?access=${encodeURIComponent(authorization.access)}">Back to Snova Search</a><a class="button" href="${escapeHtml(url.href)}">Open original</a></div><article class="card"><h1>${escapeHtml(article.title)}</h1><p class="muted">Safe reader view · Images from Wikimedia · Interactive scripts removed</p><div class="article">${article.html}</div><p class="muted">Content from Wikipedia. See the original article for attribution, licensing, references, and the latest revision.</p></article>`;
      return sendHtml(res, shell(article.title, content, "", authorization.access));
    } catch (error) {
      const content = `<h1>Reader could not open this article</h1><p class="muted">${escapeHtml(error.message)}</p><div class="links"><a class="button secondary" href="/search?access=${encodeURIComponent(authorization.access)}">Return to Snova Search</a><a class="button" href="${escapeHtml(url.href)}">Open original</a></div>`;
      return sendHtml(res, shell("Reader unavailable", content, "", authorization.access), 502);
    }
  }));
}

module.exports = {MAX_QUERY_LENGTH, MAX_READER_BYTES, escapeHtml, plainText,
  wikipediaArticleUrl, safeReaderUrl, searchWikipedia, searchResultsHtml, searchUnavailableHtml,
  requireSnovaAccess, resolveArticleLink, resolveArticleImage, sanitizeWikipediaHtml, extractArticle,
  readWikipedia, mountSnovaWeb};
