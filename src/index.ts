export interface Env {
  OPENAI_API_KEY: string;
  DB: D1Database;
  RATE_LIMIT: KVNamespace;
}

type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function getClientIP(req: Request) {
  // Cloudflare provides this header
  return req.headers.get("CF-Connecting-IP") || "0.0.0.0";
}

async function rateLimit(env: Env, key: string, limit: number, windowSeconds: number) {
  const nowBucket = Math.floor(Date.now() / 1000 / windowSeconds); // simple fixed window
  const bucketKey = `rl:${key}:${nowBucket}`;

  const current = await env.RATE_LIMIT.get(bucketKey);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= limit) return false;

  await env.RATE_LIMIT.put(bucketKey, String(count + 1), { expirationTtl: windowSeconds + 5 });
  return true;
}

async function loadMemory(env: Env, userId: string) {
  const { results } = await env.DB.prepare(
    "SELECT key, value FROM memory WHERE user_id = ?"
  )
    .bind(userId)
    .all<{ key: string; value: string }>();

  return results || [];
}

async function upsertMemory(env: Env, userId: string, key: string, value: string) {
  const updatedAt = new Date().toISOString();
  await env.DB.prepare(
    `
    INSERT INTO memory (user_id, key, value, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, key) DO UPDATE SET
      value = excluded.value,
      updated_at = excluded.updated_at
    `
  )
    .bind(userId, key, value, updatedAt)
    .run();
}

function buildSystemPolicy() {
  // Your policy lives here. Keep it short for MVP.
  return `
You are ScriptNova AI.
Follow the developer's policy:
- Be helpful and safe.
- Do not help with wrongdoing.
- If the user asks for something unsafe, refuse briefly and offer a safer alternative.
`;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // Basic CORS so your GitHub Pages chat can call the API
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "POST, GET, OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-max-age": "86400",
        },
      });
    }

    const corsHeaders = { "access-control-allow-origin": "*" };

    // Health check
    if (url.pathname === "/health") {
      return json({ ok: true, service: "scriptnova-api" }, 200, corsHeaders);
    }

    // Step 3 endpoints: memory
    if (url.pathname === "/v1/memory/get" && req.method === "POST") {
      const body = await req.json().catch(() => null) as null | { user_id?: string };
      const userId = body?.user_id?.trim() || "";
      if (!userId) return json({ error: "user_id required" }, 400, corsHeaders);

      const mem = await loadMemory(env, userId);
      return json({ user_id: userId, memory: mem }, 200, corsHeaders);
    }

    if (url.pathname === "/v1/memory/set" && req.method === "POST") {
      const body = await req.json().catch(() => null) as null | { user_id?: string; key?: string; value?: string };
      const userId = body?.user_id?.trim() || "";
      const key = body?.key?.trim() || "";
      const value = body?.value?.trim() || "";
      if (!userId || !key || !value) return json({ error: "user_id, key, value required" }, 400, corsHeaders);

      await upsertMemory(env, userId, key, value);
      return json({ ok: true }, 200, corsHeaders);
    }

    // Main chat endpoint
    if (url.pathname === "/v1/chat" && req.method === "POST") {
      // Rate limit by IP (MVP)
      const ip = getClientIP(req);
      const allowed = await rateLimit(env, ip, 30, 60); // 30 requests per 60 seconds
      if (!allowed) return json({ error: "rate_limited" }, 429, corsHeaders);

      const body = await req.json().catch(() => null) as null | {
        messages?: ChatMessage[];
        user_id?: string;
      };

      const messages = body?.messages || [];
      const userId = (body?.user_id || "anon").trim();

      // Load memory and add it as context (safe “learning” without changing weights)
      const memory = userId !== "anon" ? await loadMemory(env, userId) : [];
      const memoryText =
        memory.length
          ? "User memory:\n" + memory.map(m => `- ${m.key}: ${m.value}`).join("\n")
          : "User memory: (none)";

      const system: ChatMessage = { role: "system", content: buildSystemPolicy() + "\n" + memoryText };

      // Call OpenAI (you can swap providers later without changing the website)
      const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "gpt-4.1-mini",
          messages: [system, ...messages],
          temperature: 0.7,
        }),
      });

      if (!openaiRes.ok) {
        const err = await openaiRes.text();
        return json({ error: "upstream_error", detail: err.slice(0, 500) }, 502, corsHeaders);
      }

      const data = await openaiRes.json() as any;
      const reply = data?.choices?.[0]?.message?.content ?? "(No response)";

      return json({ reply }, 200, corsHeaders);
    }

    return json({ error: "not_found" }, 404, corsHeaders);
  },
};