# Nebula Open capacity routing (server operations)

Order: Cloudflare primary, Cerebras, OpenRouter free router, Mistral,
Gemini, then the dedicated final Groq credential. Missing credentials are skipped.
The four intermediate services require their own accounts and quotas. A wired
route is not an activated account or a guarantee of free production capacity.

Set secrets in Vercel's production environment, then deploy:

| Service | Server secret | Default model |
| --- | --- | --- |
| Primary | `NEBULA_OPEN_API_TOKEN`, `NEBULA_OPEN_ACCOUNT_ID` | `@cf/openai/gpt-oss-20b` |
| Gemini | `NEBULA_OPEN_GEMINI_KEY` (otherwise existing Spark key) | `gemini-2.5-flash` |
| Cerebras | `NEBULA_OPEN_CEREBRAS_KEY` | `gpt-oss-120b` |
| OpenRouter | `NEBULA_OPEN_OPENROUTER_KEY` | `openrouter/free` |
| Mistral | `NEBULA_OPEN_MISTRAL_KEY` | `mistral-small-latest` |
| Final fallback | `NEBULA_OPEN_GROQ_FALLBACK_KEY` | `openai/gpt-oss-20b` |

Use free accounts without auto-recharge or paid billing for a zero-cost setup.
Provider availability, commercial-use terms and free quotas must be checked on
the selected account before activation. OpenRouter is fixed to its free router
and excludes Groq so that the dedicated Groq fallback remains separate.
Hugging Face training/storage credentials are not reused for inference.

Only inference is retried. Existing conversation, tool calls and observed tool
results are sent to the next service; browser actions are not replayed. Successful
backups remain preferred for subsequent tool rounds in that response, with Gemini second-to-last and Groq
always last. Capacity, transient network, malformed-response, missing-model,
authentication and exhausted-credit failures can move to the next service.
HTTP 200 refusals and ordinary HTTP 400 errors do not trigger failover.

Each inference attempt has a seven-second timeout within a maximum sixty-second
inference-round deadline and the existing whole-answer deadline. Cancellation
stops the chain. One logical inference counts once toward Open's existing daily
preview cap; switching services does not reset usage or grant unlimited access.

Warm instances remember provider cooldowns, honoring Retry-After up to one hour.
This is best-effort process-local protection, not a globally coordinated circuit
breaker. Logs contain only the fixed provider ID and HTTP status, never keys,
prompts, response bodies or raw errors. No third-party credentials go to clients.

Validate with `node --test test/open-providers.test.mjs test/open-preview.test.mjs`.
Before enabling each new credential, test a harmless response and a calculator
tool round-trip on that provider's actual account. Unit tests cover forced
fallback through all six routes, credential separation, cooldowns, cancellation,
quota counting and retaining a completed tool result across service failures.

## Account activation check — November 7, 2026

All three new accounts use the owner's requested massattackforall@gmail.com address.
OpenRouter's free router completed a live calculator round trip and its credential
is stored as a production-only Vercel secret. The automatically issued key is
named Nebula Open fallback and expires May 6, 2027; rotate it before expiry.
Do not enable strict provider parameter matching for openrouter/free: the live
router rejected tool requests with require_parameters=true, while its documented
automatic tool-capability routing succeeded without that setting.

Cerebras created a default key but requires a payment method to activate even its
one-time promotional credits. Mistral disables API-key creation on this new Free
account and asks for a paid upgrade. Neither is enabled in Nebula, and no payment
method or subscription was added. Their adapters remain ready for a future
separately authorized activation; these accounts are not active free backups.
