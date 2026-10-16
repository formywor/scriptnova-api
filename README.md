# Nebula API

Server-only source for the existing Vercel API project. Keep this directory separate from the public website repository. It replaces the previous API; the previous Share Browser routes are not part of Nebula.

Install with `npm install`, check with `npm run check`, and start with `npm start`. Node 24 is used. Vercel explicitly builds root `index.js` with `@vercel/node` and routes requests to it. A Node request/response adapter invokes the shared Web Request application. The preview server lives in `scripts/dev.mjs` and is not a deployment entry point. No model is included yet.

Configure the Firebase environment variables already used by the earlier API and set `NEBULA_RATE_LIMIT_SECRET` to a stable random secret of at least 32 characters. Credentials belong in Vercel environment variables, never in website files or Git. Set `NEBULA_TRAINING_ENABLED=true` only when collection is ready. Default is false. The API fails closed if rate-limit storage or its secret is unavailable. Read/write database access from browser SDKs is denied by the supplied database rules; deploy them intentionally, especially if the database has unrelated applications.

The allowed origins default to the main and www scriptnovaa.com domains. Set `NEBULA_ALLOWED_ORIGINS` explicitly to add local preview origins. CORS is a browser restriction, not authentication. Distributed Firebase counters limit a hashed Vercel network identity to 12 requests per minute and 300 daily; shared networks share these limits. The hashed rate-counter records require periodic operator cleanup if network cardinality grows. Configure Vercel firewall/bot controls to suit actual traffic; guest requests remain anonymous, while account routes require verified Firebase ID tokens.

## Training choices

The website starts with training sharing off. The public checkbox explicitly enables new-turn contributions. POST `/api/nebula/chat` contains validated chat messages for generation and an explicit `training` object. Only a true consent flag, consent version 1, a 64-character random hex data token, and valid chat/turn identifiers permit collection. Only the current user message and its generated reply are eligible; full context is never copied to training storage. Opting in later does not backfill earlier private messages. The public model name and destination cannot be changed by visitors; they are server configuration.

Accepted samples are private Firebase records under `nebulaTraining/v1/<hashed-token>/samples/<chat>/<turn>`, marked `pending` review. There is no public list/read/export endpoint. Basic email and common credential-pattern redaction reduces accidental collection but is not a comprehensive personal-data filter; review and curate samples before training. Requests and raw message content are not logged by this application. Hosting infrastructure may have its own request logging.

An unconnected model returns a friendly `MODEL_NOT_READY` status; if the user consented and collection is configured, their new message can still become a pending contribution. Collection failures never return a false success. `trainingSaved` reports actual persistence. The frontend keeps an anonymous data token in this browser. DELETE `/api/nebula/training` with that token removes that browser's stored pending contributions and leaves a small revocation tombstone to prevent in-flight requests restoring deleted samples; clearing browser data loses the deletion token. Completed training, previous exports, and external copies cannot be undone by this endpoint. Collection and deletion are limited by the same rate counters. Each token is capped at 200 candidate turns; assistant samples are capped at 24,000 characters. After deletion the website switches sharing off and generates a new data token, so a later explicit opt-in can start fresh.

This builds a consent-controlled candidate dataset. It does not modify model weights, start training, claim improvements, or automatically trust public submissions. A future offline training process needs review, quality checks, poisoning defenses, a retention policy, and an export process restricted to the operator. Deletion of local chats, archiving, and disabling future sharing do not delete already contributed samples; the separate delete-shared-data action does.

## Model connection (later)

Set `NEBULA_MODEL_URL`, optional `NEBULA_MODEL_KEY`, and `NEBULA_MODEL_NAME` in Vercel. The server sends an OpenAI-compatible JSON messages request and accepts `reply` or `choices[0].message.content`. Only the answer string is sent to the browser. No upstream errors, URLs, credentials, or metadata are exposed. Custom-model instructions and model selection should be enforced on that server. The public API URL necessarily remains visible in browser network requests; it is not a secret. The website settings contain no developer configuration.

## Deployment compatibility update

The reported Vercel CLI 64.0.2 build failed before installation with `Cannot read properties of undefined (reading fsPath)`. The logs did not include a stack trace, so the exact internal cause is unconfirmed. This update removes ambiguous backend entry-point discovery by using the explicit build/route layout used by the previous API.

Upload `index.js`, the updated `package.json` and `vercel.json`, and `scripts/dev.mjs` along with the retained `lib` files. Remove obsolete root `server.mjs` and nested `api/index.mjs` from GitHub. Keep Vercel Root Directory pointing to the directory containing `package.json` and `vercel.json`. A new commit will trigger the Git-connected deployment. This local change has not been deployed or build-tested by Vercel; 23 local API/entry-point tests pass.

## Firebase accounts

See `../FIREBASE_SETUP.md` and `.env.example` for provider setup. GET `/api/nebula/auth/config` exposes only the four public Firebase web-config values and enabled-provider flags, never admin/model credentials. GET `/api/nebula/account` and PATCH `/api/nebula/account` require `Authorization: Bearer <Firebase-ID-token>`. The Admin SDK verifies signatures, expiry, project and revocation. Client-supplied account IDs are ignored. Profiles and preferences live under `nebulaAccounts/v1/<hashed-UID>`. Passwords and social/SMS verification are handled by Firebase's browser SDK rather than proxied or logged by this API.

Signed-in training requires both an explicit new-turn flag and a server-stored account opt-in. Default is off. Consent and the contribution generation are checked again after model generation. Training ownership derives from verified UID and server generation, not the browser data token. Deleting account training data revokes its current generation, turns sharing off, and advances the generation; local chat history is unaffected. Guest token-based collection and deletion continue separately.

CORS now supports GET/PATCH and Authorization. No chat-history synchronization or provider-account linking is implemented. 23 local tests pass, with injected Firebase identity/database boundaries. Live authentication, SMS, and deployment still need verification.
