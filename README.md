# ScriptNovaa API

## Project Z addition — September 3, 2026

This upload also supports Project Z **0.1.5** without changing Share Browser's
required launcher version (1.2.7). Deploy this API before publishing the new
website/download. No new secrets, paid provider, Firebase index, or separate
Vercel function is required. Keep the support assistant.

Project Z 0.1.5 adds `/search` for Snova Search and `/reader` for the formatted
Wikipedia reader. The reader is deliberately restricted to Wikipedia articles;
it is not an unrestricted public proxy.

- `GET /api/z/config` — versioned public configuration.
- `POST /api/z/status` — verifies the paired account and current device proof.
- `POST /api/z/session/activate` — Z-only token and atomic session activation.
- `POST /api/z/session/heartbeat` — validates account, device, token and lease.
- `POST /api/z/session/end` — idempotent terminal operation.
- `POST /api/tokens/create` accepts `product: "share" | "z"` (default Share).
- `GET /api/public-config` includes `projectZ.tokenOptions` and connection limits.
- Shared pairing endpoints accept `X-Project-Z-Version: 0.1.5` or the existing
  Share header. Pairing completion consumes the code and registers the device
  atomically, without awarding the setup bonus twice.

Z configuration says **direct**, `vpnAvailable: false`, `fastAvailable: false`.
Requests asking for a proxy/FAST connection are rejected, not billed. Heartbeats
require the paired account bearer credential, session secret and device proof.
An expired 30-second lease is terminal. No scheduled cleanup or paid service was
added. Root transactions follow the existing database architecture and should be
load-tested against your real Firebase quotas before scaling.

Tokens without a product field are legacy Share tokens. The two-unused-token
limit counts both products. Purchases debit points and create the token in one
transaction. Active Share and Z sessions share the same per-account launch lock.

Run `npm run check` to validate syntax and the policy/pairing/session regression
tests. Test the deployed app with a real connected computer before public rollout;
local simulations do not prove production hosting or every website sign-in works.

Backend for Share Browser, served publicly from:

`https://api.scriptnovaa.com`

The API uses Firebase Realtime Database and is deployed through Vercel.

Current public launcher version: **1.2.7**

The API rejects outdated launchers on pairing, connection validation,
configuration, activation, launch confirmation, and active-session
heartbeats. Update the `CURRENT_LAUNCHER_VERSION` value in `index.js` only
when the matching launcher is already available on the website.

An activated session must confirm that its browser process started. If an
unconfirmed session becomes stale, the API restores its token to `UNUSED`;
heartbeat timeouts only consume tokens after launch confirmation.

Launcher 1.2.7 retries browser startup once, tolerates up to two temporary
network/server heartbeat failures. Authenticated API rejections, revocation,
expiration, and an outdated launcher still end the session immediately.
It also uses WMI, `WScript.Shell`, and `ShellExecute` launch fallbacks and
temporarily locks the End control to prevent queued Start clicks from ending a
newly launched session.
It waits for the browser to remain alive before confirming launch. An early
browser exit triggers one API-provided compatibility launch; an unconfirmed
failure restores the token. Balanced mode and the browser's standard identity
are the public defaults, while stronger modes remain optional.

Additional API-controlled browsing modes are available:

- `T44`: normal browser identity with no additional preset options;
- `T55`: ScriptNovaa compatibility identity with no additional preset options;
- `T77`: extensions disabled, with local history discarded when the temporary
  session profile is removed. It does not force Incognito.

The API removes `--incognito` and `--guest` from every preset and fallback
before returning browser configuration. No public browsing mode can force
either private-window mechanism.

The public website also uses `/api/demo/start` and `/api/demo/status` for a
10-minute online interface preview. A browser can start one preview per rolling
24 hours. A shared network can start up to 20 previews in that period so school
and library networks are not treated as one person.

Sponsored-reward waits use account-age trust tiers. Clean accounts have an
instant-claim chance of 20% when new, 55% after four days, 84% after one week,
and 99% after four weeks. Accounts under fraud or reversal review always wait
12–14 minutes.

## Guided support assistant

Support chat uses a server-side troubleshooting rules engine and the signed-in
user's sanitized account state and recent launcher diagnostics. It does not use
Google or a paid AI API. Users can request a representative at any time.

The assistant is read-only: it cannot change points, restrictions, devices,
tokens, sessions, or administrator data. Closed chats remain available as
history and never prevent the user from starting a new conversation. Deploy
the Realtime Database rules with the `launcherDiagnostics.accountId` index when
publishing this version.

When a representative resolves and closes a chat, the API may create a private
learning suggestion. It is never used automatically. A full administrator must
remove account-specific details, edit the reusable answer and keywords, and
approve it in Operations → Learning. Approved guidance is stored in
`supportKnowledge` and can be matched in future conversations. This is reviewed
knowledge retrieval, not untrusted self-training or code modification.

## Uploading to GitHub

Upload the contents of this folder to the root of the `scriptnova-api`
repository.

Do not upload:

- `node_modules`
- `.vercel`
- `.env` or `.env.local`
- Firebase service-account JSON files

Those files are blocked by `.gitignore`.

## Required Vercel environment variables

- `FIREBASE_PROJECT_ID`
- `FIREBASE_DATABASE_URL`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
- `PIN_PEPPER`
- `SESSION_PEPPER`
- `RECOVERY_PEPPER`
- `ADMIN_SECRET`
- `REDIRECT_TARGET_URL`

The setup script configures these values:

```bash
npm run setup
```

Only run setup when initially configuring or intentionally replacing the
production secrets. A normal GitHub update does not require running setup
again because the Vercel project is already linked to the repository.

## Creating an administrator

The `/admin44` website page is not the security boundary. Every privileged API
request checks an active role stored in Realtime Database.

1. Find the account ID at `usernames/{username}/accountId` in Firebase.
2. Create `administrators/{accountId}` with:

```json
{
  "active": true,
  "role": "ADMIN",
  "displayName": "ScriptNovaa Admin"
}
```

Use `ADMIN` for full account, point, trust, appeal, ticket, and chat controls.
Use `SUPPORT` for ticket and live-chat access without sanctions, trust changes,
point adjustments, or appeal decisions. Never grant a role from a public API
request. Removing the record or setting `active` to `false` revokes access on
the next request.

All privileged changes are recorded under `adminAuditLog`. Do not delete audit
entries during routine moderation.

## Account safety states

New accounts store only a protected recovery-code credential and remain in a
`recoveryPromptRequired` state until the user confirms the one-time code screen.
Accounts created before this feature are grandfathered and are not locked.

Supported moderation states are `ACTIVE`, `SUSPENDED`, `BANNED`, and
`TERMINATED`. The API—not the web page—blocks normal endpoints for restricted
accounts. Appeals remain available through the restricted session.

## Reviewing support tickets

Support tickets are stored in Firebase Realtime Database under:

```text
supportTickets/{ticketId}
```

Administrators can review them from `/admin44` or Firebase Console. For a
connection-code replacement request, the review states include:

```text
APPROVED
DECLINED
```

You can also add an `adminResponse` string that the user will see on the
Support page. Do not delete the ticket. When an approved replacement code is
generated, the API automatically changes the ticket to `FULFILLED` and records
`replacementConsumedAt`.

Live chats are stored under `supportChats`; appeals are stored under `appeals`.
Live chat is best-effort only and cannot authorize point refunds or restore
lost rewards. Use tickets for decisions that need a durable support record.

## Security notes

- Realtime Database client access remains deny-all. Only the Vercel API uses
  Firebase Admin credentials.
- Never upload the service-account JSON or copy private keys into website code.
- The website does not execute third-party notification scripts on signed-in
  pages because those pages hold account login data.
- Network information shown to administrators is reduced to a network prefix;
  raw full IP addresses and device fingerprints are not shown.
- No system can be guaranteed impossible to hack. Keep dependencies updated,
  review Vercel/Firebase access, rotate exposed secrets, and monitor the audit
  log and failed-login limits.

## Validation

Install dependencies and run the checks:

```bash
npm install
npm run check
```

After Vercel finishes deploying, verify:

`https://api.scriptnovaa.com/api/health`

The response should identify the Share Browser API and Firebase Realtime
Database and report launcher version `1.2.7`.

## Normal release

Do not rerun the setup script for ordinary code updates. Push the updated API
files to GitHub and allow the linked Vercel project to deploy them. When a
release changes the required launcher version, publish the matching website
download first, then deploy the API. For the online-demo update, deploy this API
before the website so visitors never reach a missing route.
