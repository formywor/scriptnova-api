# ScriptNovaa API

Backend for Share Browser, served publicly from:

`https://api.scriptnovaa.com`

The API uses Firebase Realtime Database and is deployed through Vercel.

Current public launcher version: **1.2.0**

The API rejects outdated launchers on pairing, connection validation,
configuration, activation, launch confirmation, and active-session
heartbeats. Update the `CURRENT_LAUNCHER_VERSION` value in `index.js` only
when the matching launcher is already available on the website.

The public website also uses `/api/demo/start` and `/api/demo/status` for a
10-minute online interface preview. A browser can start one preview per rolling
24 hours. A shared network can start up to 20 previews in that period so school
and library networks are not treated as one person.

Sponsored-reward waits use account-age trust tiers. Clean accounts have an
instant-claim chance of 20% when new, 55% after four days, 84% after one week,
and 99% after four weeks. Accounts under fraud or reversal review always wait
12–14 minutes.

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

## Reviewing support tickets

Support tickets are stored in Firebase Realtime Database under:

```text
supportTickets/{ticketId}
```

Administrators and developers review them in Firebase Console. For a
connection-code replacement request, change `status` from `PENDING` to:

```text
APPROVED
DECLINED
```

You can also add an `adminResponse` string that the user will see on the
Support page. Do not delete the ticket. When an approved replacement code is
generated, the API automatically changes the ticket to `FULFILLED` and records
`replacementConsumedAt`.

## Validation

Install dependencies and run the checks:

```bash
npm install
npm run check
```

After Vercel finishes deploying, verify:

`https://api.scriptnovaa.com/api/health`

The response should identify the Share Browser API and Firebase Realtime
Database and report launcher version `1.2.0`.

## Normal release

Do not rerun the setup script for ordinary code updates. Push the updated API
files to GitHub and allow the linked Vercel project to deploy them. When a
release changes the required launcher version, publish the matching website
download first, then deploy the API. For the online-demo update, deploy this API
before the website so visitors never reach a missing route.
