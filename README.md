# ScriptNovaa API

Backend for Share Browser, served publicly from:

`https://api.scriptnovaa.com`

The API uses Firebase Realtime Database and is deployed through Vercel.

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
Database.
