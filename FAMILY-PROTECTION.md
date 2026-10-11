# ScriptNovaa Family

The parent dashboard is at https://scriptnovaa.com/parentdashboard/. Family routes are isolated under `/api/family/*` and data is under Firebase `familyProtection`. Existing account authentication and PIN verification are reused; parent controls also require a short-lived family grant. Child credentials are scoped to family device routes.

Automatic Gemini review defaults off and requires the parent to enable it. The existing server-side `GEMINI_API_KEY` is reused; flagged media is not saved in Firebase. Clear nudity samples still require parent approval before removing a site block. Remote assistance is visible, limited to five minutes, and has no shell execution.

Signed Windows release metadata is read from https://raw.githubusercontent.com/formywor/Ooga-Booga/main/family-update.json unless `FAMILY_UPDATE_MANIFEST` overrides it. Clients verify Ed25519 signatures and SHA-256 before installation. Never publish the private release signing key.

Publish the extension to browser stores and set `FAMILY_CHROME_EXTENSION_ID` and/or `FAMILY_EDGE_EXTENSION_ID` to enable installer-assisted extension setup. Until then use the bundled unpacked extension.

Validation: `node --check index.js` and `node --test test/*.test.js`. Deploy the latest complete commit after all family files are present. Verify `/api/family/extension` returns JSON and `/api/family/state` rejects unauthenticated requests. Test account pairing and the first Windows update with a parent present.

## Private family console (0.2.1)

Parent authorization checks the authenticated account username against `iii_dev` on every family parent route, including unlock. Other accounts cannot claim the console or use a stolen family grant. Existing username/PIN login remains unchanged for other products. The static login page is public, but family data and controls require the owner account and a PIN-confirmed, ten-minute grant.

Full-screen remote viewing uses the existing visible, five-minute session. Commands allow normalized pointer movement, left/right click, one/two clicks, ASCII text, navigation keys, scrolling and Ctrl+A/C/V/X/Z/Y. Arbitrary keyboard combinations and shell commands are rejected. Child heartbeat version reporting lets the viewer warn on older agents.

Validation for this release: 141 API tests and nine Windows policy/update tests passed. Browser controls were verified against a synthetic screen; real owner login and paired-child input require the owner to sign in.

## Version 0.2.2

Family unlock accepts remember:true for a 30-day grant, otherwise ten minutes. POST /api/family/parent/lock revokes the current account-session grant. The account/PIN and iii_dev owner restriction are unchanged. Parent settings persist through the existing family database.

Parent pairing accepts test:true; pairing retains that flag, labels the device [TEST], and reports it in parent state. POST /api/family/parent/test/alert queues a short-lived connection test. POST /api/family/parent/test/stop rejects real devices and stops only isolated same-PC tests. Heartbeats accept an update-status string. No other products, secrets or login routes were modified.

All 143 API tests pass, including remembered-grant expiration/revocation/account isolation and test-device boundaries.
