# ScriptNovaa Family

The parent dashboard is at https://scriptnovaa.com/parentdashboard/. Family routes are isolated under `/api/family/*` and data is under Firebase `familyProtection`. Existing account authentication and PIN verification are reused; parent controls also require a short-lived family grant. Child credentials are scoped to family device routes.

Automatic Gemini review defaults off and requires the parent to enable it. The existing server-side `GEMINI_API_KEY` is reused; flagged media is not saved in Firebase. Clear nudity samples still require parent approval before removing a site block. Remote assistance is visible, limited to five minutes, and has no shell execution.

Signed Windows release metadata is read from https://raw.githubusercontent.com/formywor/Ooga-Booga/main/family-update.json unless `FAMILY_UPDATE_MANIFEST` overrides it. Clients verify Ed25519 signatures and SHA-256 before installation. Never publish the private release signing key.

Publish the extension to browser stores and set `FAMILY_CHROME_EXTENSION_ID` and/or `FAMILY_EDGE_EXTENSION_ID` to enable installer-assisted extension setup. Until then use the bundled unpacked extension.

Validation: `node --check index.js` and `node --test test/*.test.js`. Deploy the latest complete commit after all family files are present. Verify `/api/family/extension` returns JSON and `/api/family/state` rejects unauthenticated requests. Test account pairing and the first Windows update with a parent present.
