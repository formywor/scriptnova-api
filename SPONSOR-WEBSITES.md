# Sponsor website catalogue

New website sessions are separate from paid Galaxy tokens. They have no expiry timer; one current session is stored at `websiteSessions/<accountId>`. Only the signed-in owner can read or end that record. Start is idempotent for the same sponsor. Ending checks the session ID to protect newer sessions from stale tabs.

Administrators manage `sponsors/<unique-lowercase-id>` in the private Firebase console. Keep database client writes locked. Fields:

```
status: "ACTIVE"
permissionConfirmed: true
name: "Example partner"
description: "Reviewed partner website"
url: "https://partner.example/"
mode: "embed"
```

Use `mode: "link"` for websites that prohibit framing. Only activate after checking ownership/permission, HTTPS, content safety, framing headers and navigation. Set status to `SUSPENDED` to stop listing and invalidate website sessions on their next check. Never include credentials in the URL. The built-in ScriptNovaa demo is not an external sponsor.

Galaxy 1.0.5 fetches this public catalogue and opens the signed-in website session page. It does not extract Chrome cookies. Website sign-in may be needed. The site's session viewer checks authorization every 30 seconds while visible and when returning to the tab. Account notices refresh every minute. No points or token spending occurs. This is not DRM: ending a session removes the managed view but cannot disable public partner websites or close external tabs.

Previously issued gateway/hosting grants keep their original timer for backward compatibility. The new sponsor session flow uses `/sponsors`; it does not automatically migrate arbitrary uploaded sites or deploy partner source code.
