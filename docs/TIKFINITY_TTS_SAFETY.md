# Nebula LIVE TTS Safety (preview)

This service accepts TikFinity chat webhooks and speaks only the moderated result through a Nebula browser-source overlay. It cannot intercept TikFinity's own TTS. Turn off TikFinity direct comment-to-speech so its separate, unfiltered path is not audible.

## Setup

1. Open `https://scriptnovaa.com/tts-safety/` and create a connection. Save the webhook key and private overlay URL; the key is returned once. Each connection expires after 30 days.
2. In TikFinity Actions & Events, make a chat-triggered webhook action. Set `POST https://api.scriptnovaa.com/v1/tts/events` with JSON:

```json
{
  "apiKey": "YOUR_PRIVATE_NEBULA_KEY",
  "event": "chat",
  "data": {
    "username": "{username}",
    "comment": "{comment}"
  }
}
```

TikFinity documents `{username}` and `{comment}` action placeholders. Confirm in TikFinity's test flow that they are substituted in the webhook JSON you use.
3. Add the private Nebula overlay URL as a browser source in OBS or LIVE Studio. Allow the source to play audio. Disable TikFinity's native comment TTS.

## HTTP API

### Create an anonymous connection

`POST /v1/tts/sessions`

```json
{"installationId":"a-random-client-generated-id-with-at-least-16-characters"}
```

Returns a one-time API key, overlay URL, and expiry. Setup is limited to three issued connections per IP per day. Do not log or expose the key or overlay URL.

### Submit a chat event

`POST /v1/tts/events`, with `Authorization: Bearer YOUR_KEY` or `apiKey` in the JSON body for webhook clients that cannot set headers. Accepts `data.comment`, `data.message`, `data.text`, or top-level `comment`, `message`, `text`; username accepts `username`, `nickname`, or `uniqueId`.

Response:

```json
{"eventId":"...","decision":"allow","category":"dictionary_match","usage":{"remaining":10999,"resetsAt":0},"queued":true}
```

Decisions are `allow` or `block`. The detected text is never returned to the webhook caller or put in the public voice queue. Blocked events queue a generic moderator reminder. The checked English dictionary is SCOWL US; words outside it, unsupported alphabets, malformed text, and blocked terms fail closed. This is a filter, not a guarantee that every harmful message is caught; retain moderator review and TikTok safeguards.

### Usage and revoke

- `GET /v1/tts/usage` with `Authorization: Bearer YOUR_KEY`
- `POST /v1/tts/revoke` with Bearer key (or `{"apiKey":"YOUR_KEY"}`)

Free anonymous usage is limited to 11,000 submitted messages per 120-hour window. Hour buckets are used for efficient counting. Revoke immediately invalidates the key and overlay.

## Account tools

These routes require a Firebase ID token in `Authorization: Bearer FIREBASE_ID_TOKEN`, plus a verified email:

- `POST /api/nebula/tts-safety/claim` with `{"apiKey":"YOUR_KEY"}` links a connection to your account.
- `GET /api/nebula/tts-safety/events` returns your linked connections' unexpired flagged records (up to 200).
- `POST /api/nebula/tts-safety/settings` with `{"apiKey":"YOUR_KEY","aiEnabled":true,"model":"nebula-ultra"}` enables optional AI review only when the account has a Nebula+ entitlement. D2 and D2 Lite cannot be selected. AI reviews only borderline English messages and fail closed on timeout or allowance limits.

Flagged records contain the detected term, username, timestamp, event ID, category, and a hash of the original message. Records are logically available for seven days; clean comments are not saved. The public overlay path exposes only queued speech or a generic moderator alert, not review records.
