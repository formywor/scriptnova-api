# Developer tools, uploads, voice chat and model availability

Implemented as an update to the existing Nebula plain-JS website and single Node API.
The prepared changes have been applied directly to this project's api and main-website folders.
Existing Devices implementation files were preserved. Nothing has been deployed.

## What the developer tools do

The owner/invite gate remains separate from target authorization. No public ownership-verification
service was added. Passive checks require an explicit authorization checkbox. Active timing samples
also require an exact server-configured URL; being invited does not authorize arbitrary targets.

- Inspect one public HTTPS page plus up to three same-origin script assets. Inspect selected response
  headers and detect token/private-key/credential-assignment indicators. Report source, line and a
  fingerprint with the credential value REDACTED. Rotate a leaked credential; deleting it is insufficient.
- Only bounded public IPv4 responses, DNS-pinned TLS, no credentials/cookies, no redirects or login,
  no private-network IPs, no executable browser session, at most 128KB per response.
- Missing CSP/HSTS/content-type protections are potential findings requiring context, not proof of an exploit.
- Tiny GET timing samples: default six requests, at most ten, one request per second, concurrency one,
  per-origin 60-second cooldown, exact endpoint allowlist, stop at 429/5xx/network failure. A body over
  64KB also stops sampling. This is not a DDoS, distributed test, stress test, or capacity certification.
- The synthetic PIN lab demonstrates a missing/empty-PIN bypass with fictional in-memory users.
  It runs positive/negative regression cases, explains the defect and remediation, and loads only the
  vulnerable code into the review form. Choose Ultra plan or actual V-D2 separately to assess the AI.
  The deterministic lab passing does not establish that V-D2 identified the bug.
- Hidden server code, session behavior, full codebases, third-party accounts, brute-force resistance
  and backend exploitability cannot be inferred from public page text. Upload authorized source
  snippets or use your own isolated staging test suite for those checks.

Routes (owner/explicit eligible invite only): POST `/api/nebula/developer/inspect`, `/lab`,
`/load-sample`, plus existing `/plan` and `/review`. No model-controlled arbitrary attack executor
was added. Source text and uploaded files never become application permissions or instructions.

Server settings:
```
NEBULA_LOAD_TEST_TARGETS=https://your-owned-staging.example/status
NEBULA_VD2_INVITES_ENABLED=false
NEBULA_ULTRA_MODEL=openai/gpt-oss-120b
NEBULA_ENABLE_LEGACY_MODELS=true
```
An empty load-target list disables timing samples. Use a safe, owned staging GET endpoint with
no state changes. URLs must match exactly and must not contain queries. No real public target
was sampled by the assistant. Keep existing CORS, Firebase verification and deny-all client DB rules.

## Uploads for all users

The main composer now has Attach files and drag-and-drop. Guests use their existing quota; signed-in
users use their existing account. Supported: UTF-8 text/code/Markdown/JSON/CSV/config/log files.
PDF, Office, raster images, audio and video are explicitly unsupported by the text-only endpoint.
Up to four files, 128KB each, 256KB total bytes and 12,000 extracted characters. Combined message
plus file content must fit 16,000 characters; no silent truncation. Files are parsed locally as text,
never executed or rendered as HTML, and sent as an untrusted JSON data block only on Send.
Known credential patterns are redacted before sending; this is a heuristic, not a guarantee that
all secrets or personal information can be detected. Do not upload credentials/private user records.
Remove staged files individually. They clear on successful persistence, account/chat changes and exit.

Text is included in ordinary chat history (account-saved when signed in; temporary for guests).
It is NOT a separate cloud file bucket/long-term downloadable attachment store. The original binary
file is not uploaded. File-containing conversations and voice conversations carry a server-persisted,
immutable contextPrivate marker that overrides training/review eligibility. Later turns in that
conversation stay excluded from training and optional external reviews. Existing sharing preferences
remain unchanged. This marker cannot be removed from an existing turn through client chat edits.
A guest request also carries the privacy flag and disables training. Manual copying elsewhere is
outside these automatic protections. Appearance changes are disabled when file blocks are in context,
so instructions buried in a file cannot activate appearance tools.

## Voice chat for all users

Voice chat is beside Attach files and uses the selected available model and existing chat/quota path.
No microphone permission is requested before the user accepts the disclosure and selects Start.
Browser transcription may send audio to the browser's service; microphone capture does not prove
transcription support. No audio recording is uploaded to Nebula. Browser speech output defaults to
US English when available; voice, speed, volume, hands-free silence interval and push-to-talk are
adjustable in the voice dialog. This does not replace or overwrite unpublished Devices voice settings.

Hands-free waits for final speech and a 1.2/1.8/3-second pause. Browser endpointing adds variable latency.
Push-to-talk supports pointer holding and Space/Enter; release queues finalized transcription. The
transcript is editable with manual Send. If files are staged, send/remove them in the main composer
before voice sending, preventing an automatic voice turn from unexpectedly uploading files.

Recognizers are stopped while the assistant speaks to reduce feedback. Replies match the originating
turn ID; other replies are not spoken. Stop/Pause/close, hiding the tab, account/model/chat change,
and page exit release microphone tracks and recognition timers and cancel browser speech. Stop does
not retract a chat message already sent to the API. Replay and Stop speaking are available. Denied,
missing/busy hardware, insecure/embedded policy restrictions, missing recognition and playback errors
have text recovery states. No browser TTS API key is needed; some OS/browser voices use online services.
No offline wake-word engine or universal browser compatibility is claimed.

## Models — truthful availability

The default Ultra provider model is now `openai/gpt-oss-120b`, listed by Groq as a current production
model at https://console.groq.com/docs/models. An explicitly set NEBULA_ULTRA_MODEL remains authoritative;
update that variable to adopt the new default if your server currently pins 20B. Actual organization
permissions, credits, rate limits and inference access have not been verified in this environment.
An available API key is configuration readiness, not a guarantee of healthy service.

Four existing owned checkpoints can now route separately to their real embedded CPU inference:
Classic, V1 (V4), V1 Lite, V2.1. They are labeled LEGACY EXPERIMENTAL, not new/smarter weights. Metadata
and part presence gate the catalog; real inference verifies artifact hashes. Set legacy flag false
to disable them. They can be slow, incoherent or context-limited and are not security-review models.
No older checkpoint was automatically upgraded, trained, promoted or certified. Default remains Ultra.
Remote legacy serving uses the separate authenticated worker described below. V-D2 remains private, separate and
unavailable until a real trained checkpoint/worker exists. There is no silent Ultra substitution for it.

## Applying and deploying

Extract the package. Run `python install_vd2.py "<your nebula-public project root>"`.
The installer backs up changed existing files. New features in core API modules and main app.js use
normalised source-hash guards against the known base or already-updated version; an unfamiliar
unpublished core modification stops the whole preflight before writing. Merge those files manually
or supply the current source rather than overwriting it. The Devices JS/CSS files are untouched.
Other HTML content outside the owned developer/voice additions is preserved.

Run API checks with the project's installed dependencies, review the diff and configure the env vars.
Then publish frontend changed `index.html`, `app.js`, `developer.js/css`, `chat-inputs.js/css` through
GitHub Pages and backend changed/new modules through the existing Vercel repository workflow. Existing
model assets must remain present. Do not upload training checkpoints into the Vercel function bundle.
The installer does not deploy, purchase resources, grant invitations, modify live environment variables,
run external load tests, start training or claim the model is experienced.

## Verification

Added tests cover bounded file parsing/redaction, privacy enforcement even when inference requests
try to re-enable training, immutable markers/review exclusion, final-transcript turn buffering,
legacy model routing, redacted source findings, crawl scope, target allowlists/cooldowns, early stop,
fixture bypass/fix regressions, and pre-provider secret removal. DOM integration tests connect the
actual main chat code to the real API handler with fixture auth/model responses. They cover signed-in
file sending, guest voice sending and denied microphone access. Existing regression checks remain.
Actual speech service/OS audio, mobile visual rendering, live Firebase sign-in, real provider inference,
T4 GPU training and a real authorized timing sample were NOT verified here. No external target was
attacked, sampled or modified. The browser could not reach the runtime's localhost preview.

### Vercel deployment detail: separate legacy inference worker

The current Vercel config deliberately excludes `model-assets/**` and
`node_modules/onnxruntime-node/**`. Those exclusions are retained: bundling all old weights
and CPU inference libraries into the API function would be large and fragile. For hosted
legacy choices, deploy `scripts/legacy-worker.mjs` separately with the existing model assets
and ONNX runtime installed, behind an authenticated HTTPS ingress, then configure:
```
NEBULA_LEGACY_URL=https://your-private-legacy-worker.example/chat
NEBULA_LEGACY_KEY=<strong random shared server secret, at least 32 characters>
NEBULA_ENABLE_LEGACY_MODELS=true
```
The worker defaults to loopback on port 8002. Container hosting can set
`NEBULA_LEGACY_BIND=0.0.0.0` behind its protected HTTPS ingress. The API and worker share
the key; it is never sent to browsers. Only the four known model IDs are accepted, each
response carries its actual model ID and artifact fingerprint, and the API rejects mismatches.
No public model assets or runtime are added to the Vercel bundle by this update. Local
embedded inference still works when those assets/dependencies are actually present.

Without either the separate worker or local embedded assets, the legacy choices remain
unavailable rather than showing an enabled button that cannot produce an answer. A stronger
Ultra default is not an upgrade of their trained weights. Current remote legacy fingerprints
are saved with replies; optional review does not assume an unavailable bundled fingerprint
is the same as a remote checkpoint. V-D2 uses its own separately configured private worker.
