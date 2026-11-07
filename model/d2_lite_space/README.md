---
title: Nebula D2 Lite
emoji: 🚀
colorFrom: indigo
colorTo: purple
sdk: gradio
app_file: app.py
python_version: 3.12
pinned: false
---

Experimental native checkpoint service for Nebula D2 Lite. This is separate from D2 Preview. It loads one pinned, checksum-verified public research checkpoint; no hosted-model fallback is used. Requests are authenticated by the ScriptNovaa server and access remains owner/invitation only there. The public health endpoint reports readiness and checkpoint identity only. No request bodies or credentials are logged by this app. Free shared GPU capacity has quotas and queue limits.

The checkpoint is not quality-approved for general deployment. Outputs may be unclear or incorrect. This service provides text inference only, no browser or Cloud execution tools. The original training artifacts are read-only and are not modified.
