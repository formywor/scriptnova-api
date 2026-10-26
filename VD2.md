# Nebula V-D2 — implementation status and setup

This is a coding experiment and an owner-only developer workspace, not a completed trained model.
Nothing has been deployed, no bucket was emptied, and no source weights/data were modified.
The prepared implementation is now applied directly to this project. Existing Devices files
were preserved, and overwritten source files were backed up under .vd2-backup-* at the project root.
The V-D2 model still requires data approval, training, and a separately configured inference worker.

## What is implemented

- Developer preview beside Nebula Cloud, using the existing plain JS design and authorizedFetch wrapper.
- Four server-derived tiers: Standard, Above Standard, Advanced, Invite Only.
- Only a server-verified Firebase token with verified email `divedyacoub9@gmail.com` gets owner access.
  Pin `NEBULA_OWNER_UID` to that account's actual Firebase UID for additional protection.
- Owner-only, audited tier grants and suspension/revocation. Model text cannot grant permissions.
  Above Standard and Advanced expose beta eligibility metadata; they do not bypass existing feature guards.
  The tiers do not yet introduce specific additional beta products or higher quotas.
- V-D2 remains owner-only by default. Optional future invitations require the owner to grant Invite Only
  and deliberately enable `NEBULA_VD2_INVITES_ENABLED=true`. Standard/Above/Advanced do not get V-D2.
- Passive review of supplied code and up to three explicitly authorized public HTTPS pages.
  Existing Nebula Cloud public-page reading pins public DNS, forbids private IPs, redirects and logins.
  Optional public documentation search uses the existing server-configured search adapter.
- Potential static hints for eval, unsafe HTML insertion, shell execution, embedded credentials and
  disabled TLS verification. Hints are not confirmed vulnerabilities. No secret values are quoted.
- Detailed remediation is requested from the selected model: evidence, impact, fix, safer code,
  regression tests, uncertainty. There is no exploit execution, shell, automatic site editing or deploy tool.
- Ultra plan and optional request-brief bridge are explicitly labeled. No fake V-D2 fallback.
  Models do not have a separate magical language: the worker tokenizes ordinary text itself.
- Developer code/results are ephemeral; no chat-history, cross-chat memory or training writes occur.
- Sign-out, account changes, closing and Cancel abort requests and discard late results.

This does NOT build an unrestricted agent, rank users by AI affection, identify backdoors with certainty,
prove site ownership, execute fixes, perform invasive scans, or retrieve hidden backend code from a URL.
Public HTML text cannot reveal an entire server-side application. Paste authorized source for code review.
The user's authorization checkbox establishes task scope; it is not technical domain-ownership proof.

## API deployment configuration

Keep all existing Firebase, CORS, chat, training and Ultra environment settings.
Add these optional/new server variables; do not place secrets in the website:

```
NEBULA_OWNER_UID=<verified Firebase UID for divedyacoub9@gmail.com>
NEBULA_VD2_INVITES_ENABLED=false
NEBULA_VD2_URL=https://your-private-inference-worker.example/generate
NEBULA_VD2_TOKEN=<strong random token, at least 32 characters>
NEBULA_VD2_ULTRA_BRIDGE=false
```

`NEBULA_VD2_URL` is YOUR separately hosted model endpoint, not Hugging Face storage or Vercel.
Vercel coordinates requests; it does not train or load this 1B PyTorch model.
With URL/token absent the UI disables V-D2 and the route returns `VD2_NOT_DEPLOYED`.
Existing `NEBULA_ULTRA_API_KEY`/`GROQ_API_KEY` and `NEBULA_SEARCH_API_KEY` enable Ultra/search.
The optional bridge sends submitted code/context to Ultra too; keep it off unless that is desired.

Authenticated routes, through existing `api/index.js`:
- `GET /api/nebula/developer/access`
- owner `PUT /api/nebula/developer/tiers` with email, tier, status and audited reason
- `POST /api/nebula/developer/plan` — explicitly Nebula Ultra
- `POST /api/nebula/developer/review` — actual V-D2 only

Firebase keeps server-owned grants under `nebulaDeveloper/v1/grants/<hashed-email>`.
Existing deny-all client database rules remain unchanged; only the Admin SDK can write grants.
No direct client access or new custom claims are required. Invitations do not send emails.

Deploy backend `index.js`, new `lib/developer.mjs`, modified `lib/firebase.mjs` and existing files
through the normal API repository/Vercel process. Deploy new `developer.js`, `developer.css` and
the small `index.html` hook through the main website repository/GitHub Pages process.
Keep unrelated frontend files, especially unpublished Devices changes. Do not replace the whole
site with the published snapshot used for verification here. No production deployment was performed.

## Data inventory — what was actually inspected

Two previously identified public Hugging Face model repositories were inspected:
`iiidevv/nebula-research` and `iiidevv/nebula-raw-training`.
The pinned inventory contains 31 experiment manifests, 125 candidate data pointers,
and 100 distinct candidate object hashes. These are not counts of distinct documents/tokens.
`model/vd2_inventory.json` contains revision-pinned provenance, encoding and split candidates.
No training data objects, checkpoint weights, private buckets or private user chats were moved.
Other GCS/S3 buckets and repositories without credentials were not inspected.

Candidates are deliberately NOT automatically approved: older stores mix licensed public text,
synthetic teacher data, evaluation files and possibly consent-bound user samples. Review origins
and licenses before admission. Never import revoked/private user chat data just because a backup
is readable. Evaluation/probe/judge/weights objects are not training examples.

The consolidation path verifies hashes, decodes historical byte-u16 and BPE-u16 with the exact
associated tokenizer, imports whole approved JSONL documents, strips secret-like material,
normalizes encoding, deduplicates across runs, quarantines historical validation duplicates,
and saves one provenance-bearing corpus to a NEW PRIVATE repository. It does not concatenate
incompatible token IDs or average unrelated model weights. Prior repositories stay untouched.
Every admitted source needs `approved=true`, a reviewed license and an accurate origin.
User-chat/review-feed origins are forbidden. Holdouts never train the tokenizer.
No deletion, public/private conversion, paid storage change or training call occurred here.

The private storage requirement is meaningful: publicly downloadable weights cannot be owner-only
merely because a website hides their button. If your private HF quota is full, preparation will fail;
choose storage with enough private capacity before running. Do not delete old experiments to make room
without separately verifying backups and explicitly authorizing deletion.

## 1B coding experiment

Exact architecture: 1,007,334,912 parameters, 35 causal transformer blocks, width 1536,
24 heads, 8,192-token byte-level BPE vocabulary, 2,048-token context, tied embeddings/output,
learned positions, explicit causal SDPA and activation checkpointing. This is a fresh 1B model.
It does not inherit the earlier 100M/250M weights or their apparent benchmark performance.

Foundation sampling targets 75% code, 20% developer documentation, 5% general text (renormalized
when a pool is absent). 20% of sampled code documents use fill-in-the-middle augmentation.
This is weighted sampling, so measured small runs vary from those percentages. The general corpus
is retained for provenance but broad stories do not dominate training. At least 5,000 distinct code
training documents are required; this is a smoke-run admission floor, not enough data to promise a
competent 1B coder. Plan a substantially larger licensed coding corpus and measure held-out behavior.

The notebook defaults to inventory. It does NOT auto-approve unknown data, automatically train,
consume API teacher quotas, alter the public website, or merge every checkpoint.
After source review, set PHASE='prepare'; then PHASE='train' on sufficient hardware.
RAM -> private HF only: no local corpus/checkpoint fallback, notebook/code files aside.
Full AdamW checkpoints are about 12 GB before upload/transient copies; allow ample host RAM
(at least 32 GB; more is safer) and private storage. The conservative single-GPU trainer requires ONE >=40 GB GPU.
A separate experimental FSDP trainer now supports two T4s; see the added section below.
Two 16 GB T4s do not automatically combine into one 32 GB allocation.
Do not buy hardware or rent a pod based solely on an untested memory estimate.

Training: AdamW, betas 0.9/0.95, matrix decay 0.1, vector decay 0, clip 1.0,
10000-update smoke budget, batch 8 via single-example accumulation, LR 1e-4,
200-update warmup and cosine decay. BF16 where supported, FP16 AMP otherwise.
Actual-device causal/train-eval audit runs before optimizer updates; unchanged-tolerance math
fallback may be slower. Default save every 100 updates or 3 minutes, plus graceful stop.
Reserve 15 minutes before the requested session limit. Sudden shutdowns may still lose updates
since the last confirmed backup. Source/config changes require a separate destination run/repository.

Prepare merges only explicitly approved source entries and trains a fresh tokenizer. Existing
checkpoints are never overwritten. Own-run resume restores optimizer, scaler and RNG. Upload
failure stops updates. The minimal GPU recipe is not validated on actual 1B hardware in this runtime.
The packer includes EOS between documents but allows cross-document attention; it does not claim
block-diagonal document isolation. No arbitrary code examples are executed during preparation.

A successful foundation run is not yet a detailed security assistant. Before useful production
serving, add a separate coding-task/repair SFT phase with assistant-target masking and verified
fix/test pairs, and evaluate on genuinely held-out projects. This implementation provides the
foundation experiment, not an unvalidated claim that next-token loss yields secure code review.
Do not train on unchecked self-generated fixes. Acceptance should require compile/lint/unit tests
inside a network-isolated sandbox plus human review, never production execution.

## Serving after training

The separate worker factory is `model/vd2_serve.py`. Install torch, numpy, requests,
huggingface_hub, tokenizers, fastapi and uvicorn in the worker's environment. Set:

```
HF_TOKEN=<private read token>
NEBULA_VD2_REPO=iiidevv/nebula-vd2-private
NEBULA_VD2_WORKER_TOKEN=<same value as API NEBULA_VD2_TOKEN>
# Only for an explicitly accepted owner-only prototype, never a certification:
NEBULA_VD2_ALLOW_EXPERIMENTAL=true
```

From `model/`: `uvicorn vd2_serve:create_app --factory --host 0.0.0.0 --port 8000`.
Put this behind your own HTTPS ingress and restrict network access. The API worker token is
required on every generation; do not expose it in HTML. The current loader also checks the
namespace/private repository using its HF token, so it needs the owner's account token.
It reads the checkpoint into RAM (including optimizer serialization), so provision host RAM;
a later export should strip optimizer state for lean inference.
The worker returns the actual model ID and checkpoint checksum; the API rejects missing/wrong
attribution. Raw code-foundation weights are not assumed to understand instruction chat markers.
Prompt size must leave room inside 2,048 tokens; a too-large code excerpt is rejected, never
silently truncated. This is not a long-context repository-wide code agent.

## Verification and limits

Seven new Node tests cover owner/verified-email/pinned-UID gates, isolated and revoked grants,
invitation defaults, CORS/body/schema checks, no unconfigured V-D2 fallback, labeled Ultra,
ephemeral data and checkpoint attribution. Ten Python tests cover parameter count, encoding
separation, secret filtering, data admission, source inventory, holdout deduplication and two-rank checkpoint commit failure isolation.
UI integration checks use jsdom with fixture identities; they are not live Firebase login.
The real browser could not reach the runtime localhost (connection refused); no real browser
owner login, AI inference, GPU training, private uploads or production deployment was verified.

## Experimental two-T4 support (added at your request)

`model/vd2_fsdp.py` adds a separate two-GPU launch path using PyTorch FULL_SHARD,
per-transformer-block FSDP wrapping, FP16, ShardedGradScaler, checkpointed activations,
microbatch 1 per GPU and global batch 8 via accumulation. It synchronizes sharded
gradients on each microbatch rather than using no_sync with full accumulated gradients.
FP16 overflow skips are not counted as successful optimizer updates.

Unlike the conservative single-GPU trainer above, this path does not require a 40GB GPU.
It is intended for two 16GB T4s, but is **experimental and not memory-tested on real GPUs**.
Use the notebook's two-update smoke run first; it saves, then the normal launch resumes
that exact checkpoint/optimizer. CUDA OOM, unsupported kernels, host RAM pressure or
slow transfers can still block a real run. It is not guaranteed simply because two GPUs
are visible. The notebook does not secretly substitute a smaller model.

Checkpointing is designed to avoid gathering the full AdamW state: rank 1 uploads its
local optimizer to a separate rank manifest, rank 0 gathers CPU weights only, then writes
weights + rank-0 optimizer and atomically advances the main manifest with both optimizer
references. A failed rank-1 save cannot replace the previous complete main checkpoint.
Resume requires the same two ranks, model/config/source/code signature and PyTorch version.
No filesystem checkpoint fallback is used. GPU counts/world size cannot be changed on resume.
Host RAM still matters for tokenizer/corpus, CPU weight gathering, serialization and uploads;
watch RAM use during the smoke test. Saving/starting can take minutes, especially with ~12GB
of artifacts and restricted private storage. No source model was expanded or merged by this.

Run from the code directory:
```
HF_TOKEN=<secret in environment> python -m torch.distributed.run --standalone --nproc_per_node=2 \
  vd2_fsdp.py --repo iiidevv/nebula-vd2-private --hours 6 --reserve-minutes 15 --max-session-updates 2
# After a confirmed backup, omit --max-session-updates for the continuation.
```

The notebook defaults to TRAINER='two-t4' and can perform the smoke run then automatically
continue. Training data/quality approval are separate; two GPUs do not remove the need
for reviewed code sources. An abrupt notebook/torchrun kill can lose updates since the
last confirmed backup; use the session timer/reserve rather than assuming Ctrl+C gives
both ranks enough time to finish a large network save. Concurrent jobs for one run are
unsupported; commit-parent conflicts stop the writer instead of overwriting another run.

Additional checks: the actual model on a PyTorch meta device contains exactly 1,007,334,912
parameters. A tiny CPU version passes finite backward and causal masking checks. A genuine
two-process CPU FSDP check was attempted but blocked by this runtime denying Gloo sockets;
this is not a passed distributed test. The real two-T4 smoke check is included in the notebook.

## Website feature update
See WEBSITE_UPDATE.md for new public uploads/voice, redacted public-source inspection,
synthetic PIN lab, explicitly allowlisted timing samples, and real legacy model routing.
The new bounded samples supplement the earlier read-only review; they do not implement DDoS
or arbitrary login testing. No checkpoint is newly trained or certified by this update.
