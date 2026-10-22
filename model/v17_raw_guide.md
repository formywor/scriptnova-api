# V17 raw-text mode — enabled in this update

The original staged comparison remains available below with `RAW_DATA_MODE=False`. The default is now a separate **nebula-v17-raw-prose** branch. It starts from **current-foundationWeights**, saved before the context drills. All completed V17 checkpoints and reports remain intact.

This branch performs raw next-token language training only. It does not add context/name/color drills, teacher calls, user messages, or chat fine-tuning. Improving language is an experiment; raw pretraining alone does not teach a model to reliably follow instructions.

## Collection and packing

The default target is **64 million UTF-8 text bytes**: 50% FineWeb-Edu `sample-10BT`, 35% SmolLM-Corpus `cosmopedia-v2`, and 15% TinyStories by acquired bytes. Source targets are approximate within document boundaries; actual accepted bytes and rejection counts are saved. These proportions are a hypothesis to test, not an established optimum for Nebula. The datasets are streamed at pinned revisions rather than downloaded in full. The network may read more parquet bytes than the text retained.

Whole documents are assigned to train or validation by normalized content hash **before** packing. Two percent of document hashes go to validation, which is not necessarily exactly 2% of bytes. Normalized exact deduplication works across sources. There are also whole-document size/Unicode checks, credential-pattern exclusions and fixed-probe exclusions. Text is not fact-checked or fuzzy-deduplicated. Provenance and the actual pinned dataset cards are saved privately. Validation separation applies to this run; it does not prove that older model versions never encountered a document.

UTF-8 byte values become IDs 0–255, with real document BOS/EOS IDs 256/257. Packed `.bin` files use little-endian **uint16**, so disk size is roughly twice the text size. Continuous chunks preserve document boundary tokens without fake end markers at every chunk edge. NumPy memory maps keep the full corpus out of RAM. A SQLite index records document hashes, source references, split, offsets and stream cursors. Committed lengths recover interrupted writes; final binary checksums detect corruption.

FineWeb-Edu and SmolLM-Corpus cards list ODC-By; TinyStories lists CDLA-Sharing-1.0. Original source terms still apply. Python-Edu contains blob identifiers, not inline text, and requires a separate content-retrieval process. It and The Stack are not fetched automatically. No dataset content is executed as code or used as notebook instructions.

## Run, pause, and reuse

1. Enable the existing **NEBULA_HF_TOKEN** Colab secret. No other provider key or Drive mount is required.
2. Leave `RAW_DATA_MODE=True`. Choose T4 GPU and Run all. Optionally set `PREPARE_ONLY=True` to collect data on CPU before switching to a GPU.
3. Default training budget: **10,000 updates** at batch 8 and the source model's 1,024-position context, approximately **81.9 million supervised positions**, including repeats and structural tokens. That is different from 64 million acquired text bytes. This is a bounded pilot, not a 5–20 GB download or unlimited training.
4. Preparation privately backs up about every 8 MB and at completion or handled interruption. Training writes local checkpoints every 50 updates, cloud checkpoints every 500, and raw loss/actual generation reports every 1,000. Raw completions and chat answers stay pending human review. No score triggers deployment.
5. The two-hour session target can be exceeded by an in-progress download, evaluation or upload. Run all resumes the remaining budget with Adam/scaler state. Only confirmed cloud progress survives Colab runtime deletion. Free GPU quotas still apply. Do not start duplicate workers.

Keep `RAW_RUN_NAME` and `RAW_CONFIG` unchanged to resume. For changed settings, use a new raw run name. To continue from a completed raw branch, set `sourceRun` to that branch and `sourceKey` to `finalWeights`; this starts a new optimizer schedule from the saved weights. The source and destination run names must differ. The text collection cap is configurable up to 512 million bytes per branch; use measured branches rather than an unbounded acquisition.

The raw dashboard is `raw-dashboard.json`, backed up under `experiments/<RAW_RUN_NAME>/reports/dashboard.json`. It distinguishes unique acquired bytes, training positions, source mix and held-out loss. No website/API upload is needed to run this notebook.

---

## Original staged-comparison mode
