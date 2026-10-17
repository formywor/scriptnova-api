# Public training sources

Nebula imports data from these Hugging Face datasets, separately from account chats and API teacher collection:

- Hugging Face, **Everyday Conversations for LLMs** (2024): https://huggingface.co/datasets/HuggingFaceTB/everyday-conversations-llama3.1-2k — Apache License 2.0. Synthetic multi-turn conversations; these are not independently verified facts.
- HuggingFaceTB, **SmolTalk**, `smol-magpie-ultra` subset: https://huggingface.co/datasets/HuggingFaceTB/smoltalk — Apache License 2.0 for this newly generated subset. Other SmolTalk subsets have different licenses and are not imported by this script.

License: https://www.apache.org/licenses/LICENSE-2.0

The importer removes malformed, duplicate, truncated, and selected foreign-identity examples and redacts likely contacts or credentials. Downloaded pages remain in the ignored `model/data/public-cache/` folder. Each imported record retains its source, subset, license, original row index, and content hash. `model/data/public-sources.json` records counts and transformations. Conversation windows remain grouped together in the same train/validation partition.

Public data may contain errors or biases. A structural filter is not a claim of human review or production quality. Retain source and license notices when redistributing derived data.

## Optional language-first curriculum

`improve_training.py` downloads up to 10,000 TinyStories training rows by default (hard limit 20,000). Ronen Eldan and Yuanzhi Li, **TinyStories**: https://huggingface.co/datasets/roneneldan/TinyStories and https://arxiv.org/abs/2305.07759. License: **CDLA-Sharing-1.0**, https://cdla.dev/sharing-1-0/. Keep this attribution, license reference, and per-record source metadata with derived story data. The importer wraps stories in a synthetic story request, redacts likely contacts/credentials, and excludes malformed, oversized, duplicate, and truncated records. Counts and checksums are recorded in `stories-sources.json`. Stories are used for the language stage; chat training uses complete short conversations and original, programmatically checked arithmetic and extraction exercises. The curriculum is experimental and does not establish general chat quality. No pretrained model weights or account chat exports are added.

V3 (`overnight.py`) reuses the cached story sample and complete short conversations without further network downloads. Its additional original curriculum includes identity, help requests, exact addition exercises, and extraction from short prompts and dialogues. Owned variations of a name scenario or operand pair have a shared `splitGroup` so those variations cannot cross the training/validation partition. This does not establish decontamination of other public sources. The language stage excludes the earlier formulaic arithmetic curriculum and long technical conversations to prioritize simpler prose. V3 checkpoints are separate from earlier models, with optional optimizer/sampler state for compatible resumes. The downloadable `Nebula_V3_Data.pt` preserves exact input bytes, source records, and checksums; retain it together with model checkpoints for later recovery.
