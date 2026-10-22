"""Self-contained continuation notebook; data/checkpoints remain RAM to HF."""
import ast
import json
from pathlib import Path
from v23_longrun import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V22_Conversation.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
           'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py',
           'v20_generalize_data.py','v21_curriculum_data.py','v22_conversation_data.py','v23_public_chat.py','v23_longrun.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V23 — longer public-conversation training

Enable Kaggle **Internet**, **GPU**, and **NEBULA_HF_TOKEN**, then **Run all**.
Use one session per OUTPUT_RUN. Stop the previous trainer after its confirmed backup first.

## Continue the saved model

Loads **V22 after 4,000 additional updates**, pinned at
`6c670c3670444d7cde2b17760fea1cdde4a93b18`. The 100M architecture and byte tokenizer stay unchanged.
V19–V22 remain intact. A fresh optimizer starts the changed data mix; V23 resumes its own optimizer/scaler.
No teacher API calls, private user-chat imports, or website updates.

## More useful variety

Acquires up to **12,000 public Smol-SmolTalk conversations** at pinned revision
`f73fe857d519ff6ac5af2ea67c4d3834da7b8bcc` (Apache 2.0; synthetic public data, not human-verified).
Reads only declared train Parquet files with a RAM range cache. No full corpus download or local dataset cache.
Scans at most 80,000 records; reports the actual accepted count and exclusion reasons. If fewer than 256
complete conversations fit, it stops preparation rather than silently reverting to template-only training.
A scan limit can yield fewer than 12,000. Filtering does not guarantee factual correctness or full PII removal.

Conversations must be structurally valid, finish with a complete assistant answer, and fit the 1,024-byte context.
**No answer or conversation is truncated** to force it into the context. Contact/credential patterns, malformed
text, obvious conflicting provider identities, exact duplicates and exact benchmark prompts are excluded.
Long conversations are skipped, which biases this sample toward short exchanges.
The source card, attribution, source-row locations, preparation cursor and accepted records are saved to HF.
If preparation is interrupted, rerun the same notebook to resume from its last preparation backup.

A deterministic hash assigns whole conversations to train or held-out groups. Up to 64 held-out conversations
are measured separately; none of the validation records enter new practice. Older public exposure is unknown.
70% of optimizer updates are assistant practice; 30% retain existing raw-language practice.
Within assistant-practice examples: **80% public conversations / 20% earlier synthetic exercises**.
All assistant turns, including their real EOS, are supervised; system/user targets remain masked.
These are update/example proportions, not token proportions. Counters report actual supervised targets.

## Leave it training and resume later

Budget: **20,000 additional updates**, peak LR **8e-6**, 60-update warmup and cosine decay.
Each session runs the training loop for up to **7.5 hours**. Preparation, baseline evaluation and backups add time;
platform session and GPU quota limits still apply. This notebook cannot train forever or bypass quotas.

* Save directly to HF every **200 updates** and on a graceful pause/interrupt.
* Evaluate once at baseline, every **5,000 updates**, and at final completion.
* Intermediate evaluation uses held-out losses and the 96-question synthetic benchmark, without full open probes.
* Checkpoints improving sampled public loss over V22, with acceptable mixed-loss retention, are referenced as candidates.
  This is a loss-based selection hint, not quality approval. Training never silently rolls back to them.
* Baseline/final include actual chat and raw-generation probes. Familiar prompts can be memorized.

If it pauses before 20,000, **Run all again with the identical configuration**. It restores the last confirmed
checkpoint and optimizer rather than starting over. Do not change settings or RUN_NAME to resume.
Completed runs display their saved comparison. One GPU is used even on T4 x2. T4 uses native FP16 AMP.

## Storage

All new datasets/checkpoints/reports remain in RAM and upload to the PUBLIC repository
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v23-longrun/**.
The existing pinned V18 raw corpus is referenced, not duplicated. Only code/notebook/packages use disk.
No local dataset/checkpoint fallback, ZIP or Google Drive. Uploaded data and checkpoints are public.

Wait for **v23CheckpointConfirmed** before closing. Interrupt once for a graceful save.
Abrupt shutdown may lose progress since the last confirmed backup. Backup failures stop the run.
HF history/storage and GPU quotas still apply. Changed code/settings require a new OUTPUT_RUN.
'''
    setup=''.join(previous['cells'][1]['source'])
    config="OUTPUT_RUN='nebula-v23-longrun'\nCONFIG="+repr(DEFAULT)+'\n'
    tail='import importlib'+''.join(previous['cells'][3]['source']).split('import importlib',1)[1]
    tail=tail.replace('from v22_conversation import','from v23_longrun import').replace('nebula-v22-conversation-code','nebula-v23-longrun-code').replace('V22 checkpoint','V23 checkpoint')
    tail=tail.replace("'tutorLoss':comparison[stage]['heldoutTutor']['loss'],", "'tutorLoss':comparison[stage]['heldoutTutor']['loss'],'publicChatLoss':comparison[stage]['heldoutPublic']['loss'],")
    execute='sources='+repr(sources)+'\n'+tail
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v23-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V23_Long_Run.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
