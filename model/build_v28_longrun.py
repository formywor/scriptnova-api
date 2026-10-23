"""Package resumable V28 continuation without modifying older notebooks."""
import ast
import json
from pathlib import Path
from v28_longrun import DEFAULT

def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V27_Subword.ipynb').read_text(encoding='utf-8'))
    tree=ast.parse(''.join(previous['cells'][3]['source']))
    sources=ast.literal_eval(tree.body[0].value)
    for name in ['v27_subword_data.py','v27_subword_train.py']:sources.pop(name)
    for name in ['v28_foundation_data.py','v28_decode.py','v28_longrun.py']:sources[name]=(root/name).read_text(encoding='utf-8')
    intro="""# Nebula V28 — longer subword foundation continuation

Enable Kaggle **Internet**, **GPU** and secret **NEBULA_HF_TOKEN**, then **Run all**.
Stop other workers writing this output run. Uses **one GPU**, FP16 AMP on T4.

## Why this branch

V22 is retained as the stronger reference for familiar chat exercises. V23–V26
reduced some losses but did not deliver a clear general-conversation upgrade.
V27's 99.2M subword model completed 10,000 updates / 81.92M training positions,
but its continuations still repeated and lost meaning. V28 continues its language
foundation; it is a best-effort next recipe, **not a proven best model**.

Starts from V27's confirmed final foundation checkpoint at immutable revision
**6e46bb0a97a98867a3e6412ad549c4cefb2de84c**, tokenizer and weights checksum-verified.
No random restart, pretrained replacement, resizing, weight averaging or merge
with incompatible byte models. All prior versions stay untouched.

## Data and objective

Reuse V27's exact **8,192-token BPE tokenizer** and **1,024-token context**.
Expand the selected public foundation data to approximately **384 MB train** and
**8 MB validation** from the saved, pinned V18 corpus. This includes the previous
subset plus additional documents, not 384 MB entirely new text. Whole documents
may slightly exceed target sizes. Approximately **55% FineWeb-Edu, 30% Cosmopedia-v2,
10% Cosmopedia/OpenStax textbooks, 5% TinyStories**, measured in selected UTF-8 bytes.
Other sources can contain narratives too; 5% describes TinyStories specifically.

Tokenization retains original disjoint document-hash splits. BPE merges are
**not retrained**, and no validation text enters tokenizer training. Records,
source cards, licensing/attribution references, source revisions and checksums are
saved. Existing exact-document deduplication is checked; no claim of fuzzy
near-duplicate removal, factual verification or independent benchmark purity.

Foundation training uses continuous packed text with real document boundaries.
No chat templates, repetitive copy/color drills, teacher API calls or private chats.
The model needs better plain-text coherence before conversation SFT. A separate
conversation stage remains available after foundation completion and inspection;
it is off by default and never starts automatically.

## Training and checks

Budget **30,000 additional foundation updates** (up to **245.76M supervised
subword-token positions**, repeated exposure included), across as many resumed
sessions as necessary. Fixed approximately 99.2M architecture. Fresh continuation
AdamW at peak **3e-5**, 200-update warmup then cosine decay to 10%; bias/norm vectors
have no weight decay, other matrices 0.1, betas 0.9/0.95, gradient clipping 1.0.
Resetting the optimizer once is intentional for the new corpus/schedule. Each
V28 resume restores its own optimizer and scaler. Actual target counts are logged.

Evaluate at baseline, every **2,000 updates** and completion. Save held-out total
and per-source losses, plus both **greedy and sampled** raw continuations. No
repetition penalties conceal the model's behavior. More fluent samples or lower
loss do not prove factual correctness. Subword and legacy byte losses cannot be
compared directly. No automatic winner, rollback, release or website change.

## Earlier saves and quota headroom

Set **SESSION_HOURS below your remaining GPU quota**. Default is **6.5 hours**;
the trainer stops updates **10 minutes earlier**, leaving a backup margin. This
is an elapsed-time budget, **not automatic detection of Kaggle's quota**. If you
have 2 hours left, set SESSION_HOURS=2.0. Every new Run all gets a new time window,
so adjust it to your remaining quota each session. Do not change CONFIG on resume.

Save every **100 updates OR five minutes**, whichever comes first, plus on a
graceful interruption or time-budget pause. Stop-time pauses save and skip extra
final generation checks. Preparation counts toward the session time window.
Uploads and final evaluation can overrun estimates; the margin cannot guarantee
survival of sudden platform shutdowns or network stalls. Abrupt termination can
lose progress after the last confirmed backup.

Wait for **v28CheckpointConfirmed** before closing. An upload progress bar alone
does not confirm the manifest commit. Backup failures stop training. Keep RUN_NAME,
CONFIG and code unchanged to restore the latest confirmed V28 state. Completed
stages show saved reports. Change RUN_NAME for changed training settings.

## Storage

Datasets, tokenizer, checkpoints, optimizer and reports stay in RAM and upload to
PUBLIC **iiidevv/nebula-raw-training**, **experiments/nebula-v28-longrun/**.
Code/packages/notebooks may use disk; no local model/data fallback, Drive or ZIP.
No private user conversations are imported. Original V27 data and weights remain
at their pinned revision. The isolated tokenizer package avoids changing Kaggle's
Transformers installation. Training starts only when you run this notebook.
"""
    setup=''.join(previous['cells'][1]['source']).replace('nebula-v27-tokenizer-packages','nebula-v28-tokenizer-packages')
    config="RUN_NAME='nebula-v28-longrun'\nRUN_STAGE='foundation'\nSESSION_HOURS=6.5\nRESERVE_MINUTES=10.0\nCONFIG="+repr(DEFAULT)+'\n'
    execute='sources='+repr(sources)+"""
import importlib
code_root=Path.cwd()/'nebula-v28-longrun-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v28_longrun import run
report=run(RUN_NAME,CONFIG,stage=RUN_STAGE,hours=SESSION_HOURS,reserve_minutes=RESERVE_MINUTES)
if report.get('rawCompletions'):
    for item in report['rawCompletions']:
        print('MODE:',item.get('mode'),'PREFIX:',item['prefix'])
        print('CONTINUATION:',item['continuation'])
else:
    print('Paused and saved. Run all again with unchanged configuration; set session time below your remaining quota.')
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v28-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for value in sources.values():ast.parse(value)
    path=root/'Nebula_Kaggle_V28_Longrun.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
