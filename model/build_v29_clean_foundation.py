"""Build a bounded cleaned-foundation experiment while preserving prior runs."""
import ast
import json
from pathlib import Path
from v29_clean_foundation import DEFAULT

INTRO='''# Nebula V29 - clean foundation continuation

Enable Kaggle **Internet**, a **GPU**, and secret **NEBULA_HF_TOKEN**, then **Run all**.
Uses **one GPU**; FP16 AMP on T4. Stop other workers writing this run.

## Why this experiment

V28 completed 30,000 continuation updates, but its inspected answers still looped
or missed the question. Its lower next-token loss did not establish useful chat.
An audit reconstructed all 245.76M V28 training positions: **57.2770% FineWeb,
27.7031% Cosmopedia, 9.5336% textbooks, 5.4863% TinyStories**. TinyStories alone
was not dominating. Other sources contain narratives too.

Eight decoded corpus windows exposed **embedded base64 image data in a textbook**
and **mangled punctuation in a story**. This proves those artifacts exist, not
how widespread they are or that they explain every model failure. V29 measures
and removes them across the selected documents before a bounded continuation.

## Preserve the current model

Continue V28's final **99,221,760-parameter** foundation weights at immutable
revision **9cfc225eae2fefe1fee5e01d77690487172d6dce**, confirmed at **30,000 updates**.
Keep its exact **8,192-token BPE tokenizer**, architecture and **1,024-token context**.
Checksums are verified. No pretrained substitution, resizing, random restart or
weight merging. Older experiments remain untouched. The tokenizer is inherited
for compatibility; this does not remove any artifact-related vocabulary merges.

## Clean the text, then check splits again

Select the same original approximately **384 MB train / 8 MB validation** documents
as V28: original UTF-8 byte quotas are 55% FineWeb, 30% Cosmopedia, 10% textbooks,
5% TinyStories. These are original selection quotas, not promises about the
remaining cleaned bytes or token mix. Whole documents can exceed quotas slightly.

Repair encoding with ftfy; strip embedded data/image payloads and script/style
blocks; remove excessive repeated long lines. Reject mostly encoded documents,
very short remnants, reserved markers, replacement/control characters, and
remaining detected encoding damage. This is artifact cleanup, **not factual
verification or fuzzy deduplication**. It can reject useful text too.

Process validation first, reserve its normalized cleaned hashes, then exclude
matching training documents. Deduplicate again after repair because different
originals can become identical. Save accepted original/cleaned hashes, cleaning
counts, actual retained bytes, token ranges, source revisions and attribution.
Validation text never trains the tokenizer. Rebuild interrupted preparation in RAM
if needed; a fully confirmed prepared corpus is reused on subsequent sessions.

## Bounded training, not another indefinite run

Run **2,000 additional foundation updates**, up to **16.384M subword-token positions**.
Fresh AdamW once for the changed corpus: **3e-5**, warmup **100 updates**, then hold
constant through this short trial; betas 0.9/0.95, matrix decay 0.1, vectors 0,
gradient clipping 1.0. Resume restores V29's optimizer/scaler. This learning-rate
choice is an experiment, not evidence that V28's schedule caused its failures.

Before updates, audit the actual checkpoint/device for causal masking, prefix
consistency, train/eval agreement and finite logits. Abort if it fails. This small
pipeline check does not certify competence or all historical training behavior.

Evaluate at baseline, 1,000 updates and completion using the **same cleaned held-out
set**, per-source losses, and greedy plus sampled raw continuations. Compare these
reports with each other; old uncleaned V28 losses use a different validation set.
No repetition penalties conceal behavior. Inspect actual continuation meaning;
lower loss or a fluent sample alone does not prove general conversation ability.
Conversation SFT stays off and never begins automatically. No automatic release
or public website change. No teacher APIs or private chats are used.

## Resume and earlier saves

Default **SESSION_HOURS=6.5**, with **10 minutes reserved** for saving. Set session
time below your remaining GPU quota; the notebook cannot detect that quota.
Preparation counts toward elapsed time. Save every **100 updates or five minutes**,
plus graceful stop/time pause. Wait for **v29CheckpointConfirmed**. An upload bar
alone does not confirm the manifest commit. Failed backups stop training.
Sudden platform termination or network stalls can still lose unsaved progress.

Run all again with the same RUN_NAME, CONFIG and code to resume. For changed
settings use a new output run. Each resumed session gets a new elapsed-time budget.
Set PREPARE_ONLY=True if you want to prepare data with GPU disabled; set it back
to False and enable GPU to train. Completed stages display the saved final report.

## Storage

Corpus, tokenizer, weights, optimizer and reports stay in **RAM**, uploaded to
PUBLIC **iiidevv/nebula-raw-training**, **experiments/nebula-v29-clean-foundation/**.
Code/packages/notebooks can use disk; no local data/checkpoint fallback, Drive or
ZIP. Public means anyone can download these artifacts. Prior runs are preserved.
Only run one worker per output run. The isolated package directory preserves
Kaggle's globally installed Transformers dependencies. Training starts when you
execute this notebook; model improvement is not yet demonstrated.
'''

def build():
    root=Path(__file__).parent
    old=json.loads((root/'Nebula_Kaggle_V28_Longrun.ipynb').read_text(encoding='utf-8'))
    sources=ast.literal_eval(ast.parse(''.join(old['cells'][3]['source'])).body[0].value)
    for name in ['v28_longrun.py','v28_foundation_data.py']:sources.pop(name)
    for name in ['v29_clean_foundation.py','v29_clean_data.py','v29_clean_text.py','v29_pipeline_audit.py']:
        sources[name]=(root/name).read_text(encoding='utf-8')
    setup=''.join(old['cells'][1]['source']).replace('nebula-v28-tokenizer-packages','nebula-v29-isolated-packages')
    setup=setup.replace("'tokenizers==0.22.2'", "'tokenizers==0.22.2','ftfy==6.3.1','wcwidth==0.2.13'")
    config="RUN_NAME='nebula-v29-clean-foundation'\nRUN_STAGE='foundation'\nSESSION_HOURS=6.5\nRESERVE_MINUTES=10.0\nPREPARE_ONLY=False\nCONFIG="+repr(DEFAULT)+'\n'
    execute='sources='+repr(sources)+'''
import importlib
code_root=Path.cwd()/'nebula-v29-clean-foundation-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v29_clean_foundation import run
report=run(RUN_NAME,CONFIG,stage=RUN_STAGE,hours=SESSION_HOURS,
           reserve_minutes=RESERVE_MINUTES,prepare_only=PREPARE_ONLY)
if report.get('rawCompletions'):
    for item in report['rawCompletions']:
        print('MODE:',item.get('mode'),'PREFIX:',item['prefix'])
        print('CONTINUATION:',item['continuation'])
elif PREPARE_ONLY:
    print('Data preparation saved. Enable GPU and set PREPARE_ONLY=False to train.')
else:
    print('Paused and saved. Run all with unchanged configuration and session time below remaining quota.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',INTRO),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v29-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for value in sources.values():ast.parse(value)
    path=root/'Nebula_Kaggle_V29_Clean_Foundation.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=old['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
