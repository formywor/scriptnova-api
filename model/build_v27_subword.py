"""Self-contained Kaggle V27 subword foundation and separate SFT notebook."""
import ast
import json
from pathlib import Path
from v27_subword_train import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V26_Learning_Rates.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
        'v18_foundation_control.py','v18_decode_probe.py','v27_subword_model.py','v27_subword_data.py','v27_subword_train.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro="""# Nebula V27 — subword language foundation

Enable Kaggle **Internet**, **GPU** and secret **NEBULA_HF_TOKEN**. Then **Run all**.
Uses **one GPU**, FP16 AMP on T4. Stop other workers writing this same output run.
Nebula's pinned tokenizer installs in a separate package directory; Kaggle's global
Transformers/tokenizer installation is not changed by this notebook.

## A new experiment, not a promised upgrade

This branch starts **random weights**, with a newly learned byte-backed **BPE**
tokenizer, target **8,192 vocabulary items**, and **1,024 subword-token context**.
The model is approximately **99.2M parameters** (768 width, 12 heads, 13 layers,
tied input/output embeddings, learned absolute positions). No pretrained weights
and no conversion of byte-model checkpoints. V22–V26 remain untouched.

BPE merges are learned only from approximately **16 MB of training text**. The
byte alphabet preserves arbitrary UTF-8 roundtrips. Effective text per context is
measured by tokenization; no fixed 4x improvement is promised. Changing tokenizer,
initialization and training stage together makes this a new recipe, not an isolated
proof that tokenization caused any improvement.

## Foundation first

Reuse the existing immutable PUBLIC V18 corpus, with whole indexed documents and
the original disjoint train/validation split. Select approximately **128 MB train**
and **4 MB validation**. UTF-8 byte targets: **55% FineWeb-Edu, 30% Cosmopedia-v2,
10% Cosmopedia/OpenStax textbooks, 5% TinyStories**. Whole documents can slightly
exceed quotas. Sources are mixed through random packed-window sampling; tokenizer
compression means these percentages are not training-token percentages.

All original selected document hashes, source revisions, licenses and attribution
references are saved. The complete upstream attribution index stays at its pinned
V18 revision. Original exact-document deduplication is checked; this does not
claim fuzzy deduplication, factual verification or zero historical contamination.

Documents are packed with actual BOS/EOS boundaries, without padding each document.
Windows can cross document boundaries. No artificial EOS is inserted at window edges.
The initial goal is coherent plain-text continuation, **not answering chat prompts**.
No repetitive name/color templates, teacher APIs, private chats or web crawling.

Foundation budget: **10,000 updates × batch 8 × context 1,024 = 81,920,000 supervised
subword-token positions**, including repeated exposure. This is a bounded first run,
not full-scale pretraining or a guarantee of conversational competence.
AdamW: peak **3e-4**, 500-update warmup, cosine decay to 10%, betas 0.9/0.95,
weight decay 0.1 on matrix parameters, zero on bias/norm vectors, gradient clip 1.0.
A larger LR than V25 is intentional: these are newly initialized weights.

## Inspect before conversation training

Default **RUN_STAGE='foundation'**. Evaluate fixed held-out language blocks plus
three raw completions at baseline, every **2,000 updates** and completion. Scores
and outputs are saved. Subword loss is **not directly comparable** to byte-model loss.
There is no automated intelligence grade or model promotion.

After foundation finishes, inspect the actual continuations. If they are coherent,
you can change only **RUN_STAGE='conversation'** and Run all again in the same notebook.
That separate stage starts from the saved foundation weights with a fresh AdamW
optimizer, **1,000 updates**, peak **3e-5**, 100-update warmup. It uses the existing
pinned public Smol-SmolTalk snapshot: complete conversations, assistant-only targets,
whole-conversation hash split, no truncation. It remains a limited, previously used
synthetic subset, not new human-verified data. No raw-language updates are mixed into
this stage. Foundation weights are preserved under their own checkpoint key.

If foundation still produces loops or nonsense, keep conversation training off and
inspect the saved report instead of treating low loss as success.

## Resume and storage

Save every **250 updates** and on graceful interruption. Reports, tokenizer, packed
corpus and weights/optimizer/scaler stay in RAM and upload directly to PUBLIC
**iiidevv/nebula-raw-training**, under **experiments/nebula-v27-subword/**. Only code,
notebooks and packages use disk. No local artifact fallback, Drive or ZIP.
Source public text is appropriate for this public repository; never add private chats.
Uploads can take time: **v27BackupStarting** is followed by **v27CheckpointConfirmed**.
A completed file-upload progress bar alone does not confirm the manifest commit.

Session time is limited to **7 hours**, including preparation/baseline work; final
saving/evaluation can add time. Kaggle GPU quotas and session limits still apply.
Run all again with **identical CONFIG, RUN_NAME and code** to resume the selected
stage from its latest confirmed checkpoint and optimizer. Finished stages show saved
reports. Abrupt termination can lose progress after the last confirmed backup.
Failed backup stops the run; no silently unsaved continuation. If preparation stops,
confirmed tokenizer and completed packed splits are reused; an unfinished split may
be rebuilt in RAM. No auto-deployment or change to Nebula Ultra.

Changing CONFIG/code requires a new RUN_NAME; RUN_STAGE and SESSION_HOURS are safe
to change. This notebook prepares and trains when you run it; it has not been trained
or proven better merely because its software checks passed.
"""
    setup="""import os, sys, subprocess
from pathlib import Path
os.environ['HF_HUB_DISABLE_XET']='1'
os.environ['TOKENIZERS_PARALLELISM']='false'
subprocess.run([sys.executable,'-m','pip','install','-q','huggingface_hub>=0.34,<2',
    'requests>=2.32,<3','numpy>=1.26,<3'],check=True)
# Keep Nebula's pinned tokenizer separate from Kaggle's Transformers dependencies.
# This path contains package code only, never datasets or checkpoints.
loaded_tokenizer=sys.modules.get('tokenizers')
if loaded_tokenizer is not None and loaded_tokenizer.__version__!='0.22.2':
    raise RuntimeError('A different tokenizer is already loaded. Restart the kernel, then Run all with this notebook.')
tokenizer_packages=Path.cwd()/'nebula-v27-tokenizer-packages'
subprocess.run([sys.executable,'-m','pip','install','-q','--no-deps','--upgrade',
    '--target',str(tokenizer_packages),'tokenizers==0.22.2'],check=True)
sys.path.insert(0,str(tokenizer_packages))
import tokenizers
if tokenizers.__version__!='0.22.2':raise RuntimeError('Nebula tokenizer isolation failed')
from huggingface_hub import constants
constants.HF_HUB_DISABLE_XET=True
# Preserve platform PyTorch/CUDA. Do not reinstall torch.
token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
if not token:
    try:
        from kaggle_secrets import UserSecretsClient
        token=UserSecretsClient().get_secret('NEBULA_HF_TOKEN')
    except Exception:
        raise RuntimeError('Add and enable Kaggle secret NEBULA_HF_TOKEN.') from None
if not token.strip():raise RuntimeError('NEBULA_HF_TOKEN is empty')
os.environ['NEBULA_HF_TOKEN']=token.strip()
del token
"""
    config="RUN_NAME='nebula-v27-subword'\nRUN_STAGE='foundation'\nSESSION_HOURS=7.0\nCONFIG="+repr(DEFAULT)+'\n'
    execute='sources='+repr(sources)+"""
import importlib
code_root=Path.cwd()/'nebula-v27-subword-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v27_subword_train import run
report=run(RUN_NAME,CONFIG,stage=RUN_STAGE,hours=SESSION_HOURS)
if report.get('rawCompletions'):
    print('Inspect these continuations; a low loss alone does not establish quality.')
    for item in report['rawCompletions']:
        print('PREFIX:',item['prefix']);print('CONTINUATION:',item['continuation'])
    for item in report.get('openReplies',[]):
        print('QUESTION:',item['prompt']);print('REPLY:',item['reply'])
else:
    print('Session paused. Run all again with identical settings to resume the confirmed checkpoint.')
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v27-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for value in sources.values():ast.parse(value)
    path=root/'Nebula_Kaggle_V27_Subword.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
