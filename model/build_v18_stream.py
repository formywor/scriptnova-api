"""Portable Jupyter notebook and standalone launcher; corpus/checkpoints stay in RAM/HF."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V18 — GPU training with direct Hugging Face saves

**Destination:** https://huggingface.co/iiidevv/nebula-raw-training — a separate PUBLIC model repository.
Your existing weights, old experiments and public 63.7 MB corpus are preserved. The new corpus is prepared separately.
The source checkpoint defaults to `current-foundationWeights` in `nebula-v17-lab`, before narrow context-drill training.
The source repository may be private or public; this notebook does not change its visibility.

## No local dataset/checkpoint files

Raw source parquet is read remotely through in-memory block buffers. New packed shards, indexes and
model/optimizer/scaler checkpoints are uploaded from RAM. Training caches only two training and two validation
shards in RAM. **No corpus, checkpoint, report, SQLite database or token file is written to the worker filesystem.**
Only this notebook, Python code and installed packages use disk. No Google Drive or ZIP is used.
Host RAM is still required: **16 GB or more is recommended** for a 100M model and full optimizer uploads.
Unique-document deduplication hashes also use RAM. Uploaded files and accessible history are PUBLIC.
This runner does not collect account chats, private review feeds or API configuration. The inherited model may
already reflect earlier training, and public web text can contain personal information.

## Data experiment

Default: **1,000,000,000 unique UTF-8 bytes**, about 16 times our 63.7 MB pilot, with whole-document filtering,
normalized exact deduplication, pinned revisions, attribution and a 2% document-hash validation split.
50% FineWeb-Edu, 25% Cosmopedia v2, 15% TinyStories, 10% original Cosmopedia `openstax` synthetic educational text.
The mix is measured by acquired UTF-8 bytes, not ordinary subword tokens or optimizer steps.
Credential/control/size checks are applied; data is not fully fact-checked, PII-audited or fuzzy-deduplicated.
Public overlap with earlier training is possible. The first run streams and saves this larger corpus rather than
silently relabeling the old small corpus. Each data save is around 32 MB of new UTF-8 text plus packing overhead.

## Run order

1. Enable a Hugging Face WRITE token as `NEBULA_HF_TOKEN` in Runpod's secret/environment settings.
   If missing, setup uses a masked prompt, or the enabled Colab secret when running on Colab.
   The token is never written to a file or printed.
2. **ACTION='prepare'** first. This is CPU/network work; do it before paying for GPU time when possible.
   Run all until `v18DataReady: true`. A session stops after SESSION_HOURS; Run all resumes public cursors.
3. Change only ACTION to **'benchmark'**, enable your CUDA GPU, and Run all. Up to 100 disposable optimizer updates
   measure throughput; the protected source and actual training checkpoint are unchanged.
4. Change ACTION to **'train'** and Run all. Full-parameter raw next-token training uses FP16 with a scaler on T4,
   or BF16 when supported. CUDA is required; there is no silent CPU fallback. Microbatch=1, accumulated batch=8.
5. Use **'evaluate'** for raw completions and open chat probes. Read actual replies; low loss does not certify intelligence.

Training starts with the existing model. It does not restart random weights. New source snapshots contain only
the model and sanitized metadata; private chat exports or old arbitrary checkpoint metadata are not copied.
Default total budget: 100,000 updates = about 819 million byte-token positions at a 1024 context and batch 8,
including repeated exposure. This can require many GPU sessions; the benchmark estimates compute time.
SESSION_HOURS=2 bounds each training loop, but uploads/evaluation/one update can overshoot the deadline.
GPU billing continues while a machine is running, including transfers and idle time; stop the machine after backups finish.

Full model/optimizer/scaler state saves directly to PUBLIC Hugging Face every 500 updates and at a graceful stop.
Evaluation runs at baseline, every 1000 updates and session end. Older public checkpoint history remains;
public storage is best-effort, not unlimited. Do not run two workers against the same RUN_NAME.
**Only v18PublicBackupConfirmed marks durable progress.** RAM since the last successful commit can be lost
if the process or machine disappears. No disk copy is retained as a fallback, as requested.
Interrupt the running cell once for a graceful checkpoint; do not kill the process during upload.

Keep CONFIG and RUN_NAME identical to resume exactly (optimizer/scaler and data cursors included).
ACTION and SESSION_HOURS may change. For changed data size, learning rate or training budget, choose a NEW RUN_NAME.
You may configure up to 4 GB of unique raw text, subject to source availability, host RAM, network and storage limits.
More raw text does not guarantee good conversation; no model is automatically released to website users.
'''
    setup='''import os, sys, subprocess, getpass
from pathlib import Path
os.environ['HF_HUB_DISABLE_XET']='1'
subprocess.run([sys.executable,'-m','pip','install','-q',
    'huggingface_hub>=0.34,<2','requests>=2.32,<3','numpy>=1.26,<3',
    'pyarrow>=18,<24','fsspec>=2024.6,<2027'],check=True)
from huggingface_hub import constants
constants.HF_HUB_DISABLE_XET=True
# Keep the platform's existing PyTorch/CUDA installation (Runpod PyTorch 2.8 is suitable).
token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
if not token:
    try:
        from google.colab import userdata
        token=userdata.get('NEBULA_HF_TOKEN')
    except Exception:
        pass
if not token:token=getpass.getpass('Hugging Face write token (hidden): ')
if not token:raise RuntimeError('A Hugging Face write token is required.')
os.environ['NEBULA_HF_TOKEN']=token
del token
'''
    config='''# Prepare on CPU first; then benchmark, train or evaluate on your CUDA GPU.
ACTION = 'prepare'
SESSION_HOURS = 2
OUTPUT_REPO = 'iiidevv/nebula-raw-training'
RUN_NAME = 'nebula-v18-raw-1gb'
CONFIG = {
    'sourceRepo':'iiidevv/nebula-research','sourceRun':'nebula-v17-lab',
    'sourceKey':'current-foundationWeights',
    'textBytes':1_000_000_000,
    'weights':{'fineweb':50,'cosmopedia':25,'stories':15,'textbooks':10},
    'seed':1802026,'validationPercent':2,'minDocumentBytes':200,'maxDocumentBytes':1_000_000,
    'shardTextBytes':32_000_000,'steps':100_000,'batch':8,'microbatch':1,
    'learningRate':0.00003,'warmup':200,'cloudSaveEvery':500,
    'evaluateEvery':1000,'shardHoldSteps':64
}
'''
    execute='sources='+repr(sources)+'''
import importlib
# Code only: this folder never receives datasets, checkpoints, reports or secrets.
code_root=Path.cwd()/'nebula-v18-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():
    (code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in [Path(name).stem for name in sources]:sys.modules.pop(name,None)
importlib.invalidate_caches()
from v18_stream import run
try:
    result=run(OUTPUT_REPO,RUN_NAME,CONFIG,ACTION,SESSION_HOURS)
except Exception as error:
    from v8_store import safe_server_detail
    print({'sessionStopped':True,'errorType':type(error).__name__,
           'serverDetail':safe_server_detail(error),'lastConfirmedPublicBackupPreserved':True})
    if isinstance(error,(ValueError,RuntimeError)):print(str(error)[:500])
    raise RuntimeError('Session stopped. Keep the same configuration to resume the last confirmed public backup.') from None
'''
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},
             'language_info':{'name':'python'}},'cells':[]}
    for i,(kind,text) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        item={'id':f'v18-stream-{i}','cell_type':kind,'metadata':{},'source':text.splitlines(True)}
        if kind=='code':ast.parse(text);item.update(execution_count=None,outputs=[])
        notebook['cells'].append(item)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_GPU_Stream_Training.ipynb';path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    # A single portable Python launcher for users who prefer a terminal; only code is extracted.
    launch='''"""Nebula V18 portable launcher. Set NEBULA_HF_TOKEN in your environment."""
from pathlib import Path
import sys
import os
os.environ['HF_HUB_DISABLE_XET']='1'
'''+ 'sources='+repr(sources)+'''
code_root=Path(__file__).resolve().parent/'nebula-v18-code'
code_root.mkdir(exist_ok=True)
for name,value in sources.items():(code_root/name).write_text(value,encoding='utf-8')
sys.path.insert(0,str(code_root))
from v18_stream import main
if __name__=='__main__':main()
'''
    ast.parse(launch)
    (root/'Nebula_GPU_Stream_Training.py').write_text(launch,encoding='utf-8')
    return path


if __name__=='__main__':print(build())
