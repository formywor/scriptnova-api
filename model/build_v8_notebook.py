"""Build the private Kaggle V8 training notebook from current source."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
        'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
        'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
        'v4_store.py','v4_experiment.py','v5_data.py','v5_experiment.py','conversation_mix.py','review_feed.py','v6_data.py','v6_experiment.py','v7_checks.py','v7_data.py','v7_teacher.py','v7_train.py','v7_eval.py','v7_experiment.py','v8_grow.py','v8_train.py','v8_store.py','v8_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    seed=root/'data/v7-teacher-seed.jsonl'
    sources['model/data/v7-teacher-seed.jsonl']=seed.read_text(encoding='utf-8') if seed.is_file() else ''
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v7-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V8 - 100 million parameters

Stop V7 after `checkpointBackupConfirmed: true`. Use a **private Kaggle notebook**, enable **Internet**, **T4 x2**, and existing `NEBULA_TRAINER_TOKEN`, `NEBULA_HF_TOKEN`, and optional `NEBULA_TEACHER_GROQ_KEY` secrets. Run all. No API or website upload is required.

V8 initializes once from the latest saved **V7 best** checkpoint, retains its step count, data and checked teacher examples, and writes a separate `nebula-v8-100m` experiment. V7 files remain preserved. The owned network expands from width 256 to **768**, with **24 attention heads**, **14 layers**, and a 1,024-byte context: **100,219,392 trainable parameters**. There are no imported pretrained weights. Existing channels are replicated with compensated projections and new residual layers initially add zero. A numerical forward check must pass; expansion adds capacity rather than immediate knowledge. New parameters still need substantial training and data.

The quality-focused 80/20 conversation/mixed training, explicit memory practice, separate checked Groq teacher and fresh consent-checked review feed remain. A small preserved V7 model anchors existing skills, with stronger rehearsal on mixed and memory updates. Logs separately count Groq teacher updates, consent-checked review updates and past-best conversation replay. Earlier validated practice and newly checked teacher dialogues both participate in real weight updates. Training uses activation checkpointing, **one example per GPU microbatch**, accumulated into **16 examples per optimizer update**. Both GPUs replicate the model rather than combining their memory into one pool. The GPU capacity probe must pass before the initial baseline backup and research rounds. Real T4 capacity is verified there, not guaranteed by local CPU tests.

Every **200 updates**, inspect original task checks, held-out conversation loss and 20 generated-response diagnostics. A working trajectory can continue without replacing the protected best. Backups preserve optimizer state and verify every shard and reconstructed checkpoint. Model weights are about **400 MB**, full AdamW checkpoints about **1.2 GB**, sharded into at most 128 MiB parts. Each round can upload about **2 GB** of new checkpoint data; history may consume substantial private storage and transfer quota. Default limits are **20 rounds or eight hours**, with at most 96 teacher calls. Start with one round to inspect capacity and behavior if desired; set MAX_ROUNDS below.

The first run starts from the most recently **confirmed** V7 backup. Teacher errors defer collection while owned/curated training continues. Provider checks can still miss errors. Raw user-review examples stay temporary; only synthetic teaching examples are included in dataset backups. Look for `v8CapacityProbePassed` and, after a round, `checkpointBackupConfirmed: true`. Intermediate local saves alone do not survive a reset. Rerun with the same `nebula-v8-100m` name to resume. Do not run duplicate trainers. Publishing to the website is separate and remains off.
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2'],check=True)
def secret(name):
    try:value=UserSecretsClient().get_secret(name)
    except Exception:raise RuntimeError(f'Add and enable Kaggle secret {name}; check Internet is on.') from None
    if not isinstance(value,str) or not value.strip():raise RuntimeError(f'Empty Kaggle secret: {name}')
    return value.strip()
os.environ['NEBULA_WORKER_TOKEN']=secret('NEBULA_TRAINER_TOKEN')
os.environ['NEBULA_HF_TOKEN']=secret('NEBULA_HF_TOKEN')
try:teacher_key=UserSecretsClient().get_secret('NEBULA_TEACHER_GROQ_KEY')
except Exception:teacher_key=''
os.environ['NEBULA_TEACHER_GROQ_KEY']=(teacher_key or '').strip()
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_RESEARCH_API']='https://api.scriptnovaa.com/api/nebula/research'
RUN_NAME='nebula-v8-100m'  # Keep this name to resume saved progress.
HOURS=8
MAX_ROUNDS=20
STEPS_PER_ROUND=200
TEACHER_MAX_CALLS=96
project=Path('/kaggle/working/nebula-v8-100m/api')
project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle GPU accelerator.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False})
''')
    add('code','sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v8_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
''')
    add('markdown','''## Stop and resume

Use Kaggle's stop button to stop. The last confirmed remote backup remains available. For a graceful stop, create `/kaggle/working/nebula-v8-100m/api/STOP_AFTER_ROUND` from a second cell and wait for the active round to finish. Remove that file before starting again in the same runtime. After a runtime reset, import this notebook, enable the same secrets, and Run all with `RUN_NAME='nebula-v8-100m'`. It resumes the saved working model with optimizer state when available, preserves the best model, and retains the latest trial for inspection.

The public website keeps its deliberately published model. V8 research does not replace it automatically. Inspect actual replies before releasing later checkpoints. Improvements are possible, not guaranteed; a larger model still needs enough varied data and successful evaluations.
''')
    target=root/'Nebula_Kaggle_V8_100M.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
