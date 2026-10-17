"""Build the private Kaggle V5 training notebook from current source."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
        'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
        'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
        'v4_store.py','v4_experiment.py','v5_data.py','v5_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v5-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V5 — keep learning, keep the best model

Import into a **private Kaggle notebook**, enable **Internet** and **GPU T4 x2**, and stop older Nebula trainers first. Enable the existing `NEBULA_TRAINER_TOKEN` and `NEBULA_HF_TOKEN` secrets. Run all. No Gemini, Groq, or Colab GPU is needed.

V5 continues the strongest saved V4 trial, rather than its rejected latest trial or the original model. Original models remain intact. It adds original short conversations, follow-up dialogue, and exact arithmetic with complete terminating answers. Source notices for the existing public data remain in the preserved dataset manifest. Known familiar questions are explicit rehearsal, not unseen evaluation.

Every 500 updates it evaluates final and lowest-loss checkpoints on frozen V4 tasks, six new conversation checks, and the same validation sample. Research selection permits modest category tradeoffs when overall results improve. It retains the best research head, rotates practice on plateaus, and **does not stop after three rejected trials**. These tiny diagnostics do not establish general chat quality.

After the updated API is deployed, currently opted-in account contributions provide coarse topic counts. At most one round in four follows those topics. The trainer uses owned, verified practice for those topics; raw chats, names, IDs, and the model's unchecked answers are not uploaded or learned as facts. If the feed is unavailable or too small, training continues on the prepared curriculum. Account opt-outs and deleted contributions are checked again on each feed request.

Each completed round saves weights, reports, and a resume manifest to your **private** Hugging Face repository. A failed backup stops the run. Uploaded weights omit optimizer state to reduce storage; resumed rounds start fresh AdamW. Saved best and latest models are separate. The notebook never changes the public release.

Run for up to eight hours or 100 backup rounds per session, then rerun the same notebook and run name to continue. Kaggle GPU quotas and session limits still apply. Checkpoint history consumes storage; 100 latest snapshots of an 8.2M model are about 3.3 GB, plus improved-best snapshots and reports. Do not run duplicate notebooks. A refresh or disconnect can lose work since the last `checkpointBackupConfirmed` message. Backups restore only successfully uploaded rounds.
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
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_RESEARCH_API']='https://api.scriptnovaa.com/api/nebula/research'
RUN_NAME='nebula-v5'  # Keep this name to resume saved progress.
HOURS=8
MAX_ROUNDS=100
STEPS_PER_ROUND=500
project=Path('/kaggle/working/nebula-v5/api')
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
from v5_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND)])
''')
    add('markdown','''## Stop and resume

Use Kaggle's stop button to stop. The last confirmed remote backup remains available. For a graceful stop, create `/kaggle/working/nebula-v5/api/STOP_AFTER_ROUND` from a second cell and wait for the active round to finish. Remove that file before starting again in the same runtime. After a runtime reset, import this notebook, enable the same secrets, and Run all with `RUN_NAME='nebula-v5'`. It resumes the saved best model and retains the latest trial for inspection.

The public website uses the deliberately pinned experimental V4 release packaged with the API. V5 research does not replace it automatically. Inspect actual replies before releasing later checkpoints. Improvements are possible, not guaranteed; an 8.2M-parameter model has substantial limits.
''')
    target=root/'Nebula_Kaggle_V5.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
