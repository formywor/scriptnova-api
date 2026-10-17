"""Build the private Kaggle V6 training notebook from current source."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
        'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
        'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
        'v4_store.py','v4_experiment.py','v5_data.py','v5_experiment.py','conversation_mix.py','review_feed.py','v6_data.py','v6_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v6-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V6 - conversation and memory practice

Stop other Nebula trainers after their confirmed backups. Import this notebook into a **private Kaggle notebook**, enable **Internet** and **GPU T4 x2**, and enable the existing `NEBULA_TRAINER_TOKEN` and `NEBULA_HF_TOKEN` secrets. Run all. No new keys are needed.

V6 starts from the **best confirmed V5 checkpoint** in your private repository, preserving its weights and training step count. It uses a separate `nebula-v6` experiment; V5 snapshots remain untouched. If V5 progress is missing, it stops rather than silently restarting from scratch.

**80% of optimizer updates practice conversations; 20% practice mixed skills. Half of mixed updates explicitly practice memory and context recall.** This is a batch/update ratio, not an exact token ratio. New owned dialogues cover follow-ups, changed details, writing revisions, plans and stories. Existing permitted public conversation data is retained. Final and lowest-loss candidates are evaluated every 500 updates, with preference for chat improvement and limits on losing memory and other skills. These small checks cannot prove general usefulness.

After the updated API is deployed, new user corrections that pass a second AI review, owner-rule checks and text filters can join training. The private trainer feed rechecks both sharing settings and current consent each round. Secrets/contact markers and personal-memory questions are excluded. At most 10% of conversation updates use these corrections; the rest use prepared practice. Reviewed text is temporary in the Kaggle runtime and is not included in Hugging Face dataset snapshots. Withdrawal excludes future feed reads, but cannot undo training that already completed. Two AI reviews can still make mistakes.

The logs show `checkedReviewExamples` and `reviewedTrainingWindows`. Zero means no eligible corrections were used. API errors clear the old review feed and keep training on owned/public practice. No Gemini key is placed in Kaggle; reviews happen on your private API.

Weights and reports are backed up after each round, with optimistic concurrency checks. Run only one notebook session: both GPU workers inside it cooperate. The public model does not update automatically. Runtime/GPU quotas and session limits still apply.
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
RUN_NAME='nebula-v6'  # Keep this name to resume saved progress.
HOURS=8
MAX_ROUNDS=100
STEPS_PER_ROUND=500
project=Path('/kaggle/working/nebula-v6/api')
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
from v6_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND)])
''')
    add('markdown','''## Stop and resume

Use Kaggle's stop button to stop. The last confirmed remote backup remains available. For a graceful stop, create `/kaggle/working/nebula-v6/api/STOP_AFTER_ROUND` from a second cell and wait for the active round to finish. Remove that file before starting again in the same runtime. After a runtime reset, import this notebook, enable the same secrets, and Run all with `RUN_NAME='nebula-v6'`. It resumes the saved best model and retains the latest trial for inspection.

The public website keeps its deliberately published model. V6 research does not replace it automatically. Inspect actual replies before releasing later checkpoints. Improvements are possible, not guaranteed; an 8.2M-parameter model has substantial limits.
''')
    target=root/'Nebula_Kaggle_V6.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
