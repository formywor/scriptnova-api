"""Build the private Kaggle V7 training notebook from current source."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
        'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
        'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
        'v4_store.py','v4_experiment.py','v5_data.py','v5_experiment.py','conversation_mix.py','review_feed.py','v6_data.py','v6_experiment.py','v7_checks.py','v7_data.py','v7_teacher.py','v7_train.py','v7_eval.py','v7_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    seed=root/'data/v7-teacher-seed.jsonl'
    sources['model/data/v7-teacher-seed.jsonl']=seed.read_text(encoding='utf-8') if seed.is_file() else ''
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v7-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V7 - better conversations without throwing away existing skills

Stop previous trainers after a confirmed backup. Import into a **private Kaggle notebook**, enable **Internet** and **T4 x2**, and enable existing `NEBULA_TRAINER_TOKEN` and `NEBULA_HF_TOKEN` secrets. Add **NEBULA_TEACHER_GROQ_KEY** using your separate training key. It is never read from the review key or printed. Run all. Without that secret, the embedded seed conversations and owned/public practice still work, but no fresh Groq teacher calls are made.

V7 chooses the strongest saved best checkpoint from V5/V6, preserves its weights and inherited step count, and starts a separate `nebula-v7` experiment. It keeps a permanent baseline, a best candidate, a protected working trajectory and the latest trial. It does not restart from scratch or update the public website automatically.

The requested mix stays **80% conversation / 20% mixed optimizer updates**, including explicit memory, identity and arithmetic rehearsal. V7 samples varied examples rather than adjacent templates, normalizes loss equally per example, uses a small warm-up/decay learning rate, and gently anchors predictions to the preserved model (weaker on conversation, stronger on mixed skills). No pretrained third-party weights are imported and model size stays unchanged.

Groq generates diverse, short, original four-message conversations. A separate AI check must accept them, and local checks reject malformed roles, foreign identities, sensitive content, incomplete answers, excessive length and frozen evaluation questions. This is useful teaching data, not a guarantee of truth. Teacher collection is bounded to 96 calls per session by default; failures keep saved examples and defer new calls. Different keys on the same provider project can still share quotas. Do not put keys into notebook cells or source files.

Only short, complete existing conversations are kept in the chat pool. Small teacher/review pools get roughly two passes per round rather than being repeated throughout dozens of batches. Synthetic teacher data is stored privately with provenance. Fresh user-review data still requires both sharing settings, is fetched again each round, and stays in temporary storage outside Kaggle outputs. No user chat is sent to the separate teacher-generation key.

Every **200 updates**, V7 checks the original frozen tasks, held-out conversation loss with equal example weighting, and **20 additional generated-response diagnostics** excluded from training and teacher prompts. These are small heuristic checks, not proof of general intelligence. A working checkpoint can continue when conversation loss improves and existing skills remain protected; a worse trajectory rolls back. Best research checkpoint selection also requires generated-answer checks. Publishing to the website remains a separate action. Working backups preserve AdamW/scaler state so learning can continue across rounds and sessions. The legacy best checkpoints contain weights only.

Teacher data and training progress are backed up separately. Accepted working checkpoints can be about 100 MB with optimizer state, so bounded sessions still consume private storage over time. Backup failure or a concurrent trainer stops the run. Confirm `checkpointBackupConfirmed: true` before disconnecting. Maximum session: eight hours or 100 rounds. You can rerun this notebook with the same run name to resume. Do not run duplicate sessions.
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
RUN_NAME='nebula-v7'  # Keep this name to resume saved progress.
HOURS=8
MAX_ROUNDS=100
STEPS_PER_ROUND=200
TEACHER_MAX_CALLS=96
project=Path('/kaggle/working/nebula-v7/api')
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
from v7_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
''')
    add('markdown','''## Stop and resume

Use Kaggle's stop button to stop. The last confirmed remote backup remains available. For a graceful stop, create `/kaggle/working/nebula-v7/api/STOP_AFTER_ROUND` from a second cell and wait for the active round to finish. Remove that file before starting again in the same runtime. After a runtime reset, import this notebook, enable the same secrets, and Run all with `RUN_NAME='nebula-v7'`. It resumes the saved working model with optimizer state when available, preserves the best model, and retains the latest trial for inspection.

The public website keeps its deliberately published model. V7 research does not replace it automatically. Inspect actual replies before releasing later checkpoints. Improvements are possible, not guaranteed; an 8.2M-parameter model has substantial limits.
''')
    target=root/'Nebula_Kaggle_V7.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
