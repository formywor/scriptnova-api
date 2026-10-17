"""Build a private, resumable Kaggle V4 experiment with embedded source only."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
           'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
           'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
           'v4_store.py','v4_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v4-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V4: broader data and measured model growth

Run this on Kaggle with Internet on and GPU T4 x2 if available. **Stop the older trainer/evaluator notebooks first.** Keep this notebook private. It uses the existing preserved model and data through your API, even though that earlier campaign is paused. It never resets its rejection counter or changes its selected model, and never updates the public website.

In **Add-ons > Secrets**, enable notebook access to `NEBULA_TRAINER_TOKEN` (matching Vercel) and `NEBULA_HF_TOKEN` (repository-scoped read/write). The private repository is `iiidevv/nebula-research`. No new Vercel variables, API deployment, Gemini/Groq key, Google Drive mount, or paid teacher API is needed.

V4 adds exact, original name-copying and arithmetic exercises; holds out whole scenarios and wordings; and rehearses complete short conversations from previously permitted data. It optionally scans 1,000 additional SmolTalk records. A public download failure uses available data instead. Public replies are filtered, not independently verified.

The GPU probes compare the current model with four extra layers (about 8.2M parameters for your 5.1M baseline), falling back to two extra layers or the original size if needed. The added residual branches start at zero; a forward-equivalence test must pass before training. Your original weights remain preserved. The larger option must achieve at least 45% of baseline throughput to be chosen. More parameters are an experiment, not a promise of better answers.

Every 500 updates, V4 evaluates final and lowest-validation-loss weights on frozen task checks and an independent validation sample. It keeps the experiment's best candidate only if no tracked category regresses and task accuracy or validation loss improves under the documented rule. Three rejected attempts pause this new experiment. These are limited diagnostics, not proof of general intelligence.

Snapshots, data, exact replies, and resume metadata are saved directly to private Hugging Face under `experiments/nebula-v4/`. Each successful snapshot and resume manifest is one commit. A failed backup stops training. Reuse the same RUN_NAME to resume uploaded progress; unsaved work since the last successful upload can be lost if Kaggle ends. Free GPU/storage quotas still apply. The default budget is at most 6 hours or 24 rounds, and may end earlier.
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2'],check=True)
def secret(name):
    try: value=UserSecretsClient().get_secret(name)
    except Exception: raise RuntimeError(f'Add and enable Kaggle secret {name}; check Internet is on.') from None
    if not isinstance(value,str) or not value.strip():raise RuntimeError(f'Empty Kaggle secret: {name}')
    return value.strip()
os.environ['NEBULA_WORKER_TOKEN']=secret('NEBULA_TRAINER_TOKEN')
os.environ['NEBULA_HF_TOKEN']=secret('NEBULA_HF_TOKEN')
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_RESEARCH_API']='https://api.scriptnovaa.com/api/nebula/research'
RUN_NAME='nebula-v4'  # Keep this unchanged to resume this experiment.
RUN_EXPERIMENT=True  # Approved private experiment; Run All starts the bounded run.
HOURS=6
MAX_ROUNDS=24
STEPS_PER_ROUND=500
ADDITIONAL_PUBLIC_ROWS=1000
project=Path('/kaggle/working/nebula-v4/api')
project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle GPU accelerator before running.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False})
''')
    add('code','sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v4_experiment import main
if RUN_EXPERIMENT:
    main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),
          '--steps',str(STEPS_PER_ROUND),'--public-rows',str(ADDITIONAL_PUBLIC_ROWS)])
else:
    print('V4 is prepared. Data uploads and training are switched off.')
''')
    add('markdown','''## Review and resume

Read `v4Evaluation`, `v4RoundAccepted`, and `v4BackupSaved` in the logs. A backup message confirms a private commit completed; the notebook's Output size alone does not indicate backup success. On Kaggle, confirm Save Version output after the run. The complete reply reports are under your private repository's experiment folder.

To continue after a runtime ends, reopen this notebook, enable the same secrets and GPU settings, and run all with the same RUN_NAME. It downloads the saved dataset, preserved source model, and selected experiment checkpoint with hash checks. It starts a new bounded budget from that saved state. A quality pause is preserved rather than silently reset. If it reports a concurrent repository update, stop duplicate runs and reopen before retrying.

No model from this experiment is approved for public use automatically. Keep the preserved model and inspect actual answers before considering a website model update. Repository history retains past snapshots and uses storage; monitor the account's usage.
''')
    target=root/'Nebula_Kaggle_V4.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{
        'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    print(target)
    return target

if __name__=='__main__':build()
