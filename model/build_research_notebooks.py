"""Build private Kaggle/Colab workers; never embed credentials in notebooks."""
import ast
import json
from pathlib import Path

root=Path(__file__).resolve().parent

def build(role):
    names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py','kaggle_migrate.py',
           'research_train.py','research_client.py','research_eval.py','research_worker.py','research_combined.py','research_cases.json']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'nebula-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    title={'trainer':'Kaggle trainer','evaluator':'Colab evaluator and training experiments','combined':'Kaggle training and evaluation (Colab optional)'}[role]
    add('markdown',f'''# Nebula: {title}

This coordinates private, versioned checkpoints through your API. It never updates the public chat model.

**Configure the API first:** deploy the updated API, set `NEBULA_HF_REPO=iiidevv/nebula-research` and `NEBULA_HF_TOKEN` to a fine-grained read/write token limited to that private model repository. Set two different random worker tokens (`NEBULA_TRAINER_TOKEN` and `NEBULA_EVALUATOR_TOKEN`, at least 32 characters each), then enable `NEBULA_RESEARCH_ENABLED=true`. No Firebase Storage bucket or Blaze upgrade is needed for this path. Hugging Face free-tier limits apply. Both notebooks need their role secret plus `NEBULA_HF_TOKEN` in their platform secret manager. Never paste tokens into cells.

The controller accepts a new checkpoint only when the locked task checks and held-out loss pass conservative comparisons. These are limited diagnostics, not proof of broad intelligence. Three consecutive rejected rounds pause the campaign for review. Old unreferenced paths are pruned, retaining recent versions and rollback parents. Repository history still retains deleted files and may consume storage; monitor Hugging Face usage. The service limits file size and upload frequency.
''')
    if role in ['trainer','combined']:
        add('markdown','''## Kaggle setup

1. Import this notebook and keep it private.
2. Attach your private recovery Dataset with `Nebula_V3_Data.pt`, `v3-chat.pt`, and `v3-chat.best.pt` for the first run.
3. Enable **Internet** and select **GPU T4 ×2**, if available.
4. In **Add-ons → Secrets**, add `NEBULA_TRAINER_TOKEN`, matching the trainer token in Vercel, and enable this notebook's access.
5. Start the Colab evaluator notebook too. Use **Save Version → Save & Run All** for a bounded saved run; confirm Output after it finishes. Local notebook output remains a secondary backup.

The initial shared model is your best V3 checkpoint (31,012 steps); your later 33,012-step model remains in the private input Dataset. The worker benchmarks one versus two GPUs on the same global batch and selects two only when it is faster. Kaggle pauses at each 2,000-step boundary for Colab's decision.
''')
        add('code','''import os,sys,json
import subprocess
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2'],check=True)
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
API_BASE='https://api.scriptnovaa.com/api/nebula/research'
HOURS=6
MAX_ROUNDS=12
GPU_MODE='auto'  # 'auto' benchmarks 1 vs 2; '2' forces two when available.
def read_secret(name):
    try:
        value=UserSecretsClient().get_secret(name)
    except Exception:
        raise RuntimeError(f'Kaggle cannot read {name}. Open Add-ons > Secrets, add that exact name, and enable notebook access. Check Internet is on.') from None
    if not isinstance(value,str) or not value.strip():
        raise RuntimeError(f'Kaggle secret {name} is empty.')
    return value.strip()
token=read_secret('NEBULA_TRAINER_TOKEN')
hf_token=read_secret('NEBULA_HF_TOKEN')
os.environ['NEBULA_WORKER_TOKEN']=token
os.environ['NEBULA_RESEARCH_API']=API_BASE
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_HF_TOKEN']=hf_token
project=Path('/kaggle/working/nebula-research/api')
project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available(): raise RuntimeError('Enable the GPU accelerator before running.')
''')
    else:
        add('markdown','''## Colab setup

1. Upload this notebook into Colab, select a GPU runtime, and keep it private.
2. In Colab **Secrets**, add `NEBULA_EVALUATOR_TOKEN`, matching the evaluator token in Vercel, and grant this notebook access.
3. Run the cells. Kaggle uploads the starting model and dataset; Colab downloads them directly from private storage. No Google Drive mount or teacher API key is used.

Colab alternates evaluation with one bounded 200-step experiment on an approved training subset. It never trains on the locked benchmark questions or reserved names. A candidate must beat the current head without dropping the tracked task categories before the API can select it. An old or expired job cannot replace a newer head.

Colab may disconnect or end its runtime. Uploaded checkpoints remain in the private Hugging Face repository. Work since the last successful upload can still be lost. Restart the worker to claim a new job when an old lease expires.
''')
        add('code','''import os,sys,json
import subprocess
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2'],check=True)
from pathlib import Path
import torch
from google.colab import userdata
API_BASE='https://api.scriptnovaa.com/api/nebula/research'
HOURS=6
MAX_ROUNDS=12
try:
    token=userdata.get('NEBULA_EVALUATOR_TOKEN')
    hf_token=userdata.get('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Add and enable Colab secrets NEBULA_EVALUATOR_TOKEN and NEBULA_HF_TOKEN.') from None
os.environ['NEBULA_WORKER_TOKEN']=token
os.environ['NEBULA_RESEARCH_API']=API_BASE
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_HF_TOKEN']=hf_token
project=Path('/content/nebula-research/api')
project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available(): raise RuntimeError('Select a GPU runtime before running.')
''')
    add('code','sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for module in ['nebula','train','dataflow','teacher_http','rules','kaggle_migrate',
               'research_train','research_client','research_eval','research_worker','research_combined']:
    sys.modules.pop(module,None)
from research_client import Client
client=Client()
status=client.call('state')
print({'coordinatorConnected':True,'initialized':bool(status.get('head')),
       'revision':status.get('revision',0),'publicAutoUpdate':False})
''')
    if role=='combined':
        add('markdown','''## Run everything on Kaggle

This mode alternates training and evaluation in the same runtime. Colab is optional and should remain stopped while using this mode. Add and enable all three Kaggle secrets: `NEBULA_TRAINER_TOKEN`, `NEBULA_EVALUATOR_TOKEN`, and `NEBULA_HF_TOKEN`. The role tokens must match Vercel. Separate phase folders preserve each worker's output. It resumes any pending evaluation before starting more training.
''')
        add('code','''os.environ['NEBULA_TRAINER_TOKEN']=token
os.environ['NEBULA_EVALUATOR_TOKEN']=read_secret('NEBULA_EVALUATOR_TOKEN')
from research_combined import main
main(['--project',str(project),'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--gpus',GPU_MODE])
''')
    else:
        options=f"['--role',{role!r},'--project',str(project),'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS)]"
        if role=='trainer':options+="+['--gpus',GPU_MODE]"
        add('code','from research_worker import main\nmain('+options+')\n')
    add('markdown','''## After the run

Keep the previous stable checkpoints and verify reports before any public deployment. On Kaggle, confirm the saved version's Output. The API selects research checkpoints only; the website's model endpoint and embedded live model are unchanged. Worker secrets must remain in the platform secret manager, never in saved cells or output.
''')
    if role=='combined':
        for cell in cells:
            if cell['cell_type']=='markdown':
                text=''.join(cell['source']).replace('Start the Colab evaluator notebook too.', 'The evaluator runs here; Colab is not required.').replace("Kaggle pauses at each 2,000-step boundary for Colab's decision.", 'Kaggle evaluates after every 2,000 training steps before continuing.')
                cell['source']=text.splitlines(True)
    name={'trainer':'Nebula_Kaggle_Trainer.ipynb','evaluator':'Nebula_Colab_Evaluator.ipynb','combined':'Nebula_Kaggle_Complete.ipynb'}[role]
    target=root/name
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,
        'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    print(target)
    return target

if __name__=='__main__':
    for role in ['trainer','evaluator','combined']:build(role)
