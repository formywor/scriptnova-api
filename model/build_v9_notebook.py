"""Build the private Kaggle V9 training notebook from current source."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py',
        'kaggle_migrate.py','research_client.py','research_train.py','research_eval.py',
        'research_worker.py','research_cases.json','v4_data.py','v4_grow.py','v4_eval.py',
        'v4_store.py','v4_experiment.py','v5_data.py','v5_experiment.py','conversation_mix.py','review_feed.py','v6_data.py','v6_experiment.py','v7_checks.py','v7_data.py','v7_teacher.py','v7_train.py','v7_eval.py','v7_experiment.py','v8_grow.py','v8_train.py','v8_store.py','v8_experiment.py','v9_data.py','v9_train.py','v9_eval.py','v9_teacher.py','v9_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    seed=root/'data/v7-teacher-seed.jsonl'
    sources['model/data/v7-teacher-seed.jsonl']=seed.read_text(encoding='utf-8') if seed.is_file() else ''
    v9_seed=root/'data/v9-teacher-seed.jsonl'
    sources['model/data/v9-teacher-seed.jsonl']=v9_seed.read_text(encoding='utf-8') if v9_seed.is_file() else ''
    import base64,zlib
    public_root=root/'data/v9-public'
    public_names=('train-chat.jsonl','train-language.jsonl','valid-chat.jsonl','valid-language.jsonl','public-manifest.json','licenses.json')
    if not all((public_root/name).is_file() for name in public_names):raise ValueError('Acquire and include the V9 public seed and license texts before building')
    public_files={name:(public_root/name).read_text(encoding='utf-8') for name in public_names}
    encoded_public=base64.b64encode(zlib.compress(json.dumps(public_files).encode(),9)).decode()
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v9-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V9 - broader conversations and basic language practice

Stop V8 after a confirmed remote backup. Import into a **private Kaggle notebook**, enable **Internet**, **T4 x2**, and the same `NEBULA_TRAINER_TOKEN`, `NEBULA_HF_TOKEN`, and optional separate `NEBULA_TEACHER_GROQ_KEY`. Run all. No new secret, API or website update is required. The public models remain pinned.

This is a separate `nebula-v9-curriculum` experiment using your existing owned 100M weights. It restores V8's protected best and evaluates its saved working trajectory too. An eligible improving working model continues; older runs and checkpoints remain intact. New data and validation require a fresh optimizer at the initial transition, with inherited weights and step counts preserved. Subsequent V9 resumes preserve its optimizer state.

The expanded data uses **Smol-SmolTalk** short conversations and **TinyStories** excerpts. Targets: 12,000 new public conversations, 5,000 sentence-continuation examples, plus 500 held-out examples from each source's official test/validation split. The actual accepted counts are reported. Records retain source, original split, license and conversation grouping. Filters remove duplicates, incomplete turns, foreign identities, credential/contact markers and frozen evaluation questions. Long conversations can contribute a complete prefix of exchanges that fits the existing 1,024-byte context; answers are not cut midway. Public examples are structurally filtered, not individually proven factual.

Training keeps **80% conversation updates**, with earlier practice, new public conversations, checked Groq teaching and fresh consent-checked review corrections. The remaining **20%** mixes memory (10%), simple language continuation (5%), identity and arithmetic (5%). Earlier skills are anchored to the preserved model. Groq's tasks adapt to weak skill categories using aggregate scores only; frozen prompts and private user chats are never sent to the separate teacher. Exact written addition checks supplement its second-pass review.

The dataset and fixed unseen validation are backed up before training. Training rejects overlaps with evaluation prompts, including teacher/review candidates. Every 200 updates, evaluation checks previous frozen skills, generated conversation replies, new held-out conversation loss (reported separately as publicChatLoss) and held-out language loss. Small heuristic task counts are not proof of general ability. A lower training loss alone does not publish a model. Best, working and latest checkpoints stay separate.

Public acquisition is bounded and cached. Supplied processed seed data is reused; incomplete caches retry remaining data. Downloads can approach several hundred MB when no seed is available. A failed required validation source prevents starting with misleading evaluation. No new pretrained model weights are downloaded. Defaults: 20 rounds or eight hours, 96 teacher calls, microbatch one per GPU, global batch 16. Full working backups remain about 1.2 GB and history can grow by tens of GB. Reduce MAX_ROUNDS if needed. Confirm `checkpointBackupConfirmed: true` before disconnecting.

Data attribution: HuggingFaceTB **Smol-SmolTalk**, Apache-2.0: https://huggingface.co/datasets/HuggingFaceTB/smol-smoltalk ; Ronen Eldan and Yuanzhi Li **TinyStories**, CDLA-Sharing-1.0: https://huggingface.co/datasets/roneneldan/TinyStories . Retain these dataset terms and provenance when redistributing the included data. The complete license texts are bundled in the seed and private data backup. License texts: https://www.apache.org/licenses/LICENSE-2.0 and https://cdla.dev/sharing-1-0/ .
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2','pyarrow>=18,<30','requests>=2.32,<3'],check=True)
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
RUN_NAME='nebula-v9-curriculum'  # Keep this name to resume saved progress.
HOURS=8
MAX_ROUNDS=20
STEPS_PER_ROUND=200
TEACHER_MAX_CALLS=96
project=Path('/kaggle/working/nebula-v9-curriculum/api')
project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle GPU accelerator.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False})
''')
    add('code','sources='+repr(sources)+'\npublic_seed='+repr(encoded_public)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
import base64,zlib,json
public_dir=project/'model/data/v9-public';public_dir.mkdir(parents=True,exist_ok=True)
seed_files=json.loads(zlib.decompress(base64.b64decode(public_seed)))
for name,content in seed_files.items():
    if name not in ('train-chat.jsonl','train-language.jsonl','valid-chat.jsonl','valid-language.jsonl','public-manifest.json','licenses.json'):raise RuntimeError('Invalid public seed name')
    target=public_dir/name
    if not target.exists():target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v9_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
''')
    add('markdown','''## Stop and resume

Use Kaggle's stop button to stop. The last confirmed remote backup remains available. For a graceful stop, create `/kaggle/working/nebula-v9-curriculum/api/STOP_AFTER_ROUND` from a second cell and wait for the active round to finish. Remove that file before starting again in the same runtime. After a runtime reset, import this notebook, enable the same secrets, and Run all with `RUN_NAME='nebula-v9-curriculum'`. It resumes the saved working model with optimizer state when available, preserves the best model, and retains the latest trial for inspection.

The public website keeps its deliberately published model. V9 research does not replace it automatically. Inspect actual replies before releasing later checkpoints. Improvements are possible, not guaranteed; a larger model still needs enough varied data and successful evaluations.
''')
    target=root/'Nebula_Kaggle_V9_Curriculum.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
