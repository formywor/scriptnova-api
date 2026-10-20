"""Build the isolated V14 Kaggle notebook without changing earlier versions."""
import ast,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    old=json.loads((root/'Nebula_Kaggle_V13_No_Groq.ipynb').read_text(encoding='utf-8'))
    code=next(''.join(c['source']) for c in old['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    names=ast.literal_eval(ast.parse(code).body[0].value).keys()
    sources={name:(root.parent/name).read_text(encoding='utf-8') for name in names}
    for name in ['v14_data.py','v14_train.py','v14_eval.py','v14_experiment.py']:
        sources['model/'+name]=(root/name).read_text(encoding='utf-8')
    introduction="""# Nebula V14 - foundation, then conversation

Stop the older trainer first. Import this notebook into a private Kaggle notebook, enable Internet and T4 x2, and enable NEBULA_HF_TOKEN in Kaggle Secrets. Run all starts training after preparation. No teacher/reviewer API key is required. All earlier runs and the public website stay unchanged.

This keeps the owned approximately 100M-parameter model and its 1,024-byte context. It copies V13's protected saved best into a separate experiment; it does not replace the model with pretrained weights. The tokenizer stays unchanged so this experiment measures the training change.

Phase 1: 4,000 additional updates of raw language modeling. Candidate acquisition targets: 10,000 TinyStories stories, 4,000 Cosmopedia v2 passages and 4,000 FineWeb-Edu passages. Existing preparation downloads are reused and extended. Filtering, deduplication, pinned revisions and source attribution remain. The update mix is 40% stories, 30% Cosmopedia and 30% FineWeb. Each update samples original records uniformly within its source before selecting windows. No chat templates or imitation of the old model are used in this phase.

Phase 2: 1,200 additional assistant-only conversation updates: 70% filtered public chats, 20% owned varied context exercises and 10% eligible historical conversation examples. Full assistant answers use rolling windows with user/system loss masked. Profile questions vary the requested attribute, field order and changed facts; related profile variants share a split. Context remains limited to 1,024 bytes. No unlimited memory is claimed.

The full working trajectory continues for the fixed budget; intermediate loss changes do not cause rollback. Optimizer state is preserved between compatible chunks and intentionally reset when changing phase. Old-model anchoring is removed. Both final and lowest-loss diagnostic checkpoints are retained, but lowest-loss checkpoints never silently replace the working trajectory. A non-finite loss or invalid data still stops the run.

Fixed questions, rotating context questions, actual multi-turn follow-ups and raw sentence completions are saved at the baseline, every 1,000 updates, and each phase end. Exact checks are conservative. Open-ended answers stay pending for inspection, with humanVerified and qualityApproved false. There is no external semantic judge and no automatic publication. Lower loss alone does not certify better conversation. These small probes are diagnostics, not a comprehensive benchmark, and old baseline probes may already be familiar to the model.

New data is split by complete source record/group before windowing. Existing fixed/public holdouts and fixed V14 questions are blocked. Exact text duplicates are removed; this is not a claim of exhaustive semantic near-deduplication. Whole public conversations from V13 are reused, not private user chats or the evaluation answers. Source license texts and preparation provenance are retained. Downloading or training more data does not guarantee improvement.

Confirmed backups go to experiments/nebula-v14-foundation in the same private Hugging Face repository. Preparation saves separately to experiments/nebula-v14-foundation-preparation. A cloud backup occurs after each completed chunk (default 500 updates), with local checkpoints every 100 updates. Wait for checkpointBackupConfirmed before ending the session. An unexpected runtime loss can discard progress since the last cloud backup. The 8-hour session limit includes preparation and evaluation; run again with the same settings to resume an unfinished phase. Do not run duplicate trainers. A changed plan requires a separate experiment, not an incompatible resume.
"""
    setup="""import os,subprocess,sys
from pathlib import Path
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','-q','huggingface_hub>=0.34,<2','requests>=2.32,<3','datasets>=3.6,<5','pyarrow>=18,<24'],check=True)
try:
    token=UserSecretsClient().get_secret('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Add and enable Kaggle secret NEBULA_HF_TOKEN.') from None
if not token.strip():raise RuntimeError('NEBULA_HF_TOKEN is empty.')
os.environ['NEBULA_HF_TOKEN']=token
os.environ['HF_TOKEN']=token
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
project=Path('/kaggle/working/nebula-v14-foundation/api')
project.mkdir(parents=True,exist_ok=True)
HOURS=8
FOUNDATION_STEPS=4000
CONVERSATION_STEPS=1200
CHUNK=500
import torch
if not torch.cuda.is_available():raise RuntimeError('Enable GPU T4 x2 in Kaggle notebook settings.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False,'externalTeacherCalls':0})
"""
    execution='sources='+repr(sources)+"""
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v14_experiment import main
main(['--project',str(project),'--hours',str(HOURS),'--foundation-steps',str(FOUNDATION_STEPS),'--conversation-steps',str(CONVERSATION_STEPS),'--chunk',str(CHUNK)])
"""
    ending="""## Stop and resume

For a graceful stop, create /kaggle/working/nebula-v14-foundation/api/STOP_AFTER_CHUNK and wait for the current chunk's confirmed backup. Remove that file before resuming. An interrupt may lose the current chunk; Run all resumes the last confirmed cloud backup. Download raw-completion and question reports to inspect actual outputs before considering a public release. Final foundation checkpoints are intermediate language models; they are not automatically certified chat assistants.
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',introduction),('code',setup),('code',execution),('markdown',ending)]):
        cell={'id':f'v14-{i:02d}','cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for name,source in sources.items():
        if name.endswith('.py'):ast.parse(source)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'language_info':{'name':'python'}},'cells':cells}
    target=root/'Nebula_Kaggle_V14_Foundation.ipynb';target.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
