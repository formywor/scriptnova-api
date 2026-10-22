"""One reusable notebook; configure a new run instead of rebuilding source each time."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).resolve().parent
    old=json.loads((root/'Nebula_Colab_V16_Diagnostics.ipynb').read_text(encoding='utf-8'))
    prior=next(''.join(c['source']) for c in old['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    names=ast.literal_eval(ast.parse(prior).body[0].value).keys()
    sources={name:(root.parent/name).read_text(encoding='utf-8') for name in names}
    sources['nebula-rules.json']=(root.parent/'nebula-rules.json').read_text(encoding='utf-8')
    for name in ['v17_data.py','v17_train.py','v17_lab.py','v17_raw_data.py','v17_raw_lab.py']:sources['model/'+name]=(root/name).read_text(encoding='utf-8')
    intro='''# Nebula V17 — reusable training lab

Use this notebook for configurable experiments instead of creating a new notebook for every run. It cannot guarantee a useful model, unlimited GPU time, or every possible architecture experiment. It keeps the byte architecture unchanged so this experiment can isolate training and data effects. It never publishes weights to website users.

**Start:** Stop other workers. Select Runtime > Change runtime type > T4 GPU. Enable your existing NEBULA_HF_TOKEN in Colab Secrets, then Run all. No Drive mount, Groq, Gemini, teacher calls or website/API upload. Do not run duplicate copies against the same RUN_NAME.

**Default comparison:** existing pre-V16 100M V15 fullWeights versus a fresh random model with exactly the same architecture. Each receives the same record pools, batch, sampling seed, stage budgets and learning rates. This is a single-seed controlled trial, not statistical proof. The existing model has prior exposure to public data; the fresh arm does not. Never compare raw optimizer-step totals as if their lifetime exposure were equal.

**Default stages, sequential on one GPU:** 1,000 foundation-language updates, 1,500 varied context-practice updates, 1,000 conversation updates, for each arm (7,000 updates total). All stages use full-parameter training, FP16 mixed precision with FP32 weights/Adam state, gradient scaling and clipping. The conversation stage is 80% public-conversation updates and 20% new context/multi-turn practice. Foundation uses raw text only; chat stages learn assistant targets only. The working trajectory continues without rolling back to old low-loss weights. New stages start fresh optimizers; resumptions of the same stage restore the full optimizer/scaler.

**Data:** Reuse licensed public language and conversation corpora already saved in V14, plus new programmatically checked context exercises. No broad web crawl, new provider quota, V15 unchecked-chat corpus, private account chats, user reviews, or V16 memorization weights. Up to 6,000 whole public records per pool and 4,000 synthetic scenarios are used by default. Language selection is balanced across available source datasets; conversation selection is balanced across available components, rather than taking a story-heavy or template-heavy file prefix. Exact component/source counts are saved in the data manifest. Synthetic practice shuffles name/color/location associations and field order, with multi-turn questions and corrections. Exact duplicates, overlapping public validation identities/openings, and exact synthetic benchmark openings are excluded from the relevant training pools. Public data is structurally screened, not guaranteed correct. Original licenses and attribution are retained.

**Separate held-out axes:** new name/color combinations; new values; new question wording; withheld field order; multi-turn questions; corrected facts. Fixed test identities never train V17. 'Unseen' means excluded from V17, not never present anywhere in older model training. Follow-up evaluation uses the model's actual preceding reply. Every baseline/stage report contains exact scores by axis, independent validation losses, actual answers, four ungraded open chat replies and two ungraded raw completions. Public loss validation was reserved in V14; it is not claimed as a newly collected benchmark. These tests do not certify public readiness.

**Persistence:** local full model/Adam/scaler checkpoints every 50 updates, cloud backups every 250 and at a graceful stop, plus compact snapshots/reports for every completed stage. Confirm v17CloudBackupConfirmed or checkpointBackupConfirmed before disconnecting. Large checkpoints can take minutes to upload. Transfers/evaluation are not training. Colab can terminate abruptly; only confirmed cloud progress survives runtime deletion. The two-hour session target excludes overshoot from an in-progress evaluation/upload. Run all resumes remaining updates rather than restarting.

**Reuse:** Keep the same RUN_NAME and CONFIG to resume. HOURS may change. To compare another learning rate, stage order, dataset size or mix, choose a NEW RUN_NAME and edit CONFIG; existing runs stay intact. To continue from this lab's trained weights, set sourceRun to the previous RUN_NAME and sourceKey to a completed stage key such as current-conversationWeights or fresh-contextWeights. This initializes a new optimizer/schedule from those saved weights; it does not restore the old optimizer into a changed experiment. Changing budgets on an existing name is rejected to preserve optimizer/schedule comparability. You can run context-only, language-only, conversation-only, or the full staged sequence. A finished run displays its dashboard without training forever. No automatic deployment is enabled, even if exact scores improve.
'''
    intro=(root/'v17_raw_guide.md').read_text(encoding='utf-8')+'\n\n'+intro
    setup='''import os, sys, subprocess, json
from pathlib import Path
from google.colab import userdata
subprocess.run([sys.executable,'-m','pip','install','-q','huggingface_hub>=0.34,<2','requests>=2.32,<3','datasets>=3.6,<5','pyarrow>=18,<24','numpy>=1.26,<3'],check=True)
try:
    token=userdata.get('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Enable NEBULA_HF_TOKEN in Colab Secrets.') from None
if not token or not token.strip(): raise RuntimeError('NEBULA_HF_TOKEN is empty.')
os.environ['NEBULA_HF_TOKEN']=token
os.environ['HF_TOKEN']=token
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
'''
    config='''# Change RUN_NAME for changed settings; keep it unchanged to resume.
RUN_NAME = 'nebula-v17-lab'
HOURS = 2
RAW_DATA_MODE = True
RAW_RUN_NAME = 'nebula-v17-raw-prose'
PREPARE_ONLY = False
RAW_CONFIG = {
    'sourceRun':'nebula-v17-lab', 'sourceKey':'current-foundationWeights',
    'textBytes':64000000, 'weights':{'fineweb':50,'cosmopedia':35,'stories':15},
    'validationPercent':2, 'minDocumentBytes':200, 'maxDocumentBytes':1000000,
    'maxScannedPerSource':100000, 'seed':1702026,
    'steps':10000, 'learningRate':0.00003, 'batch':8, 'microbatch':1,
    'warmup':200, 'localSaveEvery':50, 'cloudSaveEvery':500, 'evaluateEvery':1000
}
CONFIG = {
    'seed':17017,
    'sourceRun':'nebula-v15-full-chats', 'sourceKey':'fullWeights',
    'arms':['current','fresh'],
    'stages':['foundation','context','conversation'],
    'steps':{'foundation':1000,'context':1500,'conversation':1000},
    'learningRates':{'foundation':0.00003,'context':0.0001,'conversation':0.00002},
    'batch':8, 'microbatch':1, 'warmup':100,
    'localSaveEvery':50, 'cloudSaveEvery':250,
    'contextScenarios':4000, 'publicRecords':6000,
    'casesPerAxis':12, 'conversationPercent':80
}
project=Path('/content')/(RAW_RUN_NAME if RAW_DATA_MODE else RUN_NAME)/'api'
project.mkdir(parents=True,exist_ok=True)
'''
    run='sources='+repr(sources)+'''
for name, content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
if RAW_DATA_MODE:
    from v17_raw_lab import main_raw
    main_raw(project,run_name=RAW_RUN_NAME,config=RAW_CONFIG,hours=HOURS,prepare_only=PREPARE_ONLY)
else:
    from v17_lab import main
    main(project,run_name=RUN_NAME,plan=CONFIG,hours=HOURS)
'''
    pause='''## Pause / resume

Use Colab's stop button and wait for cloud confirmation. Do not refresh to stop. A STOP file also requests a pause at the next completed optimizer update if created through the runtime file panel or another process. Ordinary cells queue behind the active cell, so running the optional cell below cannot interrupt a currently executing training cell. Remove STOP before Run all. Settings and engine changes require a new RUN_NAME; the existing experiment remains protected.
'''
    stop='''# OPTIONAL — leave commented during Run all.
# (project/'STOP').touch()  # request a graceful stop
# (project/'STOP').unlink(missing_ok=True)  # enable resume
'''
    results='''## Read the evidence

After a pause or completion, the next cell prints the dashboard. Full reports and snapshots remain in the private repository under experiments/<RUN_NAME>/. Inspect per-axis scores AND the actual answers before choosing a further experiment. A context-copy success is not conversational intelligence; open replies stay pending human review. Baseline and every stage snapshot remain available even if a later stage regresses. The current arm's source and all older runs stay untouched.
'''
    show='''dashboard=project/('raw-dashboard.json' if RAW_DATA_MODE else 'dashboard.json')
if dashboard.exists():
    print(dashboard.read_text())
else:
    print('No dashboard yet. Inspect the latest checkpoint log; resume the same run if needed.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',run),
                                     ('markdown',pause),('code',stop),('markdown',results),('code',show)]):
        cell={'id':f'v17-{i:02d}','cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for name,text in sources.items():
        if name.endswith('.py'):ast.parse(text)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'accelerator':'GPU',
              'colab':{'name':'Nebula_Colab_V17_Training_Lab.ipynb'},
              'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells}
    path=root/'Nebula_Colab_V17_Training_Lab.ipynb';path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    repair='''"""Run in the existing Colab runtime after the V17 raw backup error."""
import importlib
import os
import sys
from pathlib import Path

namespace=get_ipython().user_ns
required=['RAW_RUN_NAME','RAW_CONFIG','HOURS']
if any(key not in namespace for key in required):
    raise RuntimeError('Use the existing V17 raw notebook runtime with its original configuration cells.')
project=Path('/content')/namespace['RAW_RUN_NAME']/'api'
target=project/'model'/'v8_store.py'
if not target.is_file() or not (project/'raw-data'/'documents.sqlite').is_file():
    raise RuntimeError('Existing local raw preparation was not found. Use the updated full notebook to resume the cloud backup.')
if (project/'STOP').exists():
    raise RuntimeError('STOP is present. Remove it when you are ready to resume, then run this recovery file again.')
if not os.environ.get('NEBULA_HF_TOKEN'):
    raise RuntimeError('Run the existing secrets setup cell first. Do not paste keys into this file.')
'''
    repair+='target.write_text('+repr(sources['model/v8_store.py'])+",encoding='utf-8')\n"
    repair+='''sys.path.insert(0,str(project/'model'))
for name in ['v17_raw_lab','v10_store','v8_store']:
    sys.modules.pop(name,None)
importlib.invalidate_caches()
print('Backup recovery installed. Resuming the same raw run; local preparation is retained.',flush=True)
from v17_raw_lab import main_raw
main_raw(project,run_name=namespace['RAW_RUN_NAME'],config=namespace['RAW_CONFIG'],
         hours=namespace['HOURS'],prepare_only=namespace.get('PREPARE_ONLY',False))
'''
    ast.parse(repair)
    (root/'Nebula_Colab_Resume_Raw.py').write_text(repair,encoding='utf-8')
    return path


if __name__=='__main__':print(build())
