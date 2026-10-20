"""Build a self-contained read-only Colab companion for the Kaggle V9 trainer."""
import ast,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    names=['nebula.py','train.py','rules.py','dataflow.py','teacher_http.py','public_data.py','research_cases.json','research_eval.py','research_client.py','kaggle_migrate.py','v4_eval.py','v4_data.py','v4_store.py','v6_data.py','v7_data.py','v7_checks.py','v7_train.py','conversation_mix.py','v8_store.py','v9_eval.py','colab_v9_evaluator.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'colab-v9-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V9 - Colab evaluation companion

Keep Kaggle V9 training running. Upload this notebook into Colab, select a T4 GPU, then Run all. In Colab Secrets (the key icon), add **NEBULA_HF_TOKEN** and enable notebook access. Since this is a different Google account, its Colab secrets must be configured separately. A token with read access to your private `iiidevv/nebula-research` repository is sufficient. Never paste a token into a code cell. No trainer/evaluator API token, teacher key, Drive mount or new model upload is required.

This companion reads Kaggle's saved V9 snapshots. It cannot publish checkpoints, change Kaggle training, change its curriculum or update the public website. Kaggle retains its own checks and checkpoint decisions. Colab is a second view of model quality, not a third training GPU. There is no automatic feedback loop from these reports to Kaggle in this version.

It checks the protected best and latest saved trial, reusing results for unchanged checkpoints. The original task checks, held-out conversation/language losses, and fresh conversation questions appear in a report. Fresh questions are excluded if they match prompts in the known training, teacher, validation or frozen diagnostic data. This exact-match filtering cannot prove semantic novelty. Simple context and arithmetic checks are scored; writing, stories, editing and explanations are shown for human review. A small keyword/numeric score is not proof of general ability.

The initial protected checkpoint can be tested before Kaggle completes a round. It then checks for new saved rounds once a minute, up to eight hours or twenty new snapshot reports. It reads a pinned snapshot revision per evaluation, so an active Kaggle upload does not mix checkpoint versions. Only compact best/latest weights are downloaded; full optimizer checkpoints are unnecessary. The first download/evaluation may take a few minutes.

A JSON report and readable Markdown report are saved under `/content/nebula-v9-evaluator/reports`. By default the readable report downloads after each evaluation; allow multiple downloads if the browser asks. Download these reports before a Colab reset: evaluator files are temporary. Model checkpoints remain in your existing private repository. No checkpoint or report is written back there by this notebook. Downloads may fail if the browser disconnects; use the final cell to download the latest report again.

Stop with the cell's stop button, or create `/content/nebula-v9-evaluator/STOP_EVALUATING` in another cell. Stop Colab when finished to free its GPU. Stop/run does not stop Kaggle. Running again in the same runtime skips completed snapshot reports; a new runtime downloads and evaluates the latest saved version again. Availability and session limits still apply.
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
from google.colab import userdata,files
import torch
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2','requests>=2.32,<3'],check=True)
try:
    hf_token=userdata.get('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError("Add NEBULA_HF_TOKEN in this account's Colab Secrets and enable notebook access.") from None
if not isinstance(hf_token,str) or not hf_token.startswith('hf_'):raise RuntimeError('NEBULA_HF_TOKEN is empty or invalid.')
if not torch.cuda.is_available():raise RuntimeError('Select a Colab GPU runtime before running this notebook.')
project=Path('/content/nebula-v9-evaluator');project.mkdir(parents=True,exist_ok=True)
os.environ['HF_HOME']=str(project/'private-hf-cache')
REPOSITORY='iiidevv/nebula-research'
HOURS=8
MAX_NEW_REPORTS=20
DOWNLOAD_EACH_REPORT=True
print({'role':'read-only evaluator','GPU':torch.cuda.get_device_name(0),'KaggleTrainingChanged':False})
''')
    add('code','sources='+repr(sources)+'''
code_dir=project/'code';code_dir.mkdir(exist_ok=True)
for name,content in sources.items():
    if Path(name).name!=name:raise RuntimeError('Unexpected source filename')
    (code_dir/name).write_text(content,encoding='utf-8')
sys.path.insert(0,str(code_dir))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from colab_v9_evaluator import watch
from IPython.display import display,Markdown

def show_report(json_path,readable_path):
    import json
    report=json.loads(json_path.read_text(encoding='utf-8'))
    display(Markdown('### Saved Kaggle round '+str(report['sourceRound'])))
    for label,result in report['results'].items():
        metrics=result['metrics'];fresh=result['freshConversationChecks']
        print(label,{'frozenChecks':str(metrics['correct'])+'/'+str(metrics['cases']),'chatChecks':str(metrics['chatChecks'])+'/'+str(metrics['chatCases']),'publicChatLoss':metrics['publicChatLoss'],'languageLoss':metrics['languageLoss'],'freshExactChecks':str(fresh['exactChecksPassed'])+'/'+str(fresh['exactChecks'])})
    if DOWNLOAD_EACH_REPORT:
        try:files.download(str(readable_path))
        except Exception:print('Report saved locally. Download it with the last cell before resetting this runtime.')

watch(project,REPOSITORY,hf_token,hours=HOURS,max_rounds=MAX_NEW_REPORTS,poll_seconds=60,on_report=show_report)
''')
    add('markdown','''## Download the latest report again

Run the cell below after stopping the monitoring cell, or from a second cell when a report is available. The JSON contains full comparison metrics; the Markdown shows readable questions and replies. No ZIP is created.
''')
    add('code','''reports=sorted((project/'reports').glob('round-*.json'))
if not reports:print('No completed evaluation report yet.')
else:
    files.download(str(reports[-1]))
    files.download(str(reports[-1].with_suffix('.md')))
''')
    target=root/'Nebula_Colab_V9_Evaluator.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'accelerator':'GPU','colab':{'provenance':[]}},'cells':cells},indent=1),encoding='utf-8')
    return target

if __name__=='__main__':print(build())
