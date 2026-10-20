"""Build the separate Kaggle V10 dialogue repair experiment."""
import ast,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    tree=ast.parse((root/'build_v9_notebook.py').read_text(encoding='utf-8'))
    names=next(ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='names' for target in node.targets))
    names+=['v10_data.py','v10_store.py','v10_teacher.py','v10_train.py','v10_eval.py','v10_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    seed=root/'data/v10-teacher-seed.jsonl'
    sources['model/data/v10-teacher-seed.jsonl']=seed.read_text(encoding='utf-8') if seed.is_file() else ''
    cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v10-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V10 - clear replies and consistent follow-ups

Stop V9 after a confirmed remote backup. Import into a private Kaggle notebook, enable Internet and T4 x2, enable the same `NEBULA_HF_TOKEN`, `NEBULA_TRAINER_TOKEN`, and optional separate `NEBULA_TEACHER_GROQ_KEY`, then Run all. No API/website upload or Colab session is needed.

V10 starts from the **protected best** saved by V9, never its rejected latest trial. It retains your owned 100M weights and inherited step count, and writes only to `experiments/nebula-v10-dialogue`. V9 and earlier checkpoints remain intact. The first transition starts a fresh optimizer for the new data and anchor. Compatible accepted V10 working checkpoints retain optimizer state and accumulated warm-up progress on resume. A rollback intentionally resumes the protected model instead.

The repair curriculum keeps complete conversation answers of at most 220 characters with at most 768 bytes of total context. This focuses practice on short coherent replies without cutting off existing answers. Repeated phrases, explicit incorrect additions, incomplete turns, foreign identities and known evaluation prompts are excluded. Forty original multi-turn exercises cover clarification, identity, corrections, simple explanations, grounded stories and natural follow-ups; exact overlaps with fixed validation are removed. Historical short conversations and licensed public examples remain. No new pretrained weights or bulk web crawl is used.

Training remains 80% conversation updates and 20% mixed practice. Conversation slots combine historical rehearsal, original repair exercises, checked synthetic Groq dialogues, public chats and fresh consent-checked review corrections. Repair examples have an aggregate four-pass exposure budget and teacher/review examples an aggregate two-pass budget per round, with fallback to broader practice. Mixed practice is 10% memory, 5% identity, 2.5% simple language and 2.5% arithmetic over full 40-update cycles. Assistant turns are weighted equally within each conversation, so a short follow-up is not overwhelmed by a longer first reply. The exact protected 100M best is now the anchor. Rehearsal guidance is stronger for memory, identity and historical replies.

The separate Groq teacher is directed to relevant answers, useful clarification and coherent follow-ups, with a separate confirmation pass. Logs report filter reasons without rejected dialogue text. Private review corrections still use the existing live consent-checked feed; no user conversations are sent to the separate teacher key. Missing keys or teacher outages leave owned/public training available. Teacher judgments and structural filters can still miss errors.

Default rounds are **100 updates**, with local saves every 25 updates. Candidate replies are evaluated at updates 25, 50, the final step, and an additional lowest-loss candidate when distinct. This can retain an earlier genuine improvement instead of discarding it after a later drift. Evaluation still uses the fixed V9 validation split and original frozen questions. Protected memory, identity, arithmetic, extraction, readability and loss requirements are not loosened; generated-chat readability also may not regress. Logs show the current phase and named failed checks. Chat and writing competence still require inspection of actual replies.

Three consecutive rejected rounds pause the experiment after a confirmed backup instead of repeating the same unsuccessful training all night. Re-running that paused run asks for its reports to be inspected first. Defaults are up to twenty rounds/eight hours and 96 separate teacher calls. Progress is not guaranteed. No research checkpoint automatically replaces a public website model.

Snapshots use temporary verified downloads, so historical checkpoint downloads do not accumulate in a local Hugging Face weight cache. Full accepted working checkpoints still contain optimizer state (about 1.2 GB), and remote repository history can still grow substantially. Intermediate checkpoints remain local until `checkpointBackupConfirmed: true`. A GPU capacity probe checks the larger anchor before training. Do not confuse successful initialization or a lower loss with better generated replies.
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2','requests>=2.32,<3'],check=True)
def secret(name):
    try:value=UserSecretsClient().get_secret(name)
    except Exception:raise RuntimeError(f'Add and enable Kaggle secret {name}; enable Internet.') from None
    if not isinstance(value,str) or not value.strip():raise RuntimeError(f'Empty Kaggle secret: {name}')
    return value.strip()
os.environ['NEBULA_HF_TOKEN']=secret('NEBULA_HF_TOKEN')
os.environ['NEBULA_WORKER_TOKEN']=secret('NEBULA_TRAINER_TOKEN')
try:teacher=UserSecretsClient().get_secret('NEBULA_TEACHER_GROQ_KEY')
except Exception:teacher=''
os.environ['NEBULA_TEACHER_GROQ_KEY']=(teacher or '').strip()
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_RESEARCH_API']='https://api.scriptnovaa.com/api/nebula/research'
RUN_NAME='nebula-v10-dialogue'
HOURS=8
MAX_ROUNDS=20
STEPS_PER_ROUND=100
TEACHER_MAX_CALLS=96
project=Path('/kaggle/working/nebula-v10-dialogue/api');project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available():raise RuntimeError('Enable the Kaggle GPU accelerator.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False,'source':'protected V9 best'})
''')
    add('code','sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v10_experiment import main
main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
''')
    add('markdown','''## Stop and resume

For a graceful stop create `/kaggle/working/nebula-v10-dialogue/api/STOP_AFTER_ROUND` from another cell. Wait for `checkpointBackupConfirmed: true`. Remove the stop file before resuming the same runtime. Kaggle's stop button can discard the unfinished round; confirmed remote backups remain intact. Import and Run all with the same run name to resume the last confirmed working checkpoint. A pause after three rejections is deliberate and needs investigation, not an automatic restart loop.

Inspect `v10CandidateDecision`, generated evaluation replies and `v10RoundSaved`. A best or working acceptance is useful evidence; lower loss alone is not sufficient. Saved teacher data and dataset licenses carry over privately. Public publishing remains a separate decision.
''')
    target=root/'Nebula_Kaggle_V10_Dialogue.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8');return target

if __name__=='__main__':print(build())
