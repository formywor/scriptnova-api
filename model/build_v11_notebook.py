"""Build a self-contained Kaggle notebook with verified, fail-closed grading."""
import ast,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    tree=ast.parse((root/'build_v9_notebook.py').read_text(encoding='utf-8'))
    names=next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='names' for t in n.targets))
    names+=['v10_data.py','v10_store.py','v10_teacher.py','v10_train.py','v10_eval.py','v10_experiment.py','verified_grading.py','v11_eval.py','v11_experiment.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names};cells=[]
    def add(kind,text):
        if kind=='code':ast.parse(text)
        cell={'cell_type':kind,'id':f'v11-{len(cells):02d}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown','''# Nebula V11 — honest grading and preserved progress

**Stop V10 after `checkpointBackupConfirmed: true` before starting this notebook.** Import this file into a private Kaggle notebook, enable Internet and T4 x2, enable the same `NEBULA_HF_TOKEN`, `NEBULA_TRAINER_TOKEN`, and separate `NEBULA_TEACHER_GROQ_KEY` secrets, then Run all. Do not run competing writers against the same private checkpoint repository. No API/website upload or Colab session is needed for this research run.

V11 keeps your own 100M model, all previous saved runs, fixed validation data, dataset licenses, and the V10 training curriculum. It does not import pretrained weights or restart the neural network. It first **re-grades V10's protected baseline, best, accepted working checkpoint and latest saved trial** under one new protocol. Old keyword-based scores are not compared with these stricter scores. A safe accepted working checkpoint retains its optimizer state when compatible; a checkpoint that fails the new checks remains preserved in V10.

## What changed

Matching a word no longer establishes correctness. Exact arithmetic checks inspect complete answers and equations. Exact copying requires the requested text alone. Simple name, identity and extraction answers have restricted complete-answer checks; other answers require semantic review. Copying and name/context tasks are reported separately, rather than implying a broad memory test. Readability scores are explicitly separate from correctness.

Open-ended answers receive rubric checks for relevance, coherence, factual/contextual correctness and following the request. A positive verdict requires **two successful review calls**. One negative verdict fails the answer. Missing keys, rate limits, malformed verdicts and incomplete confirmations leave it **pending**, never passed. These are fallible AI judgments, not human verification or proof of general intelligence. Read actual generated replies in the reports.

The evaluator uses the existing separate training Groq key unless you enable an optional dedicated `NEBULA_JUDGE_GROQ_KEY` secret. Two calls use the same default model and can share its biases; you can configure a different confirmation model if your account supports it. Only synthetic frozen test questions and generated test replies go to this evaluator. Evaluation questions, replies and verdicts never become training examples or go to the dialogue generator. Live user review corrections retain the existing fresh consent check and remain separate.

Training stays **80% conversation / 20% mixed** with equal assistant-turn weighting, checked teacher conversations, licensed public conversations, original repair exercises, historical rehearsal and a protected best-model anchor. It retains identity, arithmetic, copying and context practice. This version fixes selection of training results; it does not promise smarter replies just because loss declines.

Defaults: 100 updates per round, local candidates at 25/50/final and distinct lowest loss, up to 20 rounds/eight hours, 96 dialogue-teacher calls. Evaluation review has a separate bound of 16 calls per candidate, caches completed judgments, and also consumes provider quota. A round is selected only after all candidates finish review. If reviewing fails, candidate weights and partial reports are backed up, training stops, and the next Run all retries the pending review **before** further training. An outage does not count as a rejected round. Three fully reviewed rejected rounds pause for inspection.

Everything writes only to `experiments/nebula-v11-verified`. Public model updates stay off regardless of an old `publicAutoUpdate` flag. Full optimizer snapshots and pending candidates can consume several GB; repository history also grows. Until `checkpointBackupConfirmed: true`, local work can still be lost if Kaggle ends the runtime.
''')
    add('code','''import os,sys,subprocess
from pathlib import Path
import torch
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','--quiet','huggingface_hub>=0.34,<2','requests>=2.32,<3'],check=True)
def secret(name,required=True):
    try:value=UserSecretsClient().get_secret(name)
    except Exception:value=''
    if not isinstance(value,str):value=''
    if required and not value.strip():raise RuntimeError(f'Add and enable Kaggle secret {name}; enable Internet.')
    return value.strip()
os.environ['NEBULA_HF_TOKEN']=secret('NEBULA_HF_TOKEN')
os.environ['NEBULA_WORKER_TOKEN']=secret('NEBULA_TRAINER_TOKEN')
os.environ['NEBULA_TEACHER_GROQ_KEY']=secret('NEBULA_TEACHER_GROQ_KEY',False)
os.environ['NEBULA_JUDGE_GROQ_KEY']=secret('NEBULA_JUDGE_GROQ_KEY',False)
if not (os.environ['NEBULA_JUDGE_GROQ_KEY'] or os.environ['NEBULA_TEACHER_GROQ_KEY']):raise RuntimeError('Enable NEBULA_TEACHER_GROQ_KEY or a dedicated NEBULA_JUDGE_GROQ_KEY for meaningful answer review.')
os.environ['NEBULA_JUDGE_GROQ_MODEL']='openai/gpt-oss-20b'
os.environ['NEBULA_JUDGE_CONFIRM_MODEL']='openai/gpt-oss-20b'
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
os.environ['NEBULA_RESEARCH_API']='https://api.scriptnovaa.com/api/nebula/research'
RUN_NAME='nebula-v11-verified'
HOURS=8
MAX_ROUNDS=20
STEPS_PER_ROUND=100
TEACHER_MAX_CALLS=96
project=Path('/kaggle/working/nebula-v11-verified/api');project.mkdir(parents=True,exist_ok=True)
if not torch.cuda.is_available():raise RuntimeError('Enable the Kaggle GPU accelerator.')
print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),'publicAutoUpdate':False,'firstPhase':'re-grade saved V10 checkpoints'})
''')
    add('code','sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v11_experiment import main
from research_client import ResearchError
try:
    main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
except ResearchError as error:
    print({'v11Stopped':error.code,'publicWebsiteUpdated':False})
    if 'REVIEW_PENDING' in error.code:print('Review could not finish. Wait for provider quota/service recovery, then Run all again. Existing saved models are preserved.')
    else:raise
''')
    add('markdown','''## Stop, inspect and resume

For a graceful stop, create `/kaggle/working/nebula-v11-verified/api/STOP_AFTER_ROUND` from another cell and wait for a confirmed backup. Remove the file before resuming. Kaggle's stop button can lose unfinished local work. Run all with the same run name resumes confirmed progress; pending evaluation is retried first.

Reports contain the complete generated replies, grading method, reasons, review votes and pending counts. Review `v11SourceRegraded`, `v11CandidateDecision`, and `v11RoundSaved`. Lower scores than V10 can reflect removal of false positives; only compare V11 scores with V11 scores. A lower validation loss alone cannot qualify a model for best. Three rejected rounds deliberately pause this run. No research model is automatically published to users.
''')
    target=root/'Nebula_Kaggle_V11_Verified.ipynb'
    target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells},indent=1),encoding='utf-8');return target

if __name__=='__main__':print(build())
