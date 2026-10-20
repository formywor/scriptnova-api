"""Package the unreviewed full-chat experiment with independent filtered control."""
import ast,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent;old=json.loads((root/'Nebula_Kaggle_V14_Foundation.ipynb').read_text(encoding='utf-8'))
    code=next(''.join(c['source']) for c in old['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    names=ast.literal_eval(ast.parse(code).body[0].value).keys();sources={name:(root.parent/name).read_text(encoding='utf-8') for name in names}
    for name in ['v15_data.py','v15_train.py','v15_compare.py','v15_experiment.py']:sources['model/'+name]=(root/name).read_text(encoding='utf-8')
    intro="""# Nebula V15 - complete public chats, no semantic screening

Stop older trainers first. Import into a PRIVATE Kaggle notebook, enable Internet and your existing NEBULA_HF_TOKEN secret. No new API/website upload is required. No Groq, Gemini, teacher or judge key is used. With GPU available, Run all starts a bounded comparison. If your GPU quota is exhausted, set PREPARE_ONLY=True and use CPU to acquire/back up data now; later set it False and enable T4 x2 to train. Preparation does not train a model.

This is an experiment, not a guaranteed improvement or a public release. It preserves V14 and all older runs. Both trial arms copy V14's final conversation weights, approximately 100M parameters, with unchanged byte tokenizer and 1,024-byte context. They begin with fresh optimizers and receive the same update budget, learning rate, batch size, sampling seed and held-out questions. Arm A trains on the existing filtered V14 conversations. Arm B trains on the complete unscreened public conversations. The starting model is also evaluated, so improvement merely from extra training can be distinguished from a benefit of the new corpus. This is one seeded comparison, not statistical proof.

The default target is 20,000 full Smol-SmolTalk TRAIN records from the same pinned source revision (Apache 2.0). Acquisition is bounded at 128 MiB of saved corpus or five times the target scanned records. It does not download all 460,000 conversations or promise every acquired chat is seen during this pilot. No grammar, topic, coding, roleplay, identity, factual-accuracy or AI-quality screening is applied. Original text, source system messages and all turns are retained without shortening. No private account chats are used. Only valid role structure, credential-pattern exclusion, exact deduplication, evaluation separation and a 2 MiB whole-record resource limit remain. A rejected oversized/invalid record is skipped completely, never truncated. Exclusion reasons and counts are logged. Full chats may contain incorrect answers or conflicting identities; that is deliberately part of this experiment.

Every assistant target byte, including EOS at actual message endings, is represented once across that record's rolling windows. User and system content are masked. Complete records are sampled uniformly, then windows uniformly within a selected record, so very long chats do not automatically dominate. Default budget: 200 optimizer updates per arm, 400 total. The pilot samples windows; it does not guarantee full exposure to every record or window. The 1,024-byte attention limit remains, so a distant fact may still be outside context. Retaining a whole chat does not give the model unlimited cross-turn memory. Ordinary source system instructions stay as masked training context; no external tools execute them.

Baselines and final arm reports contain the SAME fixed questions and rotating context exercise seed, actual generated follow-up history and raw completions. Pending semantic grades remain pending. The comparison never promotes model weights to public users. A clear local regression against BOTH the starting model and the filtered control removes the new corpus from the active V15 experiment. Specifically: a loss of at least two exact passes with two extra failed answers, OR four fewer readable answers with three extra failures and no extra exact passes, against each reference. Two extra exact passes with no extra failures or readability decline against each reference counts as provisional local improvement. Matching aggregate scores counts only as no detected change. Mixed or unknown outcomes keep the corpus pending review. Readable does not mean correct, and unchanged scores do not prove unchanged behavior.

Automatic removal targets only experiments/nebula-v15-full-chats/data/full-chats.jsonl (or its explicit shards). Original public datasets, V14, other runs, comparison reports and diagnostic checkpoints are preserved. Hugging Face version history can still contain older copies; this is removal from active use, not a secure history purge. If removal fails, the next Run all retries it. Data acquisition and every 100 training updates are privately backed up; local training checkpoints occur every 50 updates. Wait for checkpointBackupConfirmed or v15PreparationBackupConfirmed before ending a session. Since the last cloud backup, work may be lost if the runtime disconnects. Do not run duplicate workers.

Use the same settings to resume. The default two-hour session limit includes acquisition/evaluation, but an in-progress preparation or evaluation may run beyond that approximate bound. Unfinished arms resume next time. At completion, inspect reports/comparison.json and both answer reports before planning more training. Lower held-out loss alone never triggers retention as an improvement or publication. Logs may retain v14Checkpoint/v14ProbeReport labels because the tested training/evaluation engine is reused.
"""
    setup="""import os,subprocess,sys
from pathlib import Path
from kaggle_secrets import UserSecretsClient
subprocess.run([sys.executable,'-m','pip','install','-q','huggingface_hub>=0.34,<2','requests>=2.32,<3','datasets>=3.6,<5','pyarrow>=18,<24'],check=True)
try:
    token=UserSecretsClient().get_secret('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Add and enable Kaggle secret NEBULA_HF_TOKEN.') from None
os.environ['NEBULA_HF_TOKEN']=token
os.environ['HF_TOKEN']=token
os.environ['NEBULA_HF_REPO']='iiidevv/nebula-research'
project=Path('/kaggle/working/nebula-v15-full-chats/api');project.mkdir(parents=True,exist_ok=True)
PREPARE_ONLY=False
HOURS=2
UPDATES_PER_ARM=200
TARGET_CHATS=20000
import torch
print({'GPUs':torch.cuda.device_count(),'prepareOnly':PREPARE_ONLY,'publicAutoUpdate':False,'semanticScreening':False})
"""
    run='sources='+repr(sources)+"""
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v15_experiment import main
args=['--project',str(project),'--hours',str(HOURS),'--updates',str(UPDATES_PER_ARM),'--target-chats',str(TARGET_CHATS)]
if PREPARE_ONLY:args+=['--prepare-only']
main(args)
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',run),('markdown','Create /kaggle/working/nebula-v15-full-chats/api/STOP_AFTER_CHUNK for a graceful stop after the current backed-up chunk. Remove it before resuming. Turn off the GPU when finished.')]):
        cell={'id':f'v15-{i:02d}','cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for name,source in sources.items():
        if name.endswith('.py'):ast.parse(source)
    target=root/'Nebula_Kaggle_V15_Full_Chats.ipynb';target.write_text(json.dumps({'nbformat':4,'nbformat_minor':5,'metadata':old['metadata'],'cells':cells},indent=1),encoding='utf-8');return target

if __name__=='__main__':print(build())
