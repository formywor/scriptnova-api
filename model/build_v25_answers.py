"""Self-contained V25 notebook, RAM-to-HF datasets and checkpoints."""
import ast
import json
from pathlib import Path
from v25_answers import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V24_Context.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
        'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py','v20_generalize_data.py',
        'v21_curriculum_data.py','v22_conversation_data.py','v23_public_chat.py','v24_context_data.py',
        'v25_answer_data.py','v25_answers.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V25 - answer-turn repair

Enable Kaggle **Internet**, **GPU**, and secret **NEBULA_HF_TOKEN**, then **Run all**.
Stop other trainers using this output run first. This is an experiment, not a promised upgrade.

## Why this experiment

V24 preserved some skills but gave acknowledgments in place of answers and regressed
on corrected facts. The hypothesis is that training intermediate acknowledgments
alongside final answers reinforced the wrong response pattern. This run tests a
changed repair objective and sampling mix; it cannot isolate every contributing cause.

Starts from protected **V22 final weights**, pinned at
`6c670c3670444d7cde2b17760fea1cdde4a93b18` (4,000 updates).
V24 and V23 stay preserved. Architecture remains about 100M parameters, a byte vocabulary,
and a 1,024-byte context. No pretrained model is substituted.

## Focused lessons

New original synthetic repair examples cover corrected facts, unchanged facts about
another person, switching between names/colors/locations, copying label strings,
and short multi-turn writing and practical requests.

**Only the final assistant answer and its real EOS are supervised on new repair records.**
Earlier assistant messages remain visible as context, but have no loss targets.
Intermediate acknowledgment-only turns are never selected as repair targets. This does
not remove acknowledgments from earlier V22 replay or public conversations; those retain
their original assistant-only objective.

80% of optimizer updates are assistant practice; 20% retain pinned raw-language practice.
Within assistant examples: **60% new repair / 20% V22 replay / 20% public conversations**.
Repair families favor corrections (weight 4), query switching/practical/writing (3),
ownership/multi-turn/copy (2), and field-order/location (1). Replay families are uniform.
These are update/example proportions, not byte proportions. Actual target counts are logged.

The same saved 12,000 public Smol-SmolTalk conversations are reused at a pinned revision.
Whole-conversation train/validation splits remain separate; no answers are cut to fit.
New repair values exclude the existing held-out inventory and exact benchmark prompts.
No teacher calls, private user-chat imports, broad crawls or dataset files on disk.

## Run and compare

Budget **1,000 additional updates**, peak LR **3e-6**, warmup 60 and cosine decay.
Save to HF every **100 updates** and on graceful interruption. Session cap **7.5 hours**;
preparation/evaluation/backups add time and platform GPU quotas still apply.
Baseline, update 500 and final evaluations use the existing 96 questions. Full open probes
run at baseline/final only. These questions are now a **development comparison**, because
results have informed several curricula. They are not an independent final certification.
Inspect actual replies as well as scores; familiar answers can be memorized.

A candidate must improve total exact answers, preserve corrected facts, entity binding,
unseen values, unseen wording and copying, and keep sampled mixed/public loss within 5%
of V22. Candidate references never roll training back or publish anything automatically.

If paused, **Run all again with this identical notebook and settings** to restore the last
confirmed checkpoint and optimizer. If finished, it displays the saved comparison.
Do not extend the run unchanged before inspecting results. One GPU is used; T4 uses FP16 AMP.

## Storage and preservation

New datasets/checkpoints/reports stay in RAM and upload directly to the PUBLIC repository
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v25-answers/**.
Existing raw/public data are referenced. Only code, notebooks and packages use disk.
No local checkpoint/data fallback, Google Drive or ZIP. Previous versions remain intact.
Wait for **v25CheckpointConfirmed** before closing. An abrupt shutdown may lose progress
since the last backup. Backup errors stop training. No website deployment is performed.
Changed settings/code require a new OUTPUT_RUN.
'''
    setup=''.join(previous['cells'][1]['source'])
    config="OUTPUT_RUN='nebula-v25-answers'\nCONFIG="+repr(DEFAULT)+'\n'
    tail='import importlib'+''.join(previous['cells'][3]['source']).split('import importlib',1)[1]
    tail=tail.replace('from v24_context import','from v25_answers import').replace('nebula-v24-context-code','nebula-v25-answers-code').replace('V24 checkpoint','V25 checkpoint')
    execute='sources='+repr(sources)+'\n'+tail
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v25-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for s in sources.values():ast.parse(s)
    path=root/'Nebula_Kaggle_V25_Answers.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
