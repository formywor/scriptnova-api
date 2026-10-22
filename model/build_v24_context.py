"""Build a self-contained Kaggle notebook without modifying older notebooks."""
import ast
import json
from pathlib import Path
from v24_context import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V23_Long_Run.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
        'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py','v20_generalize_data.py',
        'v21_curriculum_data.py','v22_conversation_data.py','v23_public_chat.py','v24_context_data.py','v24_context.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V24 - context and skill preservation

Enable Kaggle **Internet**, **GPU**, and secret **NEBULA_HF_TOKEN**, then **Run all**.
Run only one trainer per OUTPUT_RUN. This is an experiment, not a promised upgrade.

## Starting point and purpose

Starts from the protected **V22 final weights (4,000 updates)**, not V23 weights.
The architecture stays at approximately 100M parameters with a 1,024-byte context.
V23 reduced public conversation loss but regressed from 35 to 26 exact answers on the
same benchmark. This run changes the mixture and limits the first budget to **2,000 updates**.
It is a combined curriculum experiment, not an isolated causal test of each change.

## Training mixture

**80% of optimizer updates use assistant-only practice; 20% use the pinned raw corpus.**
Within assistant examples: **50% varied new context practice, 30% saved V22 practice,
20% public conversations**. Families are sampled uniformly within context and replay pools.
These are update/example proportions, not token proportions; actual targets are counted.

New original synthetic exercises vary people, cups/bags/coats/scarves and other objects,
fact order, question order, locations, arbitrary label strings, multi-turn queries,
and corrections that change one person's fact while leaving another person's fact alone.
Training values exclude the V23 benchmark's held-out inventory. Exact benchmark prompts
are excluded. Historical training exposure is unknown; template success is not general intelligence.

Reuses V23's **12,000 saved public Smol-SmolTalk conversations** from an immutable revision.
There is no new public crawl, teacher call, private user-chat import, or dataset download to disk.
Rechecks structure/context fit/excluded prompts and preserves the original whole-conversation
train/validation split. No answer is truncated. The source is synthetic Apache-2.0 data;
filtering does not certify factual correctness or remove every possible personal detail.
The original source card and attribution remain with V23's snapshot.

## Bounded training and comparison

Peak LR **3e-6**, warmup **60**, cosine decay; fresh optimizer for this changed mixture.
Resume restores V24's optimizer/scaler. One GPU is used; T4 uses FP16 AMP.
Save directly to Hugging Face every **100 updates**, and on a graceful pause.
Evaluate at baseline, **1,000 updates**, and completion. Intermediate evaluation omits
the full open probes. Baseline/final include the same 96 exact questions and actual replies
as V23 so results are directly comparable. Familiar replies can be memorized.

Candidate references require improved exact answers, no regression on the four protected
context axes, and no more than 5% regression in sampled public or mixed loss. These references
never roll back training or publish weights; open conversation still needs inspection.
A lower loss alone cannot qualify a candidate. Final reports list protected-axis regressions.

The training loop has a **7.5-hour session cap**, in addition to the 2,000-update total budget.
Preparation/evaluation/backups add time; platform GPU and session quotas still apply.
If paused, rerun this identical notebook/configuration to resume the last confirmed backup.
Do not keep extending this run before inspecting its final comparison.

## Preservation and storage

V22, V23 and older runs remain intact. New data/checkpoints/reports stay in RAM and upload
to the **public** repository https://huggingface.co/iiidevv/nebula-raw-training under
**experiments/nebula-v24-context/**. Existing public conversations/raw data are referenced,
not duplicated. Only code/notebook/packages use disk. No local artifact fallback or Google Drive.
Stop once for a graceful save; wait for **v24CheckpointConfirmed** before closing.
Abrupt shutdown can lose progress since that backup. Backup errors stop training.
No automatic website update. Changed code/settings require a new OUTPUT_RUN.
'''
    setup=''.join(previous['cells'][1]['source'])
    config="OUTPUT_RUN='nebula-v24-context'\nCONFIG="+repr(DEFAULT)+'\n'
    old=''.join(previous['cells'][3]['source'])
    tail='import importlib'+old.split('import importlib',1)[1]
    tail=tail.replace('from v23_longrun import','from v24_context import').replace('nebula-v23-longrun-code','nebula-v24-context-code').replace('V23 checkpoint','V24 checkpoint')
    execute='sources='+repr(sources)+'\n'+tail
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v24-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V24_Context.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
