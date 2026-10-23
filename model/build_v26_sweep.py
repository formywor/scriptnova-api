"""Build a self-contained Kaggle notebook for a controlled LR sweep."""
import ast
import json
from pathlib import Path
from v26_answers import DEFAULT

def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V25_Answers.ipynb').read_text(encoding='utf-8'))
    tree=ast.parse(''.join(previous['cells'][3]['source']))
    sources=ast.literal_eval(tree.body[0].value)
    sources.pop('v25_answers.py')
    for name in ['v26_answers.py','v26_sweep.py']:sources[name]=(root/name).read_text(encoding='utf-8')
    intro="""# Nebula V26 — controlled learning-rate comparison

Enable Kaggle Internet, GPU and secret **NEBULA_HF_TOKEN**, then **Run all**.
Stop any other worker using these V26 output runs. Uses one GPU, FP16 AMP on T4.

V25 improved some losses but did not improve general conversation. This experiment
compares **1e-6, 3e-6 and 1e-5** peak learning rates, **500 updates each**, sequentially.
All three start independently from the same protected V22 final weights. They use
identical V25 data, example order, seed, batch 8, microbatch 1, 60-step warmup,
cosine decay, AdamW weight decay 0.01 and gradient clipping 1.0. The only training
setting varied is peak learning rate. This tests a short training budget; it does
not establish which rate would work best for a much longer run.

The same 80% assistant-update / 20% raw-update mix is retained. Assistant examples
are 60% answer-turn repair, 20% V22 replay, 20% saved public conversations. These
are update/example proportions, not byte proportions. Earlier acknowledgments are
masked only on repair records. No new teacher calls or private chats are imported.

One shared V22 baseline is evaluated and saved; each arm gets a final 96-question
development comparison, held-out losses, and full open/raw replies. No intermediate
generation evaluations. Familiar answers and development scores are not independent
proof of general ability. Inspect unfamiliar replies. Added brackets fail strict
copying even when the inner string is correct; inspect the reported strings.

No automatic winner, rollback, deployment or extra training. An arm is only flagged
for manual inspection if total exact correctness improves, all five protected axes
are preserved, and mixed/public loss remains within 5% of baseline. It may be that
none qualify. All arms and original versions remain intact.

Checkpoints, optimizer/scaler state, datasets and reports stay in RAM and upload to
PUBLIC Hugging Face **iiidevv/nebula-raw-training**, under separate
**experiments/nebula-v26-lr-low/**, **nebula-v26-lr-reference/** and
**nebula-v26-lr-high/** prefixes. Code/packages use disk; no local artifact fallback,
Drive or ZIP. Existing pinned public/raw sources are reused. Only run this notebook
with public-appropriate data. No private user conversations are included.

Save every **100 updates** and on graceful interruption. Wait for
**v26CheckpointConfirmed** before closing. Abrupt shutdown can lose unsaved updates.
Run all again with identical settings/code to resume; finished arms are read from
HF and skipped. An optimizer reset is expected at each new arm; resume restores it.

The session budget is **7 hours total across arms**; setup/evaluation/upload may run
past it. GPU platform quotas still apply. The notebook pauses without starting
additional training after the deadline. Changing training settings requires new
output run names in the code; don't overwrite existing runs. Final reports are
saved separately per arm, and the notebook displays a comparison table.
"""
    setup=''.join(previous['cells'][1]['source'])
    config='BASE_CONFIG='+repr(DEFAULT)+'\nSESSION_HOURS=7.0\n'
    execute='sources='+repr(sources)+"""
import importlib
code_root=Path.cwd()/'nebula-v26-lr-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v26_sweep import run_sweep
comparison=run_sweep(BASE_CONFIG,hours=SESSION_HOURS)
import pandas as pd
from IPython.display import display
if comparison['results']:display(pd.DataFrame(comparison['results']))
print(comparison.get('notice','Paused: Run all again with unchanged settings.'))
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v26-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V26_Learning_Rates.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
