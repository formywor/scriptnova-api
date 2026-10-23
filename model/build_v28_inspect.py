"""Package a short read-only V28 inspection notebook, not a new training run."""
import ast
import json
from pathlib import Path

def build():
    root=Path(__file__).parent
    old=json.loads((root/'Nebula_Kaggle_V28_Longrun.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py','v27_subword_model.py','v28_inspect.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro="""# Inspect the finished Nebula V28 model — no training

This is a **short read-only model inspection**, not V29 and not another long
training run. Enable Kaggle Internet, one GPU and secret **NEBULA_HF_TOKEN**.
Then Run all. Disable the accelerator after the inspection finishes.

## What it checks

Load the exact final V28 foundation checkpoint: **30,000 V28 updates**, immutable
revision **9cfc225eae2fefe1fee5e01d77690487172d6dce**. Verify checkpoint/tokenizer
checksums and require that the saved foundation stage is complete. No latest-model
selection, architecture changes, weight updates, optimizer creation or deployment.

Use **12 varied new development prefixes**, each with greedy decoding and temperature
0.7/top-p 0.9 sampling: everyday prose, science, practical sequences, short context,
explanations, dialogue and a story. Maximum **48 generated subword tokens per reply**,
24 replies total. Use plain-text prefixes because this is a foundation model that
has not completed conversation SFT. These are not claims of independent held-out
questions: historical public exposure is unknown.

Keep the model in float32 inference, matching V28's earlier evaluation. No repetition
penalty, forced answer, automatic correction or teacher-generated replacement hides
the original behavior. Print each reply, repetition fraction, generated token count
and EOS/token/time stop reason. A completed report is **not a passing model**.

Every response stays **pending human review**. Inspect relevance, correctness,
coherent meaning and repetition. Lower repetition under sampling is not proof of
understanding; a short fluent opening does not establish a correct explanation.
Do not feed these probes or answers back into training.

## Time and saving

Default elapsed budget **15 minutes**, including model download/loading. Network
operations, loading and final report uploads can overrun that budget; this is not a
quota detector or guaranteed runtime. Generation stops between tokens when time
runs out. Partial completed probes save every **four replies** and on graceful
pause. Rerun with identical settings to continue missing probes without regenerating
saved ones. Completed inspections display their saved report without loading weights.

Weights/tokenizer are read into RAM. Optimizer data contained in the old checkpoint
is discarded after loading; no optimizer or backward pass is used. Only inspection
reports are written to PUBLIC Hugging Face under
**experiments/nebula-v28-inspect-1/**. Existing training manifests, tokenizer,
weights and optimizer checkpoints are never overwritten. Code/packages use disk;
no local model/data/report fallback, Drive or ZIP. Interrupted unsaved probes can
be rerun. If uploads fail, reports remain in the active process RAM; do not assume
an unconfirmed report is backed up.

Keep RUN_NAME/settings unchanged for resume. Use a new inspection RUN_NAME if
prompts, token limit or code change. This notebook deliberately does not start SFT,
continue foundation training or promote any model. After reading the report, decide
whether to change the data/training recipe; no improvement is promised in advance.
"""
    setup=''.join(old['cells'][1]['source']).replace('nebula-v28-tokenizer-packages','nebula-v28-inspect-packages')
    config="RUN_NAME='nebula-v28-inspect-1'\nMAX_SECONDS=900\nMAX_NEW_TOKENS=48\n"
    execute='sources='+repr(sources)+"""
import importlib
code_root=Path.cwd()/'nebula-v28-inspect-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v28_inspect import run
report=run(RUN_NAME,seconds=MAX_SECONDS,limit=MAX_NEW_TOKENS)
for row in report['answers']:
    print(row['category'],row['mode'],'PREFIX:',row['prefix'])
    print('CONTINUATION:',row['continuation'])
    print('STOP:',row['stopReason'],'REPETITION:',row['repeatedTrigramFraction'])
print({'inspectionComplete':report['complete'],'answers':len(report['answers']),
       'trainingStarted':False,'qualityApproved':False,'publicWebsiteUpdated':False})
"""
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='inspect-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V28_Inspect.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=old['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
