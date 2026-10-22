"""Build the self-contained Kaggle audit and controlled foundation notebook."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_Raw_Training.ipynb').read_text(encoding='utf-8'))
    setup=''.join(previous['cells'][1]['source'])
    sources={n:(root/n).read_text(encoding='utf-8') for n in
             ['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
              'v18_decode_probe.py','v18_foundation_control.py']}
    intro='''# Nebula — audit and controlled story foundation experiment

Import as a **separate Kaggle notebook**. Enable Internet, a GPU and the `NEBULA_HF_TOKEN` write secret.
Stop any old training session after its confirmed save, then **Run all** here.

The fixed control is your saved **step-10,102 V18 model**. The experiment keeps its architecture, batch,
optimizer state and continued learning-rate schedule. It practices only a deterministic subset of existing
public TinyStories data: up to 8 MB training text and 0.5 MB validation text. This is a small foundation test,
not another full training campaign. No new dataset downloads or teacher API calls are needed;
it reads existing saved corpus shards from Hugging Face.

## What it checks

- Every document index: ranges, packed lengths, source totals, hash splits, duplicates and shard coverage.
- Sampled actual documents from every source/split: true BOS/EOS, UTF-8 integrity and matching content hashes.
- The original V18 batch at update 10,102: correct one-position input/target shift, lengths and token ranges.
- The source model on real batch text: future-token changes cannot affect past logits; manual next-token loss agrees.
- All selected story payloads and separation of their training/validation hashes.

Audit samples show actual public training text. Checks do not certify all corpus content, exclude near-duplicates,
or prove that earlier training never saw the validation texts. Validation is disjoint within the saved corpus.
Mixed windows beginning mid-word/UTF-8 character are expected for byte-level training.

## Controlled run

Baseline evaluation → **1,000 additional optimizer updates** → identical final evaluation.
Both evaluate held-out mixed text and held-out stories, greedy and seeded temperature-0.7/top-p-0.9 completions,
and ordinary chat prompts. Two prefixes come from validation stories. All replies remain visible for inspection.
Relevance/grammar require human judgment; lower loss or less repetition does not automatically approve the model.

One practical precision correction: a T4 uses native FP16 AMP with a gradient scaler, rather than emulated BF16.
The report records this. Because precision also changes if the source used emulated BF16, this is a diagnostic
experiment, not a perfectly isolated causal estimate of the data change. One GPU is used, even with T4 x2.
Expect roughly an hour of training at the previous speed, plus audits, baseline/final probes and uploads.
The training loop stops after two hours per session; setup/evaluation/uploads add time.

## Saves and resume

All datasets, model/optimizer checkpoints and reports stay in RAM and save directly to the PUBLIC repository
`iiidevv/nebula-raw-training`, under **experiments/nebula-v18-foundation-control/**.
Original V18 weights and manifest are preserved. Source documents are referenced from their existing saved shards.
No website update, automatic promotion, Google Drive, ZIP or local dataset/checkpoint files.
Only code, installed packages and the notebook use disk. Host RAM of 16 GB or more is recommended.

Saves every **100 updates** and on a graceful interrupt. Wait for `controlCheckpointConfirmed` before closing.
After a disconnect, Run all with identical settings/code to resume the last confirmed control checkpoint.
Completed runs display their saved comparison instead of training again. Changing settings requires a new OUTPUT_RUN.
Abrupt worker loss can lose RAM progress since the last confirmed save; public storage/history and GPU quotas still apply.
'''
    config='''OUTPUT_RUN='nebula-v18-foundation-control'
CONFIG={
    'sourceRepo':'iiidevv/nebula-raw-training',
    'sourceRun':'nebula-v18-raw-1gb',
    'sourceRevision':'e167fff3bb27c36c25460fcd4c61915a5b7016ed',
    'expectedUpdates':10102,
    'updates':1000,
    'trainUtf8Bytes':8_000_000,
    'validationUtf8Bytes':500_000,
    'seed':19021,
    'saveEvery':100,
    'maxSessionHours':2,
}
'''
    execute='sources='+repr(sources)+'''
import importlib
code_root=Path.cwd()/'nebula-foundation-control-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v18_foundation_control import run_control
comparison=run_control(OUTPUT_RUN,CONFIG)
if 'baseline' in comparison and 'final' in comparison:
    import pandas as pd
    from IPython.display import display,Markdown
    losses=[]
    for stage in ['baseline','final']:
        for pool in ['heldoutMixed','heldoutStories']:
            losses.append({'stage':stage,'pool':pool,**comparison[stage][pool]})
    display(pd.DataFrame(losses))
    for stage in ['baseline','final']:
        display(Markdown('## '+stage.title()))
        display(pd.DataFrame(comparison[stage]['summary']))
        for row in comparison[stage]['answers']:
            print(row['kind'],row['mode'],'seed',row['seed'])
            print('PROMPT:',row['prompt'])
            print('REPLY:',row['reply'])
            print()
else:
    print('Session paused. Run all again with the same configuration to continue.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell={'id':'foundation-control-'+str(i),'cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':previous['metadata'],'cells':cells}
    path=root/'Nebula_Kaggle_Foundation_Control.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
