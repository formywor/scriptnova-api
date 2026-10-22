"""Self-contained Kaggle continuation of V19 with a fresh generalization benchmark."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V19_Tutor.ipynb').read_text(encoding='utf-8'))
    setup=''.join(previous['cells'][1]['source'])
    sources={n:(root/n).read_text(encoding='utf-8') for n in
             ['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
              'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py',
              'v20_generalize_data.py','v20_generalize.py']}
    intro='''# Nebula V20 — use the question, context and updated facts

Import as a separate Kaggle notebook. Enable **Internet**, a **GPU**, and **NEBULA_HF_TOKEN**, then **Run all**.
End the old GPU session after its confirmed save before starting this one.

## Starting point and size

This continues your **saved V19 checkpoint after 1,200 tutor updates**, pinned at revision
`8ad6fefab9ed4c20ded8d650150825630058510a`. It retains the ~100M model and its byte tokenizer.
We are keeping size fixed while testing whether varied practice transfers better. Jumping to 250M would change
the architecture/compute budget and cannot simply load all these weights unchanged. We have not established a capacity bottleneck.
Original V19 and V18 weights/manifests remain protected. No random model restart or website update.

## Practice changes

- One profile supports different name/color/code/location questions. Field order and query order vary independently.
- Paired multi-turn questions use the same facts, so answering every query with a name cannot succeed.
- Explicit copying practice uses many arbitrary labels and generated names, rather than a tiny name/color list.
- Two-person examples test which person owns which color. Update dialogues retain a name while changing a color.
- Instruction examples contrast selecting first/second/third items. Arithmetic contrasts sum/first operand/second operand.
- Meanings are practiced in both directions; short writing/revision dialogues preserve facts while changing wording.

There are thousands of original synthetic practice examples, not externally reviewed natural conversations.
They are useful diagnostics, not a substitute for broad language learning. No teacher API calls or new upstream downloads.

**70% of optimizer updates** are tutor practice; **30%** retain existing general-language practice.
Within tutor practice, sampling chooses **80% new curriculum / 20% V19 replay** on average.
New-practice sampling emphasizes copying during the first 200 updates, then shifts toward binding, updates and instructions.
These are update/example sampling proportions, not byte proportions. Counters report actual supervised targets and family usage.
Raw practice keeps the earlier obvious-mojibake rejection checks; the existing corpus is not rewritten.

## Measurement

The fixed baseline is V19 itself. A **fresh 96-case benchmark** checks copying, new values, new wording,
two-person binding, updated facts, instruction selection, held-out arithmetic pairs and meaning transfer.
New benchmark values/prompts are held out of V20 synthetic practice; historical public-data exposure is unknown.
The benchmark is saved publicly for inspection, so later independent claims need new tests.

Strict full-answer checks remain. Code-copy tests also require exact character case and whitespace.
An additional conservative content check recognizes only exact values or a small set
of complete sentence forms appropriate to the requested field. Mere keyword containment never passes.
Unknown prose remains pending human review. The content score is a limited parser, not a semantic judge or intelligence score.
Open replies and raw completions remain visible; mixed held-out loss checks preservation of broader language.
A >10% mixed-loss increase is flagged, without silent rollback or automatic promotion.

## Budget and resume

Default: **1,600 additional updates**, peak learning rate **1.5e-5**, 60-update warmup, saves every 100 updates.
A fresh optimizer starts this changed curriculum; resuming V20 restores its optimizer/scaler.
Evaluation runs at baseline, every 400 updates and final; full open/raw probes run at baseline/final.
The training loop is bounded to three hours per session; setup, probes and uploads add time.
One GPU is used even with T4 x2. T4 uses native FP16 AMP and a scaler. Host RAM of 16 GB or more is recommended.

Data/checkpoints/reports stay in RAM and save directly to the PUBLIC repository
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v20-generalize/**.
Only notebook, Python code and packages use local disk. No local dataset/checkpoint fallback, Google Drive or ZIP.
The raw corpus is read from its original pinned V18 revision; it is not duplicated into this run.
Generic storage confirmation lines may say `v18PublicBackupConfirmed`; V20 progress uses additional updates.

Wait for **v20CheckpointConfirmed** before closing. Interrupt once for a graceful save.
Run this identical notebook and configuration again to resume; completed runs display their saved comparison.
Changed settings/code require a new OUTPUT_RUN. Public storage/history and GPU quotas still apply.
Abrupt shutdown can lose RAM progress since the last confirmed save. No automatic model release to users.
'''
    config='''OUTPUT_RUN='nebula-v20-generalize'
CONFIG={
    'sourceRepo':'iiidevv/nebula-raw-training',
    'sourceRun':'nebula-v19-tutor',
    'sourceRevision':'8ad6fefab9ed4c20ded8d650150825630058510a',
    'expectedSourceUpdates':1200,
    'rawCorpusRun':'nebula-v18-raw-1gb',
    'rawCorpusRevision':'e167fff3bb27c36c25460fcd4c61915a5b7016ed',
    'updates':1600,
    'seed':200221,
    'learningRate':0.000015,
    'warmup':60,
    'batch':8,
    'microbatch':1,
    'saveEvery':100,
    'evaluateEvery':400,
    'maxSessionHours':3,
}
'''
    execute='sources='+repr(sources)+'''
import importlib
code_root=Path.cwd()/'nebula-v20-generalize-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v20_generalize import run_tutor
comparison=run_tutor(OUTPUT_RUN,CONFIG)
if 'baseline' in comparison and 'final' in comparison:
    from IPython.display import display,Markdown
    import pandas as pd
    display(pd.DataFrame([{'stage':stage,'mixedLoss':comparison[stage]['heldoutMixed']['loss'],
          'tutorLoss':comparison[stage]['heldoutTutor']['loss'],
          'strictCorrect':comparison[stage]['exactCorrect'],'cases':comparison[stage]['exactCases'],
          'contentVerifiedCorrect':comparison[stage]['contentVerifiedCorrect'],
          'contentPendingReview':comparison[stage]['contentPendingReview']}
          for stage in ['baseline','final']]))
    for stage in ['baseline','final']:
        display(Markdown('## '+stage.title()))
        display(pd.DataFrame.from_dict(comparison[stage]['byAxis'],orient='index'))
        for row in comparison[stage]['exactAnswers']:
            print(row['axis'],'EXPECTED:',row['expected'],'REPLY:',row['reply'],
                  'STRICT:',row['exactCorrect'],'CONTENT:',row['contentCheck'])
        for row in comparison[stage].get('generation',{}).get('answers',[]):
            print(row['kind'],row['mode'],'PROMPT:',row['prompt'])
            print('REPLY:',row['reply'])
    print({'mixedLossRegressionFlag':comparison['mixedLossRegressionFlag'],'publicWebsiteUpdated':False})
else:
    print('Session paused. Run all again with identical settings to continue from the confirmed V20 checkpoint.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell={'id':'v20-generalize-'+str(i),'cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':previous['metadata'],'cells':cells}
    path=root/'Nebula_Kaggle_V20_Generalize.ipynb';path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
