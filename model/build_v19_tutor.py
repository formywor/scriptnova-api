"""Self-contained Kaggle V19 notebook, with no local dataset/checkpoint storage."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_Raw_Training.ipynb').read_text(encoding='utf-8'))
    setup=''.join(previous['cells'][1]['source'])
    sources={n:(root/n).read_text(encoding='utf-8') for n in
             ['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
              'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py','v19_tutor.py']}
    intro='''# Nebula V19 — varied tutor lessons and general-language practice

Import as a separate Kaggle notebook. Enable **Internet**, a **GPU** and secret **NEBULA_HF_TOKEN**, then **Run all**.
End the old GPU session after its confirmed backup before starting this one.

## What changed after the story experiment

This starts from the protected **V18 step-10,102 model**, not random weights or the story-only experiment.
The architecture and byte tokenizer stay the same. The new objective practices assistant replies to lessons
instead of only predicting stories. The source model and its training manifest are never overwritten.

**70% of optimizer updates** practice original synthetic tutor lessons. **30%** practice existing raw general text.
These are update proportions, not byte proportions: raw windows usually contain more supervised bytes than tutor answers.
Tutor practice samples equally across eight families, preventing the larger template families from dominating:
word meanings and usage; simple explanations; conversation/clarification; context extraction; multi-turn fact updates;
instructions/rewriting; small arithmetic; and applying concepts such as empty/full or hot/cold.
Examples are deterministic, varied, and checked structurally. They are not a comprehensive human-reviewed curriculum.
No teacher API calls or new upstream dataset downloads are needed. No Spanish translation layer or hidden model language.

User/system text and role markers have zero training loss during tutoring. Actual assistant bytes and true EOS are supervised.
Complete lessons are retained; overlong examples cause an error rather than silent truncation.
Full model weights are reused. **A fresh optimizer starts this changed SFT objective**, with a 60-update warmup
and a 3e-5 peak learning rate. Continuing this V19 run restores its optimizer and scaler exactly.
T4 uses native FP16 AMP with a gradient scaler. One GPU is used even if Kaggle allocates two T4s.

Raw practice rejects sampled windows containing obvious garbled-punctuation patterns found in the audit.
It does not rewrite the old corpus or claim all encoding, factual, PII or near-duplicate issues are fixed.

## Evaluation and budget

Default: **1,200 additional updates**, bounded to three hours of training per session; setup/probes/uploads add time.
Saves every 100 updates. Baseline and final evaluations show actual raw completions and open chat replies.
At updates 400 and 800, checks measure mixed held-out loss plus 64 strict short-answer tests.
The same mixed-text validation sample is used throughout. Tutor validation answers are never used in training.
Tests include different wording, values held out of tutor practice, updated facts across turns, instruction following,
arithmetic and meanings. Held out here does not mean guaranteed absent from historical public pretraining.
The benchmark is public for inspection, so future independently claimed results will require fresh tests.

Strict checks require the complete requested answer, not just a matching word inside an incorrect story.
Open replies need human judgment. A >10% rise in mixed held-out loss flags possible regression; it does not silently
roll back training or automatically approve a model. No website update or automatic model promotion.
We will inspect the final comparison rather than assume a lower training loss means a useful chatbot.

## Public saves and resume

Data/checkpoints/reports remain in RAM and save directly to PUBLIC Hugging Face:
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v19-tutor/**.
Only notebook, code and packages use local disk. No local checkpoint/data fallback, Google Drive or ZIP.
Original V18 corpus shards are referenced from their pinned revision, not uploaded again.
The new practice lessons, separate benchmark, counters, model/optimizer/scaler and reports are saved remotely.
16 GB or more host RAM is recommended. Public history consumes storage; GPU quotas still apply.

Wait for **v19CheckpointConfirmed** before closing. Interrupt the running cell once for a graceful save.
Run this identical notebook/settings again to resume; a completed run displays its saved report.
Changed settings/code require a NEW OUTPUT_RUN. Abrupt runtime loss can lose updates after the last confirmed checkpoint.
Generic `v18PublicBackupConfirmed` messages come from the shared storage helper; V19 progress uses additional updates.
'''
    config='''OUTPUT_RUN='nebula-v19-tutor'
CONFIG={
    'sourceRepo':'iiidevv/nebula-raw-training',
    'sourceRun':'nebula-v18-raw-1gb',
    'sourceRevision':'e167fff3bb27c36c25460fcd4c61915a5b7016ed',
    'expectedSourceUpdates':10102,
    'updates':1200,
    'seed':190221,
    'learningRate':0.00003,
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
code_root=Path.cwd()/'nebula-v19-tutor-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v19_tutor import run_tutor
comparison=run_tutor(OUTPUT_RUN,CONFIG)
if 'baseline' in comparison and 'final' in comparison:
    from IPython.display import display,Markdown
    import pandas as pd
    display(pd.DataFrame([{'stage':stage,'mixedLoss':comparison[stage]['heldoutMixed']['loss'],
          'tutorLoss':comparison[stage]['heldoutTutor']['loss'],
          'exactCorrect':comparison[stage]['exactCorrect'],'exactCases':comparison[stage]['exactCases']}
          for stage in ['baseline','final']]))
    for stage in ['baseline','final']:
        display(Markdown('## '+stage.title()))
        display(pd.DataFrame.from_dict(comparison[stage]['byAxis'],orient='index'))
        for row in comparison[stage]['exactAnswers']:
            print(row['axis'],'EXPECTED:',row['expected'],'REPLY:',row['reply'],'PASS:',row['exactCorrect'])
        for row in comparison[stage].get('generation',{}).get('answers',[]):
            print(row['kind'],row['mode'],'PROMPT:',row['prompt'])
            print('REPLY:',row['reply'])
    print({'mixedLossRegressionFlag':comparison['mixedLossRegressionFlag'],'publicWebsiteUpdated':False})
else:
    print('Session paused. Run all again with identical settings to continue from the confirmed V19 checkpoint.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell={'id':'v19-tutor-'+str(i),'cell_type':kind,'metadata':{},'source':source.splitlines(True)}
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':previous['metadata'],'cells':cells}
    path=root/'Nebula_Kaggle_V19_Tutor.ipynb';path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
