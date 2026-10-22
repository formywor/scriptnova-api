"""Build a self-contained Kaggle notebook without embedding credentials or datasets."""
import ast
import json
from pathlib import Path
from v21_curriculum import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V20_Generalize.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
           'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py',
           'v20_generalize_data.py','v21_curriculum_data.py','v21_curriculum.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V21 — learn the question, then the conversation

Enable Kaggle **Internet**, **GPU**, and secret **NEBULA_HF_TOKEN**, then **Run all**.
Finish or stop the old session after its confirmed backup before starting this notebook.

Starts from protected **V19 after 1,200 additional updates**, at pinned revision
`8ad6fefab9ed4c20ded8d650150825630058510a`. Size remains **100M**; byte tokenizer unchanged.
V19/V20 checkpoints stay intact. No teacher API calls or automatic website update.

## Training, with fewer evaluations

**2,400 additional updates**: 70% tutor updates, 30% existing general-language updates.
Within tutor examples, 15% replay V19 practice and 85% use the new curriculum.
New-practice proportions change by stage, rather than interpreting the entire dataset as one uniform mix:

* Updates 0–399 emphasize single facts and copying, alongside conversation.
* Updates 400–999 emphasize contrasting questions about the same facts.
* Updates 1,000–2,399 increase two-person ownership and updated-fact practice.

All stages retain ordinary conversation, language replay and earlier skills.
Item order is shuffled so selecting the first item cannot solve every instruction.
Arithmetic practice supervises sums, without follow-ups rewarding operand copying.
Updated-fact practice uses neutral acknowledgments and independently asks about both retained and changed facts.
These are original synthetic exercises, not externally verified natural conversations.

**Evaluation only at baseline and final completion.** No periodic generation benchmarks, automatic rollback,
or automatic early rejection. Each comparison includes the same fresh 96-case benchmark, held-out language
loss and actual replies. Lower loss and narrow task scores do not certify conversational quality.
Held-out synthetic values may still have appeared in historical public text.
Code identifiers use strict character-case/whitespace checks; uncertain prose remains pending review.

Backups still run **every 100 updates** without generating benchmark answers.
Peak learning rate 1.5e-5, warmup 60; fresh optimizer for V21, exact optimizer/scaler restore on resume.
One GPU is used, including on T4 x2. T4 uses FP16 AMP with a scaler.
Training stops after three hours per session; setup, uploads and baseline/final probes add time.
If paused before 2,400, run this identical notebook/configuration again to continue.

## Saving

Data, model checkpoints and reports stay in RAM and upload directly to the public repository
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v21-curriculum/**.
The raw corpus is read from pinned V18 storage, not copied into a new dataset.
Only notebook/code/packages use local disk. No local dataset/checkpoint fallback, ZIP or Google Drive.
Public storage means uploaded artifacts are public. No private user chats are imported by this experiment.

Wait for **v21CheckpointConfirmed** before closing. Interrupt once for a graceful checkpoint.
Abrupt runtime loss may lose changes after the last confirmed save. GPU/storage quotas still apply.
Do not run two workers against the same OUTPUT_RUN. Changes to code/settings require a new run name.
Completed runs display their saved result, rather than training again.
'''
    setup=''.join(previous['cells'][1]['source'])
    config="OUTPUT_RUN='nebula-v21-curriculum'\nCONFIG="+repr(DEFAULT)+'\n'
    old_execute=''.join(previous['cells'][3]['source'])
    tail='import importlib'+old_execute.split('import importlib',1)[1]
    tail=tail.replace('from v20_generalize import','from v21_curriculum import').replace('nebula-v20-generalize-code','nebula-v21-curriculum-code').replace('V20 checkpoint','V21 checkpoint')
    execute='sources='+repr(sources)+'\n'+tail
    cells=[]
    for index,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v21-'+str(index),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V21_Curriculum.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
