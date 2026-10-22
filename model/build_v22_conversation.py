"""Self-contained continuation notebook; data/checkpoints remain RAM to HF."""
import ast
import json
from pathlib import Path
from v22_conversation import DEFAULT


def build():
    root=Path(__file__).parent
    previous=json.loads((root/'Nebula_Kaggle_V21_Curriculum.ipynb').read_text(encoding='utf-8'))
    names=['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py',
           'v18_decode_probe.py','v18_foundation_control.py','v19_tutor_data.py',
           'v20_generalize_data.py','v21_curriculum_data.py','v22_conversation_data.py','v22_conversation.py']
    sources={name:(root/name).read_text(encoding='utf-8') for name in names}
    intro='''# Nebula V22 — answer directly and continue the conversation

Import as a new Kaggle notebook. Enable **Internet**, **GPU**, and **NEBULA_HF_TOKEN**, then **Run all**.
End the old session after its confirmed checkpoint before starting this one.

## Continues V21

Loads the saved V21 2,400-update checkpoint from revision
`47cba3a6b8af6554af78c986900c7936eac50062`, not a random restart or V19 rollback.
The architecture remains 100,219,392 parameters with the same byte tokenizer.
V19, V20 and V21 stay intact. No teacher API calls and no website deployment.

## One longer training block

**4,000 additional updates**. A fresh optimizer starts this changed curriculum at peak learning rate
1.5e-5 with 60 warmup updates and cosine decay. Resuming V22 restores its optimizer and scaler.
70% of optimizer updates train assistant responses; 30% replay existing raw language.
Within tutor examples, 15% replay earlier synthetic practice and 85% use new lessons.
The new-lesson sampling proportions are:

* 45% complete short dialogues: beginner plans, constraints, writing/revisions, event planning and follow-up questions.
* 30% direct answers versus acknowledgments: identical facts with a question require an answer; statements alone can be acknowledged.
* 20% two-person fact ownership, with both people queried and the order shuffled.
* 5% arithmetic sums, without operand-copy follow-ups.

These are sampling proportions, not token proportions. Actual target and family counters are logged.
Lessons are original template-generated examples, with varied user-provided facts and topics. They are not
new natural public-chat downloads or externally reviewed dialogues. Generalization remains uncertain.
Every assistant turn is supervised, including genuine acknowledgments; user/system targets are masked.

## Backups, not repeated benchmarks

Evaluation runs **only at baseline and final completion**. The comparison includes 96 synthetic cases,
held-out losses and visible raw/chat replies, including additional requests with new combinations.
Familiar examples can be memorized; no automatic quality approval, rollback or public release occurs.
Synthetic benchmark prompts and held-out values are excluded from the new practice; older public exposure is unknown.
The conservative content parser leaves unknown prose pending human review.

Checkpoint every **100 updates**, directly from RAM to public Hugging Face storage.
Default training-loop time limit is **four hours per session**; setup, probes and backups add time.
If it pauses before 4,000 updates, run the identical notebook/config again to continue.
Completed runs display the saved comparison. One GPU is used even on T4 x2; T4 uses FP16 AMP with a scaler.
GPU and storage quotas still apply. Interrupt once for a graceful save; abrupt loss can lose unsaved RAM progress.

## Storage

The existing pinned V18 corpus is read without copying it into a new dataset.
New lessons, checkpoints and reports upload to the PUBLIC repository
https://huggingface.co/iiidevv/nebula-raw-training under **experiments/nebula-v22-conversation/**.
No private user chats are imported. Data/checkpoints/reports do not use local files or Google Drive.
Only notebook/code/packages use disk. No ZIP or local checkpoint fallback.

Wait for **v22CheckpointConfirmed** before closing. Generic backup lines may still say v18PublicBackupConfirmed.
Do not run two sessions against the same OUTPUT_RUN; changed code/configuration requires a new run name.
'''
    setup=''.join(previous['cells'][1]['source'])
    config="OUTPUT_RUN='nebula-v22-conversation'\nCONFIG="+repr(DEFAULT)+'\n'
    tail='import importlib'+''.join(previous['cells'][3]['source']).split('import importlib',1)[1]
    tail=tail.replace('from v21_curriculum import','from v22_conversation import').replace('nebula-v21-curriculum-code','nebula-v22-conversation-code').replace('V21 checkpoint','V22 checkpoint')
    execute='sources='+repr(sources)+'\n'+tail
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v22-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for source in sources.values():ast.parse(source)
    path=root/'Nebula_Kaggle_V22_Conversation.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=previous['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
