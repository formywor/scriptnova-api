"""Self-contained Kaggle inference notebook; keeps the training engine unchanged."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).parent
    old=json.loads((root/'Nebula_Kaggle_Raw_Training.ipynb').read_text(encoding='utf-8'))
    setup=''.join(old['cells'][1]['source'])
    sources={name:(root/name).read_text(encoding='utf-8') for name in
        ['nebula.py','v18_stream.py','v8_store.py','v4_store.py','research_client.py','v18_decode_probe.py']}
    intro='''# Nebula — compare decoding before more training

Import into Kaggle, enable Internet and a GPU, and enable the `NEBULA_HF_TOKEN` secret. Select **Run all**.
This notebook tests the **saved step-10,102 checkpoint** at its fixed Hugging Face revision.
It performs inference only: it does not prepare data, train, update optimizer state, or change the training manifest.
Do not replace your training notebook with this one; keep it for continuing training afterward.

Compares greedy decoding with temperature 0.7 / top-p 0.9 and temperature 1.0 / top-p 0.95.
Each sampled setting uses seeds 17 and 43. All settings get identical prompts, FP32 weights and a 128-byte generation budget.
There are **40 generations**: three raw prefixes and five chat prompts, each tested five ways.
No byte repetition penalty is applied. EOS/context stopping still applies. Raw and chat results remain separate.
Replies print as they finish, then a table shows repetition and empty replies. Read the answers for relevance and grammar;
lower repetition alone does not mean the model improved. These few probes do not certify general ability.

Checkpoint reads and report uploads use RAM. Only code, notebook and packages use local disk.
The JSON report saves to a unique `decode-reports/` path in the public model repository, with a link printed on completion.
No checkpoint or training state is overwritten. You can set SAVE_REPORT=False for a read-only remote test.
One GPU is used; the second allocated T4 is idle. This test can take several minutes; stop the GPU session afterward.
'''
    config='''REPO='iiidevv/nebula-raw-training'
RUN_NAME='nebula-v18-raw-1gb'
CHECKPOINT_REVISION='e167fff3bb27c36c25460fcd4c61915a5b7016ed'
EXPECTED_UPDATES=10102
SAVE_REPORT=True
MAX_GENERATED_BYTES=128
'''
    execute='sources='+repr(sources)+'''
import importlib
code_root=Path.cwd()/'nebula-decode-probe-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v18_decode_probe import run_probe
report=run_probe(REPO,RUN_NAME,CHECKPOINT_REVISION,EXPECTED_UPDATES,SAVE_REPORT,MAX_GENERATED_BYTES)
from IPython.display import display,Markdown
import pandas as pd
display(pd.DataFrame(report['summary']))
for kind in ['raw','chat']:
    display(Markdown('## '+kind.title()+' replies'))
    display(pd.DataFrame([{k:a[k] for k in ['prompt','mode','seed','reply','repeatedTrigramFraction','stopReason']}
                          for a in report['answers'] if a['kind']==kind]))
print({'comparisonFinished':True,'trainingStarted':False,'qualityApproved':False})
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',intro),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='decode-probe-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    notebook=dict(nbformat=4,nbformat_minor=5,metadata=old['metadata'],cells=cells)
    path=root/'Nebula_Kaggle_Decoding_Test.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
