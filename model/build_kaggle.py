"""Build a self-contained Kaggle migration and optional training notebook."""
import ast
import json
from pathlib import Path

root=Path(__file__).resolve().parent

def build():
    names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py','evaluate.py','kaggle_migrate.py']
    bundle={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def markdown(text): cells.append({'cell_type':'markdown','id':f'nebula-{len(cells):02d}','metadata':{},'source':text.splitlines(True)})
    def code(text):
        ast.parse(text)
        cells.append({'cell_type':'code','id':f'nebula-{len(cells):02d}','metadata':{},'source':text.splitlines(True),'execution_count':None,'outputs':[]})
    markdown('''# Move Nebula V3 to Kaggle

Import this notebook, then attach a **private Dataset** with these three existing files:

- `Nebula_V3_Data.pt`
- `v3-chat.pt` (latest: 33,012 saved steps)
- `v3-chat.best.pt` (best validation: 31,012 saved steps)

The first run verifies and restores the files. Training is **off by default**. No teacher keys, Internet downloads, Google Drive mount, or pretrained model are required.

Use **Save Version → Save & Run All** to execute a saved run and retain its completed output. Files live under `/kaggle/working/nebula/`. Saving checkpoints during an interactive session alone is not a durable backup. Keep downloaded copies too. GPU availability and session limits still apply.
''')
    code('''from pathlib import Path
import json,sys
import torch

RUN_TRAINING = False  # First migrate and save outputs. Enable only for a deliberate new experiment.
RUN_EVALUATION = False  # Optional: print test replies using the best checkpoint.
ADDITIONAL_STEPS = 1000
MAX_TRAINING_SECONDS = 1800
project = Path('/kaggle/working/nebula/api')
project.mkdir(parents=True,exist_ok=True)
torch.set_num_threads(2)
print({'GPU':torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
       'project':str(project),'trainingEnabled':RUN_TRAINING})
''')
    code('sources='+repr(bundle)+'''
for name,content in sources.items():
    target=project/name; target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for module in ['nebula','train','dataflow','teacher_http','rules','evaluate','kaggle_migrate']:
    sys.modules.pop(module,None)
from kaggle_migrate import migrate
report=migrate(Path('/kaggle/input'),project)
''')
    markdown('''## Optional bounded training

Leave `RUN_TRAINING=False` for the migration run. The latest checkpoint contains optimizer and sampler state. The saved V3 run had already stopped improving, so more repetitions are not a guaranteed quality upgrade. This optional run preserves the existing best model unless validation improves, saves every 200 updates, and stops after 1,000 additional updates, 30 minutes, or stalled validation. Only one GPU is used; selecting T4 ×2 does not automatically double speed.

To continue a future saved run, attach this notebook's saved output as an additional input. The restore cell chooses the latest matching checkpoint and the best matching validation checkpoint. Also retain the original private Dataset as input.
''')
    code('''if RUN_TRAINING:
    if not torch.cuda.is_available():
        raise RuntimeError('Enable a GPU accelerator in Kaggle settings before training.')
    from types import SimpleNamespace
    from train import train
    checkpoint=project/'model/checkpoints/v3-chat.pt'
    result=train(SimpleNamespace(
        data=project/'model/data/v3-chat.jsonl',output=checkpoint,resume=checkpoint,
        snapshot=None,preset='cpu-large',steps=ADDITIONAL_STEPS,batch=16,threads=2,
        seed=42,lr=.00005,continuous=False,save_every=200,patience=10,
        device='cuda',amp=True,objective='assistant',grouped_split=True,bucketed=True,
        max_validation=256,save_training_state=True,max_seconds=MAX_TRAINING_SECONDS))
    print(result)
else:
    print('Migration only: existing weights and optimizer state have been preserved.')
''')
    code('''if RUN_EVALUATION:
    import subprocess
    result=subprocess.run([sys.executable,str(project/'model/evaluate.py'),
        '--checkpoint',str(project/'model/checkpoints/v3-chat.best.pt')],
        capture_output=True,text=True,check=True)
    print(result.stdout)
    print(result.stderr)
''')
    markdown('''## Confirm and retain the output

After **Save & Run All** completes, open that version's **Output** and confirm the following files exist. You can download them or attach this saved notebook output to another notebook. Do not assume unsaved interactive files survive a reset. The original uploaded Dataset is separate from the temporary working directory.
''')
    code('''for filename in ['model/checkpoints/v3-chat.pt','model/checkpoints/v3-chat.best.pt',
                 'Nebula_V3_Data.pt','migration-report.json']:
    path=project/filename
    if not path.is_file(): raise FileNotFoundError(path)
    print(str(path),f'{path.stat().st_size/1_000_000:.1f} MB')
print('Finished. Confirm these files in the saved notebook version Output.')
''')
    notebook={'nbformat':4,'nbformat_minor':5,
        'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},
                    'language_info':{'name':'python'}},'cells':cells}
    path=root/'Nebula_Kaggle.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    print(path)
    return path

if __name__=='__main__': build()
