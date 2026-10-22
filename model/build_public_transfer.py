"""Self-contained CPU-only migration notebook; no dependency on old cell variables."""
import ast
import json
from pathlib import Path


def build():
    root=Path(__file__).resolve().parent
    base=json.loads((root/'Nebula_Colab_V17_Training_Lab.ipynb').read_text(encoding='utf-8'))
    code=next(''.join(c['source']) for c in base['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    sources=ast.literal_eval(ast.parse(code).body[0].value)
    sources['model/public_raw_transfer.py']=(root/'public_raw_transfer.py').read_text(encoding='utf-8')
    intro='''# Nebula — transfer the public raw corpus

This notebook creates **https://huggingface.co/datasets/iiidevv/nebula-public-data** using your existing Colab secret.
It restores the original `iiidevv/nebula-research` model repository to **private** if necessary.
It publishes only validated public-source packed data, a freshly rebuilt attribution/index database,
preparation metadata, upstream dataset cards and a README. It does not upload model weights,
account chats, reviews, API files, credentials or the old repository history. It does not delete anything.

**In the current Colab runtime:** upload this notebook using File > Upload notebook.
If prompted, connect to the existing runtime to retain its newer local preparation.
Enable `NEBULA_HF_TOKEN` in the Secrets panel, then Runtime > Run all.
No GPU is needed. Switching the runtime type or deleting a runtime may discard its local files;
if the local files are gone, the last confirmed online raw snapshot is restored instead.

The notebook first audits and saves the existing raw corpus, verifies the uploaded data through anonymous
downloads, then continues the remaining public-data preparation on CPU (up to one hour).
Look for **publicCorpusBackupConfirmed: true**. Transfer progress bars alone do not establish a successful commit.
Run all again resumes the newest consistent local/public snapshot. Stop other data-preparation workers first.

Public documents retain their upstream licenses and can themselves contain personal information;
this checks the known corpus format and excludes private Nebula files, but is not a full privacy or factual audit.
Public storage is best-effort. No training or website deployment starts.
Copying data does not free private storage: older checkpoint/history cleanup remains a separate task.
'''
    setup='''import os, sys, subprocess
from pathlib import Path
from google.colab import userdata
subprocess.run([sys.executable,'-m','pip','install','-q',
    'huggingface_hub>=0.34,<2','datasets>=3.6,<5','numpy>=1.26,<3','requests>=2.32,<3','pyarrow>=18,<24'],check=True)
try:
    token=userdata.get('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Enable NEBULA_HF_TOKEN for this notebook in Colab Secrets.') from None
if not token:raise RuntimeError('NEBULA_HF_TOKEN is empty.')
os.environ['NEBULA_HF_TOKEN']=token
os.environ['HF_TOKEN']=token
SOURCE_REPO='iiidevv/nebula-research'
PUBLIC_REPO='iiidevv/nebula-public-data'
PROJECT=Path('/content/nebula-v17-raw-prose/api')
'''
    # Write dependencies to a separate code directory: do not change the surviving run's engine.
    run='sources='+repr(sources)+'''
import importlib
code_root=Path('/content/nebula-public-transfer-code')
for name,value in sources.items():
    path=code_root/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(value,encoding='utf-8')
sys.path.insert(0,str(code_root/'model'))
for name in [Path(n).stem for n in sources if n.endswith('.py')]:
    sys.modules.pop(name,None)
importlib.invalidate_caches()
from public_raw_transfer import main
try:
    main(PROJECT,source_repo=SOURCE_REPO,public_repo=PUBLIC_REPO,hours=1)
except Exception as error:
    from v8_store import safe_server_detail
    print({'transferFinished':False,'errorType':type(error).__name__,
           'serverDetail':safe_server_detail(error),'localFilesRetained':True})
    if isinstance(error,(ValueError,RuntimeError)):
        print(str(error)[:500])
    raise RuntimeError('Transfer stopped. Keep local files and inspect the explanation above; no deletion was performed.') from None
'''
    cells=[]
    for i,(kind,text) in enumerate([('markdown',intro),('code',setup),('code',run)]):
        item={'cell_type':kind,'id':f'public-transfer-{i}','metadata':{},'source':text.splitlines(True)}
        if kind=='code':ast.parse(text);item.update(execution_count=None,outputs=[])
        cells.append(item)
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'colab':{'name':'Nebula_Public_Data_Transfer.ipynb'},
              'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'cells':cells}
    path=root/'Nebula_Public_Data_Transfer.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__=='__main__':print(build())
