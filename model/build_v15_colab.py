"""Build a Colab-native V15 notebook using Colab Secrets and the same private run."""
import ast,json
from pathlib import Path
from build_v15_notebook import build as kaggle_build

def build():
    source=kaggle_build();notebook=json.loads(source.read_text(encoding='utf-8'))
    intro=''.join(notebook['cells'][0]['source'])
    intro=intro.replace('# Nebula V15 - complete public chats, no semantic screening','# Nebula V15 for Google Colab - complete public chats')
    intro=intro.replace('Import into a PRIVATE Kaggle notebook, enable Internet and your existing NEBULA_HF_TOKEN secret.','Upload this notebook into Google Colab. In the left sidebar Secrets panel (key icon), add NEBULA_HF_TOKEN and enable notebook access. Select Runtime > Change runtime type > T4 GPU.')
    intro=intro.replace('With GPU available, Run all starts a bounded comparison. If your GPU quota is exhausted, set PREPARE_ONLY=True and use CPU to acquire/back up data now; later set it False and enable T4 x2 to train.','Run all starts the bounded comparison on one Colab GPU. If GPU is unavailable, set PREPARE_ONLY=True to acquire and back up public data on CPU, then set it False when a GPU is available.')
    intro+='\nThe same V15 Hugging Face snapshot is used on Kaggle and Colab. Stop the Kaggle worker before running Colab. Downloaded/prepared data and completed training chunks are reused. Compatible V15 checkpoints can resume with one or two GPUs while preserving Adam state, global batch, data, seed and schedule. A change in precision or other training settings still requires attention; it is not silently ignored. Colab local files are temporary. Hugging Face holds confirmed backups; Google Drive is not used.\n'
    notebook['cells'][0]['source']=intro.splitlines(True)
    setup=''.join(notebook['cells'][1]['source']).replace('from kaggle_secrets import UserSecretsClient','from google.colab import userdata')
    setup=setup.replace("UserSecretsClient().get_secret('NEBULA_HF_TOKEN')","userdata.get('NEBULA_HF_TOKEN')")
    setup=setup.replace('Add and enable Kaggle secret NEBULA_HF_TOKEN.','Add NEBULA_HF_TOKEN in Colab Secrets and enable notebook access.')
    setup=setup.replace('/kaggle/working/nebula-v15-full-chats/api','/content/nebula-v15-full-chats/api')
    setup=setup.replace("os.environ['NEBULA_HF_TOKEN']=token","if not token or not token.strip():raise RuntimeError('NEBULA_HF_TOKEN is empty.')\nos.environ['NEBULA_HF_TOKEN']=token")
    notebook['cells'][1]['source']=setup.splitlines(True)
    ending=''.join(notebook['cells'][3]['source']).replace('/kaggle/working/','/content/')
    notebook['cells'][3]['source']=(ending+'\nUse Runtime > Run all to start. No Drive mount, local training-data upload, Gemini key or Groq key is needed.').splitlines(True)
    notebook['metadata']['colab']={'name':'Nebula_Colab_V15_Full_Chats.ipynb'};notebook['metadata']['accelerator']='GPU'
    for i,cell in enumerate(notebook['cells']):
        cell['id']=f'v15-colab-{i:02d}'
        if cell['cell_type']=='code':ast.parse(''.join(cell['source']));cell.update(outputs=[],execution_count=None)
    target=Path(__file__).resolve().parent/'Nebula_Colab_V15_Full_Chats.ipynb';target.write_text(json.dumps(notebook,indent=1),encoding='utf-8');return target

if __name__=='__main__':print(build())
