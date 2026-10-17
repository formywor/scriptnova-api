"""Build a self-contained notebook from an explicit allowlist of non-secret source files."""
import ast
import json
from pathlib import Path

root=Path(__file__).resolve().parent
names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py','public_data.py','train_public.py','evaluate.py','export_node.py','DATA_SOURCES.md']
bundle={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
bundle['nebula-rules.json']=(root.parent/'nebula-rules.json').read_text(encoding='utf-8')
cells=[]
def markdown(text): cells.append({'cell_type':'markdown','metadata':{},'source':text.splitlines(True)})
def code(text):
    ast.parse(text)
    cells.append({'cell_type':'code','metadata':{},'source':text.splitlines(True),'execution_count':None,'outputs':[]})
markdown('# Nebula: larger owned model on a Colab GPU\n\nIn Colab, select **Runtime → Change runtime type → GPU**. Free GPU access is limited and not guaranteed. This trains randomly initialized Nebula weights on a bounded public dataset; no teacher keys, private chats, pretrained weights, or paid service are used. This is an experiment, not a promise of useful chat quality.\n\nRun cells in order. Download checkpoints before the Colab session ends. Nothing here deploys to Vercel. Sources and license links are in `model/DATA_SOURCES.md`.')
code('from pathlib import Path\nimport json, subprocess, sys\nimport torch\nproject=Path("/content/nebula/api")\nproject.mkdir(parents=True,exist_ok=True)\nsources='+repr(bundle)+'\nfor name,content in sources.items():\n    target=project/name\n    target.parent.mkdir(parents=True,exist_ok=True)\n    target.write_text(content,encoding="utf-8")\nprint({"cudaAvailable":torch.cuda.is_available(),"device":torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"})\nif not torch.cuda.is_available():\n    raise RuntimeError("Select a GPU runtime before training. GPU availability is controlled by Colab.")\n')
markdown('## Download public examples\n\nThe importer caches pages and keeps source information. Public examples can contain errors. It does not use your Gemini or Groq account.')
code('subprocess.run([sys.executable,"model/public_data.py"],cwd=project,check=True)\n')
markdown('## Stage 1: learn language patterns\n\nThe default is about five million parameters. Stop a cell to interrupt training; the trainer saves periodically and on a normal keyboard interrupt. A forced runtime shutdown can lose work since the last save. Download the language checkpoint after this stage. If a session restarts, re-upload its checkpoint and use `--resume` to resume its weights.\n\nThe larger `gpu` preset is also available, but changing architecture requires a new training run.')
code('subprocess.run([sys.executable,"model/train_public.py","--preset","cpu-large","--stage","language","--steps","2000","--device","cuda","--batch","4","--max-validation","128"],cwd=project,check=True)\n')
code('from google.colab import files\nfiles.download(str(project/"model/checkpoints/nebula-cpu-large-language.best.pt"))\n')
markdown('## Stage 2: train assistant replies\n\nThis starts from the language checkpoint. The same original conversations stay in the held-out partition in both stages. Validation losses from different objectives are not directly comparable.')
code('subprocess.run([sys.executable,"model/train_public.py","--preset","cpu-large","--stage","chat","--steps","1000","--device","cuda","--batch","4","--max-validation","128"],cwd=project,check=True)\n')
markdown('## Inspect replies before deployment\n\nLow validation loss does not establish chat quality. Do not replace live weights unless replies and unseen conversations pass your checks.')
code('subprocess.run([sys.executable,"model/evaluate.py","--checkpoint","model/checkpoints/nebula-cpu-large-chat.best.pt"],cwd=project,check=True)\n')
code('files.download(str(project/"model/checkpoints/nebula-cpu-large-chat.best.pt"))\n')
notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'colab':{'name':'Nebula_GPU_Training.ipynb'},'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'accelerator':'GPU'},'cells':cells}
path=root/'Nebula_GPU_Training.ipynb'
path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
print(json.dumps({'notebook':str(path),'bytes':path.stat().st_size,'embeddedSourceFiles':len(bundle)}))
