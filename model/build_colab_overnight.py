"""Build a self-contained V3 launcher for the user's current Colab runtime."""
import ast
from pathlib import Path

root=Path(__file__).resolve().parent

def build():
    names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py','overnight.py','evaluate.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    launcher='''"""Upload into /content and run %run /content/Nebula_Overnight_Colab.py."""
from pathlib import Path
import shutil,sys
import torch
if not torch.cuda.is_available(): raise RuntimeError('Select a GPU runtime first.')
original=Path('/content/nebula_improved/api')
project=Path('/content/nebula_v3/api')
copies={
 'model/checkpoints/improved-language.best.pt':'model/checkpoints/previous-language.best.pt',
 'model/checkpoints/improved-chat.best.pt':'model/checkpoints/previous-chat.best.pt',
 'model/data/stories-approved.jsonl':'model/data/stories-approved.jsonl',
 'model/data/improved-chat.jsonl':'model/data/improved-chat.jsonl',
 'model/data/stories-sources.json':'model/data/stories-sources.json',
 'model/data/public-sources.json':'model/data/public-sources.json',
 'model/DATA_SOURCES.md':'model/DATA_SOURCES.md',
 'nebula-rules.json':'nebula-rules.json',
}
required={'model/checkpoints/improved-language.best.pt','model/checkpoints/improved-chat.best.pt',
          'model/data/stories-approved.jsonl','model/data/improved-chat.jsonl','nebula-rules.json'}
for source_name,target_name in copies.items():
    target=project/target_name
    if target.exists(): continue
    source=original/source_name
    if not source.exists():
        if source_name in required:
            raise FileNotFoundError('The previous Colab training files are missing. Restore your improved checkpoints and datasets before starting V3: '+source_name)
        continue
    target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
print({'GPU':torch.cuda.get_device_name(0),'previousModelsPreserved':True,'project':str(project)},flush=True)
'''
    launcher+='sources='+repr(sources)+'\n'
    launcher+='''for name,content in sources.items():
    target=project/name; target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in ['nebula','train','dataflow','teacher_http','rules','overnight','evaluate']:
    sys.modules.pop(name,None)
from overnight import main
from google.colab import files
main(['--project',str(project),'--hours','8','--batch','16'],
     on_data_ready=lambda path: files.download(str(path)))
for stage in ['chat','language']:
    latest=project/f'model/checkpoints/v3-{stage}.pt'
    if latest.exists():
        best=latest.with_suffix('.best.pt')
        if best.exists(): files.download(str(best))
        files.download(str(latest))
        break
'''
    ast.parse(launcher)
    target=root/'Nebula_Overnight_Colab.py'; target.write_text(launcher,encoding='utf-8')
    print(target)
    return target

if __name__=='__main__': build()
