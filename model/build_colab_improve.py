"""Build one uploadable Colab launcher; existing checkpoints stay untouched."""
import ast
from pathlib import Path

root=Path(__file__).resolve().parent

def build():
    names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py',
           'public_data.py','train_public.py','evaluate.py','improve_training.py']
    sources={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    launcher='''"""Upload into /content, then run %run /content/Nebula_Improve_Colab.py."""
from pathlib import Path
import json,shutil,sys
import torch
if not torch.cuda.is_available():
    raise RuntimeError("Select a GPU runtime first. This needs the existing restored Colab data and checkpoint.")
project=Path('/content/nebula_improved/api')
project.mkdir(parents=True,exist_ok=True)
baseline=project/'model/checkpoints/source-before-improvement.pt'
if not baseline.exists():
    candidates=[]
    for source in Path('/content/nebula_resume').glob('*/api'):
        best=source/'model/checkpoints/nebula-cpu-large-chat.best.pt'
        if best.exists():
            value=torch.load(best,map_location='cpu',weights_only=True)
            if value.get('format')==1:
                candidates.append((value.get('metadata',{}).get('steps',0),source,best))
    if not candidates:
        raise FileNotFoundError('Your restored Nebula Colab project was not found. Restore your transfer and latest trained checkpoint first.')
    steps,original,checkpoint=max(candidates,key=lambda item:item[0])
    for name in ['model/data/public-approved.jsonl','model/data/conversations-approved.jsonl',
                 'model/data/conversations-teacher-accepted.jsonl','model/data/gemini-accepted.jsonl',
                 'model/data/public-sources.json','model/seed.jsonl','model/DATA_SOURCES.md','nebula-rules.json']:
        source=original/name
        if source.exists():
            target=project/name; target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists(): shutil.copy2(source,target)
    baseline.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(checkpoint,baseline)
    print({'preservedBaselineSteps':steps,'originalCheckpointsUntouched':True},flush=True)
'''
    launcher+='sources='+repr(sources)+'\n'
    launcher+='''for name,content in sources.items():
    target=project/name; target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
# A previous launcher may have imported older modules in the same runtime.
for module in ['nebula','train','dataflow','teacher_http','rules','public_data','train_public','evaluate','improve_training']:
    sys.modules.pop(module,None)
from improve_training import main
print({'GPU':torch.cuda.get_device_name(0),'batch':16,'languageSteps':6000,'chatSteps':3000},flush=True)
main(['--project',str(project),'--resume',str(baseline)])
print('Saved checkpoints: /content/nebula_improved/api/model/checkpoints',flush=True)
from google.colab import files
for stage in ['chat','language']:
    latest=project/f'model/checkpoints/improved-{stage}.pt'
    if latest.exists():
        best=latest.with_suffix('.best.pt')
        if best.exists(): files.download(str(best))
        files.download(str(latest))
        break
'''
    ast.parse(launcher)
    target=root/'Nebula_Improve_Colab.py'; target.write_text(launcher,encoding='utf-8')
    print(target)
    return target

if __name__=='__main__': build()
