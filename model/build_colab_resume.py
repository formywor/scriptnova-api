"""Build direct-upload Colab resume files, without Google Drive."""
import argparse
import ast
import json
from pathlib import Path

root=Path(__file__).resolve().parent

def build(transfer,manifest):
    names=['nebula.py','train.py','dataflow.py','teacher_http.py','rules.py','public_data.py','train_public.py','evaluate.py','export_node.py','colab_transfer.py']
    bundle={'model/'+name:(root/name).read_text(encoding='utf-8') for name in names}
    cells=[]
    def markdown(value): cells.append({'cell_type':'markdown','metadata':{},'source':value.splitlines(True)})
    def code(value):
        ast.parse(value)
        cells.append({'cell_type':'code','metadata':{},'source':value.splitlines(True),'execution_count':None,'outputs':[]})
    stamp=manifest['snapshotId']
    checkpoint=manifest['resumeCheckpoint']
    steps=manifest['checkpoints'][checkpoint]['steps']
    markdown(f'# Resume your existing Nebula model\n\nThis notebook imports your saved model at **{steps:,} steps**, the other saved checkpoints, and your exact current prepared dataset. It does not initialize new model weights.\n\nSelect **Runtime > Change runtime type > GPU**, then run cells in order. Upload the transfer directly from your PC when prompted. No Google Drive mount or API keys are used. The snapshot excludes unsaved updates still running on your PC.\n\nYour legacy checkpoints contain model weights, but no optimizer or sampler state, so those restart while the learned weights remain. Runtime files are temporary: download checkpoints before disconnecting. Nothing here deploys the model or changes your website.')
    code('from pathlib import Path\nimport json, subprocess, sys\nimport torch\nproject=Path("/content/nebula_resume/'+stamp+'/api")\nproject.mkdir(parents=True,exist_ok=True)\nsources='+repr(bundle)+'\nfor name,content in sources.items():\n    target=project/name\n    target.parent.mkdir(parents=True,exist_ok=True)\n    target.write_text(content,encoding="utf-8")\nif not torch.cuda.is_available():\n    raise RuntimeError("Select a GPU runtime, then rerun this cell.")\nprint({"GPU":torch.cuda.get_device_name(0),"project":str(project)})\n')
    markdown('## Upload the transfer and restore saved progress\n\nSelect the Nebula transfer `.pt` file from your PC. It contains your existing weights and exact dataset. Existing healthy runtime checkpoints are preserved when this cell runs again.')
    code('from google.colab import files\nimport os\nos.chdir(project)\ntransfer=project/'+repr(Path(transfer).name)+'\nif not transfer.is_file():\n    files.upload()\nif not transfer.is_file():\n    raise FileNotFoundError("Select the named Nebula transfer .pt file from your PC.")\nsys.path.insert(0,str(project/"model"))\nfrom colab_transfer import restore, valid_checkpoint\nmanifest,preserved=restore(transfer,project)\nresume_checkpoint=project/manifest["resumeCheckpoint"]\nconfig,checkpoint_info=valid_checkpoint(resume_checkpoint)\nprint({"resumeCheckpoint":str(resume_checkpoint),"savedSteps":checkpoint_info.get("steps"),"stage":manifest["resumeStage"],"existingCheckpointsPreserved":preserved})\n')
    markdown('## Continue training on the GPU\n\nThe default runs up to 1,000 additional updates, with early stopping if validation stops improving. Checkpoints are saved every 100 steps to runtime storage. Keep the notebook open; runtime storage is temporary. Download checkpoints before the runtime ends.\n\nThis uses the exact prepared data from your PC, without downloading a replacement dataset. Change `ADDITIONAL_STEPS` if desired.')
    code('ADDITIONAL_STEPS=1000\nstage=manifest["resumeStage"]\nlatest=project/f"model/checkpoints/nebula-cpu-large-{stage}.pt"\nif latest.is_file():\n    resume_checkpoint=latest\ncommand=[sys.executable,"model/train_public.py","--preset","cpu-large","--stage",stage,"--steps",str(ADDITIONAL_STEPS),"--device","cuda","--batch","4","--threads","2","--lr","0.0001","--save-every","100","--max-validation","128","--prepared-data",manifest["preparedData"],"--resume",str(resume_checkpoint)]\nsubprocess.run(command,cwd=project,check=True)\nprint("Training cell finished. Check the final trainer message for completion or early stopping.")\n')
    markdown('## Test the best saved checkpoint\n\nReadable replies, correct answers, and unseen conversations matter more than loss alone. This cell does not deploy anything.')
    code('best=project/f"model/checkpoints/nebula-cpu-large-{stage}.best.pt"\nsubprocess.run([sys.executable,"model/evaluate.py","--checkpoint",str(best)],cwd=project,check=True)\n')
    markdown('## Download your updated model\n\nRuntime files can disappear when the session ends. Download your checkpoint to your PC when training finishes.')
    code('from google.colab import files\nfiles.download(str(best))\n')
    notebook={'nbformat':4,'nbformat_minor':5,'metadata':{'colab':{'name':'Nebula_GPU_Training.ipynb'},'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'accelerator':'GPU'},'cells':cells}
    path=root/'Nebula_GPU_Resume.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    launcher='''"""Run this uploaded file in Colab to resume the uploaded Nebula transfer."""
from pathlib import Path
import subprocess,sys
import torch
if not torch.cuda.is_available():
    raise RuntimeError("Select a GPU runtime before running this launcher.")
'''
    launcher+='project=Path('+repr('/content/nebula_resume/'+stamp+'/api')+')\nproject.mkdir(parents=True,exist_ok=True)\nsources='+repr(bundle)+'\n'
    launcher+='for name,content in sources.items():\n    target=project/name\n    target.parent.mkdir(parents=True,exist_ok=True)\n    target.write_text(content,encoding="utf-8")\n'
    launcher+='sys.path.insert(0,str(project/"model"))\nfrom colab_transfer import restore,valid_checkpoint\ntransfer=Path("/content")/'+repr(Path(transfer).name)+'\nif not transfer.is_file():\n    raise FileNotFoundError("Upload the Nebula transfer .pt file into the Colab Files panel first.")\nmanifest,preserved=restore(transfer,project)\nstage=manifest["resumeStage"]\nresume=project/manifest["resumeCheckpoint"]\n_,info=valid_checkpoint(resume)\nprint({"resumingSavedSteps":info.get("steps"),"stage":stage,"existingCheckpointsPreserved":preserved,"GPU":torch.cuda.get_device_name(0)})\n'
    launcher+='subprocess.run([sys.executable,"model/train_public.py","--preset","cpu-large","--stage",stage,"--steps","1000","--device","cuda","--batch","4","--threads","2","--lr","0.0001","--save-every","100","--max-validation","128","--prepared-data",manifest["preparedData"],"--resume",str(resume)],cwd=project,check=True)\nfrom google.colab import files\nbest=project/f"model/checkpoints/nebula-cpu-large-{stage}.best.pt"\nfiles.download(str(best))\n'
    ast.parse(launcher)
    launcher_path=root/'Nebula_Colab_Resume.py'; launcher_path.write_text(launcher,encoding='utf-8')
    print(json.dumps({'notebook':str(path),'launcher':str(launcher_path),'transfer':str(transfer),'resumeSteps':steps,'stage':manifest['resumeStage'],'cells':len(cells),'googleDriveUsed':False}))
    return path

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--transfer',required=True); parser.add_argument('--manifest',required=True)
    args=parser.parse_args(); build(args.transfer,json.loads(Path(args.manifest).read_text(encoding='utf-8')))
