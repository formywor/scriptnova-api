"""Restore verified V3 data and checkpoints into Kaggle's saved output folder."""
import hashlib
import json
import math
from pathlib import Path
import shutil
import zlib

import torch
from nebula import load

DATA_FILES={
    'model/data/stories-approved.jsonl','model/data/improved-chat.jsonl',
    'model/data/v3-language.jsonl','model/data/v3-chat.jsonl',
    'model/data/v3-foundations.jsonl','model/data/v3-conversations.jsonl',
    'model/data/stories-sources.json','model/data/public-sources.json',
    'model/DATA_SOURCES.md','nebula-rules.json',
}

def sha256(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def restore_data(backup,project):
    payload=torch.load(backup,map_location='cpu',weights_only=True)
    if payload.get('format')!='nebula-v3-data-1' or payload.get('compression')!='zlib':
        raise ValueError('This is not a Nebula V3 data backup')
    entries=payload.get('files',{}); hashes=payload.get('sha256',{})
    if set(entries)!=set(hashes) or not set(entries)<=DATA_FILES:
        raise ValueError('Unexpected files in data backup')
    required={'model/data/v3-chat.jsonl','model/data/v3-language.jsonl','nebula-rules.json'}
    if not required<=set(entries): raise ValueError('Required training data or rules are missing')
    decoded={}; total=0
    for name,tensor in entries.items():
        if not isinstance(tensor,torch.Tensor) or tensor.dtype!=torch.uint8 or tensor.ndim!=1:
            raise ValueError('Invalid compressed data entry')
        decoder=zlib.decompressobj()
        value=decoder.decompress(tensor.numpy().tobytes(),64*1024*1024+1)
        total+=len(value)
        if not decoder.eof or decoder.unused_data or total>256*1024*1024:
            raise ValueError('Oversized or incomplete data backup')
        if hashlib.sha256(value).hexdigest()!=hashes[name]: raise ValueError('Training data checksum mismatch')
        decoded[name]=value
    project=Path(project).resolve()
    # Validate all existing targets before writing any file.
    for name,value in decoded.items():
        target=project/name
        if not target.resolve().is_relative_to(project): raise ValueError('Unsafe destination')
        if target.exists() and sha256(target)!=hashes[name]:
            raise ValueError('Existing training data differs; choose a new project folder')
    for name,value in decoded.items():
        target=project/name; target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists(): continue
        temporary=target.with_suffix(target.suffix+'.restore-tmp')
        temporary.write_bytes(value); temporary.replace(target)
    return hashes

def checkpoint_info(path,data_hash):
    model,metadata=load(path); del model
    if metadata.get('dataSha256')!=data_hash or metadata.get('objective')!='assistant':
        raise ValueError('Checkpoint does not match the backed-up V3 chat dataset')
    return metadata

def find_backup(input_root):
    paths=sorted(Path(input_root).rglob('Nebula_V3_Data.pt'))
    if not paths: raise FileNotFoundError('Add your private dataset containing Nebula_V3_Data.pt and both v3-chat checkpoint files.')
    if len({sha256(p) for p in paths})!=1:
        raise ValueError('Different V3 data backups are attached. Keep only the intended dataset version.')
    return paths[0]

def atomic_copy(source,target):
    source=Path(source); target=Path(target)
    if source.resolve()==target.resolve(): return
    target.parent.mkdir(parents=True,exist_ok=True)
    temporary=target.with_suffix(target.suffix+'.copy-tmp')
    shutil.copyfile(source,temporary); temporary.replace(target)

def migrate(input_root,project):
    input_root=Path(input_root); project=Path(project)
    backup=find_backup(input_root)
    hashes=restore_data(backup,project)
    data_hash=hashes['model/data/v3-chat.jsonl']
    checkpoints=project/'model/checkpoints'
    selected={}; summary={}
    for filename in ['v3-chat.pt','v3-chat.best.pt']:
        candidates=list(input_root.rglob(filename))
        target=checkpoints/filename
        if target.exists(): candidates.append(target)
        compatible=[]
        for path in candidates:
            info=checkpoint_info(path,data_hash)
            compatible.append((path,info))
        if not compatible: raise FileNotFoundError('Missing '+filename+'. Add both V3 model files as notebook inputs.')
        if filename.endswith('.best.pt'):
            def score(item):
                value=item[1].get('validationLoss')
                return value if isinstance(value,(float,int)) and math.isfinite(value) else float('inf')
            source,info=min(compatible,key=score)
        else: source,info=max(compatible,key=lambda item:item[1].get('steps',0))
        selected[target]=source
        summary[filename]={'savedSteps':info.get('steps'),'validationLoss':info.get('validationLoss'),
                           'trainingStateIncluded':info.get('trainingStateIncluded',False)}
    # Only install model files after both inputs have passed validation.
    for target,source in selected.items(): atomic_copy(source,target)
    atomic_copy(backup,project/'Nebula_V3_Data.pt')
    summary['dataSha256']=data_hash
    summary['project']=str(project)
    summary['trainingStarted']=False
    (project/'migration-report.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2),flush=True)
    return summary
