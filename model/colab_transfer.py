"""Verified, key-free checkpoint/data transfer. No ZIP archives are created."""
import hashlib
import json
from pathlib import Path,PurePosixPath
import sys
import time
import zlib
from datetime import datetime,timezone

root=Path(__file__).resolve().parent
runtime=root.parents[3]/'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir(): sys.path.insert(0,str(runtime))
import torch

FORMAT='nebula-colab-transfer-2'
CHECKPOINTS=['nebula-cpu-large-language.pt','nebula-cpu-large-language.best.pt','nebula-cpu-large-chat.pt','nebula-cpu-large-chat.best.pt']

def stable_bytes(path):
    for _ in range(4):
        before=path.stat(); value=path.read_bytes(); after=path.stat()
        if (before.st_size,before.st_mtime_ns,before.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino): return value
        time.sleep(.2)
    raise ValueError('A source file kept changing; retry after its checkpoint save finishes')

def valid_checkpoint(path):
    value=torch.load(path,map_location='cpu',weights_only=True)
    if value.get('format')!=1 or not isinstance(value.get('state'),dict): raise ValueError('Invalid model checkpoint')
    if any(not torch.isfinite(v).all() for v in value['state'].values()): raise ValueError('Checkpoint contains non-finite weights')
    return value['config'],value.get('metadata',{})

def build(destination):
    import io
    torch.set_num_threads(1)
    files={}; metadata={}
    for name in CHECKPOINTS:
        path=root/'checkpoints'/name
        if not path.exists(): continue
        raw=stable_bytes(path)
        try: config,meta=valid_checkpoint(io.BytesIO(raw))
        except ValueError: continue
        relative='model/checkpoints/'+name
        files[relative]=raw
        metadata[relative]={'config':config,'steps':meta.get('steps',0),'objective':meta.get('objective'),'validationLoss':meta.get('validationLoss'),'dataSha256':meta.get('dataSha256')}
    if not metadata: raise ValueError('No healthy checkpoints found')
    # Copy only known model data; no .env, credentials, browser profiles, or Firebase keys.
    names=['public-approved.jsonl','public-sources.json','approved.jsonl','continuous.jsonl','conversations-approved.jsonl','conversations-seed.jsonl','conversations-teacher-accepted.jsonl','conversations-teacher-pending.jsonl','gemini-accepted.jsonl','gemini-pending.jsonl']
    for name in names:
        path=root/'data'/name
        if not path.exists(): continue
        raw=stable_bytes(path)
        if name.endswith('.jsonl'):
            rows=[json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
            if any(row.get('source',{}).get('kind')=='user' for row in rows):
                if name=='public-approved.jsonl': raise ValueError('Prepared public data unexpectedly contains account chat exports')
                continue
        files['model/data/'+name]=raw
    data_path='model/data/public-approved.jsonl'
    if data_path not in files: raise ValueError('Prepared training data is missing')
    data_hash=hashlib.sha256(files[data_path]).hexdigest()
    for name in ['seed.jsonl','DATA_SOURCES.md']:
        files['model/'+name]=stable_bytes(root/name)
    files['nebula-rules.json']=stable_bytes(root.parent/'nebula-rules.json')
    matching=[name for name,meta in metadata.items() if meta['dataSha256']==data_hash]
    if not matching: raise ValueError('Saved checkpoint does not match the prepared dataset')
    # Prefer the latest saved chat progress; keep best and language checkpoints too.
    selected=next((name for name in ['model/checkpoints/nebula-cpu-large-chat.pt','model/checkpoints/nebula-cpu-large-chat.best.pt','model/checkpoints/nebula-cpu-large-language.pt','model/checkpoints/nebula-cpu-large-language.best.pt'] if name in matching),None)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    manifest={'format':FORMAT,'snapshotId':stamp,'createdAtUTC':datetime.now(timezone.utc).isoformat(),'resumeCheckpoint':selected,'resumeStage':'chat' if metadata[selected]['objective']=='assistant' else 'language','preparedData':data_path,'dataSha256':data_hash,'checkpoints':metadata,'files':{name:{'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()} for name,value in files.items()},'resumeState':'Weights and data are preserved. Legacy checkpoints do not contain optimizer or sampler state.','accountChatsIncluded':False,'apiKeysIncluded':False}
    destination=Path(destination); destination.mkdir(parents=True,exist_ok=True)
    path=destination/f'Nebula_Transfer_{stamp}.pt'
    temporary=path.with_suffix('.tmp')
    compressed={name:torch.frombuffer(bytearray(zlib.compress(value,6)),dtype=torch.uint8) for name,value in files.items()}
    torch.save({'format':FORMAT,'compression':'zlib','manifest':manifest,'files':compressed},temporary); temporary.replace(path)
    (destination/'transfer-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    # Verify the serialized bundle, rather than trusting a successful file write.
    verify(torch.load(path,map_location='cpu',weights_only=True))
    print(json.dumps({'transfer':str(path),'megabytes':round(path.stat().st_size/1e6,1),'files':len(files),'resumeCheckpoint':selected,'steps':metadata[selected]['steps'],'stage':manifest['resumeStage']}),flush=True)
    return path,manifest

def verify(payload):
    if payload.get('format')!=FORMAT or payload.get('manifest',{}).get('format')!=FORMAT: raise ValueError('Unsupported transfer format')
    manifest=payload['manifest']; files=payload.get('files',{})
    if set(files)!=set(manifest['files']): raise ValueError('Transfer file list mismatch')
    decoded={}
    for name,encoded in files.items():
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name: raise ValueError('Unsafe transfer path')
        allowed=(len(path.parts)==3 and path.parts[:2] in [('model','data'),('model','checkpoints')]) or name in ['nebula-rules.json','model/seed.jsonl','model/DATA_SOURCES.md']
        if not allowed or not isinstance(encoded,torch.Tensor) or encoded.dtype!=torch.uint8 or encoded.ndim!=1: raise ValueError('Transfer contains unexpected content')
        expected=manifest['files'][name]
        decoder=zlib.decompressobj()
        value=decoder.decompress(encoded.numpy().tobytes(),expected['bytes']+1)
        if not decoder.eof or decoder.unused_data: raise ValueError('Invalid compressed transfer entry')
        if len(value)!=expected['bytes'] or hashlib.sha256(value).hexdigest()!=expected['sha256']: raise ValueError('Transfer checksum mismatch')
        decoded[name]=value
    if manifest['resumeCheckpoint'] not in files or manifest['preparedData'] not in files: raise ValueError('Resume inputs missing')
    payload['decodedFiles']=decoded
    return manifest

def restore(transfer,project,checkpoint_directory=None):
    payload=torch.load(transfer,map_location='cpu',weights_only=True)
    manifest=verify(payload)
    project=Path(project).resolve(); checkpoint_directory=Path(checkpoint_directory).resolve() if checkpoint_directory else project/'model/checkpoints'
    project.mkdir(parents=True,exist_ok=True); checkpoint_directory.mkdir(parents=True,exist_ok=True)
    preserved=[]
    for name,value in payload['decodedFiles'].items():
        checkpoint=name.startswith('model/checkpoints/')
        target=checkpoint_directory/PurePosixPath(name).name if checkpoint else project.joinpath(*PurePosixPath(name).parts)
        allowed_root=checkpoint_directory if checkpoint else project
        if not target.resolve().is_relative_to(allowed_root): raise ValueError('Transfer target leaves its allowed directory')
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest()==manifest['files'][name]['sha256']: continue
            if checkpoint:
                config,_=valid_checkpoint(target)
                if config!=manifest['checkpoints'][name]['config']: raise ValueError('Existing checkpoint architecture differs')
                preserved.append(name); continue
            raise ValueError('Existing dataset or rules differ from the snapshot; refusing to overwrite')
        temporary=target.with_suffix(target.suffix+'.restore-tmp'); temporary.write_bytes(value); temporary.replace(target)
    link=project/'model/checkpoints'
    if checkpoint_directory!=link.resolve():
        if link.exists(): raise ValueError('Checkpoint folder already exists; choose a fresh project directory')
        link.symlink_to(checkpoint_directory,target_is_directory=True)
    return manifest,preserved

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',required=True)
    build(parser.parse_args().output)
