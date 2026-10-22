"""RAM-only raw corpus preparation and CUDA training; durable state lives on HF."""
import argparse
from collections import OrderedDict
import copy
import fnmatch
import gc
import gzip
import hashlib
import io
import json
import math
import os
import random
import re
import time
import unicodedata
from urllib.parse import quote
import numpy as np
import requests
import torch
import torch.nn.functional as F
from nebula import Nebula,Config,BOS,EOS
from v8_store import safe_server_detail

FORMAT='nebula-v18-ram-stream-1'
SOURCES={
 'fineweb':{'dataset':'HuggingFaceFW/fineweb-edu','subset':'sample-10BT','revision':'87f09149ef4734204d70ed1d046ddc9ca3f2b8f9','license':'odc-by'},
 'cosmopedia':{'dataset':'HuggingFaceTB/smollm-corpus','subset':'cosmopedia-v2','revision':'3ba9d605774198c5868892d7a8deda78031a781f','license':'odc-by'},
 'stories':{'dataset':'roneneldan/TinyStories','subset':'default','revision':'f54c09fd23315a6f9c86f9dc80f725de7d8f9c64','license':'cdla-sharing-1.0'},
 'textbooks':{'dataset':'HuggingFaceTB/cosmopedia','subset':'openstax','revision':'0ae6ec63f91742bd2d1eaef4f02232c55d719385','license':'apache-2.0'}}
DEFAULT={'sourceRepo':'iiidevv/nebula-research','sourceRun':'nebula-v17-lab','sourceKey':'current-foundationWeights',
 'textBytes':1_000_000_000,'weights':{'fineweb':50,'cosmopedia':25,'stories':15,'textbooks':10},
 'seed':1802026,'validationPercent':2,'minDocumentBytes':200,'maxDocumentBytes':1_000_000,
 'shardTextBytes':32_000_000,'steps':100_000,'batch':8,'microbatch':1,'learningRate':0.00003,
 'warmup':200,'cloudSaveEvery':500,'evaluateEvery':1000,'shardHoldSteps':64}
SECRET=re.compile(r'\b(?:hf_|gsk_|sk-|AIza|AQ\.)[\w-]{18,}|\bBearer\s+[\w.~/+=-]{18,}')
PROBES=['A child found a small boat beside the pond.','Ice melts when it takes in heat.',
        'The rain stopped, and the neighbors opened their windows.']


def emit(**value):print(json.dumps(value),flush=True)
def sha(value):return hashlib.sha256(value).hexdigest()
def digest(value):return sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
def engine_hash():
    # Source code is allowed on disk; corpus/model/optimizer artifacts never use local files.
    from pathlib import Path
    return sha((Path(__file__).read_text(encoding='utf-8')+Path(__file__).with_name('nebula.py').read_text(encoding='utf-8')).encode())


def validate(config):
    if set(config)!=set(DEFAULT):raise ValueError('Use exactly the documented CONFIG keys')
    if not re.fullmatch(r'[\w-]+/[\w.-]+',config['sourceRepo']) or not re.fullmatch(r'nebula-[\w-]{1,55}',config['sourceRun']) or not re.fullmatch(r'[a-zA-Z][\w-]{0,90}',config['sourceKey']):
        raise ValueError('Invalid source reference')
    bounds={'textBytes':(10000,4_000_000_000),'seed':(0,2**31),'validationPercent':(1,10),
       'minDocumentBytes':(32,10000),'maxDocumentBytes':(1000,1_000_000),'shardTextBytes':(1000,64_000_000),
       'steps':(1,1_000_000),'batch':(1,32),'microbatch':(1,8),'warmup':(1,5000),
       'cloudSaveEvery':(1,5000),'evaluateEvery':(1,10000),'shardHoldSteps':(1,256)}
    for key,(lo,hi) in bounds.items():
        if type(config[key]) is not int or not lo<=config[key]<=hi:raise ValueError('Invalid '+key)
    mix=config['weights']
    if set(mix)!=set(SOURCES) or any(type(v) is not int or not 0<=v<=100 for v in mix.values()) or sum(mix.values())!=100:raise ValueError('Data percentages must total 100')
    if config['microbatch']>config['batch'] or config['minDocumentBytes']>config['maxDocumentBytes']:raise ValueError('Invalid batch/document limits')
    if type(config['learningRate']) not in (int,float) or not math.isfinite(config['learningRate']) or not 0<config['learningRate']<=.001:raise ValueError('Invalid learning rate')
    return config


class Hub:
    """Explicit byte transfers: no hf_hub_download, filesystem cache or temporary data files."""
    def __init__(self,repo,token,run):
        from huggingface_hub import HfApi
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'nebula-v18-[\w-]{1,45}',run):raise ValueError('Invalid public destination/run')
        self.repo=repo;self.token=token;self.prefix='experiments/'+run+'/'
        self.api=HfApi(token=token);self.session=requests.Session()
        if self.api.whoami()['name']!=repo.split('/')[0]:raise ValueError('Use your own public output namespace')
        self.api.create_repo(repo,repo_type='model',private=False,exist_ok=True)
        info=self.api.model_info(repo)
        if info.private is not False:raise ValueError('V18 output must be a separate public repository')
        self.revision=info.sha

    def fetch(self,repo,path,revision,*,dataset=False):
        prefix='datasets/' if dataset else ''
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or '..' in path.split('/') or path.startswith('/') or '\\' in path:
            raise ValueError('Invalid remote file reference')
        url='https://huggingface.co/'+prefix+repo+'/resolve/'+quote(revision,safe='')+'/'+quote(path,safe='/')
        for attempt in range(4):
            response=self.session.get(url,headers={'Authorization':'Bearer '+self.token},timeout=(30,180))
            if response.status_code in [408,429,500,502,503,504] and attempt<3:
                response.close();time.sleep(min(60,5*2**attempt));continue
            response.raise_for_status();return response.content
        raise RuntimeError('Remote read failed')

    def state(self):
        try:return json.loads(self.fetch(self.repo,self.prefix+'state.json',self.revision))
        except requests.HTTPError as error:
            if error.response.status_code==404:return None
            raise

    def read_entry(self,entry,repo=None,revision=None,prefix=None):
        repo=repo or self.repo;revision=revision or self.revision;prefix=prefix or self.prefix
        if type(entry.get('bytes')) is not int or not 0<entry['bytes']<=2_147_483_648:raise ValueError('Invalid object size')
        parts=entry.get('parts',[entry])
        if not 1<=len(parts)<=32 or sum(p['bytes'] for p in parts)!=entry['bytes']:raise ValueError('Invalid object parts')
        data=bytearray()
        for part in parts:
            if not part['path'].startswith(prefix):raise ValueError('Unexpected object namespace')
            value=self.fetch(repo,part['path'],revision)
            if len(value)!=part['bytes'] or sha(value)!=part['sha256']:raise ValueError('Object part checksum mismatch')
            data.extend(value)
        if sha(data)!=entry['sha256']:raise ValueError('Object checksum mismatch')
        return data

    def publish(self,state,blobs=None,root_readme=None):
        from huggingface_hub import CommitOperationAdd
        result=copy.deepcopy(state);operations=[];blobs=blobs or {}
        for key,(name,blob) in blobs.items():
            if '..' in name.split('/') or name.startswith('/') or '\\' in name:raise ValueError('Invalid output name')
            size=len(blob)
            if not 0<size<=2_147_483_648:raise ValueError('Invalid output object size')
            identifier=sha(blob);parts=[]
            for offset in range(0,size,64*1024*1024):
                chunk=bytes(memoryview(blob)[offset:offset+64*1024*1024])
                remote=self.prefix+'objects/'+identifier+'/'+name+f'.part{len(parts):03d}.bin'
                parts.append({'path':remote,'bytes':len(chunk),'sha256':sha(chunk)})
                operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=chunk))
            result[key]={'bytes':size,'sha256':identifier,'parts':parts}
        # Raw object pointers added by the caller are resolved before this small atomic manifest.
        for split in ['train','validation','index']:
            key='_new_'+split
            if key in result:
                result['corpus'][split].append(result.pop(key))
        operations.append(CommitOperationAdd(path_in_repo=self.prefix+'state.json',path_or_fileobj=json.dumps(result,indent=2).encode()))
        if root_readme:operations.append(CommitOperationAdd(path_in_repo='README.md',path_or_fileobj=root_readme.encode()))
        for attempt in range(4):
            try:
                saved=self.api.create_commit(repo_id=self.repo,parent_commit=self.revision,operations=operations,commit_message='Save Nebula RAM-only raw experiment')
                break
            except Exception as error:
                response=getattr(error,'response',None);status=getattr(response,'status_code',None)
                retry=status in [408,429,500,502,503,504] and attempt<3
                emit(v18BackupFailed=True,httpStatus=status,serverDetail=safe_server_detail(error),retrying=retry)
                if not retry:raise
                time.sleep(min(60,5*2**attempt))
        self.revision=saved.oid
        if json.loads(self.fetch(self.repo,self.prefix+'state.json',self.revision))!=result:raise ValueError('Remote manifest verification failed')
        emit(v18PublicBackupConfirmed=True,revision=self.revision,uniqueTextBytes=result.get('uniqueTextBytes',0),
             updates=result.get('updates',0),corpusComplete=result.get('corpusComplete',False),publicWebsiteUpdated=False)
        return result


def source_paths(hub,key):
    spec=SOURCES[key];info=hub.api.dataset_info(spec['dataset'],revision=spec['revision'])
    card=info.card_data.to_dict() if hasattr(info.card_data,'to_dict') else dict(info.card_data or {})
    selected=next((c for c in card.get('configs',[]) if c.get('config_name')==spec['subset']),None)
    patterns=[]
    if selected:
        for item in selected.get('data_files',[]):
            if isinstance(item,dict) and item.get('split')=='train':
                value=item['path'];patterns.extend(value if isinstance(value,list) else [value])
    elif spec['subset']=='default':patterns=['data/train-*.parquet']
    if not patterns:raise ValueError('Pinned source has no declared train-file pattern: '+key)
    paths=[name for name in hub.api.list_repo_files(spec['dataset'],repo_type='dataset',revision=spec['revision'])
           if name.endswith('.parquet') and any(fnmatch.fnmatch(name,p) for p in patterns)]
    if not paths:raise ValueError('No pinned parquet training files found: '+key)
    return sorted(paths)


def source_rows(hub,key,cursor,seed):
    from huggingface_hub import HfFileSystem
    import pyarrow.parquet as pq
    spec=SOURCES[key];paths=source_paths(hub,key)
    random.Random(seed+sum(key.encode())).shuffle(paths)
    fs=HfFileSystem(token=hub.token)
    for file_index in range(cursor['file'],len(paths)):
        remote=f"datasets/{spec['dataset']}@{spec['revision']}/{paths[file_index]}"
        start=cursor['row'] if file_index==cursor['file'] else 0
        # HfFileSystem's fsspec block cache lives in RAM. No local parquet/cache files.
        with fs.open(remote,'rb',block_size=4*1024*1024,cache_type='bytes') as stream:
            parquet=pq.ParquetFile(stream);columns=[c for c in ['text','id','url','file_path','audience','format'] if c in parquet.schema.names]
            if 'text' not in columns:raise ValueError('Pinned source is missing raw text: '+key)
            position=0
            for group in range(parquet.num_row_groups):
                size=parquet.metadata.row_group(group).num_rows
                if position+size<=start:position+=size;continue
                for batch in parquet.iter_batches(batch_size=32,row_groups=[group],columns=columns):
                    for row in batch.to_pylist():
                        index=position;position+=1
                        if index<start:continue
                        yield row,{'file':file_index,'row':index+1},paths[file_index]
    # Exhaustion is checked against the requested source budget by prepare().


def convert(row,config):
    text=row.get('text')
    if not isinstance(text,str):return None
    text=text.replace('\r\n','\n').replace('\r','\n').strip()
    try:content=text.encode('utf-8')
    except UnicodeError:return None
    if not config['minDocumentBytes']<=len(content)<=config['maxDocumentBytes']:return None
    if '\ufffd' in text or any(ord(c)<32 and c not in '\n\t' for c in text) or SECRET.search(text):return None
    if any(p.casefold() in text.casefold() for p in PROBES):return None
    identifier=sha(' '.join(unicodedata.normalize('NFKC',text).casefold().split()).encode())
    return content,identifier


def prepare(hub,state,hours,rows_fn=source_rows):
    config=state['config'];state=copy.deepcopy(state);seen=set()
    for entry in state['corpus']['index']:
        for line in gzip.decompress(hub.read_entry(entry)).splitlines():seen.add(json.loads(line)['hash'])
    buffers={'train':bytearray(),'validation':bytearray()};records=[];pending_bytes=0
    started=time.monotonic();last_log=state['uniqueTextBytes']
    def flush():
        nonlocal state,pending_bytes,records,buffers
        blobs={}
        for split in buffers:
            if buffers[split]:blobs['_new_'+split]=(split+'.bin',buffers[split])
        if records:blobs['_new_index']=('public-index.jsonl.gz',gzip.compress(b'\n'.join(json.dumps(r).encode() for r in records),mtime=0))
        state=hub.publish(state,blobs)
        buffers={'train':bytearray(),'validation':bytearray()};records=[];pending_bytes=0
    try:
        for key in SOURCES:
            goal=config['textBytes']*config['weights'][key]//100
            if state['sourceBytes'][key]>=goal*.995:continue
            emit(v18Acquiring=key,goalUniqueBytes=goal,resumeCursor=state['cursors'][key])
            for row,cursor,path in rows_fn(hub,key,state['cursors'][key],config['seed']):
                if time.monotonic()-started>=hours*3600:flush();emit(v18PreparationPaused=True);return state
                converted=convert(row,config)
                state['cursors'][key]=cursor
                if converted:
                    content,identifier=converted
                    if identifier not in seen and len(content)<=goal-state['sourceBytes'][key]:
                        split='validation' if int(identifier[:8],16)%100<config['validationPercent'] else 'train'
                        tokens=np.empty(len(content)+2,dtype='<u2');tokens[0]=BOS;tokens[-1]=EOS;tokens[1:-1]=np.frombuffer(content,dtype=np.uint8)
                        offset=len(buffers[split])//2;buffers[split].extend(tokens.tobytes())
                        provenance={k:str(row[k])[:1000] for k in ['id','url','file_path','audience','format'] if k in row}
                        if SECRET.search(json.dumps(provenance)):raise ValueError('Credential pattern in upstream attribution')
                        records.append({'hash':identifier,'source':key,'sourceFile':path,'sourceRow':cursor['row']-1,
                            'split':split,'shard':len(state['corpus'][split]),'startToken':offset,'endToken':len(buffers[split])//2,
                            'utf8Bytes':len(content),'provenance':provenance})
                        seen.add(identifier);state['sourceBytes'][key]+=len(content);state['uniqueTextBytes']+=len(content)
                        state['documents']+=1;pending_bytes+=len(content)
                if state['uniqueTextBytes']-last_log>=1_000_000:
                    last_log=state['uniqueTextBytes'];emit(v18PreparedBytes=last_log,source=key,documents=state['documents'])
                if pending_bytes>=config['shardTextBytes']:flush()
                if state['sourceBytes'][key]>=goal*.995 or goal-state['sourceBytes'][key]<config['minDocumentBytes']:break
            if state['sourceBytes'][key]<goal*.90:flush();raise ValueError('Source exhausted below budget: '+key)
        state['corpusComplete']=True;flush();return state
    except KeyboardInterrupt:
        flush();emit(v18PreparationPaused=True);return state


class RemotePool:
    def __init__(self,hub,entries,context,hold=64):
        self.hub=hub;self.entries=[e for e in entries if e['bytes']//2>context];self.context=context;self.hold=hold
        self.cache=OrderedDict()
        if not self.entries:raise ValueError('Not enough packed tokens for a full context window')
        self.weights=[e['bytes']//2-context for e in self.entries]
    def data(self,index):
        if index not in self.cache:
            self.cache[index]=np.frombuffer(self.hub.read_entry(self.entries[index]),dtype='<u2')
            if len(self.cache)>2:self.cache.popitem(last=False)
        self.cache.move_to_end(index);return self.cache[index]
    def batch(self,step,batch,seed):
        # Shard locality bounds network traffic; selection is weighted by valid start positions.
        index=random.Random(seed+step//self.hold).choices(range(len(self.entries)),weights=self.weights,k=1)[0]
        data=self.data(index);rng=random.Random(seed+step*7919);result=[]
        for _ in range(batch):
            start=rng.randrange(len(data)-self.context)
            values=torch.from_numpy(np.array(data[start:start+self.context+1],dtype=np.int64))
            result.append((values[:-1],values[1:]))
        return result


def serialize(model,metadata,training=None):
    if any(not torch.isfinite(p).all() for p in model.parameters()):raise ValueError('Non-finite weights cannot replace a healthy public checkpoint')
    stream=io.BytesIO()
    payload={'format':1,'config':vars(model.config),'state':model.state_dict(),'metadata':metadata}
    if training is not None:payload['trainingState']=training
    torch.save(payload,stream)
    return stream


def deserialize(blob):
    payload=torch.load(io.BytesIO(blob),map_location='cpu',weights_only=True)
    if payload.get('format')!=1:raise ValueError('Unsupported Nebula checkpoint')
    model=Nebula(Config(**payload['config']));model.load_state_dict(payload['state'])
    if any(not torch.isfinite(p).all() for p in model.parameters()):raise ValueError('Non-finite source weights')
    return model,payload


@torch.inference_mode()
def evaluate(model,pool):
    emit(v18EvaluationPhase='heldout-loss-and-generation')
    device=next(model.parameters()).device;model.eval();total=0.;n=0
    for i in range(24):
        x,y=pool.batch(i,1,880019)[0];logits=model(x[None].to(device))
        total+=float(F.cross_entropy(logits.flatten(0,1),y.to(device),reduction='sum'));n+=len(y)
        if (i+1)%8==0:emit(v18EvaluationLossBlocks=i+1,total=24)
    raw=[]
    for prefix in PROBES:
        tokens=[BOS]+list(prefix.encode())
        for _ in range(128):
            value=int(model(torch.tensor([tokens[-model.config.context:]],device=device))[0,-1].argmax())
            if value>=256:break
            tokens.append(value)
        raw.append({'prefix':prefix,'continuation':bytes(t for t in tokens[1+len(prefix.encode()):] if t<256).decode('utf-8',errors='replace'),'grade':'pending-human-review'})
        emit(v18RawProbesComplete=len(raw),total=3)
    chat=[]
    for prompt in ['Hello! What can you help me with?','Explain why ice melts.','Write a thank-you note to a neighbor.','Which should I choose?']:
        answer=model.reply([{'role':'system','content':'You are Nebula AI.'},{'role':'user','content':prompt}],max_tokens=128,temperature=0)
        chat.append({'prompt':prompt,'reply':answer,'grade':'pending-human-review'})
        emit(v18ChatProbesComplete=len(chat),total=4)
    return {'validationLoss':total/n,'validationTargets':n,'rawCompletions':raw,'openAnswers':chat,
            'qualityApproved':False,'humanVerified':False,'publicWebsiteUpdated':False}


def train(hub,state,hours,action,device='cuda'):
    config=state['config'];state=copy.deepcopy(state)
    if not state['corpusComplete']:raise ValueError('Finish ACTION=prepare before using the GPU')
    if device=='cuda' and not torch.cuda.is_available():raise RuntimeError('CUDA GPU not detected. No CPU training fallback was started.')
    if not state.get('source'):
        info=hub.api.model_info(config['sourceRepo'])
        prefix='experiments/'+config['sourceRun']+'/'
        old=json.loads(hub.fetch(config['sourceRepo'],prefix+'state.json',info.sha))
        entry=old.get(config['sourceKey'])
        if not entry:raise ValueError('Source checkpoint unavailable; no random restart was performed')
        model,payload=deserialize(hub.read_entry(entry,config['sourceRepo'],info.sha,prefix));del payload
        stream=serialize(model,{'experimental':True,'qualityApproved':False,'originWeightSha256':entry['sha256']})
        try:state=hub.publish({**state,'sourceSha256':entry['sha256']},{'source':('source.pt',stream.getbuffer())})
        finally:stream.close()
    else:model,payload=deserialize(hub.read_entry(state.get('working') or state['source']))
    model.to(device);torch.set_num_threads(2)
    dtype=torch.bfloat16 if device=='cuda' and torch.cuda.is_bf16_supported() else torch.float16
    amp=device=='cuda';scaler=torch.amp.GradScaler('cuda',enabled=amp and dtype==torch.float16,init_scale=1024)
    optimizer=torch.optim.AdamW(model.parameters(),lr=config['learningRate'],weight_decay=.01)
    signature=digest({'config':config,'engine':state['engineSha256'],'corpus':state['corpus'],'source':state['sourceSha256']})
    updates=targets=0
    if state.get('working'):
        training=payload['trainingState']
        if training['signature']!=signature:raise ValueError('Checkpoint/config mismatch; use a new run name for changes')
        optimizer.load_state_dict(training['optimizer'])
        if scaler.is_enabled() and training['scaler']:scaler.load_state_dict(training['scaler'])
        elif scaler.is_enabled():emit(v18ScalerReset=True,reason='Source precision used no gradient scaler; optimizer state retained')
        updates=training['updates'];targets=training['targets'];del payload,training
    elif 'payload' in locals():del payload
    pool=RemotePool(hub,state['corpus']['train'],model.config.context,config['shardHoldSteps'])
    validation=RemotePool(hub,state['corpus']['validation'],model.config.context,1)
    emit(v18TrainingDevice=torch.cuda.get_device_name(0) if amp else 'CPU test',parameters=sum(p.numel() for p in model.parameters()),
         optimizerRestored=bool(state.get('working')),uniqueCorpusBytes=state['uniqueTextBytes'],precision=str(dtype) if amp else 'fp32',
         plannedTrainingBytePositions=config['steps']*config['batch']*model.config.context)
    def report(label):
        nonlocal state
        result=evaluate(model,validation)
        state=hub.publish({**state,'latestEvaluation':{'label':label,'validationLoss':result['validationLoss']}},
                          {'evaluation':('evaluation.json',json.dumps(result).encode())})
        emit(v18Evaluation=result)
    if action=='evaluate':report('manual-'+str(updates));return state
    if action=='train' and not state.get('baselineEvaluated'):
        report('baseline');state=hub.publish({**state,'baselineEvaluated':True})
    started=time.monotonic();start_targets=targets;start_updates=updates;last_backup=updates;bad=0
    budget=min(config['steps'],updates+100) if action=='benchmark' else config['steps']
    def backup():
        nonlocal state,last_backup
        if updates==last_backup and state.get('working'):return
        stream=serialize(model,{'updates':updates,'supervisedBytePositions':targets,'qualityApproved':False,'experimental':True},
              {'signature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict(),'updates':updates,'targets':targets})
        try:state=hub.publish({**state,'updates':updates,'trainingBytePositions':targets}, {'working':('working.pt',stream.getbuffer())})
        finally:stream.close()
        last_backup=updates
    interrupted=False
    try:
        while updates<budget and time.monotonic()-started<hours*3600:
            pairs=pool.batch(updates,config['batch'],config['seed']);model.train();optimizer.zero_grad(set_to_none=True)
            rate=config['learningRate']*min(1.,(updates+1)/config['warmup'])*(.1+.9*.5*(1+math.cos(math.pi*updates/config['steps'])))
            for group in optimizer.param_groups:group['lr']=rate
            loss_value=0.;denominator=sum(len(y) for _,y in pairs)
            for offset in range(0,len(pairs),config['microbatch']):
                micro=pairs[offset:offset+config['microbatch']]
                x=torch.stack([p[0] for p in micro]).to(device);y=torch.stack([p[1] for p in micro]).to(device)
                with torch.autocast('cuda',dtype=dtype,enabled=amp):
                    objective=F.cross_entropy(model(x).flatten(0,1),y.flatten(),reduction='sum')/denominator
                if not torch.isfinite(objective):raise ValueError('Non-finite loss; previous public checkpoint retained')
                loss_value+=float(objective.detach());scaler.scale(objective).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            if not torch.isfinite(norm):
                bad+=1
                if not scaler.is_enabled() or bad>12:raise ValueError('Non-finite gradients; previous checkpoint retained')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            bad=0;scaler.step(optimizer);scaler.update();updates+=1;targets+=denominator
            if updates%25==0:emit(v18Update=updates,budget=config['steps'],loss=round(loss_value,4),learningRate=rate,
                supervisedBytePositions=targets,bytePositionsPerSecond=round((targets-start_targets)/max(1,time.monotonic()-started)))
            if action=='train' and updates%config['cloudSaveEvery']==0:
                backup()
                if updates%config['evaluateEvery']==0:report('update-'+str(updates))
    except KeyboardInterrupt:interrupted=True
    if action=='benchmark':
        elapsed=time.monotonic()-started;rate=(targets-start_targets)/max(.01,elapsed)
        result={'benchmarkUpdates':updates-start_updates,'seconds':elapsed,'bytePositionsPerSecond':rate,
                'estimatedComputeHoursForRemainingBudget':(config['steps']-start_updates)*config['batch']*model.config.context/max(1,rate)/3600,
                'weightsDiscarded':True,'note':'Includes corpus downloads; excludes remote full-checkpoint saves and evaluation.'}
        state=hub.publish(state,{'benchmark':('benchmark.json',json.dumps(result).encode())});emit(v18Benchmark=result)
    else:
        backup();report('session-'+str(updates))
        state=hub.publish({**state,'trainingComplete':updates>=config['steps']})
    emit(v18SessionFinished=True,interrupted=interrupted,updatesSaved=state.get('updates',0),publicWebsiteUpdated=False)
    del optimizer,model,pool,validation;gc.collect()
    if torch.cuda.is_available():torch.cuda.empty_cache()
    return state


def readme(repo):
    attribution='\n'.join(f"- {key}: [{s['dataset']}](https://huggingface.co/datasets/{s['dataset']}/tree/{s['revision']}), `{s['subset']}`, `{s['license']}`." for key,s in SOURCES.items())
    return f'''---
license: other
license_name: per-source-data-licenses
license_link: https://huggingface.co/{repo}/blob/main/README.md#licenses
library_name: pytorch
tags:
- nebula
- experimental
---
# Nebula V18 — raw text and GPU experiment

Public experimental continuation of the owner's Nebula weights. Durable datasets, packed byte-token shards,
source indexes, model/optimizer/scaler checkpoints and reports are uploaded directly from RAM.
No dataset or checkpoint is written to the worker's filesystem. Python code, installed packages and
the notebook itself can exist on disk. This runner does not ingest account chats or review feeds.
Inherited weights and public web data are not guaranteed free of personal information.
No website deployment or automatic quality approval is enabled.

## Licenses

Each corpus retains its upstream terms and attribution; this collection does not relicense it.
Pinned upstream cards are stored with each run; original FineWeb document URLs are retained in compressed indexes.
The new textbooks component is synthetic Cosmopedia text seeded from OpenStax outlines.
ODC-By: https://opendatacommons.org/licenses/by/1-0/
CDLA-Sharing-1.0: https://cdla.dev/sharing-1-0/
Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0

{attribution}

## Representation and limitations

Packed tokens are little-endian uint16: byte IDs 0–255, BOS=256, EOS=257. Whole UTF-8 documents
are normalized-exact-deduplicated and assigned by hash to train or validation before packing.
Credential-pattern/control/size filters are applied; this is not a full PII, factual or fuzzy-duplicate audit.
The model may have seen overlapping public text before this experiment.
Source mix percentages describe acquired UTF-8 bytes; training samples packed positions, including repeated exposure.
Training batches use deterministic shard locality (64 updates per sampled shard) to bound network traffic.
At most two training shards and two validation shards are cached in RAM; deduplication hashes also use RAM.
Full optimizer snapshots consume substantial host RAM and public storage; GPU memory alone is not sufficient.
Only confirmed public checkpoints survive worker loss. The history is retained and public storage is not unlimited.
'''


def run(repo='iiidevv/nebula-raw-training',run_name='nebula-v18-raw-1gb',config=None,action='prepare',hours=2,
        *,hub_factory=Hub,rows_fn=source_rows,device='cuda'):
    config=validate(copy.deepcopy(DEFAULT if config is None else config))
    if action not in ['prepare','benchmark','train','evaluate'] or not 0<hours<=12:raise ValueError('Invalid action/session hours')
    if action!='prepare' and device=='cuda' and not torch.cuda.is_available():raise RuntimeError('CUDA GPU not detected; no CPU training fallback started')
    if (repo,run_name)==(config['sourceRepo'],config['sourceRun']):raise ValueError('Do not overwrite the source experiment')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise RuntimeError('Set NEBULA_HF_TOKEN in the platform secret/environment settings')
    hub=hub_factory(repo,token,run_name);state=hub.state();code=engine_hash()
    if state is None:
        state={'format':FORMAT,'config':config,'engineSha256':code,'sources':SOURCES,'uniqueTextBytes':0,'documents':0,
          'sourceBytes':{k:0 for k in SOURCES},'cursors':{k:{'file':0,'row':0} for k in SOURCES},
          'corpus':{'train':[],'validation':[],'index':[]},'corpusComplete':False,'updates':0,'qualityApproved':False,'publicAutoUpdate':False}
        blobs={}
        for key,spec in SOURCES.items():blobs['card-'+key]=(key+'-README.md',hub.fetch(spec['dataset'],'README.md',spec['revision'],dataset=True))
        state=hub.publish(state,blobs,root_readme=readme(repo))
    if state['format']!=FORMAT or state['config']!=config or state['sources']!=SOURCES or state['engineSha256']!=code:
        raise ValueError('Run settings/code changed. Keep the original settings to resume or use a NEW RUN_NAME')
    if action=='prepare':
        if not state['corpusComplete']:state=prepare(hub,state,hours,rows_fn)
        emit(v18DataReady=state['corpusComplete'],uniqueUtf8Bytes=state['uniqueTextBytes'],trainingStarted=False)
        return state
    return train(hub,state,hours,action,device)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action',choices=['prepare','benchmark','train','evaluate'],default='prepare')
    parser.add_argument('--repo',default='iiidevv/nebula-raw-training');parser.add_argument('--run-name',default='nebula-v18-raw-1gb')
    parser.add_argument('--hours',type=float,default=2)
    args=parser.parse_args();run(args.repo,args.run_name,action=args.action,hours=args.hours)


if __name__=='__main__':main()
