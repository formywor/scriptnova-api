"""Raw-prose branch of the reusable V17 lab; older lab engine remains unchanged."""
import copy
import gc
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from pathlib import Path
import torch
from nebula import load,save
from rules import with_owner_rules
from v10_store import Store
from v14_train import language_sum
from v14_eval import completion
from v16_diagnostic import atomic_json,emit,audit
from v17_lab import DEFAULT
from v17_train import fit,code_hash
from v17_data import digest
from v17_raw_data import FORMAT,SPECS,prepare,PackedPool,file_sha256

RAW_DEFAULT={'sourceRun':'nebula-v17-lab','sourceKey':'current-foundationWeights',
    'textBytes':64000000,'weights':{'fineweb':50,'cosmopedia':35,'stories':15},
    'validationPercent':2,'minDocumentBytes':200,'maxDocumentBytes':1000000,
    'maxScannedPerSource':100000,'seed':1702026,'steps':10000,'learningRate':.00003,
    'batch':8,'microbatch':1,'warmup':200,'localSaveEvery':50,'cloudSaveEvery':500,
    'evaluateEvery':1000}


def validate(config):
    if set(config)!=set(RAW_DEFAULT):raise ValueError('Use the documented RAW_CONFIG keys')
    if not isinstance(config['sourceRun'],str) or not re.fullmatch(r'nebula-[a-zA-Z0-9_-]{1,55}',config['sourceRun']):raise ValueError('Invalid source run')
    if not isinstance(config['sourceKey'],str) or not re.fullmatch(r'[a-zA-Z][\w-]{0,90}',config['sourceKey']):raise ValueError('Invalid source key')
    for key,lo,hi in [('textBytes',10000,512000000),('validationPercent',1,20),('minDocumentBytes',32,10000),
        ('maxDocumentBytes',1000,2000000),('maxScannedPerSource',100,1000000),('seed',0,2**31),
        ('steps',1,1000000),('batch',1,32),('microbatch',1,8),('warmup',1,5000),
        ('localSaveEvery',1,2000),('cloudSaveEvery',1,5000),('evaluateEvery',1,10000)]:
        if type(config[key]) is not int or not lo<=config[key]<=hi:raise ValueError('Invalid '+key)
    weights=config['weights']
    if set(weights)!=set(SPECS) or any(type(v) is not int or not 0<=v<=100 for v in weights.values()) or sum(weights.values())!=100:raise ValueError('Source percentages must total 100')
    if config['microbatch']>config['batch'] or config['minDocumentBytes']>config['maxDocumentBytes']:raise ValueError('Invalid batch/document limits')
    rate=config['learningRate']
    if type(rate) not in (int,float) or not math.isfinite(rate) or not 0<rate<=.001:raise ValueError('Invalid learning rate')
    return config


def raw_hash():
    return digest({'baseEngine':code_hash(),'rawModules':{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                  for name in ['v17_raw_lab.py','v17_raw_data.py']}})


def cards(folder):
    from huggingface_hub import hf_hub_download
    folder=Path(folder);folder.mkdir(exist_ok=True)
    for key,spec in SPECS.items():
        path=folder/(key+'-README.md')
        if path.exists():continue
        fetched=hf_hub_download(spec['dataset'],'README.md',repo_type='dataset',revision=spec['revision'],token=os.environ.get('HF_TOKEN'))
        path.write_bytes(Path(fetched).read_bytes())


def local_corpus_ready(folder, config, minimum_bytes):
    """Keep consistent local preparation newer than the last upload."""
    try:
        db=sqlite3.connect(f'file:{(folder/"documents.sqlite").as_posix()}?mode=ro',uri=True)
        try:value=json.loads(db.execute("SELECT value FROM metadata WHERE key='state'").fetchone()[0])
        finally:db.close()
        expected=digest({'format':FORMAT,'config':config,'sources':SPECS})
        return (value['signature']==expected and value['textBytes']>=minimum_bytes
                and all((folder/(split+'.bin')).stat().st_size>=value['tokenCounts'][split]*2 for split in ['train','validation'])
                and json.loads((folder/'manifest.json').read_text())==value)
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):return False


@torch.inference_mode()
def evaluate_raw(model, validation):
    model.eval();total=0.;targets=0;device=next(model.parameters()).device
    for pair in validation.validation(24):
        value,n=language_sum(model,[pair],device,False,torch.float32);total+=float(value);targets+=n
    loss=total/targets
    prefixes=['A child found a small boat beside the pond.','Ice melts when it takes in heat.',
              'The rain stopped, and the neighbors opened their windows.']
    raw=[completion(model,p,160) for p in prefixes]
    opens=[]
    for text in ['Hello! What can you help me with?','Explain why ice melts.',
                 'Write a thank-you note to a neighbor.','Which should I choose?']:
        reply=model.reply(with_owner_rules([{'role':'user','content':text}]),max_tokens=160,temperature=0)
        opens.append({'prompt':text,'reply':reply,'grade':'pending-human-review'})
    summary={'validationLossNatsPerTarget':loss,'bitsPerTarget':loss/math.log(2),
             'validationTargets':targets,'rawCompletionsPending':len(raw),'chatAnswersPending':len(opens),
             'qualityApproved':False,'humanVerified':False,'publicWebsiteUpdated':False}
    emit(rawEvaluation=summary)
    return {'summary':summary,'rawCompletions':raw,'openAnswers':opens,
            'notice':'Raw next-token practice does not directly teach instruction following. Inspect generated text; low loss is not a release criterion.'}


def main_raw(project,run_name='nebula-v17-raw-prose',config=None,hours=2,prepare_only=False,device='cuda'):
    config=validate(copy.deepcopy(RAW_DEFAULT if config is None else config))
    if not re.fullmatch(r'nebula-v17-[a-zA-Z0-9_-]{1,45}',run_name) or config['sourceRun']==run_name:raise ValueError('Choose a separate nebula-v17-... run name')
    if not 0<hours<=8 or device not in ['cuda','cpu']:raise ValueError('Invalid session configuration')
    project=Path(project);project.mkdir(parents=True,exist_ok=True);folder=project/'raw-data';folder.mkdir(exist_ok=True)
    os.environ['NEBULA_RULES_FILE']=str(project/'nebula-rules.json')
    deadline=time.monotonic()+hours*3600;torch.set_num_threads(2)
    store=Store(os.environ['NEBULA_HF_REPO'],os.environ['NEBULA_HF_TOKEN'],run_name);state=store.state()
    if state and (state.get('format')!=FORMAT or state.get('config')!=config or state.get('engineSha256')!=raw_hash()):
        raise ValueError('Raw settings/code changed: keep old settings to resume or choose a NEW RAW_RUN_NAME')
    emit(rawPipelineAudit=audit())
    if state is None:
        previous=Store(store.repo,store.token,config['sourceRun']);old=previous.state() or {}
        if not old.get(config['sourceKey']):raise RuntimeError('Requested protected checkpoint is not available')
        source=previous.download(old[config['sourceKey']],project/'protected-source.pt')
        rules=project/'nebula-rules.json'
        state=store.publish({'format':FORMAT,'config':config,'engineSha256':raw_hash(),
             'sourceSha256':old[config['sourceKey']]['sha256'],'sourceRevision':previous.revision,
             'phase':'preparation','publicAutoUpdate':False,'qualityApproved':False,'evaluations':{}},
             {'protectedSource':(source,'protected-source.pt'),'rules':(rules,'nebula-rules.json')},project)
    store.download(state['rules'],project/'nebula-rules.json')
    if state['phase']=='complete':
        path=store.download(state['dashboard'],project/'raw-dashboard.json');print(path.read_text(),flush=True);return
    if not local_corpus_ready(folder,config,state.get('preparedTextBytes',0)):
        for key,name in [('rawTrain','train.bin'),('rawValidation','validation.bin'),('rawIndex','documents.sqlite'),('rawManifest','manifest.json')]:
            if state.get(key):store.download(state[key],folder/name)
    if state['phase']=='preparation':
        # Retain the actual pinned dataset cards alongside source provenance.
        cards(project/'raw-licenses')
        last_cloud=state.get('preparedTextBytes',0)
        def backup_data(path,manifest):
            nonlocal state,last_cloud
            if manifest['textBytes']-last_cloud<8000000 and not manifest['complete']:return
            files={'rawIndex':(path/'documents.sqlite','raw/documents.sqlite'),
                   'rawManifest':(path/'manifest.json','raw/manifest.json')}
            for key,name in [('rawTrain','train.bin'),('rawValidation','validation.bin')]:
                if (path/name).stat().st_size:files[key]=(path/name,'raw/'+name)
            for card in (project/'raw-licenses').glob('*.md'):files[card.stem]=(card,'licenses/'+card.name)
            state=store.publish({**state,'preparedTextBytes':manifest['textBytes']},files,project)
            last_cloud=manifest['textBytes'];emit(rawPreparationBackupConfirmed=True,uniqueUtf8Bytes=last_cloud)
        try:
            manifest=prepare(folder,config,on_save=backup_data,max_seconds=max(1,deadline-time.monotonic()),stop_file=project/'STOP')
        except BaseException:
            # Preserve completed documents even when a source rate-limits or a user interrupts.
            if (folder/'manifest.json').exists():
                value=json.loads((folder/'manifest.json').read_text());last_cloud=-8000000;backup_data(folder,value)
            raise
        if not manifest['complete']:
            last_cloud=-8000000;backup_data(folder,manifest);emit(rawPausedDuringPreparation=True);return
        state=store.publish({**state,'phase':'training'}, {},project)
    if prepare_only or device=='cuda' and not torch.cuda.is_available():
        emit(rawDataReady=True,instructions='Select a GPU and Run all with PREPARE_ONLY=False. No training started.');return
    if (project/'STOP').exists() or time.monotonic()>=deadline:return
    manifest=json.loads((folder/'manifest.json').read_text())
    if not manifest.get('complete'):raise ValueError('Raw corpus is not complete')
    for split,expected in manifest['binarySha256'].items():
        if file_sha256(folder/(split+'.bin'))!=expected:raise ValueError('RAW_PACKED_CORPUS_CHECKSUM_MISMATCH')
    db=sqlite3.connect(folder/'documents.sqlite')
    counts=dict(db.execute('SELECT split,COUNT(*) FROM docs GROUP BY split'));db.close()
    source=store.download(state['protectedSource'],project/'protected-source.pt')
    working=project/'raw-working.pt';resume=store.download(state['working'],working) if state.get('working') else None
    model,_=load(resume or source);model.to(device)
    train=PackedPool(folder/'train.bin',model.config.context,counts.get('train',0))
    validation=PackedPool(folder/'validation.bin',model.config.context,counts.get('validation',0))
    if 'baseline' not in state['evaluations']:
        report=evaluate_raw(model,validation);path=project/'raw-evaluation.json';atomic_json(path,report)
        state=store.publish({**state,'evaluations':{'baseline':report['summary']}},
             {'baselineReport':(path,'reports/baseline.json')},project)
    plan=copy.deepcopy(DEFAULT);plan.update(arms=['current'],stages=['foundation'],seed=config['seed'],
         batch=config['batch'],microbatch=config['microbatch'],warmup=config['warmup'],
         localSaveEvery=config['localSaveEvery'],cloudSaveEvery=config['cloudSaveEvery'])
    plan['steps']['foundation']=config['steps'];plan['learningRates']['foundation']=config['learningRate']
    plan['rawConfig']=config
    rules_sha=hashlib.sha256((project/'nebula-rules.json').read_bytes()).hexdigest()
    def backup_model(path,metadata):
        nonlocal state
        if state.get('progress',{}).get('updates')==metadata['updates'] and state.get('working'):return
        files={'working':(path,'raw-working.pt')};evaluations=state['evaluations']
        if metadata['updates']%config['evaluateEvery']==0 or metadata['updates']>=config['steps']:
            report=evaluate_raw(model,validation);target=project/'raw-evaluation.json';atomic_json(target,report)
            files['latestReport']=(target,'reports/update-'+str(metadata['updates'])+'.json')
            evaluations={**evaluations,str(metadata['updates']):report['summary']}
        state=store.publish({**state,'progress':metadata,'evaluations':evaluations},files,project)
        emit(rawCloudBackupConfirmed=True,updates=metadata['updates'],supervisedTokens=metadata['supervisedTokens'],publicWebsiteUpdated=False)
    try:
        metadata=fit(model,{'language':train},'foundation',working,plan=plan,resume=resume,
            source_sha=state['sourceSha256'],dataset_sha=digest({'manifest':manifest,'engine':raw_hash()}),
            rules_sha=rules_sha,max_seconds=max(1,deadline-time.monotonic()),callback=backup_model,stop_file=project/'STOP')
        complete=metadata['updates']>=config['steps']
        if complete:
            model.cpu();save(model,project/'raw-final.pt',metadata)
        dashboard={'format':FORMAT,'status':'complete' if complete else 'paused','uniqueUtf8Bytes':manifest['textBytes'],
            'trainDocuments':counts.get('train',0),'validationDocuments':counts.get('validation',0),
            'updates':metadata['updates'],'inputPositions':metadata['inputPositions'],'supervisedTokens':metadata['supervisedTokens'],
            'sourceMix':manifest['sources'],'evaluations':state['evaluations'],'publicWebsiteUpdated':False,'qualityApproved':False,
            'notice':'Raw bytes acquired and training exposure are different counters. Repeated exposure included in supervisedTokens. This is language pretraining, not a chat-quality guarantee.'}
        atomic_json(project/'raw-dashboard.json',dashboard)
        files={'dashboard':(project/'raw-dashboard.json','reports/dashboard.json')}
        if complete:files['finalWeights']=(project/'raw-final.pt','raw-final.pt')
        state=store.publish({**state,'phase':'complete' if complete else 'training'},files,project)
        emit(rawSession=dashboard,checkpointBackupConfirmed=True)
    except KeyboardInterrupt:
        emit(rawPaused=True,instructions='Run all resumes the last confirmed private checkpoint.');return
    finally:
        train.close();validation.close();del model;gc.collect()
        if torch.cuda.is_available():torch.cuda.empty_cache()
