"""Reusable Colab lab: configurable runs, protected controls, staged private backups."""
import gc
import hashlib
import json
import math
import os
import re
import time
from collections import Counter
from pathlib import Path
import torch
from nebula import Nebula, Config, load, save
from v10_store import Store
from v16_diagnostic import audit, atomic_json, emit
from v17_data import VERSION, curriculum, digest, public_pools, Pool
from v17_train import fit, evaluate, code_hash

DEFAULT = {'seed':17017,'sourceRun':'nebula-v15-full-chats','sourceKey':'fullWeights','arms':['current','fresh'],
           'stages':['foundation','context','conversation'],
           'steps':{'foundation':1000,'context':1500,'conversation':1000},
           'learningRates':{'foundation':.00003,'context':.0001,'conversation':.00002},
           'batch':8,'microbatch':1,'warmup':100,'localSaveEvery':50,'cloudSaveEvery':250,
           'contextScenarios':4000,'publicRecords':6000,'casesPerAxis':12,
           'conversationPercent':80}


def validate(plan):
    if set(plan)!=set(DEFAULT):raise ValueError('Unsupported setting; use the documented CONFIG keys')
    if not isinstance(plan['sourceRun'],str) or not re.fullmatch(r'nebula-[a-zA-Z0-9_-]{1,55}',plan['sourceRun']):raise ValueError('Invalid sourceRun')
    if not isinstance(plan['sourceKey'],str) or not re.fullmatch(r'[a-zA-Z][\w-]{0,90}',plan['sourceKey']):raise ValueError('Invalid sourceKey')
    if not plan['arms'] or len(plan['arms'])!=len(set(plan['arms'])) or any(a not in ['current','fresh'] for a in plan['arms']):raise ValueError('Invalid arms')
    if not plan['stages'] or len(plan['stages'])!=len(set(plan['stages'])) or any(s not in DEFAULT['stages'] for s in plan['stages']):raise ValueError('Invalid stages')
    for key,low,high in [('seed',0,2**31),('batch',1,32),('microbatch',1,8),('warmup',1,2000),
        ('localSaveEvery',1,1000),('cloudSaveEvery',1,2000),('contextScenarios',100,50000),
        ('publicRecords',20,50000),('casesPerAxis',2,100),('conversationPercent',0,100)]:
        if type(plan[key]) is not int or not low<=plan[key]<=high:raise ValueError('Invalid '+key)
    if plan['microbatch']>plan['batch']:raise ValueError('Microbatch exceeds batch')
    if set(plan['steps'])!=set(DEFAULT['steps']) or set(plan['learningRates'])!=set(DEFAULT['steps']):raise ValueError('Each stage needs a step budget and learning rate')
    for key in DEFAULT['stages']:
        if type(plan['steps'][key]) is not int or not 1<=plan['steps'][key]<=100000:raise ValueError('Invalid step budget')
        lr=plan['learningRates'][key]
        if type(lr) not in (int,float) or not math.isfinite(lr) or not 0<lr<=.001:raise ValueError('Invalid learning rate')
    return plan


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def source_file(previous, state, key, project, name):
    if not state.get(key):raise RuntimeError('Required saved public source is missing: '+key)
    return previous.download(state[key],project/name)


def initialize(store, project, plan):
    source_store=Store(store.repo,store.token,plan['sourceRun']);old=source_store.state() or {}
    v14=Store(store.repo,store.token,'nebula-v14-foundation');prior=v14.state() or {}
    source=source_file(source_store,old,plan['sourceKey'],project,'protected-source.pt')
    files={'protectedSource':(source,'source/protected-source.pt')}
    for key in ['foundationData','foundationValidation','conversationData','conversationValidation','licenseTexts']:
        path=source_file(v14,prior,key,project,key+'.json' if key=='licenseTexts' else key+'.jsonl')
        files[key]=(path,'data/source-'+path.name)
    records=curriculum(plan['contextScenarios'],plan['seed'],plan['casesPerAxis'])
    pools=public_pools(jsonl(files['foundationData'][0]),jsonl(files['foundationValidation'][0]),
                       jsonl(files['conversationData'][0]),jsonl(files['conversationValidation'][0]),
                       plan['publicRecords'],records['tests'],plan['seed'])
    dataset={**records,**pools}
    path=project/'lab-data.json';atomic_json(path,dataset)
    manifest={'format':VERSION,'dataSha256':digest(dataset),'sourceRevisions':{'publicDataV14':v14.revision,'weights':source_store.revision},
              'sourceRun':plan['sourceRun'],'sourceKey':plan['sourceKey'],
              'records':{k:len(dataset[k]) for k in ['training','validation','tests','language','languageValidation','public','publicValidation']},
              'languageSources':dict(Counter(r['source']['dataset'] for r in pools['language'])),
              'conversationComponents':dict(Counter(str(r['source'].get('component') or r['source']['dataset']) for r in pools['public'])),
              'rulesSha256':hashlib.sha256((project/'nebula-rules.json').read_bytes()).hexdigest(),
              'screening':'Reuse structurally screened public V14 records, exact deduplication and reserved source identities/openings. Not individually fact-checked. No private user messages.',
              'dataUse':'Whole records retained. Language windows use real document EOS; assistant-only chat windows retain every target byte.',
              'licenses':'Original source terms remain in source-licenseTexts.json; this manifest does not relicense them.'}
    atomic_json(project/'data-manifest.json',manifest)
    files.update({'data':(path,'data/lab-data.json'),'dataManifest':(project/'data-manifest.json','data/manifest.json'),
                  'rules':(project/'nebula-rules.json','data/nebula-rules.json')})
    state={'format':VERSION,'plan':plan,'engineSha256':code_hash(),'dataSha256':digest(dataset),
           'sourceSha256':old[plan['sourceKey']]['sha256'],
           'taskIndex':0,'reports':{},'phase':'running','publicAutoUpdate':False,'qualityApproved':False}
    result=store.publish(state,files,project)
    emit(v17DataPrepared=manifest,checkpointBackupConfirmed=True)
    return result


def write_dashboard(project, state):
    rows=[]
    for name,report in state['reports'].items():
        rows.append({'checkpoint':name,**report})
    progress=list(state.get('completedTasks',{}).values())
    if state.get('activeTask') and state.get('progress'):progress.append(state['progress'])
    totals={key:sum(r.get(key,0) for r in progress) for key in ['updates','inputPositions','supervisedTokens']}
    result={'format':VERSION,'status':state['phase'],'results':rows,'v17Totals':totals,
            'counterNotice':'V17 only, summed across both arms and completed/current stages. Repeated exposure included; validation and previous-version training excluded.',
            'publicWebsiteUpdated':False,'qualityApproved':False,
            'interpretation':'Compare per-axis exact answers AND actual open replies with each arm baseline. Low validation loss or a high copy-task score does not establish conversational ability.',
            'nextRun':'Keep RUN_NAME/config for resume. For changed settings choose a new RUN_NAME; sourceRun/sourceKey can select this run and a completed stage key such as current-conversationWeights. New experiments start fresh optimizer schedules from those weights. GPU quotas still apply.'}
    path=project/'dashboard.json';atomic_json(path,result)
    return path,result


def main(project, run_name='nebula-v17-lab', plan=None, hours=2, device='cuda'):
    plan=validate(json.loads(json.dumps(DEFAULT if plan is None else plan)))
    if not re.fullmatch(r'nebula-v17-[a-zA-Z0-9_-]{1,45}',run_name):raise ValueError('Use a new nebula-v17-... name for each changed configuration')
    if plan['sourceRun']==run_name:raise ValueError('Source run must be a different preserved experiment')
    if not 0<hours<=8:raise ValueError('Session limit must be at most eight hours')
    if device not in ['cpu','cuda']:raise ValueError('Unsupported device')
    if device=='cuda' and not torch.cuda.is_available():raise RuntimeError('Choose a GPU runtime. CPU data preparation is not enabled in this lab.')
    project=Path(project);project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    deadline=time.monotonic()+hours*3600
    os.environ['NEBULA_RULES_FILE']=str(project/'nebula-rules.json')
    store=Store(os.environ['NEBULA_HF_REPO'],os.environ['NEBULA_HF_TOKEN'],run_name)
    state=store.state()
    if state and (state['format']!=VERSION or state['plan']!=plan or state['engineSha256']!=code_hash()):
        raise ValueError('Settings/code changed: keep old settings to resume, or set a NEW RUN_NAME. Existing runs were preserved.')
    checks=audit();emit(v17PipelineAudit=checks)
    if not state:state=initialize(store,project,plan)
    store.download(state['rules'],project/'nebula-rules.json')
    data=json.loads(store.download(state['data'],project/'lab-data.json').read_text(encoding='utf-8'))
    if digest(data)!=state['dataSha256']:raise ValueError('Dataset fingerprint mismatch')
    rules_sha=hashlib.sha256((project/'nebula-rules.json').read_bytes()).hexdigest()
    queue=[(a,s) for a in plan['arms'] for s in plan['stages']]
    if state['phase']=='complete':
        _,dashboard=write_dashboard(project,state);emit(v17AlreadyComplete=dashboard);return
    try:
        while state['taskIndex']<len(queue):
            if (project/'STOP').exists() or time.monotonic()>=deadline:break
            arm,stage=queue[state['taskIndex']];task=arm+'-'+stage
            working=project/'working.pt';resume=None
            if state.get('activeTask')==task and state.get('working'):
                resume=store.download(state['working'],working);model,_=load(resume)
            elif stage==plan['stages'][0]:
                source=store.download(state['protectedSource'],project/'protected-source.pt')
                original,_=load(source);config=original.config
                if arm=='current':model=original
                else:
                    del original;gc.collect();torch.manual_seed(plan['seed']);model=Nebula(config)
            else:
                previous=store.download(state[state['lastWeightKey']],project/'previous-stage.pt');model,_=load(previous)
            model.to(device)
            pools={'language':Pool(data['language'],model.config.context,True),
                   'context':Pool(data['training'],model.config.context),
                   'public':Pool(data['public'],model.config.context)}
            validation={'language':Pool(data['languageValidation'],model.config.context,True).validation(),
                        'context':Pool(data['validation'],model.config.context).validation(),
                        'public':Pool(data['publicValidation'],model.config.context).validation()}
            if arm+'-baseline' not in state['reports']:
                report=evaluate(model,data['tests'],validation);path=project/'evaluation.json';atomic_json(path,report)
                reports={**state['reports'],arm+'-baseline':report['summary']}
                state=store.publish({**state,'reports':reports}, {arm+'Baseline':(path,'reports/'+arm+'-baseline.json')},project)
            def backup(path,metadata):
                nonlocal state
                if state.get('activeTask')==task and state.get('progress',{}).get('updates')==metadata['updates'] and state.get('working'):return
                state=store.publish({**state,'activeTask':task,'progress':metadata}, {'working':(path,'working.pt')},project)
                emit(v17CloudBackupConfirmed=True,arm=arm,stage=stage,updates=metadata['updates'],publicWebsiteUpdated=False)
            emit(v17Task=task,taskNumber=state['taskIndex']+1,totalTasks=len(queue),parameters=sum(p.numel() for p in model.parameters()))
            meta=fit(model,pools,stage,working,plan=plan,resume=resume,
                     source_sha=state['sourceSha256']+':'+arm,dataset_sha=state['dataSha256'],rules_sha=rules_sha,
                     max_seconds=max(1,deadline-time.monotonic()),callback=backup,stop_file=project/'STOP')
            del pools;gc.collect();torch.cuda.empty_cache()
            if meta['updates']<plan['steps'][stage]:
                del model;gc.collect();torch.cuda.empty_cache();break
            report=evaluate(model,data['tests'],validation);path=project/'evaluation.json';atomic_json(path,report)
            # Retain a compact per-stage snapshot as well as the current optimizer checkpoint.
            model.cpu();final=project/'stage-weights.pt';save(model,final,meta)
            totals={**state.get('completedTasks',{}),task:meta}
            reports={**state['reports'],task:report['summary']}
            next_state={**state,'completedTasks':totals,'reports':reports,'taskIndex':state['taskIndex']+1,'lastWeightKey':task+'Weights'}
            next_state.pop('activeTask',None);next_state.pop('working',None);next_state.pop('progress',None)
            state=store.publish(next_state,{task+'Weights':(final,'weights/'+task+'.pt'),
                  task+'Evaluation':(path,'reports/'+task+'.json')},project)
            # No rollback to a lower-loss model. Each stage continues from the preceding final weights.
            del model;gc.collect();torch.cuda.empty_cache()
            emit(v17StageCompleted=task,taskIndex=state['taskIndex'],checkpointBackupConfirmed=True)
        if state['taskIndex']==len(queue):state={**state,'phase':'complete'}
        path,dashboard=write_dashboard(project,state)
        state=store.publish(state,{'dashboard':(path,'reports/dashboard.json')},project)
        emit(v17Session=dashboard,checkpointBackupConfirmed=True)
    except KeyboardInterrupt:
        emit(v17Paused=True,instructions='Wait for CloudBackupConfirmed before disconnecting. Run all resumes the same run.');return
