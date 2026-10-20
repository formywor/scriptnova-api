"""Bounded full-chat comparison; preserve V14 and never publish to public users."""
import argparse,json,os,time,gc,math,subprocess,sys,signal
from pathlib import Path
import torch
from v10_store import Store
from research_client import ResearchError
from kaggle_migrate import restore_data
from research_worker import configure_rules
from nebula import load,save
from v6_experiment import compact
from v13_data import atomic_json,digest
from v14_eval import evaluate
from v15_data import acquire
from v15_compare import decision

RUN='nebula-v15-full-chats'
VERSION='nebula-v15-full-chats-1'
PLAN={'updatesPerArm':200,'chunk':100,'targetChats':20000,'batch':16,'lr':.000005,'warmup':25,'samplingSeed':14014,'probeSeed':0}

def fresh(source,destination):
    model,meta=load(source)
    # New experiment optimizer, same exact trained weights; keep inherited global step count.
    save(model,destination,{'steps':meta.get('steps',0),'v15OriginMetadata':meta,'experimental':True,'qualityApproved':False})
    return destination

def initialize(store,project,plan):
    previous=Store(store.repo,store.token,'nebula-v14-foundation');old=previous.state()
    if not old or old.get('phase')!='complete' or not old.get('conversationFinal'):raise ResearchError('V15_COMPLETED_V14_REQUIRED')
    mapping={'sourceData':'sourceData','startingWeights':'conversationFinal','filteredData':'conversationData','validationData':'conversationValidation','fixedValidation':'sourceFixedValidation','publicHoldout':'sourcePublicHoldout','licenseTexts':'licenseTexts'}
    paths={}
    for key,sourcekey in mapping.items():paths[key]=previous.download(old[sourcekey],project/('source-'+key+('.pt' if key in ['sourceData','startingWeights'] else '.jsonl' if 'Data' in key or 'Validation' in key or key=='publicHoldout' else '.json')))
    restore_data(paths['sourceData'],project);configure_rules(project)
    initial=fresh(paths['startingWeights'],project/'initial.pt')
    state={'format':VERSION,'phase':'preparation','plan':plan,'sourceRevision':previous.revision,'sourceRun':previous.prefix,'publicAutoUpdate':False,'qualityApproved':False,'armSteps':{'filtered':0,'full':0},'chunk':0,'semanticScreening':False,'baselineComplete':False,'reports':{},'dataRetention':'pending'}
    files={k:(v,'source/'+v.name) for k,v in paths.items()};files['initial']=(initial,'initial.pt')
    return store.publish(state,files,project)

def prepare(store,state,project):
    folder=project/'full-data';folder.mkdir(exist_ok=True)
    for key,name in [('candidateData','full-pool.jsonl'),('acquisitionMetadata','acquisition.json')]:
        if state.get(key):store.download(state[key],folder/name)
    held=[]
    for key in ['validationData','fixedValidation','publicHoldout']:held.append(store.download(state[key],project/(key+'.jsonl')))
    def backup(path,metadata):
        nonlocal state
        files={'acquisitionMetadata':(metadata,'data/acquisition.json')}
        if path.stat().st_size:files['candidateData']=(path,'data/full-chats.jsonl')
        state=store.publish(state,files,project)
        print(json.dumps({'v15PreparationBackupConfirmed':True,'fullChatBytes':path.stat().st_size,'publicWebsiteUpdated':False}),flush=True)
    rows,metadata=acquire(folder,held,target=state['plan']['targetChats'],on_save=backup)
    state=store.publish({**state,'phase':'filtered','fullChatCount':len(rows),'acquisitionSummary':metadata}, {},project)
    del rows;gc.collect();return state

def launch(project,resume,output,data,validation,steps,plan,max_seconds):
    command=[sys.executable]
    if torch.cuda.device_count()>1:command+=['-m','torch.distributed.run','--standalone','--nproc_per_node','2']
    command+=[str(Path(__file__).with_name('v15_train.py')),'--stage','conversation','--data',str(data),'--validation-data',str(validation),'--resume',str(resume),'--output',str(output),'--steps',str(steps),'--stage-budget',str(plan['updatesPerArm']),'--batch',str(plan['batch']),'--lr',str(plan['lr']),'--warmup',str(plan['warmup']),'--seed',str(plan['samplingSeed']),'--max-seconds',str(max_seconds),'--save-every','50']
    process=subprocess.Popen(command,cwd=project,start_new_session=os.name!='nt')
    try:code=process.wait()
    except BaseException:
        if process.poll() is None:
            if os.name!='nt':os.killpg(process.pid,signal.SIGTERM)
            else:process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if os.name!='nt':os.killpg(process.pid,signal.SIGKILL)
                else:process.kill()
                process.wait()
        raise
    if code:raise ResearchError('V15_TRAINING_INTERRUPTED_RESUME_CONFIRMED_BACKUP')

def save_chunk(store,state,arm,output,project):
    payload=torch.load(output,map_location='cpu',weights_only=True);meta=payload['metadata'];del payload
    count=meta.get('stageSteps',0)
    if not state['armSteps'][arm]<count<=state['plan']['updatesPerArm'] or not math.isfinite(meta.get('validationLoss',float('nan'))):raise ResearchError('V15_INVALID_CHECKPOINT_PROGRESS')
    checkpoint=compact(output,project/(arm+'-weights.pt'));report=project/'training-report.json';atomic_json(report,meta)
    counts={**state['armSteps'],arm:count};files={arm+'Working':(output,arm+'-working.pt'),arm+'Weights':(checkpoint,arm+'-weights.pt'),arm+'TrainingReport':(report,'reports/'+arm+'-training.json')}
    result=store.publish({**state,'armSteps':counts,'chunk':state['chunk']+1,'publicAutoUpdate':False},files,project)
    print(json.dumps({'v15ArmSaved':arm,'updates':count,'budget':state['plan']['updatesPerArm'],'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    return result

def remove_candidate_copy(store,state,project):
    """Remove only this run's active new corpus; older runs and HF history remain."""
    if state.get('decision',{}).get('dataAction')!='remove':raise ValueError('No regression decision authorizes removal')
    entry=state.get('candidateData')
    if not entry:return state
    paths=[p['path'] for p in entry['parts']] if 'parts' in entry else [entry['path']]
    expected=store.prefix+'data/full-chats.jsonl'
    if any(p!=expected and not (p.startswith(expected+'.part') and p[len(expected+'.part'):].isdigit()) for p in paths):raise ValueError('V15 candidate path outside authorized corpus')
    from huggingface_hub import CommitOperationAdd,CommitOperationDelete
    value={**state,'dataRetention':'removed-from-active-experiment','dataRemovedSha256':entry['sha256']};value.pop('candidateData',None)
    target=project/'removed-candidate-state.json';atomic_json(target,value);store.info()
    operations=[CommitOperationDelete(path_in_repo=p) for p in paths]+[CommitOperationAdd(path_in_repo=store.prefix+'state.json',path_or_fileobj=str(target))]
    try:result=store.api.create_commit(repo_id=store.repo,operations=operations,parent_commit=store.revision,commit_message='Exclude regressing V15 full-chat data')
    except Exception:raise ResearchError('V15_DATA_REMOVAL_PENDING_RETRY') from None
    store.revision=result.oid
    # Only experiment-owned local corpus copies are removed; reports/weights retained.
    for path in [project/'full-data/full-pool.jsonl',project/'full-train.jsonl']:
        if path.is_file():path.unlink()
    return value

def compare(store,state,project):
    reports={}
    for arm,key in [('baseline','baselineReport'),('filtered','filteredReport'),('full','fullReport')]:
        path=store.download(state[key],project/(arm+'-comparison.json'));reports[arm]=json.loads(path.read_text(encoding='utf-8'))
    value=decision(reports['baseline'],reports['filtered'],reports['full']);path=project/'comparison.json';atomic_json(path,value)
    state=store.publish({**state,'decision':value,'phase':'complete','dataRetention':'keep'}, {'comparison':(path,'reports/comparison.json')},project)
    if value['dataAction']=='remove':state=remove_candidate_copy(store,state,project)
    print(json.dumps({'v15Comparison':value,'checkpointBackupConfirmed':True}),flush=True);return state

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--project',type=Path,required=True);parser.add_argument('--hours',type=float,default=2)
    parser.add_argument('--updates',type=int,default=200);parser.add_argument('--target-chats',type=int,default=20000);parser.add_argument('--prepare-only',action='store_true')
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 100<=args.updates<=2000 or not 100<=args.target_chats<=50000:parser.error('Use bounded pilot settings')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);deadline=time.monotonic()+args.hours*3600;torch.set_num_threads(2)
    plan={**PLAN,'updatesPerArm':args.updates,'targetChats':args.target_chats}
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),RUN);state=store.state()
    if state and (state.get('format')!=VERSION or state.get('plan')!=plan):raise ResearchError('V15_RESUME_WITH_SAME_PLAN')
    if not state:state=initialize(store,project,plan)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    if state['phase']=='preparation':state=prepare(store,state,project)
    if args.prepare_only:print('V15 public data is prepared. No training started.');return
    if state['phase']=='complete':
        if state.get('decision',{}).get('dataAction')=='remove' and state.get('candidateData'):state=remove_candidate_copy(store,state,project)
        print(json.dumps({'v15AlreadyComplete':True,'dataRetention':state['dataRetention'],'publicWebsiteUpdated':False}));return
    if state['phase']=='compare':
        compare(store,state,project);return
    if not torch.cuda.is_available():raise ResearchError('V15_DATA_READY_ENABLE_GPU_TO_TRAIN')
    if not state.get('baselineComplete'):
        initial=store.download(state['initial'],project/'initial.pt');path=project/'baseline-probes.json';evaluate(initial,path,'v15-starting-control',0)
        state=store.publish({**state,'baselineComplete':True},{'baselineReport':(path,'reports/baseline.json')},project)
    try:
        while state['phase']!='complete' and time.monotonic()<deadline:
            if (project/'STOP_AFTER_CHUNK').exists():break
            arm=state['phase']
            if arm=='compare':state=compare(store,state,project);continue
            if state['armSteps'][arm]>=plan['updatesPerArm']:
                weights=store.download(state[arm+'Weights'],project/(arm+'-weights.pt'));path=project/(arm+'-probes.json');evaluate(weights,path,'v15-'+arm,0)
                state=store.publish({**state,'phase':'full' if arm=='filtered' else 'compare'}, {arm+'Report':(path,'reports/'+arm+'-probes.json')},project);continue
            resume_key=arm+'Working' if state['armSteps'][arm] else 'initial'
            resume=store.download(state[resume_key],project/'resume.pt');data=store.download(state['filteredData' if arm=='filtered' else 'candidateData'],project/(arm+'-train.jsonl'));valid=store.download(state['validationData'],project/'valid.jsonl')
            output=project/'round.pt';steps=min(plan['chunk'],plan['updatesPerArm']-state['armSteps'][arm])
            launch(project,resume,output,data,valid,steps,plan,max(1,min(7200,deadline-time.monotonic())))
            state=save_chunk(store,state,arm,output,project);gc.collect();torch.cuda.empty_cache()
    except KeyboardInterrupt:print('Resume from the latest confirmed V15 backup with the same settings.',flush=True)
    print(json.dumps({'v15SessionFinished':True,'phase':state['phase'],'armSteps':state['armSteps'],'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':main()
