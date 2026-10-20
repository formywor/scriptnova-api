"""Isolated V14 foundation -> conversation experiment; no production publishing."""
import argparse,gc,json,math,os,signal,subprocess,sys,time
from pathlib import Path
import torch
from dataflow import read_jsonl
from kaggle_migrate import restore_data
from research_worker import configure_rules
from research_client import ResearchError
from v10_store import Store
from v6_experiment import compact
from v13_data import acquire,atomic_json,digest
from v14_data import prepare
from v14_eval import evaluate

RUN='nebula-v14-foundation'
VERSION='nebula-v14-foundation-1'
TARGETS={'stories':10000,'cosmopedia':4000,'fineweb':4000}
DEFAULT_PLAN={'foundationSteps':4000,'conversationSteps':1200,'batch':16,'foundationLR':.00003,'conversationLR':.000005,'warmup':100,'chunk':500,'targets':TARGETS,'scenarios':1000}

def initialize(store,project,plan):
    previous=Store(store.repo,store.token,'nebula-v13-four-sources');old=previous.state()
    if not old or not old.get('best') or not old.get('data'):raise ResearchError('V14_SAVED_V13_REQUIRED')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    control=previous.download(old['best'],project/'preserved-v13-best.pt')
    base=previous.download(old['data'],project/'source-conversations.jsonl');fixed=previous.download(old['validationData'],project/'source-fixed-validation.jsonl')
    public_heldout=previous.download(old['newPublicHoldout'],project/'source-public-heldout.jsonl')
    licenses=previous.download(old['licenseTexts'],project/'licenses.json')
    # Reuse source downloads without writing anything to V13's preparation snapshot.
    folder=project/'public-corpus';folder.mkdir(exist_ok=True)
    stage=Store(store.repo,store.token,RUN+'-preparation');prepared=stage.state()
    from_previous=not prepared
    if from_previous:
        stage_source=Store(store.repo,store.token,'nebula-v13-four-sources-preparation');prepared=stage_source.state() or {}
    else:stage_source=stage
    allowed={k+s for k in TARGETS for s in ['.json','.jsonl']}
    files=prepared.get('preparationFiles') or {k:v for k,v in prepared.items() if k in allowed}
    for key,entry in files.items():
        if key in allowed:stage_source.download(entry,folder/key)
    def backup():
        files={p.name:(p,'public/'+p.name) for p in folder.iterdir() if p.name in allowed and p.stat().st_size}
        stage.publish({'format':'nebula-v14-preparation-1','publicAutoUpdate':False},files,project)
        print(json.dumps({'v14PreparationBackupConfirmed':True,'oldRunsUntouched':True}),flush=True)
    try:acquisition=acquire(folder,targets=plan['targets'],kinds=set(TARGETS),on_source=backup)
    except Exception:
        backup();raise ResearchError('V14_PUBLIC_DOWNLOAD_PENDING_RETRY_LATER') from None
    texts=[]
    for key in TARGETS:texts.extend(read_jsonl(folder/(key+'.jsonl')))
    data=project/'model/data/v14';summary=prepare(base,fixed,public_heldout,texts,data,scenarios=plan['scenarios'])
    summary['acquisition']=acquisition;atomic_json(data/'manifest.json',summary)
    original_licenses=json.loads(licenses.read_text(encoding='utf-8'))
    atomic_json(licenses,{'originalAttribution':original_licenses,'v14Processing':summary,'notice':'Filtered and normalized source excerpts; original source licenses and conditions remain applicable. Generated context exercises are owned programmatically checked examples.'})
    file_map={'sourceData':(source,'source-data.pt'),'control':(control,'preserved-v13-best.pt'),'working':(compact(control,project/'initial-working.pt'),'working.pt'),
      'foundationData':(data/'foundation.jsonl','data/foundation.jsonl'),'foundationValidation':(data/'foundation-valid.jsonl','data/foundation-valid.jsonl'),
      'conversationData':(data/'conversation.jsonl','data/conversation.jsonl'),'conversationValidation':(data/'conversation-valid.jsonl','data/conversation-valid.jsonl'),
      'dataManifest':(data/'manifest.json','data/manifest.json'),'licenseTexts':(licenses,'data/licenses.json'),'sourceFixedValidation':(fixed,'data/source-fixed-validation.jsonl'),'sourcePublicHoldout':(public_heldout,'data/source-public-heldout.jsonl')}
    state={'format':VERSION,'phase':'foundation','stageSteps':0,'chunk':0,'plan':plan,'sourceRun':previous.prefix,'sourceRevision':previous.revision,'sourceRound':old['round'],
      'sourceCheckpoint':'verified-saved-best','sourceVerifiedReport':old.get('bestReport'),'publicAutoUpdate':False,'qualityApproved':False,'dataSummary':summary,'baselineProbeComplete':False,'oldModelImitationPenalty':0,'tokenizerUnchanged':True}
    store.revision=stage.revision
    result=store.publish(state,file_map,project)
    print(json.dumps({'v14Initialized':True,'phase':'foundation','source':'V13 protected saved best','architectureUnchanged':True,'optimizer':'fresh for new phase objective','checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    return result

def launch(project,resume,output,data,validation,phase,steps,plan,gpus,max_seconds):
    command=[sys.executable]
    if gpus>1:command+=['-m','torch.distributed.run','--standalone','--nproc_per_node',str(gpus)]
    command+=[str(Path(__file__).with_name('v14_train.py')),'--stage',phase,'--data',str(data),'--validation-data',str(validation),'--resume',str(resume),'--output',str(output),
      '--steps',str(steps),'--stage-budget',str(plan[phase+'Steps']),'--batch',str(plan['batch']),'--lr',str(plan[phase+'LR']),'--warmup',str(plan['warmup']),'--max-seconds',str(max_seconds),'--save-every','100']
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
    if code:raise ResearchError('V14_TRAINING_PROCESS_STOPPED_USE_CONFIRMED_BACKUP')

def save_chunk(store,state,output,project):
    """Always retain the completed trajectory; never substitute early candidates."""
    payload=torch.load(output,map_location='cpu',weights_only=True);metadata=payload['metadata'];del payload
    if metadata.get('v14Stage')!=state['phase'] or not state['stageSteps']<metadata.get('stageSteps',0)<=state['plan'][state['phase']+'Steps'] or not math.isfinite(metadata.get('validationLoss',float('nan'))):raise ResearchError('V14_CHECKPOINT_PROGRESS_INVALID')
    report=project/'training-report.json';atomic_json(report,metadata)
    phase=state['phase'];files={'working':(output,'working.pt'),'latest':(compact(output,project/'latest-weights.pt'),'latest.pt'),'trainingReport':(report,f'reports/chunk-{state["chunk"]+1:04d}.json')}
    best=state.get(phase+'BestLoss')
    next_state={**state,'stageSteps':metadata['stageSteps'],'chunk':state['chunk']+1,'lastTrainingReport':metadata,'publicAutoUpdate':False,'qualityApproved':False}
    if best is None or metadata['validationLoss']<best:
        next_state[phase+'BestLoss']=metadata['validationLoss'];files[phase+'LowestLoss']=(files['latest'][0],phase+'-lowest-loss.pt')
    # This diagnostic reference is never used to roll back working optimizer state.
    result=store.publish(next_state,files,project)
    print(json.dumps({'v14ChunkSaved':result['chunk'],'phase':phase,'stageSteps':result['stageSteps'],'workingUsesFinalCheckpoint':True,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    return result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--project',type=Path,required=True);parser.add_argument('--hours',type=float,default=8)
    parser.add_argument('--foundation-steps',type=int,default=4000);parser.add_argument('--conversation-steps',type=int,default=1200);parser.add_argument('--chunk',type=int,default=500)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 100<=args.foundation_steps<=20000 or not 100<=args.conversation_steps<=10000 or not 100<=args.chunk<=1000:parser.error('Use bounded hours, phase budgets, and chunks')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);deadline=time.monotonic()+args.hours*3600;torch.set_num_threads(2)
    plan={**DEFAULT_PLAN,'foundationSteps':args.foundation_steps,'conversationSteps':args.conversation_steps,'chunk':args.chunk}
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),RUN);state=store.state()
    if state and (state.get('format')!=VERSION or state.get('plan')!=plan):raise ResearchError('V14_PLAN_CHANGED_USE_SAME_SETTINGS_TO_RESUME')
    if not state:state=initialize(store,project,plan)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    if not state.get('baselineProbeComplete'):
        control=store.download(state['control'],project/'preserved-v13-best.pt');destination=project/'baseline-probes.json'
        evaluate(control,destination,'preserved-control',0)
        state=store.publish({**state,'baselineProbeComplete':True},{'baselineProbes':(destination,'reports/baseline-probes.json')},project)
    try:
        while state['phase']!='complete' and time.monotonic()<deadline:
            if (project/'STOP_AFTER_CHUNK').exists():break
            phase=state['phase'];budget=plan[phase+'Steps']
            if state['stageSteps']>=budget:
                final=store.download(state['latest'],project/(phase+'-final.pt'));destination=project/(phase+'-final-probes.json')
                evaluate(final,destination,phase,state['chunk'])
                files={phase+'Final':(final,phase+'-final.pt'),phase+'FinalProbes':(destination,'reports/'+phase+'-final-probes.json')}
                state=store.publish({**state,'phase':'conversation' if phase=='foundation' else 'complete','stageSteps':0,phase+'CompletedSteps':state['stageSteps']},files,project)
                print(json.dumps({'v14PhaseCompleted':phase,'nextPhase':state['phase'],'checkpointBackupConfirmed':True,'semanticQualityCertified':False,'publicWebsiteUpdated':False}),flush=True)
                continue
            working=store.download(state['working'],project/'resume-working.pt')
            data=store.download(state[phase+'Data'],project/(phase+'-train.jsonl'));valid=store.download(state[phase+'Validation'],project/(phase+'-valid.jsonl'))
            steps=min(plan['chunk'],budget-state['stageSteps']);output=project/'round.pt'
            launch(project,working,output,data,valid,phase,steps,plan,min(2,torch.cuda.device_count()),max(1,min(7200,deadline-time.monotonic())))
            state=save_chunk(store,state,output,project)
            if state['stageSteps']%1000==0 and state['stageSteps']<budget:
                destination=project/'progress-probes.json';evaluate(project/'latest-weights.pt',destination,phase,state['chunk'])
                state=store.publish(state,{'progressProbes':(destination,f'reports/probes-{state["chunk"]:04d}.json')},project)
            gc.collect();torch.cuda.empty_cache()
    except KeyboardInterrupt:print('Stopped. Resume the last confirmed V14 backup with the same settings.',flush=True)
    print(json.dumps({'v14SessionFinished':True,'phase':state['phase'],'stageSteps':state['stageSteps'],'savedChunks':state['chunk'],'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':main()
