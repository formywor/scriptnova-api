"""V11: re-grade preserved weights before training; defer uncertain evaluations safely."""
import argparse,gc,json,math,os,tempfile,time
from pathlib import Path
import torch
from dataflow import read_jsonl,write_jsonl
from kaggle_migrate import restore_data
from research_client import Client,ResearchError,digests
from research_worker import configure_rules,launch
from review_feed import refresh_reviews
from v10_data import prompts
from v10_store import Store
from v10_teacher import collect
from v6_experiment import compact
from v11_eval import evaluate
from verified_grading import protocol

VERSION='nebula-v11-verified-1'

def sound(report):
    fields=['loss','health','identity','math','memory','extraction','conversation','chatLoss','chatChecks','chatCases','correct','cases','languageLoss','publicChatLoss','chatHealthy','exactCopyCorrect','contextNameCorrect']
    return report.get('gradingProtocol')==protocol() and report.get('reviewComplete') is True and all(type(report.get(k)) in (int,float) and math.isfinite(report[k]) for k in fields) and report['chatCases']==20

def preserves(base,candidate):
    if not sound(base) or not sound(candidate):return False
    return (candidate['cases']==base['cases'] and candidate['health']>=base['health']-.02 and candidate['chatHealthy']>=base['chatHealthy']
        and candidate['languageLoss']<=base['languageLoss']*1.05 and candidate['publicChatLoss']<=base['publicChatLoss']*1.05
        and candidate['loss']<=base['loss']*1.08 and candidate['correct']>=base['correct']-1
        and all(candidate[k]>=base[k] for k in ['identity','memory','extraction','exactCopyCorrect','contextNameCorrect'])
        and candidate['math']>=base['math']-.05 and candidate['conversation']>=base['conversation'])

def better_best(base,current,candidate):
    return preserves(base,candidate) and candidate['chatLoss']<=current['chatLoss']*1.03 and ((candidate['chatChecks']>current['chatChecks'] and candidate['correct']>=current['correct']) or (candidate['correct']>current['correct'] and candidate['chatChecks']>=current['chatChecks']))

def better_working(base,current,best,candidate):
    return preserves(base,candidate) and candidate['chatChecks']>=best['chatChecks'] and candidate['correct']>=current['correct'] and candidate['chatLoss']<current['chatLoss']*.997 and candidate['languageLoss']<=current['languageLoss']*1.03

def initialize(store,project):
    previous=Store(store.repo,store.token,'nebula-v10-dialogue');old=previous.state()
    if not old or not all(old.get(k) for k in ['baseline','best','data','validationData','qualityAnchor']):raise ResearchError('V11_SAVED_V10_REQUIRED')
    files={}
    names={'sourceData':'source-data.pt','data':'model/data/v10-train.jsonl','validationData':'model/data/fixed-validation.jsonl','evaluationData':'model/data/frozen-legacy.jsonl','checks':'model/data/frozen-checks.json','qualityAnchor':'quality-anchor.pt','licenseTexts':'data-licenses.json'}
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    for key,name in names.items():files[key]=(previous.download(old[key],project/name),name)
    # Dataset and anchor bytes remain unchanged, so compatible V10 optimizer states survive.
    reports={};paths={};seen={}
    for key in ['baseline','best','working','latest']:
        if not old.get(key):continue
        path=previous.download(old[key],project/('source-'+key+'.pt'));paths[key]=path
        fingerprint=digests(path)[0]
        if fingerprint in seen:reports[key]=reports[seen[fingerprint]];continue
        report_path=project/('regraded-'+key+'.json')
        reports[key]=evaluate(path,files['evaluationData'][0],files['checks'][0],files['validationData'][0],report_path)
        files['sourceReport-'+key]=(report_path,'reports/source-'+key+'.json');seen[fingerprint]=key
        if not sound(reports[key]):raise ResearchError('V11_INITIAL_REVIEW_PENDING_RETRY_LATER')
    baseline=reports['baseline'];best_key='baseline';working_key='baseline'
    for key in ['best','working','latest']:
        if key in reports and better_best(baseline,reports[best_key],reports[key]):best_key=key
    working_key=best_key
    # Prefer a still-safe accepted optimizer trajectory rather than restarting from compact weights.
    if 'working' in reports:
        candidate=reports['working'];best_report=reports[best_key]
        if preserves(baseline,candidate) and candidate['chatChecks']>=best_report['chatChecks'] and candidate['correct']>=best_report['correct'] and candidate['chatLoss']<=best_report['chatLoss']*1.03:working_key='working'
    teacher=project/'model/data/teacher.jsonl'
    if old.get('teacherData'):previous.download(old['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    files.update({'baseline':(compact(paths['baseline'],project/'baseline-weights.pt'),'baseline.pt'),'best':(compact(paths[best_key],project/'best-weights.pt'),'best.pt'),'working':(paths[working_key],'working.pt'),'teacherData':(teacher,'data/teacher.jsonl')})
    cache=project/'judge-cache.json'
    if cache.is_file():files['judgeCache']=(cache,'evaluation/judge-cache.json')
    state={'format':VERSION,'gradingProtocol':protocol(),'round':0,'rejected':0,'bestReport':reports[best_key],'workingReport':reports[working_key],'baselineReport':baseline,
        'sourceRevision':previous.revision,'sourceRun':previous.prefix,'sourceRound':old['round'],'sourceRegradedReports':reports,'selectedSourceBest':best_key,'selectedSourceWorking':working_key,
        'profile':{'gpus':min(2,torch.cuda.device_count())},'teacherNextIndex':old.get('teacherNextIndex',3000),'publicAutoUpdate':False}
    print(json.dumps({'v11SourceRegraded':True,'bestSource':best_key,'workingSource':working_key,'oldScoresNotCompared':True,'oldRunsUntouched':True}),flush=True)
    return store.publish(state,files,project)

def assess_round(state,candidates,project,legacy,checks,validation,evaluate_checkpoint=None):
    """All candidates must finish review before any selection changes."""
    reports=[];files={}
    for label,path in candidates:
        report_path=project/(label+'-report.json');candidate=(evaluate_checkpoint or evaluate)(path,legacy,checks,validation,report_path)
        reports.append((label,path,candidate));files['report-'+label]=(report_path,f'reports/{state["round"]+1:04d}-{label}.json')
    cache=project/'judge-cache.json'
    if cache.is_file():files['judgeCache']=(cache,'evaluation/judge-cache.json')
    if not all(sound(report) for _,_,report in reports):return None,files
    best_report=state['bestReport'];working_report=state['workingReport'];chosen_best=None;chosen_work=None
    for label,path,candidate in reports:
        best_ok=better_best(state['baselineReport'],best_report,candidate);work_ok=better_working(state['baselineReport'],working_report,best_report,candidate)
        print(json.dumps({'v11CandidateDecision':label,'verifiedReviewComplete':True,'protectedSkillsPreserved':preserves(state['baselineReport'],candidate),'qualifiesForBest':best_ok,'qualifiesForWorking':work_ok}),flush=True)
        if best_ok:chosen_best=path;best_report=candidate
        if work_ok:chosen_work=path;working_report=candidate
    if chosen_best is not None:chosen_work=chosen_best;working_report=best_report;files['best']=(compact(chosen_best,project/'best-weights.pt'),'best.pt')
    if chosen_work is not None:files['working']=(chosen_work,'working.pt')
    # Keep the last accepted working checkpoint on a rejected trial. No silent optimizer reset.
    next_state={**state,'round':state['round']+1,'bestReport':best_report,'workingReport':working_report,'rejected':0 if chosen_work is not None else state['rejected']+1,'pendingEvaluation':None}
    return next_state,files

def save_assessment(store,state,candidates,project,legacy,checks,validation,already_pending=False,evaluate_checkpoint=None):
    next_state,files=assess_round(state,candidates,project,legacy,checks,validation,**({"evaluate_checkpoint":evaluate_checkpoint} if evaluate_checkpoint else {}))
    if next_state is None:
        pending=[]
        for i,(label,path) in enumerate(candidates):
            key='pendingCandidate'+str(i);pending.append({'label':label,'key':key})
            if not already_pending:files[key]=(path,f'pending/{label}.pt')
        state={**state,'pendingEvaluation':pending,'publicAutoUpdate':False}
        state=store.publish(state,files,project)
        print(json.dumps({'v11WaitingForReview':True,'candidateWeightsBackedUp':True,'roundNotRejected':True,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
        return state,False
    final=next((path for label,path in candidates if label=='final'),candidates[-1][1])
    files['latest']=(compact(final,project/'latest-weights.pt'),'latest.pt')
    # Remove active pending references. Old immutable repository commits preserve trials.
    for key in list(next_state):
        if key.startswith('pendingCandidate'):next_state.pop(key)
    state=store.publish(next_state,files,project)
    print(json.dumps({'v11RoundSaved':state['round'],'bestCorrect':state['bestReport']['correct'],'bestChatChecks':state['bestReport']['chatChecks'],'chatCases':20,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    return state,True

def main(argv=None,*,initialize_run=None,version=VERSION,run_name='nebula-v11-verified',launch_training=None,evaluate_checkpoint=None,save_round=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--run',default=run_name);parser.add_argument('--hours',type=float,default=8)
    parser.add_argument('--rounds',type=int,default=20);parser.add_argument('--steps',type=int,default=100);parser.add_argument('--teacher-calls',type=int,default=96)
    args=parser.parse_args(argv)
    if args.run!=run_name:parser.error('Use the isolated run name to preserve older runs')
    if not 0<args.hours<=8 or not 1<=args.rounds<=20 or not 50<=args.steps<=200 or not 0<=args.teacher_calls<=256:parser.error('Use bounded hours, rounds, updates and teacher calls')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run);state=store.state()
    if state and (state.get('format')!=version or state.get('gradingProtocol')!=protocol()):raise ResearchError('V11_GRADING_VERSION_MISMATCH_REGRADE_REQUIRED')
    if state and state.get('rejected',0)>=3:raise ResearchError('V11_PAUSED_INSPECT_VERIFIED_REPORTS')
    if not state:state=(initialize_run or initialize)(store,project)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    data=store.download(state['data'],project/'model/data/v10-train.jsonl');validation=store.download(state['validationData'],project/'model/data/v10-validation.jsonl')
    protected_questions=set().union(*(prompts(row) for row in read_jsonl(validation)))
    legacy=store.download(state['evaluationData'],project/'model/data/legacy.jsonl');checks=store.download(state['checks'],project/'model/data/checks.json')
    anchor=store.download(state['qualityAnchor'],project/'anchor.pt')
    if state.get('judgeCache'):store.download(state['judgeCache'],project/'judge-cache.json')
    deadline=time.monotonic()+args.hours*3600;teacher_calls=0;saved=0;teacher_ready=0.;client=Client()
    if state.get('pendingEvaluation'):
        candidates=[(entry['label'],store.download(state[entry['key']],project/('pending-'+entry['label']+'.pt'))) for entry in state['pendingEvaluation']]
        state,complete=(save_round or save_assessment)(store,state,candidates,project,legacy,checks,validation,True,**({"evaluate_checkpoint":evaluate_checkpoint} if evaluate_checkpoint else {}))
        if not complete:return
    teacher=project/'model/data/teacher.jsonl'
    if state.get('teacherData'):store.download(state['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    print(json.dumps({'resumedV11':True,'savedRounds':state['round'],'gradingProtocol':protocol(),'bestReport':state['bestReport'],'conversationPercent':80,'mixedPercent':20,'publicAutoUpdate':False}),flush=True)
    try:
        while saved<args.rounds and time.monotonic()<deadline and state['rejected']<3:
            working=store.download(state['working'],project/'resume-working.pt');number=state['round']+1;remaining=args.teacher_calls-teacher_calls
            if remaining>=2 and time.time()>=teacher_ready:
                result=collect(teacher,state['workingReport'],blocked_prompts=protected_questions,max_calls=min(32 if saved==0 else 8,remaining),start=state.get('teacherNextIndex',3000))
                teacher_calls+=result['calls'];state['teacherNextIndex']=result.get('nextIndex',state.get('teacherNextIndex',3000))
                if result.get('deferred'):teacher_ready=time.time()+result['deferred']['retryAfterSeconds']
                if result['saved']:state=store.publish(state,{'teacherData':(teacher,'data/teacher.jsonl')},project)
            output=project/'round.pt';lr=max(.0000005,.0000015*(.5**min(2,state['rejected']//2)))
            print(json.dumps({'v11Phase':'training','round':number,'additionalSteps':args.steps,'learningRate':lr,'optimizerRestore':'when-compatible-see-training-log'}),flush=True)
            for stale in [output.with_name(output.stem+'.step-25.pt'),output.with_name(output.stem+'.step-50.pt')]:stale.unlink(missing_ok=True)
            with tempfile.TemporaryDirectory(prefix='nebula-v11-reviews-') as temporary:
                reviews=Path(temporary)/'reviews.jsonl';refresh_reviews(client,reviews)
                (launch_training or launch)(project,working,output,args.steps,state['profile']['gpus'],'balanced',lr=lr,data=data,best=True,conversation_mix=True,review_data=reviews,quality_anchor=anchor,teacher_data=teacher,large_model=True,microbatch=1,curriculum_v10=True,validation_data=validation,save_every=25,sampling_seed=(20261017+number*17)%(2**31),max_seconds=max(1,min(3600,deadline-time.monotonic())))
            candidates=[];seen=set();performance=json.loads(output.with_suffix('.performance.json').read_text(encoding='utf-8'))
            for label,path in [('early-25',output.with_name(output.stem+'.step-25.pt')),('early-50',output.with_name(output.stem+'.step-50.pt')),('final',output),('lowest-loss',output.with_suffix('.best.pt'))]:
                if not path.is_file() or label=='lowest-loss' and performance.get('bestStep') in [0,25,50,performance.get('completedSteps')]:continue
                digest=digests(path)[0]
                if digest in seen:continue
                seen.add(digest);candidates.append((label,path))
            if not candidates:raise ResearchError('V11_TRAINING_OUTPUT_MISSING')
            state,complete=(save_round or save_assessment)(store,state,candidates,project,legacy,checks,validation,**({"evaluate_checkpoint":evaluate_checkpoint} if evaluate_checkpoint else {}))
            if not complete:break
            saved+=1;gc.collect();torch.cuda.empty_cache()
            if (project/'STOP_AFTER_ROUND').exists():break
    except KeyboardInterrupt:print('Stopped. Resume the last confirmed V11 backup.',flush=True)
    print(json.dumps({'v11SessionFinished':True,'savedRound':state['round'],'pausedAfterRejections':state['rejected']>=3,'teacherCalls':teacher_calls,'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v11Stopped':error.code}),flush=True);raise SystemExit(1)
