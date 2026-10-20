"""V9: retain skills, improve conversations, and keep a separate learning trajectory."""
import argparse
import gc
import json
import math
import os
from pathlib import Path
import tempfile
import time
import torch
from dataflow import read_jsonl,write_jsonl
from kaggle_migrate import restore_data
from research_client import Client,ResearchError,digests
from research_worker import configure_rules,launch
from v4_experiment import profile
from v8_store import Store
from v8_experiment import preserves as preserves_previous
from v9_data import acquire,prompts,prepare as prepare_curriculum
from train import partition_rows

from v6_experiment import compact
from v7_data import prepare,short_complete
VERSION="nebula-v9-curriculum-1"
from v9_eval import evaluate
from v9_teacher import collect
from review_feed import refresh_reviews

def sound(report):
    fields=['loss','health','identity','math','memory','extraction','conversation','chatLoss','chatChecks','chatCases','correct','cases','languageLoss','publicChatLoss']
    return all(math.isfinite(report.get(k,float('nan'))) for k in fields) and report['chatCases']==20

def preserves(base,candidate):
    return sound(candidate) and candidate['languageLoss']<=base['languageLoss']*1.05 and candidate['publicChatLoss']<=base['publicChatLoss']*1.05 and candidate['cases']==base['cases'] and candidate['health']>=max(.95,base['health']-.02) and candidate['identity']>=base['identity']-.10 and candidate['memory']>=base['memory']-.05 and candidate['math']>=base['math']-.10 and candidate['extraction']>=base['extraction']-.08 and candidate['correct']>=base['correct']-2 and candidate['loss']<=base['loss']*1.08

def better_best(base,current,candidate):
    if not preserves(base,candidate) or candidate['chatLoss']>current['chatLoss']*1.03:return False
    return (candidate['chatChecks']>current['chatChecks'] and candidate['correct']>=current['correct']-1) or (candidate['correct']>current['correct'] and candidate['chatChecks']>=current['chatChecks'])

def better_working(base,current,best,candidate):
    return preserves(base,candidate) and candidate['chatChecks']>=best['chatChecks']-1 and candidate['chatLoss']<current['chatLoss']*.997 and candidate['languageLoss']<=current['languageLoss']*1.03

def initialize(store,project):
    previous=Store(store.repo,store.token,'nebula-v8-100m');old=previous.state()
    if not old or not old.get('best'):raise ResearchError('V9_SAVED_V8_REQUIRED')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    base=previous.download(old['data'],project/'model/data/previous-chat.jsonl')
    legacy=previous.download(old['evaluationData'],project/'model/data/frozen-legacy.jsonl');checks=previous.download(old['checks'],project/'model/data/frozen-checks.json')
    original=previous.download(old['best'],project/'source-best.pt');working_source=previous.download(old.get('working',old['best']),project/'source-working.pt')
    anchor=previous.download(old['qualityAnchor'],project/'anchor.pt')
    public,counts=acquire(project/'model/data/v9-public')
    data=project/'model/data/v9-train.jsonl';validation=project/'model/data/v9-validation.jsonl'
    summary=prepare_curriculum(base,public,data,validation)
    baseline=evaluate(original,legacy,checks,validation,project/'baseline-report.json')
    if not preserves_previous(old['bestReport'],baseline):raise ResearchError('V9_BASELINE_CHANGED')
    chosen=original;working_report=baseline;best_source=original;best_report=baseline
    if digests(working_source)[0]!=digests(original)[0]:
        candidate=evaluate(working_source,legacy,checks,validation,project/'source-working-report.json')
        if better_best(baseline,best_report,candidate):best_source=working_source;best_report=candidate
        if better_working(baseline,working_report,best_report,candidate) or best_source==working_source:chosen=working_source;working_report=candidate
    teacher=project/'model/data/v7-teacher.jsonl'
    if old.get('teacherData'):previous.download(old['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    seed=project/'model/data/v9-teacher-seed.jsonl'
    if seed.is_file():
        rows=read_jsonl(teacher);seen={row['id'] for row in rows}
        rows.extend(row for row in read_jsonl(seed) if row['id'] not in seen);write_jsonl(teacher,rows)
    gpus=min(2,torch.cuda.device_count());measurement=launch(project,chosen,project/'capacity-probe.pt',4,gpus,'balanced',benchmark=True,lr=.000003,max_seconds=300,data=data,validation_data=validation,quality_anchor=anchor,large_model=True,curriculum_v9=True,microbatch=1)
    state={'format':VERSION,'round':0,'rejected':0,'bestReport':best_report,'workingReport':working_report,'baselineReport':baseline,'sourceRevision':previous.revision,'sourceRun':previous.prefix,'sourceRound':old['round'],'profile':{'gpus':gpus,**measurement},'dataSummary':summary,'publicDataCounts':counts,'teacherNextIndex':old.get('teacherNextIndex',2000),'publicAutoUpdate':False,'sourceWorkingPreserved':chosen==working_source}
    files={'sourceData':(source,'source-data.pt'),'baseline':(compact(original,project/'baseline-weights.pt'),'baseline.pt'),'best':(compact(best_source,project/'best-weights.pt'),'best.pt'),'working':(compact(chosen,project/'working-weights.pt'),'working.pt'),'qualityAnchor':(anchor,'quality-anchor.pt'),'data':(data,'data/train.jsonl'),'validationData':(validation,'data/validation.jsonl'),'evaluationData':(legacy,'data/legacy.jsonl'),'checks':(checks,'data/checks.json'),'teacherData':(teacher,'data/teacher.jsonl'),'initialReport':(project/'baseline-report.json','reports/baseline.json'),'publicManifest':(project/'model/data/v9-public/public-manifest.json','data/public-manifest.json'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),'licenseTexts':(project/'model/data/v9-public/licenses.json','data/licenses.json')}
    print(json.dumps({'v9InitializedFromV8':True,'preservedWorkingTrajectory':chosen==working_source,'data':summary,'noPretrainedWeightsImported':True}),flush=True)
    return store.publish(state,files,project)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--run',default='nebula-v9-curriculum')
    parser.add_argument('--hours',type=float,default=8);parser.add_argument('--rounds',type=int,default=20)
    parser.add_argument('--steps',type=int,default=200);parser.add_argument('--teacher-calls',type=int,default=96)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 1<=args.rounds<=20 or not 100<=args.steps<=500 or not 0<=args.teacher_calls<=256:parser.error('Use bounded session hours, rounds (up to 20), steps and teacher calls')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run);state=store.state()
    if state and state.get('format')!=VERSION:raise ResearchError('V9_VERSION_MISMATCH')
    if not state:state=initialize(store,project)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    data=store.download(state['data'],project/'model/data/v9-train.jsonl')
    validation=store.download(state['validationData'],project/'model/data/v9-validation.jsonl')
    protected_questions=set().union(*(prompts(row) for row in read_jsonl(validation)))
    legacy=store.download(state['evaluationData'],project/'model/data/legacy.jsonl');checks=store.download(state['checks'],project/'model/data/checks.json')
    anchor=store.download(state['qualityAnchor'],project/'anchor.pt');best=store.download(state['best'],project/'resume-best.pt')
    working=store.download(state.get('working',state['best']),project/'resume-working.pt')
    teacher=project/'model/data/v7-teacher.jsonl'
    if state.get('teacherData'):store.download(state['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    print(json.dumps({'resumedV9':True,'savedRounds':state['round'],'bestReport':state['bestReport'],'sourceRun':state.get('sourceRun'),'preservedPreviousWeights':True,'conversationPercent':80,'mixedPercent':20,'teacherKeyPresent':bool(os.environ.get('NEBULA_TEACHER_GROQ_KEY')),'publicAutoUpdate':False}),flush=True)
    deadline=time.monotonic()+args.hours*3600;client=Client();teacher_calls=0;teacher_ready=0.;saved=0
    try:
        while saved<args.rounds and time.monotonic()<deadline:
            number=state['round']+1;remaining=args.teacher_calls-teacher_calls
            if remaining>=2 and time.time()>=teacher_ready:
                result=collect(teacher,state['workingReport'],blocked=protected_questions,max_calls=min(24 if saved==0 else 4,remaining),start=state.get('teacherNextIndex',2000))
                teacher_calls+=result['calls'];state['teacherNextIndex']=result.get('nextIndex',state.get('teacherNextIndex',2000))
                if result.get('deferred'):teacher_ready=time.time()+result['deferred']['retryAfterSeconds']
                if result['saved']:state=store.publish(state,{'teacherData':(teacher,'data/teacher.jsonl')},project)
            output=project/'round.pt';lr=max(.0000005,.000003*(.5**min(3,state['rejected']//3)))
            print(json.dumps({'v9Round':number,'additionalSteps':args.steps,'learningRate':lr,'workingCheckpointContinues':True,'teacherCallsThisSession':teacher_calls,'completeTeacherDialogues':len(read_jsonl(teacher)),'qualityAnchor':True}),flush=True)
            with tempfile.TemporaryDirectory(prefix='nebula-v9-reviews-') as temporary:
                reviews=Path(temporary)/'reviews.jsonl';review_count=refresh_reviews(client,reviews)
                launch(project,working,output,args.steps,state['profile']['gpus'],'balanced',lr=lr,data=data,best=True,conversation_mix=True,review_data=reviews,quality_anchor=anchor,teacher_data=teacher,large_model=True,microbatch=1,curriculum_v9=True,validation_data=validation,
                    save_every=50,sampling_seed=(20261017+number*17)%(2**31),max_seconds=max(1,min(3600,deadline-time.monotonic())))
            best_report=state['bestReport'];working_report=state['workingReport'];chosen_best=None;chosen_work=None;files={}
            for label,path in [('final',output),('lowest-loss',output.with_suffix('.best.pt'))]:
                if label=='lowest-loss' and digests(path)[0]==digests(output)[0]:continue
                report_file=project/(label+'-report.json');candidate=evaluate(path,legacy,checks,validation,report_file)
                files['report-'+label]=(report_file,f'reports/{number:04d}-{label}.json')
                if better_best(state['baselineReport'],best_report,candidate):chosen_best=path;best_report=candidate
                if better_working(state['baselineReport'],working_report,best_report,candidate):chosen_work=path;working_report=candidate
            if chosen_best is not None:chosen_work=chosen_best;working_report=best_report;files['best']=(compact(chosen_best,project/'best-weights.pt'),'best.pt')
            if chosen_work is not None:files['working']=(chosen_work,'working.pt')
            else:
                # Discard a degrading trajectory, preserve its trial, reduce the next rate.
                working_report=best_report;files['working']=(best,'working.pt')
            files['latest']=(compact(output,project/'latest-weights.pt'),'latest.pt')
            state={**state,'round':number,'bestReport':best_report,'workingReport':working_report,'rejected':0 if chosen_work is not None else state['rejected']+1}
            state=store.publish(state,files,project);saved+=1
            best=store.download(state['best'],project/'resume-best.pt');working=store.download(state['working'],project/'resume-working.pt')
            print(json.dumps({'v9RoundSaved':number,'bestImproved':chosen_best is not None,'workingTrajectoryAccepted':chosen_work is not None,'bestCorrect':best_report['correct'],'bestChatChecks':best_report['chatChecks'],'chatCases':best_report['chatCases'],'checkedReviewExamples':review_count,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
            gc.collect();torch.cuda.empty_cache()
            if (project/'STOP_AFTER_ROUND').exists():break
    except KeyboardInterrupt:print('Stopped. Resume the last confirmed V9 backup.',flush=True)
    print(json.dumps({'v9SessionFinished':True,'savedRound':state['round'],'teacherCalls':teacher_calls,'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v9Stopped':error.code}),flush=True);raise SystemExit(1)
