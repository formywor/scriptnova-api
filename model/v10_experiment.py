"""V10: retain skills, improve conversations, and keep a separate learning trajectory."""
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
from v10_store import Store
from v8_experiment import preserves as preserves_previous
from v10_data import prompts
from v10_data import prepare as prepare_curriculum
from train import partition_rows

from v6_experiment import compact
from v7_data import prepare,short_complete
VERSION="nebula-v10-dialogue-1"
from v10_eval import evaluate
from v10_teacher import collect
from review_feed import refresh_reviews

def sound(report):
    fields=['loss','health','identity','math','memory','extraction','conversation','chatLoss','chatChecks','chatCases','correct','cases','languageLoss','publicChatLoss','chatHealthy']
    return all(math.isfinite(report.get(k,float('nan'))) for k in fields) and report['chatCases']==20

def preserves(base,candidate):
    return sound(candidate) and candidate['chatHealthy']>=base['chatHealthy'] and candidate['languageLoss']<=base['languageLoss']*1.05 and candidate['publicChatLoss']<=base['publicChatLoss']*1.05 and candidate['cases']==base['cases'] and candidate['health']>=max(.95,base['health']-.02) and candidate['identity']>=base['identity']-.10 and candidate['memory']>=base['memory']-.05 and candidate['math']>=base['math']-.10 and candidate['extraction']>=base['extraction']-.08 and candidate['correct']>=base['correct']-2 and candidate['loss']<=base['loss']*1.08

def rejection_reasons(base,current,best,candidate):
    limits=[('languageLoss',candidate['languageLoss']<=base['languageLoss']*1.05),('publicChatLoss',candidate['publicChatLoss']<=base['publicChatLoss']*1.05),('health',candidate['health']>=max(.95,base['health']-.02)),('identity',candidate['identity']>=base['identity']-.1),('memory',candidate['memory']>=base['memory']-.05),('math',candidate['math']>=base['math']-.1),('extraction',candidate['extraction']>=base['extraction']-.08),('correct',candidate['correct']>=base['correct']-2),('legacyLoss',candidate['loss']<=base['loss']*1.08),('chatHealthy',candidate['chatHealthy']>=base['chatHealthy']),('chatChecks',candidate['chatChecks']>=best['chatChecks']-1),('chatLossImprovement',candidate['chatLoss']<current['chatLoss']*.997),('languageLossDrift',candidate['languageLoss']<=current['languageLoss']*1.03)]
    return [name for name,passed in limits if not passed]

def better_best(base,current,candidate):
    if not preserves(base,candidate) or candidate['chatLoss']>current['chatLoss']*1.03:return False
    return (candidate['chatChecks']>current['chatChecks'] and candidate['correct']>=current['correct']-1) or (candidate['correct']>current['correct'] and candidate['chatChecks']>=current['chatChecks'])

def better_working(base,current,best,candidate):
    return preserves(base,candidate) and candidate['chatChecks']>=best['chatChecks']-1 and candidate['chatLoss']<current['chatLoss']*.997 and candidate['languageLoss']<=current['languageLoss']*1.03

def initialize(store,project):
    previous=Store(store.repo,store.token,'nebula-v9-curriculum');old=previous.state()
    if not old or not old.get('best'):raise ResearchError('V10_SAVED_V9_REQUIRED')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    base=previous.download(old['data'],project/'model/data/source-train.jsonl')
    validation=previous.download(old['validationData'],project/'model/data/fixed-validation.jsonl')
    legacy=previous.download(old['evaluationData'],project/'model/data/frozen-legacy.jsonl');checks=previous.download(old['checks'],project/'model/data/frozen-checks.json')
    original=previous.download(old['best'],project/'source-best.pt')
    data=project/'model/data/v10-train.jsonl';summary=prepare_curriculum(base,validation,data)
    # Anchor to the actual protected 100M model, rather than its older small predecessor.
    anchor=compact(original,project/'anchor.pt')
    baseline=evaluate(original,legacy,checks,validation,project/'baseline-report.json')
    if not preserves_previous(old['bestReport'],baseline):raise ResearchError('V10_BASELINE_CHANGED')
    teacher=project/'model/data/teacher.jsonl'
    if old.get('teacherData'):previous.download(old['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    seed=project/'model/data/v10-teacher-seed.jsonl'
    if seed.is_file():
        rows=read_jsonl(teacher);seen={row['id'] for row in rows};rows.extend(row for row in read_jsonl(seed) if row['id'] not in seen);write_jsonl(teacher,rows)
    gpus=min(2,torch.cuda.device_count())
    measurement=launch(project,original,project/'capacity-probe.pt',4,gpus,'balanced',benchmark=True,lr=.0000015,max_seconds=300,data=data,validation_data=validation,quality_anchor=anchor,large_model=True,curriculum_v10=True,microbatch=1)
    state={'format':VERSION,'round':0,'rejected':0,'bestReport':baseline,'workingReport':baseline,'baselineReport':baseline,'sourceRevision':previous.revision,'sourceRun':previous.prefix,'sourceRound':old['round'],'profile':{'gpus':gpus,**measurement},'dataSummary':summary,'teacherNextIndex':old.get('teacherNextIndex',3000),'publicAutoUpdate':False,'protectedBestSource':True}
    licenses=previous.download(old['licenseTexts'],project/'data-licenses.json')
    files={'sourceData':(source,'source-data.pt'),'baseline':(compact(original,project/'baseline-weights.pt'),'baseline.pt'),'best':(compact(original,project/'best-weights.pt'),'best.pt'),'working':(compact(original,project/'working-weights.pt'),'working.pt'),'qualityAnchor':(anchor,'quality-anchor.pt'),'data':(data,'data/train.jsonl'),'validationData':(validation,'data/validation.jsonl'),'evaluationData':(legacy,'data/legacy.jsonl'),'checks':(checks,'data/checks.json'),'teacherData':(teacher,'data/teacher.jsonl'),'initialReport':(project/'baseline-report.json','reports/baseline.json'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),'licenseTexts':(licenses,'data/licenses.json')}
    print(json.dumps({'v10InitializedFromProtectedBest':True,'sourceSavedRound':old['round'],'data':summary,'noPretrainedWeightsImported':True}),flush=True)
    return store.publish(state,files,project)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--run',default='nebula-v10-dialogue')
    parser.add_argument('--hours',type=float,default=8);parser.add_argument('--rounds',type=int,default=20)
    parser.add_argument('--steps',type=int,default=100);parser.add_argument('--teacher-calls',type=int,default=96)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 1<=args.rounds<=20 or not 50<=args.steps<=200 or not 0<=args.teacher_calls<=256:parser.error('Use bounded session hours, rounds (up to 20), steps and teacher calls')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run);state=store.state()
    if state and state.get('format')!=VERSION:raise ResearchError('V10_VERSION_MISMATCH')
    if not state:state=initialize(store,project)
    if state.get('rejected',0)>=3:raise ResearchError('V10_PAUSED_INSPECT_REJECTION_REPORTS')
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    data=store.download(state['data'],project/'model/data/v10-train.jsonl')
    validation=store.download(state['validationData'],project/'model/data/v10-validation.jsonl')
    protected_questions=set().union(*(prompts(row) for row in read_jsonl(validation)))
    legacy=store.download(state['evaluationData'],project/'model/data/legacy.jsonl');checks=store.download(state['checks'],project/'model/data/checks.json')
    anchor=store.download(state['qualityAnchor'],project/'anchor.pt');best=store.download(state['best'],project/'resume-best.pt')
    working=store.download(state.get('working',state['best']),project/'resume-working.pt')
    teacher=project/'model/data/v7-teacher.jsonl'
    if state.get('teacherData'):store.download(state['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    print(json.dumps({'resumedV10':True,'savedRounds':state['round'],'bestReport':state['bestReport'],'sourceRun':state.get('sourceRun'),'preservedPreviousWeights':True,'conversationPercent':80,'mixedPercent':20,'teacherKeyPresent':bool(os.environ.get('NEBULA_TEACHER_GROQ_KEY')),'publicAutoUpdate':False}),flush=True)
    deadline=time.monotonic()+args.hours*3600;client=Client();teacher_calls=0;teacher_ready=0.;saved=0
    try:
        while saved<args.rounds and time.monotonic()<deadline:
            number=state['round']+1;remaining=args.teacher_calls-teacher_calls
            if remaining>=2 and time.time()>=teacher_ready:
                result=collect(teacher,state['workingReport'],blocked_prompts=protected_questions,max_calls=min(48 if saved==0 else 8,remaining),start=state.get('teacherNextIndex',2000))
                teacher_calls+=result['calls'];state['teacherNextIndex']=result.get('nextIndex',state.get('teacherNextIndex',2000))
                if result.get('deferred'):teacher_ready=time.time()+result['deferred']['retryAfterSeconds']
                if result['saved']:state=store.publish(state,{'teacherData':(teacher,'data/teacher.jsonl')},project)
            output=project/'round.pt';lr=max(.0000005,.0000015*(.5**min(2,state['rejected']//2)))
            print(json.dumps({'v10Round':number,'additionalSteps':args.steps,'learningRate':lr,'startingPoint':'protected-best-after-rollback' if state['rejected'] else 'accepted-working-checkpoint' if state['round'] else 'protected-source-best','teacherCallsThisSession':teacher_calls,'completeTeacherDialogues':len(read_jsonl(teacher)),'qualityAnchor':True}),flush=True)
            for stale in [output.with_name(output.stem+'.step-25.pt'),output.with_name(output.stem+'.step-50.pt')]:stale.unlink(missing_ok=True)
            with tempfile.TemporaryDirectory(prefix='nebula-v10-reviews-') as temporary:
                reviews=Path(temporary)/'reviews.jsonl';review_count=refresh_reviews(client,reviews)
                launch(project,working,output,args.steps,state['profile']['gpus'],'balanced',lr=lr,data=data,best=True,conversation_mix=True,review_data=reviews,quality_anchor=anchor,teacher_data=teacher,large_model=True,microbatch=1,curriculum_v10=True,validation_data=validation,
                    save_every=25,sampling_seed=(20261017+number*17)%(2**31),max_seconds=max(1,min(3600,deadline-time.monotonic())))
            best_report=state['bestReport'];working_report=state['workingReport'];chosen_best=None;chosen_work=None;files={}
            candidates=[('early-25',output.with_name(output.stem+'.step-25.pt')),('early-50',output.with_name(output.stem+'.step-50.pt')),('final',output),('lowest-loss',output.with_suffix('.best.pt'))]
            performance=json.loads(output.with_suffix('.performance.json').read_text(encoding='utf-8'))
            lowest_step=performance.get('bestStep')
            seen_candidates=set()
            for label,path in candidates:
                if not path.is_file():continue
                if label=='lowest-loss' and lowest_step in [0,25,50,performance.get('completedSteps')]:continue
                fingerprint=digests(path)[0]
                if fingerprint in seen_candidates:continue
                seen_candidates.add(fingerprint)
                print(json.dumps({'v10Phase':'evaluating','candidate':label,'completedTrainingUpdates':args.steps}),flush=True)
                report_file=project/(label+'-report.json');candidate=evaluate(path,legacy,checks,validation,report_file)
                files['report-'+label]=(report_file,f'reports/{number:04d}-{label}.json')
                print(json.dumps({'v10CandidateDecision':label,'failedWorkingChecks':rejection_reasons(state['baselineReport'],working_report,best_report,candidate),'qualifiesForBest':better_best(state['baselineReport'],best_report,candidate),'qualifiesForWorking':better_working(state['baselineReport'],working_report,best_report,candidate),'candidateSteps':json.loads(report_file.read_text(encoding='utf-8'))['metadata'].get('steps')}),flush=True)
                if better_best(state['baselineReport'],best_report,candidate):chosen_best=path;best_report=candidate
                if better_working(state['baselineReport'],working_report,best_report,candidate):chosen_work=path;working_report=candidate
            if chosen_best is not None:chosen_work=chosen_best;working_report=best_report;files['best']=(compact(chosen_best,project/'best-weights.pt'),'best.pt')
            if chosen_work is not None:files['working']=(chosen_work,'working.pt')
            else:
                # Discard a degrading trajectory, preserve its trial, reduce the next rate.
                working_report=best_report;files['working']=(best,'working.pt')
            files['latest']=(compact(output,project/'latest-weights.pt'),'latest.pt')
            state={**state,'round':number,'bestReport':best_report,'workingReport':working_report,'rejected':0 if chosen_work is not None else state['rejected']+1}
            print(json.dumps({'v10Phase':'backing-up','round':number}),flush=True)
            state=store.publish(state,files,project);saved+=1
            best=store.download(state['best'],project/'resume-best.pt');working=store.download(state['working'],project/'resume-working.pt')
            print(json.dumps({'v10RoundSaved':number,'bestImproved':chosen_best is not None,'workingTrajectoryAccepted':chosen_work is not None,'bestCorrect':best_report['correct'],'bestChatChecks':best_report['chatChecks'],'chatCases':best_report['chatCases'],'checkedReviewExamples':review_count,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
            gc.collect();torch.cuda.empty_cache()
            if state['rejected']>=3:
                print(json.dumps({'v10Paused':True,'reason':'THREE_REJECTED_ROUNDS','lastConfirmedBackup':number,'inspectReportsBeforeResuming':True}),flush=True);break
            if (project/'STOP_AFTER_ROUND').exists():break
    except KeyboardInterrupt:print('Stopped. Resume the last confirmed V10 backup.',flush=True)
    print(json.dumps({'v10SessionFinished':True,'savedRound':state['round'],'teacherCalls':teacher_calls,'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v10Stopped':error.code}),flush=True);raise SystemExit(1)
