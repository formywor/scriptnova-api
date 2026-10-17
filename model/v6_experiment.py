"""Resumable learning from V4's strongest trial, with separate public releases."""
import argparse
import gc
import json
import math
import os
from pathlib import Path
import shutil
import time
import tempfile
import torch
from huggingface_hub import hf_hub_download
from dataflow import read_jsonl
from kaggle_migrate import restore_data
from nebula import load,save
from research_client import Client,ResearchError,digests
from research_worker import configure_rules,launch
from v4_eval import evaluate,focus_for,GROUPS
from v4_experiment import profile
from v4_store import Store
from v6_data import VERSION,prepare
from review_feed import refresh_reviews

SOURCE_REVISION='916b0eaed037df63cdd0add74f10452ce394aaf1'

def research_improves(base,candidate):
    keys=['loss','health','correct','cases','identity','math','memory','extraction','conversation']
    if any(not math.isfinite(r.get(k,float('nan'))) for r in [base,candidate] for k in keys):return False
    if base['cases']!=candidate['cases'] or candidate['health']<max(.90,base['health']-.03) or candidate['loss']>base['loss']*1.08:return False
    if candidate['memory']<base['memory']-.10 or candidate['extraction']<base['extraction']-.10 or candidate['identity']<base['identity']-.20 or candidate['math']<base['math']-.15:return False
    chat_gain=candidate['conversation']>base['conversation']+.01 and candidate['correct']>=base['correct']-3
    stable_gain=candidate['conversation']>=base['conversation'] and (candidate['correct']>base['correct'] or candidate['correct']==base['correct'] and candidate['loss']<base['loss']*.99)
    return chat_gain or stable_gain

def topic_focus(report,rejected,round_number,topics):
    # At most one round in four follows opted-in usage; the rest follow errors.
    counts=topics.get('counts',{}) if isinstance(topics,dict) else {}
    valid={k:v for k,v in counts.items() if k in ['identity','math','memory','language'] and
           type(v) is int and 0<=v<=10000}
    if round_number%4==0 and valid and max(valid.values())>=5:return max(valid,key=valid.get)
    if round_number%5==0 or report.get('conversation',1)<.5 and round_number%2==1:return 'language'
    return focus_for(report,rejected)

def compact(source,destination):
    model,metadata=load(source);save(model,destination,metadata);del model
    return destination

def initial(store,project):
    # Read-only source: retain the V5 best weights and all V5 checkpoints.
    previous=Store(store.repo,store.token,'nebula-v5');old=previous.state()
    if not old or not old.get('best'):raise ResearchError('V5_BEST_CHECKPOINT_REQUIRED')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    base=previous.download(old['data'],project/'model/data/v5-chat.jsonl')
    evaluation_data=previous.download(old['evaluationData'],project/'model/data/v4-chat.jsonl')
    checks=previous.download(old['checks'],project/'model/data/v5-checks.json')
    best=previous.download(old['best'],project/'preserved-v5-best.pt')
    data=project/'model/data/v6-chat.jsonl';summary=prepare(base,data)
    measurement=profile(project,best,data,'v6')
    report=evaluate(best,evaluation_data,checks,project/'baseline-report.json')
    state={'format':VERSION,'round':0,'rejected':0,'bestReport':report,'sourceRevision':previous.revision,'sourceV5Round':old['round'],
           'publicAutoUpdate':False,'profile':measurement,'dataSummary':summary,'status':'ready'}
    return store.publish(state,{'sourceData':(source,'source-data.pt'),'baseline':(best,'preserved-v5-best.pt'),
        'evaluationData':(evaluation_data,'data/v4-chat.jsonl'),'checks':(checks,'data/v5-checks.json'),
        'data':(data,'data/v6-chat.jsonl'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),
        'baselineReport':(project/'baseline-report.json','reports/baseline.json'),
        'best':(compact(best,project/'initial-weights.pt'),'best.pt')},project)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--run',default='nebula-v6')
    parser.add_argument('--hours',type=float,default=8);parser.add_argument('--steps',type=int,default=500)
    parser.add_argument('--rounds',type=int,default=100)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 100<=args.steps<=2000 or not 1<=args.rounds<=100:parser.error('Use 0-8 hours, 100-2000 updates per round, and 1-100 rounds')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run)
    state=store.state()
    if state and state.get('format')!=VERSION:raise ResearchError('V6_VERSION_MISMATCH')
    if not state:state=initial(store,project)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    data=store.download(state['data'],project/'model/data/v6-chat.jsonl')
    evaluation_data=store.download(state['evaluationData'],project/'model/data/v4-chat.jsonl')
    checks=store.download(state['checks'],project/'model/data/v4-checks.json')
    best=store.download(state['best'],project/'resume-best.pt')
    print(json.dumps({'resumedV6':True,'completedRounds':state['round'],'bestReport':state['bestReport'],
                      'publicAutoUpdate':False,'newData':state['dataSummary']}),flush=True)
    deadline=time.monotonic()+args.hours*3600;client=Client();saved=0
    try:
        while time.monotonic()<deadline and saved<args.rounds:
            number=state['round']+1;topics={}
            try:
                topics=client.call('curriculum')
                if topics.get('format')!='nebula-topics-1' or topics.get('rawChatsExported') is not False:topics={}
            except ResearchError:
                print(json.dumps({'chatTopicFeedUnavailable':True,'verifiedPracticeContinues':True}),flush=True)
            focus=topic_focus(state['bestReport'],state['rejected'],number,topics)
            # Cycle lower rates and focus on plateaus without discarding saved gains.
            lr=[.00002,.00001,.000005][min(2,state['rejected']//3)]
            output=project/'round.pt'
            print(json.dumps({'v6Round':number,'focus':focus,'learningRate':lr,'additionalSteps':args.steps,
                              'gpus':state['profile']['gpus'],'chatTopicFeedAvailable':bool(topics),
                              'chatGuidedRound':bool(number%4==0 and any(type(v) is int and 5<=v<=10000 for k,v in topics.get('counts',{}).items() if k in ['identity','math','memory','language']))}),flush=True)
            # /tmp on Kaggle: never add private teaching text to /kaggle/working outputs.
            with tempfile.TemporaryDirectory(prefix='nebula-reviewed-') as temporary:
                review_data=Path(temporary)/'fresh-reviewed-training.jsonl'
                review_count=refresh_reviews(client,review_data)
                launch(project,best,output,args.steps,state['profile']['gpus'],focus,lr=lr,data=data,best=True,conversation_mix=True,review_data=review_data,
                       save_every=100,sampling_seed=(20261017+number)%(2**31),max_seconds=max(1,min(3600,deadline-time.monotonic())))
            selected=best;report=state['bestReport'];accepted=False;files={}
            for label,path in [('final',output),('lowest-loss',output.with_suffix('.best.pt'))]:
                if label=='lowest-loss' and digests(path)[0]==digests(output)[0]:continue
                report_file=project/f'{label}-report.json'
                candidate=evaluate(path,evaluation_data,checks,report_file)
                files['report-'+label]=(report_file,f'reports/{number:04d}-{label}.json')
                if research_improves(report,candidate):selected=path;report=candidate;accepted=True
            state={**state,'round':number,'rejected':0 if accepted else state['rejected']+1,
                   'bestReport':report,'lastAccepted':accepted,'status':'ready'}
            # Upload weights only: ~33 MB per latest snapshot, no private chats or
            # large optimizer copies. A restart intentionally starts fresh AdamW.
            files['latest']=(compact(output,project/'latest-weights.pt'),'latest.pt')
            if accepted:files['best']=(compact(selected,project/'best-weights.pt'),'best.pt')
            state=store.publish(state,files,project);saved+=1
            best=store.download(state['best'],project/'resume-best.pt')
            print(json.dumps({'v6RoundSaved':number,'acceptedResearchHead':accepted,'bestCorrect':report['correct'],
                 'cases':report['cases'],'publicWebsiteUpdated':False,'checkpointBackupConfirmed':True,'checkedReviewExamples':review_count,'conversationPercent':80,'mixedPercent':20}),flush=True)
            gc.collect();torch.cuda.empty_cache()
            stop=project/'STOP_AFTER_ROUND'
            if stop.exists():print('Stop file found; the last round is backed up.');break
    except KeyboardInterrupt:
        print('Stopped. Resume the last confirmed private backup with the same run name.',flush=True)
    print(json.dumps({'v6SessionFinished':True,'savedRound':state['round'],'resumeWithSameRunName':True,
                      'publicWebsiteUpdated':False,'reason':'stop_or_session_budget'}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v6Stopped':error.code}),flush=True);raise SystemExit(1)
