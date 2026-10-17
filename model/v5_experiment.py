"""Resumable learning from V4's strongest trial, with separate public releases."""
import argparse
import gc
import json
import math
import os
from pathlib import Path
import shutil
import time
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
from v5_data import VERSION,prepare

SOURCE_REVISION='916b0eaed037df63cdd0add74f10452ce394aaf1'

def research_improves(base,candidate):
    keys=['loss','health','correct','cases',*GROUPS]
    if any(not math.isfinite(r.get(k,float('nan'))) for r in [base,candidate] for k in keys):return False
    if base['cases']!=candidate['cases'] or candidate['health']<max(.90,base['health']-.03):return False
    if candidate['loss']>base['loss']*1.08:return False
    groups=GROUPS[:4]+(['conversation'] if 'conversation' in base else [])
    if any(not math.isfinite(r.get(k,float('nan'))) for r in [base,candidate] for k in groups):return False
    macro=lambda r:sum(r[k] for k in groups)/len(groups)
    # A research head may trade a few diagnostic cases for broader gains. A
    # public release is pinned separately and is never changed by this rule.
    return (candidate['correct']>base['correct'] and macro(candidate)>=macro(base)-.01) or (
        candidate['correct']==base['correct'] and macro(candidate)>=macro(base) and candidate['loss']<base['loss']*.99)

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
    # Pin the inspected trial rather than following a mutable latest pointer.
    def get(name,target):
        try:path=hf_hub_download(store.repo,'experiments/nebula-v4/'+name,revision=SOURCE_REVISION,token=store.token)
        except Exception:raise ResearchError('V5_SOURCE_DOWNLOAD_FAILED') from None
        target=project/target;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target);return target
    source=get('source-data.pt','source-data.pt');restore_data(source,project);configure_rules(project)
    base_data=get('data/v4-chat.jsonl','model/data/v4-chat.jsonl')
    source_manifest=get('data/manifest.json','model/data/v4-source-manifest.json')
    checks=get('data/v4-checks.json','model/data/v4-checks.json')
    cases=json.loads(checks.read_text(encoding='utf-8'))
    cases['cases'] += [
        {'category':'conversation','prompt':'Could you write a brief note thanking someone?','expected':'thank'},
        {'category':'conversation','prompt':'What do you say when someone says thank you?','expected':'welcome'},
        {'category':'conversation','prompt':'Can you tell me whether you are human?','expected':'AI'},
        {'category':'conversation','prompt':'Help me draft an email to someone.','expected':'who'},
        {'category':'conversation','prompt':'Please explain what ice is.','expected':'water'},
        {'category':'conversation','prompt':'How long is one hour in minutes?','number':60}]
    checks=project/'model/data/v5-checks.json';checks.write_text(json.dumps(cases,indent=2),encoding='utf-8')
    baseline=get('checkpoints/0001-final.pt','preserved-v4-strongest.pt')
    data=project/'model/data/v5-chat.jsonl';summary=prepare(base_data,data)
    measurement=profile(project,baseline,data,'v5')
    report=evaluate(baseline,base_data,checks,project/'baseline-report.json')
    state={'format':VERSION,'round':0,'rejected':0,'bestReport':report,'sourceRevision':SOURCE_REVISION,
           'publicAutoUpdate':False,'profile':measurement,'dataSummary':summary,'status':'ready',
           'remoteWeightSnapshotsThisSession':0}
    return store.publish(state,{'sourceData':(source,'source-data.pt'),'baseline':(baseline,'preserved-v4-strongest.pt'),
       'evaluationData':(base_data,'data/v4-chat.jsonl'),'checks':(checks,'data/v5-checks.json'),
       'data':(data,'data/v5-chat.jsonl'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),
       'sourceManifest':(source_manifest,'data/source-manifest.json'),
       'baselineReport':(project/'baseline-report.json','reports/baseline.json'),
       'best':(compact(baseline,project/'initial-weights.pt'),'best.pt')},project)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--run',default='nebula-v5')
    parser.add_argument('--hours',type=float,default=8);parser.add_argument('--steps',type=int,default=500)
    parser.add_argument('--rounds',type=int,default=100)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 100<=args.steps<=2000 or not 1<=args.rounds<=100:parser.error('Use 0-8 hours, 100-2000 updates per round, and 1-100 rounds')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True);torch.set_num_threads(2)
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run)
    state=store.state()
    if state and state.get('format')!=VERSION:raise ResearchError('V5_VERSION_MISMATCH')
    if not state:state=initial(store,project)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    data=store.download(state['data'],project/'model/data/v5-chat.jsonl')
    evaluation_data=store.download(state['evaluationData'],project/'model/data/v4-chat.jsonl')
    checks=store.download(state['checks'],project/'model/data/v4-checks.json')
    best=store.download(state['best'],project/'resume-best.pt')
    print(json.dumps({'resumedV5':True,'completedRounds':state['round'],'bestReport':state['bestReport'],
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
            print(json.dumps({'v5Round':number,'focus':focus,'learningRate':lr,'additionalSteps':args.steps,
                              'gpus':state['profile']['gpus'],'chatTopicFeedAvailable':bool(topics),
                              'chatGuidedRound':bool(number%4==0 and any(type(v) is int and 5<=v<=10000 for k,v in topics.get('counts',{}).items() if k in ['identity','math','memory','language']))}),flush=True)
            launch(project,best,output,args.steps,state['profile']['gpus'],focus,lr=lr,data=data,best=True,
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
            print(json.dumps({'v5RoundSaved':number,'acceptedResearchHead':accepted,'bestCorrect':report['correct'],
                 'cases':report['cases'],'publicWebsiteUpdated':False,'checkpointBackupConfirmed':True}),flush=True)
            gc.collect();torch.cuda.empty_cache()
            stop=project/'STOP_AFTER_ROUND'
            if stop.exists():print('Stop file found; the last round is backed up.');break
    except KeyboardInterrupt:
        print('Stopped. Resume the last confirmed private backup with the same run name.',flush=True)
    print(json.dumps({'v5SessionFinished':True,'savedRound':state['round'],'resumeWithSameRunName':True,
                      'publicWebsiteUpdated':False,'reason':'stop_or_session_budget'}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v5Stopped':error.code}),flush=True);raise SystemExit(1)
