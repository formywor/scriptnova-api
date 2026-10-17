"""A new, bounded Kaggle experiment; never resets or promotes the paused API campaign."""
import argparse
import gc
import json
import math
import os
from pathlib import Path
import time
import torch
from dataflow import read_jsonl
from kaggle_migrate import restore_data
from nebula import load
from research_client import Client,ResearchError,digests
from research_worker import configure_rules,launch
from v4_data import VERSION,prepare,public_additions
from v4_eval import evaluate,improves,focus_for
from v4_grow import grow_checkpoint
from v4_store import Store

def profile(project,checkpoint,data,label):
    measurements={}
    for gpus in range(1,min(2,torch.cuda.device_count())+1):
        try:
            value=launch(project,checkpoint,project/f'probe-{label}-{gpus}.pt',20,gpus,'balanced',
                         benchmark=True,lr=.00001,max_seconds=120,data=data)
        except ResearchError:
            print(json.dumps({'gpuProbeFailed':label,'gpus':gpus}),flush=True);continue
        measurements[gpus]=value
    if not measurements:raise ResearchError('V4_GPU_PROBE_FAILED')
    one=measurements.get(1,{}).get('targetsPerSecond',0);two=measurements.get(2,{}).get('targetsPerSecond',0)
    gpus=2 if two>one*1.05 else 1
    if gpus not in measurements:gpus=max(measurements)
    return {'gpus':gpus,**measurements[gpus]}

def size_model(project,baseline,data):
    original,metadata=load(baseline);layers=original.config.layers;del original
    original_profile=profile(project,baseline,data,'original')
    for extra in [4,2]:
        path=project/f'grown-{layers+extra}.pt'
        info=grow_checkpoint(baseline,path,layers+extra)
        try:measurement=profile(project,path,data,str(layers+extra))
        except ResearchError:continue
        if measurement['targetsPerSecond']>=original_profile['targetsPerSecond']*.45:
            print(json.dumps({'selectedLargerModel':info['growth'],'gpuProfile':measurement}),flush=True)
            return path,measurement,info['growth']
    print(json.dumps({'keptOriginalSize':True,'reason':'larger_profiles_failed_or_too_slow'}),flush=True)
    return baseline,original_profile,{'originalLayers':layers,'layers':layers,'initialFunctionPreserved':True}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--run',default='nebula-v4')
    parser.add_argument('--hours',type=float,default=6)
    parser.add_argument('--rounds',type=int,default=24)
    parser.add_argument('--steps',type=int,default=500)
    parser.add_argument('--public-rows',type=int,default=1000)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 1<=args.rounds<=48 or not 100<=args.steps<=2000 or not 0<=args.public_rows<=2000:
        parser.error('Use up to 8 hours, 1-48 rounds, 100-2000 steps, and 0-2000 public rows')
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    torch.set_num_threads(2);project=args.project.resolve();project.mkdir(parents=True,exist_ok=True)
    deadline=time.monotonic()+args.hours*3600
    store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),args.run)
    state=store.state()
    if state:
        if state.get('format')!=VERSION:raise ResearchError('V4_RESUME_VERSION_MISMATCH_USE_NEW_RUN_NAME')
        if state.get('status')=='paused':
            print('This experiment paused after three rejected attempts. Review saved reports before a new experiment.',flush=True);return
        backup=store.download(state['sourceData'],project/'source-data.pt');restore_data(backup,project);configure_rules(project)
        data=store.download(state['data'],project/'model/data/v4-chat.jsonl')
        checks=store.download(state['checks'],project/'model/data/v4-checks.json')
        best=store.download(state['best'],project/'resume-best.pt')
        baseline=store.download(state['baseline'],project/'preserved-baseline.pt')
        print(json.dumps({'resumedV4':True,'completedRounds':state['round'],'sourceModelUnchanged':True}),flush=True)
    else:
        client=Client();source=client.call('state')
        if not source.get('head'):raise ResearchError('RESEARCH_SOURCE_NOT_INITIALIZED')
        if source.get('lease') and source['lease']['expiresAt']>time.time()*1000:raise ResearchError('STOP_OLD_WORKER_AND_WAIT_FOR_LEASE')
        backup=client.download(source['dataset'],project/'source-data.pt');restore_data(backup,project);configure_rules(project)
        baseline=client.download(source['head'],project/'preserved-baseline.pt')
        prepared=store.state('prepared.json')
        if prepared and prepared.get('format')==VERSION and prepared.get('sourceDataSha256')==source['files'][source['dataset']]['sha256']:
            data=store.download(prepared['data'],project/'model/data/v4-chat.jsonl')
            checks=store.download(prepared['checks'],project/'model/data/v4-checks.json')
            path=store.download(prepared['dataManifest'],project/'model/data/v4-manifest.json')
            manifest=json.loads(path.read_text(encoding='utf-8'))
            print(json.dumps({'reusedPreparedV4Data':True,'conversations':manifest['conversations']}),flush=True)
        else:
            additions=public_additions(project/'public-additions',args.public_rows)
            data,checks,manifest=prepare(project,additions)
        best,measurement,growth=size_model(project,baseline,data)
        original_report=evaluate(baseline,data,checks,project/'original-evaluation.json')
        # Growth is checked for exact CPU forward equivalence before the GPU probe.
        # No large-model training is accepted merely for having more parameters.
        best_report=evaluate(best,data,checks,project/'grown-start-evaluation.json')
        if any(best_report[key]<original_report[key] for key in ['identity','math','memory','extraction','familiar']):
            raise ResearchError('V4_GROWTH_DIAGNOSTIC_REGRESSION')
        state={'format':VERSION,'run':args.run,'round':0,'rejected':0,'status':'ready',
               'sourceApiHead':source['head'],'dataSummary':manifest,'profile':measurement,'growth':growth,
               'originalReport':original_report,'bestReport':best_report,'publicAutoUpdate':False}
        state=store.publish(state,{
            'baseline':(baseline,'preserved-baseline.pt'),'sourceData':(backup,'source-data.pt'),
            'data':(data,'data/v4-chat.jsonl'),'checks':(checks,'data/v4-checks.json'),
            'dataManifest':(project/'model/data/v4-manifest.json','data/manifest.json'),
            'originalEvaluation':(project/'original-evaluation.json','reports/original.json'),
            'startEvaluation':(project/'grown-start-evaluation.json','reports/grown-start.json'),
            'best':(best,'initial-model.pt')},project)
    completed=0
    while completed<args.rounds and time.monotonic()<deadline:
        if state['rejected']>=3:break
        number=state['round']+1;focus=focus_for(state['bestReport'],state['rejected'])
        lr=.000025*(.5**state['rejected']);output=project/f'round-{number:04d}.pt'
        print(json.dumps({'v4Round':number,'focus':focus,'learningRate':lr,'additionalSteps':args.steps,
                          'selectedGpuCount':state['profile']['gpus']}),flush=True)
        launch(project,best,output,args.steps,state['profile']['gpus'],focus,lr=lr,
               max_seconds=max(1,min(3600,deadline-time.monotonic())),data=data,best=True,save_every=100)
        selected_report=state['bestReport'];selected_path=best;accepted=False;files={}
        for label,path in [('final',output),('lowest-loss',output.with_suffix('.best.pt'))]:
            if label=='lowest-loss' and digests(path)[0]==digests(output)[0]:continue
            report_path=project/f'round-{number:04d}-{label}.json'
            report=evaluate(path,data,checks,report_path)
            files['report-'+label]=(report_path,f'reports/{number:04d}-{label}.json')
            if improves(selected_report,report):selected_report=report;selected_path=path;accepted=True
        rejected=0 if accepted else state['rejected']+1
        state={**state,'round':number,'rejected':rejected,'status':'paused' if rejected>=3 else 'ready',
               'bestReport':selected_report,'lastRoundAccepted':accepted}
        files['latest']=(output,f'checkpoints/{number:04d}-final.pt')
        if accepted:files['best']=(selected_path,f'checkpoints/{number:04d}-selected.pt')
        state=store.publish(state,files,project)
        # Downloads validate committed bytes and also handle a new Kaggle session.
        best=store.download(state['best'],project/'resume-best.pt')
        print(json.dumps({'v4RoundAccepted':accepted,'rejectedAttempts':rejected,'bestReport':selected_report,
                          'apiHeadUnchanged':True,'publicWebsiteUpdated':False}),flush=True)
        completed+=1;gc.collect();torch.cuda.empty_cache()
    print(json.dumps({'v4RunFinished':True,'status':state['status'],'completedRounds':state['round'],
                      'resumeWithSameRunName':True,'publicWebsiteUpdated':False}),flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'v4Stopped':error.code}),flush=True);raise SystemExit(1)
