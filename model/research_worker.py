"""Bounded trainer/evaluator workers coordinating through the private API."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import torch
from kaggle_migrate import migrate,restore_data
from nebula import load
from research_client import Client,ResearchError
from research_eval import evaluate,focus_for
from research_train import main as train_one
from rules import owner_instructions

def configure_rules(project):
    # Code can live above the trainer/evaluator data folders in combined mode.
    # Bind both this process and its GPU subprocesses to the verified restored rules.
    path=(Path(project)/'nebula-rules.json').resolve()
    if not path.is_file():raise ResearchError('RESTORED_OWNER_RULES_MISSING')
    os.environ['NEBULA_RULES_FILE']=str(path)
    owner_instructions()

def prefer(base,next):
    keys=['identity','math','memory','extraction','health']
    score=lambda value:sum(value[k] for k in keys[:4])/4
    return all(next[k]>=base[k]-.05 for k in keys) and next['health']>=base['health'] and next['loss']<=base['loss']*1.10 and (
        score(next)>=score(base)+.025 or score(next)>=score(base) and next['loss']<base['loss']*.995)

def training_plan(state):
    rejected=max(0,min(3,int(state.get('rejectedRounds') or 0)))
    focus='balanced'
    report=(state.get('lastEvaluation') or {}).get('report') or {}
    if rejected:
        if report.get('health',1)<.8:focus='language'
        else:
            categories=sorted(['identity','math','memory','extraction'],key=lambda key:report.get(key,0))
            focus=categories[(rejected-1)%len(categories)]
            if focus=='extraction':focus='memory'
    # Rejected checkpoints are never reused as the stable head. Change the
    # optimization on retry instead of replaying the same deterministic run.
    return {'focus':focus,'lr':.000025*(.5**rejected),'rejectedRounds':rejected}

def launch(project,resume,output,steps,gpus,focus,lease=None,benchmark=False,lr=.00005,max_seconds=3600,
           data=None,batch=16,best=False,save_every=200,sampling_seed=42,conversation_mix=False,review_data=None,quality_anchor=None,teacher_data=None,large_model=False,microbatch=1):
    command=[sys.executable]
    if gpus>1:command+=['-m','torch.distributed.run','--standalone','--nproc_per_node',str(gpus)]
    command+=[str(Path(__file__).with_name('v8_train.py' if large_model else 'v7_train.py' if quality_anchor else 'research_train.py')),'--data',str(data or project/'model/data/v3-chat.jsonl'),
              '--resume',str(resume),'--output',str(output),'--steps',str(steps),'--batch',str(batch),
              '--focus',focus,'--lr',str(lr),'--max-seconds',str(max_seconds),'--save-every',str(save_every),'--sampling-seed',str(sampling_seed)]
    if large_model:command+=['--microbatch',str(microbatch)]
    if quality_anchor:command+=['--quality-anchor',str(quality_anchor)]
    if teacher_data:command+=['--teacher-data',str(teacher_data)]
    if conversation_mix:command+=['--conversation-mix']
    if review_data:command+=['--review-data',str(review_data)]
    if best:command+=['--best-checkpoint']
    if benchmark:command+=['--benchmark']
    env=dict(os.environ)
    if lease:env['NEBULA_JOB_LEASE']=lease
    else:env.pop('NEBULA_JOB_LEASE',None)
    process=subprocess.Popen(command,cwd=project,env=env,start_new_session=os.name!='nt')
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
    if code:raise ResearchError('TRAINING_PROCESS_STOPPED')
    return json.loads(output.with_suffix('.performance.json').read_text())

def choose_gpus(project,resume,mode):
    count=min(2,torch.cuda.device_count())
    if count<1:raise ResearchError('GPU_REQUIRED')
    if mode!='auto':return min(count,int(mode))
    if count==1:return 1
    results={}
    for devices in [1,2]:
        try:results[devices]=launch(project,resume,project/f'benchmark-{devices}.pt',20,devices,'balanced',benchmark=True)['targetsPerSecond']
        except ResearchError:results[devices]=0
    if not any(results.values()):raise ResearchError('GPU_BENCHMARK_FAILED')
    chosen=2 if results[2]>results[1]*1.05 else 1
    print(json.dumps({'gpuBenchmark':results,'selectedGPUs':chosen}),flush=True)
    return chosen

def bootstrap(client,project,input_root):
    state=client.call('state')
    if state.get('head'):return state
    migrate(input_root,project)
    checkpoint=project/'model/checkpoints/v3-chat.best.pt'
    _,metadata=load(checkpoint)
    data=client.upload(project/'Nebula_V3_Data.pt','dataset')
    model=client.upload(checkpoint)
    return client.call('seed',{'dataset':data,'checkpoint':model,'dataSha256':metadata['dataSha256']})

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role',choices=['trainer','evaluator'],required=True)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--input',type=Path,default=Path('/kaggle/input'))
    parser.add_argument('--gpus',choices=['auto','1','2'],default='auto')
    parser.add_argument('--hours',type=float,default=6)
    parser.add_argument('--rounds',type=int,default=12)
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 1<=args.rounds<=24:parser.error('Use up to 8 hours and 1-24 rounds')
    project=args.project.resolve();project.mkdir(parents=True,exist_ok=True)
    if not torch.cuda.is_available():raise ResearchError('GPU_REQUIRED')
    torch.set_num_threads(2)
    client=Client();deadline=time.monotonic()+args.hours*3600;rounds=0;gpus=None
    if args.role=='trainer':bootstrap(client,project,args.input)
    while rounds<args.rounds and time.monotonic()<deadline:
        state=client.call('state')
        if not state.get('head'):
            print('Waiting for Kaggle to upload the starting model and data.',flush=True);time.sleep(30);continue
        backup=client.download(state['dataset'],project/'Nebula_V3_Data.pt');restore_data(backup,project)
        configure_rules(project)
        if args.role=='trainer' and gpus is None:
            head=client.download(state['head'],project/'benchmark-source.pt')
            gpus=choose_gpus(project,head,args.gpus)
        try:claimed=client.call('claim',{})
        except ResearchError as error:
            if error.code in ['WORKER_BUSY','WAITING_FOR_OTHER_WORKER']:
                print(json.dumps({'waiting':error.code,'role':args.role}),flush=True);time.sleep(30);continue
            raise
        job=claimed['lease'];lease=job['id']
        if job['role']!=args.role:raise ResearchError('WRONG_WORKER_SECRET')
        base=client.download(job['base'],project/'base.pt')
        if args.role=='trainer':
            output=project/f'round-{claimed["revision"]}.pt'
            plan=training_plan(claimed)
            print(json.dumps({'trainingPlan':plan,'base':job['base']}),flush=True)
            launch(project,base,output,2000,gpus,plan['focus'],lease,lr=plan['lr'],max_seconds=max(1,min(3600,deadline-time.monotonic())))
            client.call('heartbeat',{'lease':lease})
            candidate=client.upload(output,parent=job['base'],lease=lease)
            client.call('submit',{'lease':lease,'id':candidate})
            print(json.dumps({'submittedForEvaluation':candidate,'base':job['base']}),flush=True)
        else:
            candidate=client.download(job['candidate'],project/'candidate.pt')
            data=project/'model/data/v3-chat.jsonl'
            client.call('heartbeat',{'lease':lease})
            baseline=evaluate(base,data,output=project/'baseline-evaluation.json')
            client.call('heartbeat',{'lease':lease})
            trained=evaluate(candidate,data,output=project/'candidate-evaluation.json')
            focus=focus_for(trained);experiment=project/'experiment.pt'
            print(json.dumps({'baseline':baseline,'trained':trained,'experimentFocus':focus}),flush=True)
            launch(project,candidate,experiment,200,1,focus,lease,lr=.000025,max_seconds=max(1,min(3600,deadline-time.monotonic())))
            client.call('heartbeat',{'lease':lease})
            adapted=evaluate(experiment,data,output=project/'experiment-evaluation.json')
            decision={'lease':lease,'candidate':job['candidate'],'baseline':baseline,'trained':trained}
            # Only upload a bounded experiment if it can beat both alternatives.
            selected=trained if prefer(baseline,trained) else baseline
            if prefer(baseline,adapted) and prefer(selected,adapted):
                identifier=client.upload(experiment,parent=job['candidate'],lease=lease)
                decision['experiment']={'id':identifier,'report':adapted}
            final=client.call('decide',decision)
            print(json.dumps({'evaluationDecision':final['lastEvaluation'],'publicWebsiteUpdated':False}),flush=True)
        rounds+=1
        (project/'worker-state.json').write_text(json.dumps({'completedRounds':rounds,'role':args.role}),encoding='utf-8')
    print('Worker budget finished. Checkpoints remain in object storage and local notebook outputs.',flush=True)

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'workerStopped':str(error.code),'status':error.status}),flush=True);sys.exit(1)
