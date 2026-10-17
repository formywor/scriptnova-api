"""Alternate training and evaluation in one Kaggle runtime using the same API leases."""
import argparse
import json
import os
from pathlib import Path
import time
from research_client import Client,ResearchError
from research_worker import main as worker

def next_role(state):
    return 'evaluator' if state.get('candidate') else 'trainer'

def main(argv=None,*,run_worker=worker,clock=time.monotonic):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--hours',type=float,default=6)
    parser.add_argument('--rounds',type=int,default=12)
    parser.add_argument('--gpus',choices=['auto','1','2'],default='auto')
    args=parser.parse_args(argv)
    if not 0<args.hours<=8 or not 1<=args.rounds<=24:parser.error('Use up to 8 hours and 1-24 rounds')
    tokens={role:os.environ.get(f'NEBULA_{role.upper()}_TOKEN','') for role in ['trainer','evaluator']}
    if any(len(token)<32 for token in tokens.values()) or tokens['trainer']==tokens['evaluator']:
        raise ResearchError('COMBINED_WORKER_SECRETS_MISSING')
    original=os.environ.get('NEBULA_WORKER_TOKEN')
    deadline=clock()+args.hours*3600;completed=0
    try:
        while completed<args.rounds and clock()<deadline:
            state=Client(token=tokens['trainer']).call('state')
            role=next_role(state)
            if (state.get('rejectedRounds') or 0)>=3 and role=='trainer':
                raise ResearchError('RESEARCH_PAUSED_NO_IMPROVEMENT')
            remaining=(deadline-clock())/3600
            if remaining<=0:break
            os.environ['NEBULA_WORKER_TOKEN']=tokens[role]
            # Run one phase at a time, so evaluation never competes with training for GPU memory.
            project=args.project/role
            print(json.dumps({'kagglePhase':role,'completedEvaluationRounds':completed}),flush=True)
            run_worker(['--role',role,'--project',str(project),'--hours',str(min(8,remaining)),
                        '--rounds','1','--gpus',args.gpus])
            if role=='evaluator':completed+=1
        print(json.dumps({'combinedRunFinished':True,'completedEvaluationRounds':completed,
                          'publicWebsiteUpdated':False}),flush=True)
    finally:
        if original is None:os.environ.pop('NEBULA_WORKER_TOKEN',None)
        else:os.environ['NEBULA_WORKER_TOKEN']=original

if __name__=='__main__':
    try:main()
    except ResearchError as error:print(json.dumps({'workerStopped':error.code,'status':error.status}),flush=True);raise SystemExit(1)
