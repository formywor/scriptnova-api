"""Controlled, sequential learning-rate comparison; no automatic deployment."""
import copy
import gc
import time
import torch
from v18_stream import emit
from v26_answers import DEFAULT,run_tutor

ARMS=(('low',1e-6),('reference',3e-6),('high',1e-5))
PROTECTED=('entity-binding','updated-facts','unseen-values','unseen-wording','verbatim-copy')

def arm_configs(base=None):
    base=copy.deepcopy(DEFAULT if base is None else base)
    return [(name,dict(base,learningRate=rate)) for name,rate in ARMS]

def assess(report):
    baseline,final=report['baseline'],report['final']
    regressions=[axis for axis in PROTECTED if final['byAxis'][axis]['correct']<baseline['byAxis'][axis]['correct']]
    eligible=(not regressions and final['exactCorrect']>baseline['exactCorrect']
        and final['heldoutMixed']['loss']<=baseline['heldoutMixed']['loss']*1.05
        and final['heldoutPublic']['loss']<=baseline['heldoutPublic']['loss']*1.05)
    return dict(exactCorrect=final['exactCorrect'],cases=final['exactCases'],
        delta=final['exactCorrect']-baseline['exactCorrect'],protectedAxisRegressions=regressions,
        mixedLoss=final['heldoutMixed']['loss'],publicLoss=final['heldoutPublic']['loss'],
        eligibleForManualInspection=eligible,qualityApproved=False,publicWebsiteUpdated=False)

def run_sweep(base=None,hours=7.,device='cuda',runner=None,clock=None):
    if not 0<hours<=7.5:raise ValueError('Session hours must be in (0,7.5]')
    runner=run_tutor if runner is None else runner
    clock=time.monotonic if clock is None else clock
    deadline=clock()+hours*3600
    baseline=None;results=[]
    for name,config in arm_configs(base):
        if clock()>=deadline:break
        emit(v26ArmStarting=name,peakLearningRate=config['learningRate'],updatesPerArm=config['updates'],
             sameStartingWeights=True,sameDataAndOrder=True,publicWebsiteUpdated=False)
        result=runner('nebula-v26-lr-'+name,config,device=device,clock=clock,
                      shared_baseline=baseline,deadline=deadline)
        if 'final' not in result:
            emit(v26SweepPaused=True,pausedArm=name,runAllAgainWithIdenticalSettings=True)
            return dict(complete=False,results=results,pausedArm=name,publicWebsiteUpdated=False)
        if baseline is None:baseline=copy.deepcopy(result['baseline'])
        elif result['baseline']!=baseline:raise ValueError('Comparison baseline mismatch')
        summary=dict(arm=name,learningRate=config['learningRate'],**assess(result))
        results.append(summary);emit(v26ArmResult=summary)
        del result;gc.collect()
        if device=='cuda':torch.cuda.empty_cache()
    complete=len(results)==len(ARMS)
    emit(v26SweepComplete=complete,results=results,automaticWinnerSelected=False,publicWebsiteUpdated=False)
    return dict(complete=complete,results=results,qualityApproved=False,publicWebsiteUpdated=False,
        notice='Compare saved full replies as well as development scores. No automatic winner or deployment. Each arm has its own resumable HF report.')
