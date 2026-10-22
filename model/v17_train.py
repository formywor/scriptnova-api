"""Bounded stage engine with exact optimizer resume, token accounting and strict probes."""
import hashlib
import json
import math
import time
from collections import Counter
from pathlib import Path
import torch
from nebula import load, save
from rules import with_owner_rules
from v10_train import summed_loss
from v14_train import language_sum
from v14_eval import completion
from v16_diagnostic import emit
from v17_data import VERSION, digest, training_batch


def code_hash():
    return hashlib.sha256(b''.join(Path(__file__).with_name(n).read_bytes() for n in
         ['v17_train.py','v17_data.py','v17_lab.py','nebula.py','v13_windows.py','v10_train.py','v14_train.py','rules.py'])).hexdigest()


@torch.inference_mode()
def evaluate(model, tests, validation=None):
    model.eval(); rows=[]; counts={}
    for index, case in enumerate(tests):
        messages = case['messages'][:-1]
        reply = model.reply(with_owner_rules(messages), max_tokens=32, temperature=0)
        expected = case['messages'][-1]['content']
        correct = reply.strip().casefold() == expected.strip().casefold()
        rows.append({'axis':case['axis'],'messages':messages,'expected':expected,'reply':reply,'exactMatch':correct})
        if case.get('followup'):
            # Use the MODEL'S first answer; never teacher-force the expected answer into test history.
            follow = case['followup']; history = messages+[{'role':'assistant','content':reply},{'role':'user','content':follow['prompt']}]
            answer = model.reply(with_owner_rules(history), max_tokens=32, temperature=0)
            rows.append({'axis':case['axis'],'messages':history,'expected':follow['expected'],'reply':answer,
                         'exactMatch':answer.strip().casefold()==follow['expected'].strip().casefold()})
        if (index+1)%12==0: emit(v17EvaluationProgress=index+1, total=len(tests))
    for axis in sorted({r['axis'] for r in rows}):
        group=[r for r in rows if r['axis']==axis]
        counts[axis]={'correct':sum(r['exactMatch'] for r in group),'cases':len(group)}
    opens=[]
    for text in ['Hello! What can you help me with?', 'Explain why ice melts.',
                 'Write a thank-you note to a neighbor.', 'Which should I choose?']:
        messages=[{'role':'user','content':text}]
        opens.append({'messages':messages,'reply':model.reply(with_owner_rules(messages),max_tokens=96,temperature=0),
                      'grade':'pending-human-review'})
    raw=[completion(model, prefix, 80) for prefix in ['A child found a small boat beside the pond.',
                                                   'Ice melts when it takes in heat.']]
    losses={}
    device=next(model.parameters()).device
    for key,pairs in (validation or {}).items():
        total=0.;denominator=0
        for pair in pairs:
            if key=='language':
                value,n=language_sum(model,[pair],device,False,torch.float32)
            else:
                value,n,_=summed_loss(model,[pair],device,False,torch.float32)
            total+=float(value);denominator+=n
        losses[key]=total/max(1,denominator)
    summary={'exactCorrect':sum(r['exactMatch'] for r in rows),'cases':len(rows),'byAxis':counts,
             'heldoutLoss':losses,'qualityApproved':False,'humanVerified':False,
             'openAnswersPending':len(opens),'rawCompletionsPending':len(raw)}
    emit(v17Evaluation=summary)
    return {'summary':summary,'answers':rows,'openAnswers':opens,'rawCompletions':raw,
            'notice':'Exact synthetic checks measure these tasks only; readable text and low loss do not certify usefulness.'}


def fit(model, pools, stage, output, *, plan, resume=None, source_sha='',
        dataset_sha='', rules_sha='', max_seconds=3600, callback=None, stop_file=None):
    """No teacher, old-weight anchoring, auto-promotion, or validation-answer training."""
    device=next(model.parameters()).device; amp=device.type=='cuda'
    budget=plan['steps'][stage]; batch_size=plan['batch']; lr=plan['learningRates'][stage]
    signature={'format':VERSION,'stage':stage,'plan':plan,'config':vars(model.config),
               'codeSha256':code_hash(),'sourceSha256':source_sha,'dataSha256':dataset_sha,
               'rulesSha256':rules_sha,'precision':'fp16-amp' if amp else 'fp32'}
    optimizer=torch.optim.AdamW(model.parameters(),lr=lr,weight_decay=.01)
    scaler=torch.amp.GradScaler('cuda',enabled=amp,init_scale=1024)
    updates=inputs=targets=0;counts=Counter();last_saved=-1;last_meta=None
    if resume:
        saved=torch.load(resume,map_location='cpu',weights_only=True)
        state=saved['trainingState']
        if state.get('signature')!=signature: raise ValueError('V17_RESUME_CONFIG_CHANGED_USE_NEW_RUN_NAME')
        model.load_state_dict(saved['state']);optimizer.load_state_dict(state['optimizer']);scaler.load_state_dict(state['scaler'])
        updates=state['updates'];inputs=state['inputPositions'];targets=state['supervisedTokens'];counts.update(state['poolUpdates'])
        last_saved=updates;last_meta=saved['metadata']
    emit(v17TrainingStage=stage,updates=updates,budget=budget,optimizerRestored=bool(resume),
         records={k:len(v.rows) for k,v in pools.items()},globalBatch=batch_size,microbatch=plan['microbatch'])
    started=time.monotonic();bad=0
    def checkpoint(cloud=False):
        nonlocal last_saved,last_meta
        if updates!=last_saved or not Path(output).is_file():
            last_meta={'format':VERSION,'stage':stage,'updates':updates,'inputPositions':inputs,
                       'supervisedTokens':targets,'poolUpdates':dict(counts),'trainingStateIncluded':True,
                       'parameters':sum(p.numel() for p in model.parameters()),'qualityApproved':False,
                       'tokenUnit':'byte plus structural tokens; repeated exposure counted; validation excluded'}
            save(model,output,last_meta,training_state={'signature':signature,'optimizer':optimizer.state_dict(),
                 'scaler':scaler.state_dict(),'updates':updates,'inputPositions':inputs,
                 'supervisedTokens':targets,'poolUpdates':dict(counts)})
            last_saved=updates
            emit(v17LocalCheckpoint=str(output),stage=stage,updates=updates)
        if cloud and callback:callback(Path(output),last_meta)
        return last_meta
    reason='budget-complete'
    try:
        while updates<budget:
            if stop_file and Path(stop_file).exists():reason='stop-file';break
            if time.monotonic()-started>=max_seconds:reason='session-time-limit';break
            batch,key=training_batch(pools,stage,batch_size,updates,plan['seed'],plan['conversationPercent'])
            supervised=sum(int((y!=-100).sum()) for _,y in batch)
            optimizer.zero_grad(set_to_none=True);model.train()
            rate=lr*min(1.,(updates+1)/plan['warmup'])*(.1+.9*.5*(1+math.cos(math.pi*updates/max(1,budget))))
            for group in optimizer.param_groups:group['lr']=rate
            total=0.
            for offset in range(0,len(batch),plan['microbatch']):
                micro=batch[offset:offset+plan['microbatch']]
                if stage=='foundation':
                    value,n=language_sum(model,micro,device,amp,torch.float16);objective=value/max(1,supervised)
                else:
                    value,n,_=summed_loss(model,micro,device,amp,torch.float16);objective=value/batch_size
                if not torch.isfinite(objective):raise ValueError('V17_NONFINITE_LOSS')
                total+=float(objective.detach());scaler.scale(objective).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            if not torch.isfinite(norm):
                bad+=1
                if not amp or bad>12:raise ValueError('V17_NONFINITE_GRADIENTS')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            bad=0;scaler.step(optimizer);scaler.update();updates+=1;counts[key]+=1
            inputs+=sum(len(x) for x,_ in batch);targets+=supervised
            if updates%25==0:emit(v17Update=updates,stage=stage,budget=budget,loss=round(total,4),
                 learningRate=rate,poolUpdates=dict(counts),supervisedTokens=targets,
                 targetsPerSecond=round((targets-(state['supervisedTokens'] if resume else 0))/max(1,time.monotonic()-started)))
            if updates%plan['localSaveEvery']==0:checkpoint()
            if updates%plan['cloudSaveEvery']==0:checkpoint(True)
    except KeyboardInterrupt:
        checkpoint(True);raise
    meta=checkpoint(True)
    return {**meta,'stopReason':reason}
