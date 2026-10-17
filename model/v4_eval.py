"""Frozen task checks plus an independent, grouped validation loss."""
import json
import random
from pathlib import Path
import torch
from dataflow import read_jsonl
from nebula import load
from research_eval import correct,healthy
from rules import with_owner_rules
from train import examples,partition_rows,unique_windows,evaluate_loss

GROUPS=['identity','math','memory','extraction','familiar']
def evaluate(checkpoint,data,checks,output,device='cuda'):
    model,metadata=load(checkpoint);model.to(device);model.eval()
    training,valid=partition_rows(read_jsonl(data),42)
    _,seen=unique_windows(examples(training,model.config.context,True))
    validation,_=unique_windows(examples(valid,model.config.context,True),seen)
    validation=random.Random(49317).sample(validation,min(64,len(validation)))
    validation.sort(key=lambda pair:len(pair[0]))
    if not validation:raise ValueError('V4 needs independent validation windows')
    with torch.no_grad():loss=evaluate_loss(model,validation,4)
    cases=json.loads(Path(checks).read_text(encoding='utf-8'))['cases']
    cases=cases+[
        {'category':'familiar','prompt':'What is your name?','expected':'Nebula'},
        {'category':'familiar','prompt':'What is 2 + 2?','number':4},
        {'category':'familiar','prompt':'My name is Sam. What is my name?','expected':'Sam'}]
    answers=[]
    for case in cases:
        messages=case.get('messages') or [{'role':'user','content':case['prompt']}]
        answer=model.reply(with_owner_rules(messages),max_tokens=96,temperature=0)
        answers.append({'category':case['category'],'messages':messages,'reply':answer,
                        'passed':correct(case,answer),'healthy':healthy(answer)})
    report={'loss':loss,'correct':sum(x['passed'] for x in answers),'cases':len(answers),
            'health':sum(x['healthy'] for x in answers)/len(answers),
            **{group:sum(x['passed'] for x in answers if x['category']==group)/sum(x['category']==group for x in answers) for group in GROUPS}}
    for group in {x['category'] for x in answers}-set(GROUPS):
        group_answers=[x for x in answers if x['category']==group]
        report[group]=sum(x['passed'] for x in group_answers)/len(group_answers)
    Path(output).write_text(json.dumps({'report':report,'answers':answers,'metadata':metadata},indent=2),encoding='utf-8')
    del model
    if device=='cuda':torch.cuda.empty_cache()
    print(json.dumps({'v4Evaluation':report,'checkpoint':Path(checkpoint).name}),flush=True)
    return report

def improves(base,candidate):
    import math
    keys=['loss','health','correct',*GROUPS]
    if any(not math.isfinite(value.get(key,float('nan'))) for value in [base,candidate] for key in keys):return False
    if any(candidate[k]+1e-9<base[k] for k in GROUPS) or candidate['health']<base['health']:return False
    return candidate['loss']<=base['loss']*1.03 and (
        candidate['correct']>base['correct'] or
        candidate['correct']==base['correct'] and candidate['loss']<base['loss']*.99)

def focus_for(report,rejections):
    if report['health']<.8:return 'language'
    groups=sorted(GROUPS[:4],key=lambda group:report[group])
    focus=groups[rejections%len(groups)]
    return 'memory' if focus=='extraction' else focus
