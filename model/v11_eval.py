"""Verified diagnostics. AI review is fallible; unknown answers never count as passes."""
import json,random,re
from pathlib import Path
import torch
from dataflow import read_jsonl
from nebula import load
from rules import with_owner_rules
from train import examples,partition_rows,unique_windows,evaluate_loss
from v7_checks import CASES
from v7_data import is_conversation
from v7_train import summed_loss
from verified_grading import Reviewer,protocol,readable,normalized

def copy_case(case):return normalized(messages(case)[-1]['content']).startswith(('repeat this word exactly:','repeat exactly this word:','copy this word exactly:'))

def chat_cases():
    refs={1:('identity','Nebula'),5:('extraction','turquoise'),6:('extraction','Piko'),7:('extraction','Monday'),8:('extraction','weaving'),17:('extraction','bicycle')}
    return [{'messages':case['messages'],**({'category':refs[i][0],'expected':refs[i][1]} if i in refs else {'category':'open-chat'})} for i,case in enumerate(CASES)]

def task_cases(checks):
    cases=json.loads(Path(checks).read_text(encoding='utf-8'))['cases']
    cases=cases+[
        {'category':'familiar','prompt':'What is your name?','expected':'Nebula'},
        {'category':'familiar','prompt':'What is 2 + 2?','number':4},
        {'category':'familiar','prompt':'My name is Sam. What is my name?','expected':'Sam'}]
    for case in cases:
        if 'number' not in case:continue
        if type(case['number']) is not int:raise ValueError('Frozen numeric references must be integers')
        question=messages(case)[-1]['content'].casefold();operands=re.findall(r'-?\d+',question)
        if len(operands)==2 and ('+' in question or re.search(r'\badd\b|sum of',question)) and sum(map(int,operands))!=case['number']:raise ValueError('Frozen arithmetic reference disagrees with its question')
    return cases

def messages(case):return case.get('messages') or [{'role':'user','content':case['prompt']}]

def summarize(cases,answers,grades):
    rows=[{'category':case['category'],'exactCopyTask':copy_case(case),'messages':messages(case),'reference':case.get('expected',case.get('number')),'reply':answer,'readable':readable(answer),**grade} for case,answer,grade in zip(cases,answers,grades)]
    return rows

def metrics(tasks,chats):
    all_rows=tasks+chats
    report={'gradingProtocol':protocol(),'reviewComplete':all(row['passed'] is not None for row in all_rows),'pendingReview':sum(row['passed'] is None for row in all_rows),
        'correct':sum(row['passed'] is True for row in tasks),'cases':len(tasks),'health':sum(row['readable'] for row in tasks)/len(tasks),
        'chatChecks':sum(row['passed'] is True for row in chats),'chatCases':len(chats),'chatPendingReview':sum(row['passed'] is None for row in chats),
        'chatHealthy':sum(row['readable'] for row in chats)/len(chats),'humanVerified':False}
    for group in sorted({r['category'] for r in tasks}):
        subset=[r for r in tasks if r['category']==group];report[group]=sum(r['passed'] is True for r in subset)/len(subset)
    for name,subset in [('exactCopy',[r for r in tasks if r['exactCopyTask']]),('contextName',[r for r in tasks if r['category']=='memory' and not r['exactCopyTask']])]:
        report[name+'Cases']=len(subset);report[name+'Correct']=sum(r['passed'] is True for r in subset)
    return report

def loss_for(model,rows,seed,device):
    windows,_=unique_windows(examples(rows,model.config.context,True))
    if not windows:raise ValueError('V11 requires fixed held-out windows')
    windows=random.Random(seed).sample(windows,min(64,len(windows)));total=0.;count=0
    with torch.no_grad():
        for window in windows:
            value,n,_=summed_loss(model,[window],torch.device(device),False,torch.float32);total+=float(value);count+=n
    return total/count

def evaluate(checkpoint,legacy_data,checks,chat_validation,output,device='cuda',reviewer=None):
    output=Path(output)
    print(json.dumps({'v11EvaluationPhase':'generation-and-heldout-loss','checkpoint':Path(checkpoint).name}),flush=True)
    model,metadata=load(checkpoint);model.to(device);model.eval()
    training,valid=partition_rows(read_jsonl(legacy_data),42)
    _,seen=unique_windows(examples(training,model.config.context,True));windows,_=unique_windows(examples(valid,model.config.context,True),seen)
    windows=random.Random(49317).sample(windows,min(64,len(windows)));windows.sort(key=lambda pair:len(pair[0]))
    if not windows:raise ValueError('V11 requires independent legacy validation')
    with torch.no_grad():legacy_loss=evaluate_loss(model,windows,4)
    valid=read_jsonl(chat_validation)
    losses={'loss':legacy_loss,'chatLoss':loss_for(model,[r for r in valid if is_conversation(r)],707,device),
        'publicChatLoss':loss_for(model,[r for r in valid if r['source'].get('dataset')=='HuggingFaceTB/smol-smoltalk'],711,device),
        'languageLoss':loss_for(model,[r for r in valid if r['source'].get('curriculum')=='v9-language'],709,device)}
    tasks=task_cases(checks);chats=chat_cases();answers=[]
    for i,case in enumerate(tasks+chats):
        answers.append(model.reply(with_owner_rules(messages(case)),max_tokens=96 if i<len(tasks) else 128,temperature=0))
        if (i+1)%10==0:print(json.dumps({'v11GeneratedAnswers':i+1,'total':len(tasks)+len(chats)}),flush=True)
    del model
    if device=='cuda':torch.cuda.empty_cache()
    reviewer=reviewer or Reviewer(output.parent/'judge-cache.json')
    print(json.dumps({'v11EvaluationPhase':'strict-checks-and-semantic-review','syntheticTestsOnly':True}),flush=True)
    grades=reviewer.grade(tasks+chats,answers)
    task_rows=summarize(tasks,answers[:len(tasks)],grades[:len(tasks)]);chat_rows=summarize(chats,answers[len(tasks):],grades[len(tasks):])
    report={**metrics(task_rows,chat_rows),**losses}
    report['reviewServiceStatus']=reviewer.deferred or ('missing-key' if report['pendingReview'] and not reviewer.key else 'call-budget-reached' if report['pendingReview'] else 'complete')
    output.write_text(json.dumps({'report':report,'taskAnswers':task_rows,'answers':chat_rows,'metadata':metadata,'notice':'Exact checks plus fallible AI review; unknowns are pending, not passes. Readability is not correctness. Evaluation material never enters training.'},indent=2),encoding='utf-8')
    print(json.dumps({'v11Evaluation':report,'checkpoint':Path(checkpoint).name,'reviewCallsThisEvaluation':reviewer.calls}),flush=True)
    return report
