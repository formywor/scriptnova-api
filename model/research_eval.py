"""Locked, limited diagnostics. These scores do not establish general chat quality."""
import hashlib
import json
import re
from pathlib import Path
import torch
from dataflow import eligible,read_jsonl
from nebula import load
from rules import with_owner_rules
from train import examples,partition_rows,evaluate_loss,unique_windows

ROOT=Path(__file__).resolve().parent
CASES=json.loads((ROOT/'research_cases.json').read_text(encoding='utf-8'))

def research_rows(path):
    rows=read_jsonl(path)
    if any(row.get('source',{}).get('kind')=='user' for row in rows):
        raise ValueError('Research workers accept public, owned and permitted teacher data only')
    questions={case.get('prompt','').casefold() for case in CASES['cases']}
    for case in CASES['cases']:
        questions.update(m['content'].casefold() for m in case.get('messages',[]) if m['role']=='user')
    names=[name.casefold() for name in CASES['reservedNames']]
    return [row for row in rows if eligible(row) and
            not any(m['content'].casefold() in questions or any(name in m['content'].casefold() for name in names) for m in row['messages'])]

def healthy(text):
    if not text or '\ufffd' in text: return False
    words=re.findall(r"\w+",text.lower())
    if len(words)>12:
        grams=[tuple(words[i:i+3]) for i in range(len(words)-2)]
        if len(set(grams))<len(grams)*.65: return False
    return True

def correct(case,answer):
    if not healthy(answer): return False
    if 'number' in case:
        # A correct intermediate number embedded in an incorrect final answer
        # is not counted as success.
        numbers=re.findall(r'-?\d+',answer)
        return bool(numbers) and numbers[-1]==str(case['number'])
    return bool(re.search(r'\b'+re.escape(case['expected'])+r'\b',answer,re.I))

def evaluate(checkpoint,data,device='cuda',output=None):
    torch.set_num_threads(2)
    model,metadata=load(checkpoint);model.to(device)
    rows=research_rows(data);train_rows,valid_rows=partition_rows(rows,42)
    _,seen=unique_windows(examples(train_rows,model.config.context,True,'assistant'))
    validation,_=unique_windows(examples(valid_rows,model.config.context,True,'assistant'),seen)
    import random
    validation=random.Random(43).sample(validation,min(128,len(validation)))
    validation.sort(key=lambda pair:len(pair[0]))
    with torch.no_grad(): value=evaluate_loss(model,validation,8)
    groups={name:[] for name in ['identity','math','memory','extraction']};replies=[]
    for case in CASES['cases']:
        messages=case.get('messages') or [{'role':'user','content':case['prompt']}]
        answer=model.reply(with_owner_rules(messages),max_tokens=96,temperature=0)
        passed=correct(case,answer);groups[case['category']].append(passed)
        replies.append({'category':case['category'],'messages':messages,'reply':answer,'passed':passed})
    result={'benchmark':CASES['benchmark'],'loss':value,
            **{key:sum(scores)/len(scores) for key,scores in groups.items()},
            'health':sum(healthy(r['reply']) for r in replies)/len(replies)}
    if output: Path(output).write_text(json.dumps({'checkpoint':str(checkpoint),'metadata':metadata,'report':result,'replies':replies},indent=2),encoding='utf-8')
    del model
    if device=='cuda':torch.cuda.empty_cache()
    return result

def focus_for(report):
    if report['health']<.8:return 'language'
    weakest=min(['identity','math','memory','extraction'],key=lambda key:report[key])
    return 'memory' if weakest=='extraction' else weakest

def select_focus(rows,focus):
    if focus=='balanced':return rows
    if focus=='language':return [row for row in rows if row.get('source',{}).get('kind') in ['public','teacher']]
    def match(row):
        answer=' '.join(m['content'] for m in row['messages'] if m['role']=='assistant').lower()
        if focus=='identity':return 'nebula' in answer
        if focus=='math':return bool(re.search(r'\d+\s*[+\-]\s*\d+\s*=',answer))
        return len(row['messages'])>2 or 'your name is' in answer or 'bag is' in answer
    return [row for row in rows if match(row)]
