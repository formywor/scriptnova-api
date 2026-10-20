"""Compare generated chat answers as well as fixed, balanced held-out chat loss."""
import json
from pathlib import Path
import random
import re
import torch
from dataflow import read_jsonl
from train import examples,partition_rows,unique_windows
from nebula import load
from rules import with_owner_rules
from research_eval import healthy
from v4_eval import evaluate as legacy_evaluate
from v7_train import summed_loss
from v7_data import is_conversation
from v7_checks import CASES

def evaluate(checkpoint,legacy_data,checks,chat_validation,output,device='cuda'):
    legacy=legacy_evaluate(checkpoint,legacy_data,checks,Path(output).with_suffix('.legacy.json'),device)
    model,metadata=load(checkpoint);model.to(device);model.eval()
    valid=read_jsonl(chat_validation)
    rows=[r for r in valid if is_conversation(r)]
    windows,_=unique_windows(examples(rows,model.config.context,True))
    if not windows:raise ValueError('V9 requires fixed held-out conversation windows')
    windows=random.Random(707).sample(windows,min(64,len(windows)))
    total=0.;count=0;answers=[]
    with torch.no_grad():
        for i in range(0,len(windows),4):
            value,n,_=summed_loss(model,windows[i:i+4],torch.device(device),False,torch.float32);total+=float(value);count+=n
        for case in CASES:
            answer=model.reply(with_owner_rules(case['messages']),max_tokens=128,temperature=0);lower=answer.casefold()
            contains=lambda word:bool(re.search(r'(?<!\w)'+re.escape(word)+r'(?!\w)',lower))
            passed=healthy(answer) and answer.rstrip().endswith(('.', '?', '!')) and len(answer.split())>=case.get('minWords',1) and any(contains(word) for word in case['any']) and not any(contains(word) for word in case.get('not',[]))
            answers.append({'messages':case['messages'],'reply':answer,'passed':passed})
    public_rows=[r for r in valid if r['source'].get('dataset')=='HuggingFaceTB/smol-smoltalk']
    public_windows,_=unique_windows(examples(public_rows,model.config.context,True))
    if not public_windows:raise ValueError('V9 requires unseen public conversation windows')
    public_windows=random.Random(711).sample(public_windows,min(64,len(public_windows)))
    public_total=0.;public_count=0
    with torch.no_grad():
        for window in public_windows:
            value,n,_=summed_loss(model,[window],torch.device(device),False,torch.float32);public_total+=float(value);public_count+=n
    language=[r for r in valid if r['source'].get('curriculum')=='v9-language']
    language_windows,_=unique_windows(examples(language,model.config.context,True))
    if not language_windows:raise ValueError('V9 requires held-out language windows')
    language_windows=random.Random(709).sample(language_windows,min(64,len(language_windows)))
    language_total=0.;language_count=0
    with torch.no_grad():
        for batch in language_windows:
            value,n,_=summed_loss(model,[batch],torch.device(device),False,torch.float32);language_total+=float(value);language_count+=n
    report={**legacy,'publicChatLoss':public_total/public_count,'languageLoss':language_total/language_count if language_count else None,'chatLoss':total/count,'chatChecks':sum(a['passed'] for a in answers),'chatCases':len(answers)}
    Path(output).write_text(json.dumps({'report':report,'answers':answers,'metadata':metadata},indent=2),encoding='utf-8')
    del model
    if device=='cuda':torch.cuda.empty_cache()
    print(json.dumps({'v9Evaluation':report,'checkpoint':Path(checkpoint).name}),flush=True);return report
