"""Learn every assistant byte once using rolling context, without fake answer endings."""
import torch
from nebula import BOS,encode
from rules import with_owner_rules

def windows(tokens,learn,context):
    if context<8:raise ValueError('Context must be at least eight tokens')
    # Each target appears once. Earlier tokens provide context only on later windows.
    stride=max(1,context//2)
    first=1
    while first<len(tokens):
        last=min(len(tokens),first+(context if first==1 else stride))
        begin=max(0,last-context-1)
        targets=[tokens[i] if i>=first and learn[i] else -100 for i in range(begin+1,last)]
        if any(t!=-100 for t in targets):
            yield torch.tensor(tokens[begin:last-1]),torch.tensor(targets)
        first=last

def examples(rows,context,include_owner_rules=False,objective='assistant'):
    from train import examples as legacy
    result=[]
    for row in rows:
        kind=row.get('source',{}).get('curriculum')
        if kind=='v13-language':
            # Raw educational text is language modeling, never a fabricated chat answer.
            tokens=[BOS]+list(row['messages'][1]['content'].encode('utf-8'))
            result.extend(windows(tokens,[False]+[True]*(len(tokens)-1),context))
        elif kind=='v13-conversation':
            tokens,learn=encode(with_owner_rules(row['messages']) if include_owner_rules else row['messages'])
            result.extend(windows(tokens,learn,context))
        else:result.extend(legacy([row],context,include_owner_rules,objective))
    return result
