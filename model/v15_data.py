"""Complete Smol-SmolTalk records; no semantic, grammar, identity or topic grading."""
import hashlib,json,re
from collections import Counter
from pathlib import Path
from itertools import islice
import torch
from nebula import encode
from rules import with_owner_rules
from dataflow import read_jsonl,write_jsonl,example_id,eligible
from v9_data import canonical,prompts,digest
from v13_data import SOURCES,HeldoutMatcher,atomic_json
from v14_eval import blocked_prompts,rotating

SPEC=SOURCES['chat']
CREDENTIAL=re.compile(r'\b(?:gsk_|hf_|sk-|AIza|AQ\.)[\w-]{15,}|\bBearer\s+[\w.~/+=-]{12,}',re.I)
MAX_RECORD_BYTES=2*1024*1024
MAX_POOL_BYTES=128*1024*1024

def convert(item):
    messages=item.get('messages') if isinstance(item,dict) else None
    if not isinstance(messages,list) or len(messages)<2:return None,'structure'
    start=1 if isinstance(messages[0],dict) and messages[0].get('role')=='system' else 0
    chat=messages[start:]
    if not chat or len(chat)%2:return None,'incomplete-role-sequence'
    if any(not isinstance(m,dict) or not isinstance(m.get('content'),str) or not m['content'].strip() or m.get('role')!=('system' if i<start else 'user' if (i-start)%2==0 else 'assistant') for i,m in enumerate(messages)):return None,'structure'
    text=' '.join(m['content'] for m in messages)
    if len(text.encode())>MAX_RECORD_BYTES:return None,'whole-record-resource-limit'
    if CREDENTIAL.search(text):return None,'credential-pattern'
    # Keep complete source strings, punctuation, source system messages and every turn.
    kept=[{'role':m['role'],'content':m['content']} for m in messages]
    identifier=hashlib.sha256(json.dumps(messages,sort_keys=True).encode()).hexdigest()
    first=' '.join(chat[0]['content'].casefold().split())
    row={'id':example_id(kept),'reviewStatus':'not-reviewed','approvalMethod':'public-source-no-semantic-screening',
        'splitGroup':'v15-opening-'+hashlib.sha256(first.encode()).hexdigest(),
        'source':{'kind':'public','dataset':SPEC['dataset'],'subset':SPEC['subset'],'license':SPEC['license'],'revision':SPEC['revision'],'recordId':identifier,'originalSplit':'train','curriculum':'v15-full-chat','semanticReviewComplete':False,'humanVerified':False,'fullConversationRetained':True,'component':item.get('source','unknown')},'messages':kept}
    return row,None

def allowed(row):
    source=row.get('source',{})
    if source.get('curriculum')!='v15-full-chat':return eligible(row) and source.get('kind')!='user'
    if source.get('kind')!='public' or any(source.get(k)!=SPEC[k] for k in ['dataset','subset','license','revision']):return False
    expected,reason=convert({'messages':row.get('messages')})
    return reason is None and row.get('reviewStatus')=='not-reviewed' and row.get('id')==expected['id'] and row.get('splitGroup')==expected['splitGroup']

def acquire(folder,holdouts,target=20000,stream=None,on_save=None):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);path=folder/'full-pool.jsonl';meta_path=folder/'acquisition.json'
    meta=json.loads(meta_path.read_text()) if meta_path.exists() else {}
    fingerprint=hashlib.sha256(json.dumps({'heldout':[digest(p) for p in holdouts],'target':target,'revision':SPEC['revision']},sort_keys=True).encode()).hexdigest()
    if meta and meta.get('fingerprint')!=fingerprint:raise ValueError('V15 acquisition settings changed')
    rows=read_jsonl(path) if path.exists() and digest(path)==meta.get('sha256') else []
    if meta.get('complete') and rows:return rows,meta
    blocked=blocked_prompts()
    for case in rotating(0):blocked.update(m['content'].casefold() for m in case['messages'] if m['role']=='user')
    fixed=[]
    for heldout in holdouts:fixed.extend(read_jsonl(heldout))
    blocked.update(q for r in fixed for q in prompts(r));matcher=HeldoutMatcher(blocked)
    identifiers={r.get('source',{}).get('recordId') for r in fixed};seen={canonical(r['messages']) for r in rows}
    scan=meta.get('scanned',0) if rows else 0;excluded=Counter(meta.get('excluded',{}) if rows else {});size=sum(len(json.dumps(r,ensure_ascii=False).encode())+1 for r in rows)
    def persist(complete=False):
        write_jsonl(path,rows)
        value={'format':'nebula-v15-acquisition-1','fingerprint':fingerprint,'scanned':scan,'accepted':len(rows),'excluded':dict(excluded),'sha256':digest(path),'complete':complete,'target':target,'source':SPEC,'semanticScreening':False,'stringsTruncated':False,'turnsTruncated':False}
        atomic_json(meta_path,value)
        if on_save:on_save(path,meta_path)
        return value
    if stream is None:
        from datasets import load_dataset
        stream=load_dataset(SPEC['dataset'],SPEC['subset'],split='train',streaming=True,revision=SPEC['revision']).shuffle(seed=20261018,buffer_size=256)
    try:
        for index,item in enumerate(islice(stream,scan,None),scan):
            scan=index+1;row,reason=convert(item)
            if row:
                key=canonical(row['messages']);text=' '.join(' '.join(m['content'].casefold().split()) for m in row['messages'])
                if row['source']['recordId'] in identifiers or matcher.contains(text) or prompts(row)&blocked:reason='evaluation-overlap'
                elif key in seen:reason='exact-duplicate'
                if not reason:
                    length=len(json.dumps(row,ensure_ascii=False).encode())+1
                    if size+length>MAX_POOL_BYTES:break
                    rows.append(row);seen.add(key);size+=length
            if reason:excluded[reason]+=1
            if scan%500==0:
                persist();print(json.dumps({'v15FullChatsAcquired':len(rows),'sourceRecordsScanned':scan,'target':target,'semanticReviewCalls':0}),flush=True)
            if len(rows)>=target or scan>=target*5:break
    except Exception:
        persist();raise RuntimeError('V15_PUBLIC_DOWNLOAD_PAUSED_RESUME_SAME_NOTEBOOK') from None
    if len(rows)<min(100,target):persist();raise ValueError('V15_TOO_FEW_COMPLETE_CHATS')
    return rows,persist(True)

class CompleteWindows:
    """Compact byte tensors, lazy rolling windows; no answer/turn cutoff."""
    def __init__(self,row,context):
        tokens,learn=encode(with_owner_rules(row['messages']))
        self.tokens=torch.tensor(tokens,dtype=torch.int16);self.learn=torch.tensor(learn,dtype=torch.bool);self.ranges=[]
        first=1
        while first<len(tokens):
            last=min(len(tokens),first+(context if first==1 else max(1,context//2)));begin=max(0,last-context-1)
            if any(learn[first:last]):self.ranges.append((begin,first,last))
            first=last
    def __len__(self):return len(self.ranges)
    def __getitem__(self,index):
        begin,first,last=self.ranges[index];x=self.tokens[begin:last-1].long();y=self.tokens[begin+1:last].long().clone()
        mask=self.learn[begin+1:last].clone();mask[:max(0,first-begin-1)]=False;y[~mask]=-100
        return x,y

def pools(rows,context,stage):
    if stage!='conversation':raise ValueError('V15 is conversation-only')
    result=[]
    for row in rows:
        if not allowed(row):raise ValueError('V15 requires public or owned examples with valid provenance')
        windows=CompleteWindows(row,context)
        if windows:result.append(windows)
    if not result:raise ValueError('V15 has no assistant targets')
    return {'chat':result}

def pick(data,batch,step,seed,stage):
    import random
    rng=random.Random(seed+step);return [rng.choice(rng.choice(data['chat'])) for _ in range(batch)],'chat'
