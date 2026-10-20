"""Four public corpora; full source records, bounded acquisition, disjoint holdouts."""
import hashlib,json,re,time,unicodedata
from collections import Counter
from pathlib import Path
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from v9_data import canonical,prompts,digest,locked_checks
from v7_checks import touches_checks
from v4_data import forbidden,blocked_questions
from v12_data import ROLEPLAY,REWRITE_SYSTEM

class HeldoutMatcher:
    """Aho-Corasick literal matching: scan each record once for all held-out prompts."""
    def __init__(self,patterns):
        from collections import deque
        self.edges=[{}];self.failure=[0];self.terminal=[False]
        for pattern in sorted(set(patterns)):
            if len(pattern)<=16:continue
            state=0
            for char in pattern:
                if char not in self.edges[state]:
                    self.edges[state][char]=len(self.edges);self.edges.append({});self.failure.append(0);self.terminal.append(False)
                state=self.edges[state][char]
            self.terminal[state]=True
        queue=deque(self.edges[0].values())
        while queue:
            state=queue.popleft()
            for char,child in self.edges[state].items():
                queue.append(child);fallback=self.failure[state]
                while fallback and char not in self.edges[fallback]:fallback=self.failure[fallback]
                self.failure[child]=self.edges[fallback].get(char,0)
                self.terminal[child]=self.terminal[child] or self.terminal[self.failure[child]]
    def contains(self,text):
        state=0
        for char in text:
            while state and char not in self.edges[state]:state=self.failure[state]
            state=self.edges[state].get(char,0)
            if self.terminal[state]:return True
        return False

SOURCES={
 'chat':{'revision':'f73fe857d519ff6ac5af2ea67c4d3834da7b8bcc','dataset':'HuggingFaceTB/smol-smoltalk','subset':'default','license':'apache-2.0','target':12000},
 'cosmopedia':{'revision':'3ba9d605774198c5868892d7a8deda78031a781f','dataset':'HuggingFaceTB/smollm-corpus','subset':'cosmopedia-v2','license':'odc-by','target':1000},
 'fineweb':{'revision':'87f09149ef4734204d70ed1d046ddc9ca3f2b8f9','dataset':'HuggingFaceFW/fineweb-edu','subset':'sample-10BT','license':'odc-by','target':1000},
 'stories':{'revision':'f54c09fd23315a6f9c86f9dc80f725de7d8f9c64','dataset':'roneneldan/TinyStories','subset':'default','license':'cdla-sharing-1.0','target':1000}}
SECRET=re.compile(r'https?://|\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b|(?:gsk_|hf_|sk-|AIza|AQ\.)[\w-]{12,}|\b(?:ChatGPT|Gemini|Groq|OpenAI|Claude|Anthropic)\b|<think>|</think>',re.I)
SPECIALIST=re.compile(r'```|\b(?:diagnos\w*|dosage|prescri\w*|investment advice|stock picks)\b',re.I)

def normalize(text):
    text=unicodedata.normalize('NFKC',text).translate(str.maketrans({'\u2018':"'",'\u2019':"'",'\u201c':'"','\u201d':'"','\u2014':'-','\u2013':'-'}))
    return text.replace('\r\n','\n').replace('\r','\n').strip()

def rejection(row,blocked=()):
    src=row.get('source',{})
    if src.get('curriculum') not in ['v13-language','v13-conversation']:
        from v10_data import rejection as old
        return old(row,blocked)
    if not eligible(row):return 'ineligible'
    if touches_checks(row['messages']) or prompts(row)&set(blocked):return 'heldout_prompt'
    _,checks=locked_checks()
    if forbidden(row,checks,blocked_questions(checks)):return 'frozen_check'
    if sum(len(m['content'].encode('utf-8')) for m in row['messages'])>24000:return 'record_too_large'
    for m in row['messages']:
        t=m['content']
        if SECRET.search(t) or SPECIALIST.search(t):return 'contact_identity_or_specialist'
        if any(ord(c)<32 and c not in '\n\t' for c in t) or '\ufffd' in t:return 'malformed'
        if t.endswith(('...','\u2026')):return 'truncated'
        if m['role']=='assistant':
            if not 2<=len(t.encode('utf-8'))<=12000:return 'answer_size'
            if not t.rstrip().endswith(('.', '?', '!', '"', "'",')',']','*')):return 'incomplete'
            words=re.findall(r'\w+',t.casefold());grams=[tuple(words[i:i+4]) for i in range(len(words)-3)]
            if len(grams)>15 and len(set(grams))<.80*len(grams):return 'repetition'
            for a,b,v in re.findall(r'(?<![\d-])(\d+)\s*\+\s*(\d+)\s*=\s*(-?\d+)',t):
                if int(a)+int(b)!=int(v):return 'incorrect_addition'
    if src['curriculum']=='v13-conversation' and any(ROLEPLAY.search(m['content']) for m in row['messages']):return 'roleplay'
    return None

def convert(item,kind,index,revision):
    spec=SOURCES[kind];changes=[]
    if kind=='chat':
        original=item.get('messages')
        if not isinstance(original,list):return None,'structure'
        messages=[dict(m) for m in original if isinstance(m,dict)]
        if len(messages)!=len(original):return None,'structure'
        if messages and messages[0].get('role')=='system':
            if normalize(messages[0].get('content',''))!=normalize(REWRITE_SYSTEM):return None,'unsupported_system'
            messages=messages[1:]
            if not messages or messages[0].get('role')!='user':return None,'structure'
            messages[0]['content']='Rewrite this text more concisely while keeping its meaning: '+messages[0]['content'];changes.append('Known rewriting instruction moved intact into user request')
        if not 2<=len(messages)<=12 or len(messages)%2:return None,'turn_count'
        if any(m.get('role')!=('user' if i%2==0 else 'assistant') or not isinstance(m.get('content'),str) for i,m in enumerate(messages)):return None,'roles'
        messages=[{'role':m['role'],'content':normalize(m['content'])} for m in messages]
        component=item.get('source','unknown');identity=hashlib.sha256(json.dumps(original,sort_keys=True).encode()).hexdigest()
    else:
        text=item.get('text')
        if not isinstance(text,str) or not 200<=len(text.encode('utf-8'))<=12000:return None,'text_size'
        if kind=='fineweb':
            score=item.get('score')
            if item.get('language','en')!='en' or type(score) not in (int,float) or score<3:return None,'language_or_education_score'
        text=normalize(text)
        # Retain the complete original passage. This wrapper is never used as a chat target.
        messages=[{'role':'user','content':'Read this passage.'},{'role':'assistant','content':text}]
        identity=hashlib.sha256(' '.join(text.split()).encode()).hexdigest();component=kind
    row={'id':example_id(messages),'reviewStatus':'approved','approvalMethod':'structural-screening-not-fact-checked','splitGroup':spec['dataset']+':'+identity,
         'source':{'kind':'public',**{k:v for k,v in spec.items() if k!='target'},'recordId':identity,'revision':revision,'originalSplit':'train','rowIndex':index,'component':component,'url':'https://huggingface.co/datasets/'+spec['dataset'],'curriculum':'v13-conversation' if kind=='chat' else 'v13-language','transformations':changes+['Unicode punctuation and line endings normalized; no source answer truncated'],'humanVerified':False},'messages':messages}
    reason=rejection(row)
    return (None,reason) if reason else (row,None)

def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2),encoding='utf-8');tmp.replace(path)

def acquire(folder,targets=None,stream_factory=None,on_source=None,kinds=None):
    """Pinned, streamed train splits only. Complete checkpoints survive retries in this runtime."""
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);targets=targets or {k:v['target'] for k,v in SOURCES.items()};stats={}
    for kind,spec in SOURCES.items():
        if kinds is not None and kind not in kinds:continue
        path=folder/(kind+'.jsonl');meta=folder/(kind+'.json');previous=json.loads(meta.read_text()) if meta.is_file() else None
        if previous and previous.get('complete') and previous.get('target',0)>=targets[kind] and path.is_file() and digest(path)==previous['sha256']:
            stats[kind]=previous;continue
        print(json.dumps({'v13SourceConnecting':kind,'dataset':spec['dataset'],'target':targets[kind]}),flush=True)
        if stream_factory:
            revision,stream=stream_factory(kind,spec)
        else:
            from datasets import load_dataset
            revision=previous['revision'] if previous else spec['revision']
            stream=load_dataset(spec['dataset'],spec['subset'],split='train',streaming=True,revision=revision)
            stream=stream.shuffle(seed=20261018,buffer_size=256)
        rows=read_jsonl(path) if previous and path.is_file() and digest(path)==previous.get('sha256') else []
        seen={canonical(r['messages']) for r in rows};scan=previous.get('scanned',0) if rows else 0;counts=Counter(previous.get('excluded',{}) if rows else {})
        # Stream a bounded prefix of a deterministic shuffled dataset; never download a full TB corpus.
        def persist(complete=False):
            temporary=path.with_suffix('.jsonl-tmp');write_jsonl(temporary,rows);temporary.replace(path)
            value={'dataset':spec['dataset'],'config':spec['subset'],'license':spec['license'],'revision':revision,'scanned':scan,'accepted':len(rows),'excluded':dict(counts),'sha256':digest(path),'complete':complete,'target':targets[kind],'sourceSplit':'train','individuallyFactChecked':False}
            atomic_json(meta,value);return value
        try:
            from itertools import islice
            for index,item in enumerate(islice(stream,scan,None),start=scan):
                scan=index+1;row,reason=convert(item,kind,index,revision)
                if row:
                    identity=canonical(row['messages'])
                    if identity in seen:counts['duplicate']+=1
                    else:rows.append(row);seen.add(identity)
                else:counts[reason]+=1
                if scan%500==0:
                    persist();print(json.dumps({'v13Acquiring':kind,'scanned':scan,'accepted':len(rows),'target':targets[kind]}),flush=True)
                if len(rows)>=targets[kind] or scan>=max(5000,targets[kind]*15):break
        except Exception:
            persist();raise RuntimeError('V13_SOURCE_DOWNLOAD_DEFERRED:'+kind) from None
        if len(rows)<min(100,targets[kind]):
            persist();raise ValueError('V13_SOURCE_TOO_FEW:'+kind)
        stats[kind]=persist(True)
        if on_source:on_source()
    atomic_json(folder/'manifest.json',stats);return stats

def merge(base,validation,public_rows,output,holdout,require_review=True):
    started=time.monotonic();public_rows=list(public_rows)
    print(json.dumps({'v13MergePhase':'index-existing-and-heldout-data','newCandidates':len(public_rows)}),flush=True)
    old=read_jsonl(base);fixed=read_jsonl(validation);blocked=set().union(*(prompts(r) for r in fixed));seen={canonical(r['messages']) for r in old+fixed}
    records={(r['source'].get('dataset'),r['source'].get('recordId')) for r in old+fixed};train=[];valid=[];counts=Counter();removed=Counter()
    fixed_prompts=set().union(*(prompts(r) for r in fixed))
    matcher=HeldoutMatcher(fixed_prompts)
    old_first={' '.join(r['messages'][0]['content'].casefold().split()) for r in old}
    print(json.dumps({'v13MergePhase':'filter-and-split','heldoutPrompts':len(fixed_prompts),'matcherStates':len(matcher.edges)}),flush=True)
    for index,row in enumerate(public_rows,1):
        if index==1 or index%250==0:
            print(json.dumps({'v13MergeProgress':index-1,'total':len(public_rows),'trainingAdded':len(train),'heldoutAdded':len(valid),'elapsedSeconds':round(time.monotonic()-started,1)}),flush=True)
        reason=rejection(row);key=canonical(row['messages']);record=(row['source'].get('dataset'),row['source'].get('recordId'))
        if key in seen or record in records:reason='existing_record'
        first=' '.join(row['messages'][0]['content'].casefold().split())
        if row['source']['curriculum']=='v13-conversation' and (prompts(row)&blocked or first in old_first):reason='overlapping_prompt'
        # Passages also must not contain held-out prompts verbatim, even within longer text.
        text=' '.join(' '.join(m['content'].casefold() for m in row['messages']).split())
        if matcher.contains(text):reason='heldout_text'
        if reason:removed[reason]+=1;continue
        if require_review and row['source']['curriculum']=='v13-conversation' and not row['source'].get('publicReviewProtocol'):removed['review_required']+=1;continue
        seen.add(key);records.add(record)
        if row['source']['curriculum']=='v13-conversation':
            original_group=row['splitGroup'];row={**row,'splitGroup':'v13-first-prompt-'+hashlib.sha256(first.encode()).hexdigest(),'source':{**row['source'],'originalSplitGroup':original_group}}
        group=int(hashlib.sha256(row['splitGroup'].encode()).hexdigest()[:8],16)
        (valid if group%10==0 else train).append(row);counts[row['source']['dataset']]+=1
    if any(counts[s['dataset']]<20 for s in SOURCES.values()):raise ValueError('V13_REQUIRES_NEW_DATA_FROM_ALL_FOUR_SOURCES')
    if sum(r['source']['curriculum']=='v13-conversation' for r in train)<100:raise ValueError('V13_REQUIRES_MORE_NEW_REVIEWED_CONVERSATIONS')
    print(json.dumps({'v13MergePhase':'write-datasets','trainingAdded':len(train),'heldoutAdded':len(valid),'elapsedSeconds':round(time.monotonic()-started,1)}),flush=True)
    write_jsonl(output,old+train);write_jsonl(holdout,valid)
    summary={'previousTrainingRows':len(old),'newTrainingRows':len(train),'newHeldoutRows':len(valid),'sources':dict(counts),'excluded':dict(removed),'publicChatReviewRequired':require_review,'fullAnswersRetained':True,'modelContextUnchanged':True,'publicWebsiteUpdated':False,'oldValidationSha256':digest(validation),'trainingSha256':digest(output),'publicHoldoutSha256':digest(holdout)}
    atomic_json(Path(output).with_suffix('.manifest.json'),summary)
    print(json.dumps({'v13MergeComplete':True,'elapsedSeconds':round(time.monotonic()-started,1),'trainingAdded':len(train),'heldoutAdded':len(valid)}),flush=True);return summary
