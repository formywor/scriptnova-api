"""Bounded public corpus expansion with original-source provenance and explicit holdouts."""
import hashlib,json,re,time,unicodedata
from pathlib import Path
import requests
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from nebula import encode
from rules import with_owner_rules
from train import partition_rows
from v4_data import exercises,forbidden,blocked_questions
from v7_checks import touches_checks
from v7_data import is_conversation

SOURCES={'chat':{'dataset':'HuggingFaceTB/smol-smoltalk','subset':'default','license':'apache-2.0'},'language':{'dataset':'roneneldan/TinyStories','subset':'default','license':'cdla-sharing-1.0'}}

def canonical(messages):return hashlib.sha256(json.dumps([{'role':m['role'],'content':' '.join(m['content'].casefold().split())} for m in messages],sort_keys=True).encode()).hexdigest()
def prompts(row):return {' '.join(m['content'].casefold().split()) for m in row['messages'] if m['role']=='user'}
def normalize(text):
    text=unicodedata.normalize('NFKC',text).translate(str.maketrans({'\u2018':"'",'\u2019':"'",'\u201c':'"','\u201d':'"','\u2014':'-','\u2013':'-'}))
    return ' '.join(text.split()).strip()

def valid_text(text):
    if not isinstance(text,str) or not 2<=len(text)<=800 or any(ord(c)>126 or ord(c)<32 for c in text):return False
    if re.search(r'https?://|@|(?:gsk_|hf_|sk-|AIza|AQ\.)[\w-]{12,}|\b(ChatGPT|Gemini|Groq|OpenAI|Claude|Anthropic|Llama)\b|<think>|</think>',text,re.I):return False
    return True

def convert(item,kind,index,split):
    source=SOURCES[kind]
    if kind=='chat':
        original=item.get('messages')
        if not isinstance(original,list) or not 2<=len(original)<=60:return None
        if any(not isinstance(m,dict) or m.get('role')!=('user' if i%2==0 else 'assistant') or not isinstance(m.get('content'),str) for i,m in enumerate(original)):return None
        if len(original)%2:return None
        messages=[]
        for i in range(0,min(len(original),12),2):
            pair=[{'role':m['role'],'content':normalize(m['content'])} for m in original[i:i+2]]
            if not all(valid_text(m['content']) for m in pair) or not pair[1]['content'].endswith(('.', '?', '!', '"')):break
            if re.search(r'\b(you are (?:a |an )?(?:person|human|\d+)|pretend you|act as|role.?play)\b',pair[0]['content'],re.I):return None
            if len(encode(with_owner_rules(messages+pair))[0])>1024:break
            messages+=pair
        if not messages:return None
        identity=hashlib.sha256(json.dumps(original,sort_keys=True).encode()).hexdigest()
    else:
        text=item.get('text')
        if not isinstance(text,str) or len(text)>12000:return None
        text=normalize(text.replace('<|endoftext|>',''))
        sentences=re.split(r'(?<=[.!?])\s+',text)
        if len(sentences)<3:return None
        prompt='Continue this short story: '+sentences[0]
        answer=' '.join(sentences[1:3])
        if not valid_text(prompt) or not valid_text(answer) or not answer.endswith(('.', '?', '!', '"')):return None
        messages=[{'role':'user','content':prompt},{'role':'assistant','content':answer}]
        if len(encode(with_owner_rules(messages))[0])>1024:return None
        identity=hashlib.sha256(text.encode()).hexdigest()
    _,checks=locked_checks()
    if touches_checks(messages) or forbidden({'messages':messages},checks,blocked_questions(checks)):return None
    return {'id':example_id(messages),'reviewStatus':'approved','approvalMethod':'public-structural-filter-not-individually-fact-checked','splitGroup':'v9-'+source['dataset']+'-'+identity,'source':{'kind':'public',**source,'recordId':identity,'originalSplit':split,'rowIndex':index,'url':'https://huggingface.co/datasets/'+source['dataset'],'curriculum':'v9-conversation' if kind=='chat' else 'v9-language'},'messages':messages}

_LOCKED=None
def locked_checks():
    global _LOCKED
    if _LOCKED is None:_LOCKED=exercises()
    return _LOCKED

def parquet_file(kind,split,shard,cache,fetch=requests.get):
    source=SOURCES[kind];url='https://huggingface.co/api/datasets/'+source['dataset']+'/parquet/default/'+split+'/'+str(shard)+'.parquet'
    path=Path(cache)/(kind+'-'+split+'-'+str(shard)+'.parquet');path.parent.mkdir(parents=True,exist_ok=True);hash_file=path.with_suffix('.sha256')
    if path.is_file() and hash_file.is_file() and digest(path)==hash_file.read_text().strip():return path
    last=None
    for attempt in range(3):
        temporary=path.with_suffix('.download-tmp')
        try:
            with fetch(url,stream=True,timeout=(20,120)) as response:
                response.raise_for_status();size=0
                with temporary.open('wb') as out:
                    for chunk in response.iter_content(1024*1024):
                        size+=len(chunk)
                        if size>512*1024*1024:raise ValueError('Public shard exceeds 512 MiB bound')
                        out.write(chunk)
            temporary.replace(path);hash_file.write_text(digest(path));return path
        except Exception as error:
            last=type(error).__name__;temporary.unlink(missing_ok=True)
            if attempt<2:time.sleep(2**attempt)
    raise ValueError('Public data download failed: '+str(last))

def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()

def acquire(directory,chat_target=12000,language_target=5000,validation_target=500,max_scan=100000):
    import pyarrow.parquet as pq
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    outputs={};stats={}
    for kind,target,split,role in [('chat',chat_target,'train','train-chat'),('language',language_target,'train','train-language'),('chat',validation_target,'test','valid-chat'),('language',validation_target,'validation','valid-language')]:
        output=directory/(role+'.jsonl');rows=read_jsonl(output) if output.exists() else [];seen={canonical(r['messages']) for r in rows};scanned=0;failure=None
        if len(rows)<target:
            try:
                for shard in range(2 if split=='train' else 1):
                    file=parquet_file(kind,split,shard,directory/'cache')
                    for batch in pq.ParquetFile(file).iter_batches(batch_size=512):
                        for item in batch.to_pylist():
                            scanned+=1;row=convert(item,kind,scanned,split)
                            if row and canonical(row['messages']) not in seen:seen.add(canonical(row['messages']));rows.append(row)
                            if scanned%2000==0:write_jsonl(output,rows);print(json.dumps({'publicCorpus':role,'scanned':scanned,'accepted':len(rows)}),flush=True)
                            if len(rows)>=target or scanned>=max_scan:break
                        if len(rows)>=target or scanned>=max_scan:break
                    if len(rows)>=target or scanned>=max_scan:break
            except Exception as error:failure=type(error).__name__
        write_jsonl(output,rows);outputs[role]=rows;stats[role]={'accepted':len(rows),'scannedThisRun':scanned,'target':target,'partial':len(rows)<target,'failure':failure,'sha256':digest(output)}
        print(json.dumps({'publicCorpusSaved':role,**stats[role]}),flush=True)
    (directory/'public-manifest.json').write_text(json.dumps({'sources':SOURCES,'counts':stats},indent=2),encoding='utf-8')
    return outputs,stats

def prepare(base,public,train_path,validation_path):
    rows=[r for r in read_jsonl(base) if eligible(r) and not touches_checks(r['messages'])]
    earlier,old_valid=partition_rows(rows,42)
    training=earlier+public['train-chat']+public['train-language'];validation=old_valid+public['valid-chat']+public['valid-language']
    validation_groups={r.get('splitGroup') for r in validation if r.get('splitGroup')}
    # Remove cross-source repeated prompts and exact conversations before window creation.
    validation_prompts=set().union(*(prompts(r) for r in validation));seen=set();train=[];valid=[];removed=0
    for row in training:
        identity=canonical(row['messages'])
        if identity in seen or row.get('splitGroup') in validation_groups or prompts(row)&validation_prompts:removed+=1;continue
        seen.add(identity);train.append(row)
    train_prompts=set().union(*(prompts(r) for r in train)) if train else set()
    valid_seen=set()
    for row in validation:
        identity=canonical(row['messages'])
        if identity in seen or identity in valid_seen or prompts(row)&train_prompts:continue
        valid_seen.add(identity);valid.append(row)
    if not any(r['source'].get('dataset')==SOURCES['chat']['dataset'] for r in train) or sum(is_conversation(r) for r in train)<200 or not any(r['source'].get('curriculum')=='v9-language' for r in train) or not public['valid-chat'] or not public['valid-language']:raise ValueError('V9 needs conversation/language training and separate public validation; rerun cached acquisition')
    write_jsonl(train_path,train);write_jsonl(validation_path,valid)
    summary={'trainingRows':len(train),'validationRows':len(valid),'newPublicConversations':sum(r['source'].get('dataset')==SOURCES['chat']['dataset'] for r in train),'languageExamples':sum(r['source'].get('curriculum')=='v9-language' for r in train),'removedDuplicateOrHeldOutPrompts':removed,'trainingSha256':digest(train_path),'validationSha256':digest(validation_path),'conversationPercent':80,'mixedPercent':20,'licenseProvenanceRetained':True}
    Path(train_path).with_suffix('.manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');return summary
