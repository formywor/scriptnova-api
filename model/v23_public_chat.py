"""Pinned public conversations, complete within context; RAM to HF only."""
import fnmatch
import json
import random
import re
from collections import Counter
from nebula import encode
from v18_stream import digest,emit,SECRET
from v19_tutor_data import norm

DATASET='HuggingFaceTB/smol-smoltalk'
REVISION='f73fe857d519ff6ac5af2ea67c4d3834da7b8bcc'
SPEC=dict(dataset=DATASET,revision=REVISION,license='apache-2.0',url='https://huggingface.co/datasets/'+DATASET,
          terms='https://www.apache.org/licenses/LICENSE-2.0',split='train',synthetic=True)


def records(hub,cursor,seed):
    from huggingface_hub import HfFileSystem
    import pyarrow.parquet as pq
    info=hub.api.dataset_info(DATASET,revision=REVISION)
    card=info.card_data.to_dict() if hasattr(info.card_data,'to_dict') else dict(info.card_data or {})
    patterns=[]
    for item in card.get('configs',[]):
        if item.get('config_name')=='default':
            for entry in item.get('data_files',[]):
                if entry.get('split')=='train':
                    value=entry['path'];patterns.extend(value if isinstance(value,list) else [value])
    if not patterns:patterns=['data/train-*.parquet','train/*.parquet']
    paths=sorted(p for p in hub.api.list_repo_files(DATASET,repo_type='dataset',revision=REVISION)
                 if p.endswith('.parquet') and any(fnmatch.fnmatch(p,pattern) for pattern in patterns))
    if not paths:raise ValueError('Pinned public dataset has no declared train parquet files')
    random.Random(seed).shuffle(paths);fs=HfFileSystem(token=hub.token)
    for file_index in range(cursor['file'],len(paths)):
        start=cursor['row'] if file_index==cursor['file'] else 0
        with fs.open(f'datasets/{DATASET}@{REVISION}/{paths[file_index]}','rb',block_size=4*1024*1024,cache_type='bytes') as stream:
            parquet=pq.ParquetFile(stream)
            # Parquet schema.names lists nested leaves; Arrow names preserve top-level messages.
            if 'messages' not in parquet.schema_arrow.names:raise ValueError('Public chat messages column missing')
            columns=['messages']+(['source'] if 'source' in parquet.schema_arrow.names else [])
            offset=0
            for group in range(parquet.num_row_groups):
                size=parquet.metadata.row_group(group).num_rows
                if offset+size<=start:offset+=size;continue
                for batch in parquet.iter_batches(batch_size=32,row_groups=[group],columns=columns):
                    for row in batch.to_pylist():
                        index=offset;offset+=1
                        if index<start:continue
                        yield row,dict(file=file_index,row=index+1),paths[file_index]+':'+str(index)


def convert(item,context,banned):
    messages=item.get('messages')
    if not isinstance(messages,list) or not 2<=len(messages)<=12:return None,'structure'
    clean=[];expected='user'
    for i,message in enumerate(messages):
        if not isinstance(message,dict):return None,'structure'
        role=message.get('role');text=message.get('content')
        if not isinstance(text,str) or not text.strip():return None,'structure'
        text=text.replace('\r\n','\n').replace('\r','\n').strip()
        if role=='system' and i==0:pass
        elif role==expected:expected='assistant' if role=='user' else 'user'
        else:return None,'structure'
        if SECRET.search(text) or re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',text):return None,'contact_or_credential'
        if '\ufffd' in text or any(ord(c)<32 and c not in '\n\t' for c in text):return None,'encoding'
        if role=='user' and norm(text) in banned:return None,'benchmark'
        if role in ['system','assistant'] and re.search(r'\b(ChatGPT|OpenAI|Claude|Gemini|Llama|HuggingChat)\b',text,re.I):return None,'provider_identity'
        clean.append(dict(role=role,content=text))
    if clean[-1]['role']!='assistant':return None,'incomplete'
    try:tokens,_=encode(clean)
    except (ValueError,UnicodeError):return None,'encoding'
    if len(tokens)>context+1:return None,'too_long_no_truncation'
    return dict(family='public',messages=clean,id=digest(clean),origin='public-synthetic',
                source={**SPEC,'component':str(item.get('source','unknown'))[:100],
                        'transformations':['CRLF normalized; outer whitespace stripped; complete conversation retained'],
                        'humanVerified':False}),None


def prepare_public(hub,state,config,context,banned,reader=records):
    prep=dict(state.get('publicPreparation') or dict(cursor=dict(file=0,row=0),scanned=0,excluded={},complete=False))
    rows=json.loads(hub.read_entry(state['publicRows'])) if state.get('publicRows') else []
    seen={row['id'] for row in rows};counts=Counter(prep['excluded'])
    target=config['publicConversations'];limit=config['publicMaxScanned']
    def save():
        nonlocal state
        prep.update(excluded=dict(counts),accepted=len(rows))
        state=hub.publish({**state,'publicPreparation':dict(prep)},
                         {'publicRows':('public-conversations.json',json.dumps(rows).encode())})
        emit(v23PublicPreparationSaved=True,scanned=prep['scanned'],accepted=len(rows),complete=prep['complete'])
    if prep['complete']:return state,rows
    if not state.get('publicSourceCard'):
        card=hub.fetch(DATASET,'README.md',REVISION,dataset=True)
        state=hub.publish(state,{'publicSourceCard':('smol-smoltalk-README.md',card),
              'publicSourceAttribution':('public-attribution.json',json.dumps(SPEC,indent=2).encode())})
    try:
        for item,cursor,locator in reader(hub,prep['cursor'],config['seed']):
            if len(rows)>=target or prep['scanned']>=limit:break
            prep['cursor']=cursor;prep['scanned']+=1
            row,reason=convert(item,context,banned)
            if row and row['id'] not in seen:
                seen.add(row['id']);row['source']['locator']=locator;rows.append(row)
            else:counts[reason or 'duplicate']+=1
            if prep['scanned']%2000==0:
                emit(v23PublicProgress=True,scanned=prep['scanned'],accepted=len(rows),target=target)
            if len(rows) and len(rows)%500==0 and prep.get('accepted')!=len(rows):save()
        if len(rows)<min(target,256):
            save();raise ValueError('Not enough complete public conversations fit the context; preparation saved. Inspect exclusions before training.')
        prep['complete']=True;prep['targetReached']=len(rows)>=target;save()
    except BaseException:
        if len(rows)!=prep.get('accepted',0):save()
        raise
    return state,rows


def partition(rows):
    # The whole conversation stays in one split, including every assistant turn.
    train=[row for row in rows if int(row['id'][:8],16)%20!=0]
    valid=[row for row in rows if int(row['id'][:8],16)%20==0]
    if not train or not valid:raise ValueError('Public conversation holdout is empty; acquire more records')
    return train,valid
