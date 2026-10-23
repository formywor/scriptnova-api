"""Re-tokenize selected indexed public V18 documents in RAM, preserving splits."""
import json
from collections import OrderedDict,Counter
import numpy as np
from v18_stream import RemotePool,sha,emit,SOURCES
from v18_foundation_control import load_index,document
from v27_subword_model import SPECIAL,BOS,EOS,chat_window
from v29_clean_text import clean_text


def train_tokenizer(texts,vocab=8192):
    from tokenizers import Tokenizer,models,trainers,pre_tokenizers,decoders
    tokenizer=Tokenizer(models.BPE(unk_token=None))
    tokenizer.pre_tokenizer=pre_tokenizers.ByteLevel(add_prefix_space=False)
    tokenizer.decoder=decoders.ByteLevel()
    tokenizer.train_from_iterator(texts,trainer=trainers.BpeTrainer(vocab_size=vocab,min_frequency=2,
        special_tokens=SPECIAL,initial_alphabet=pre_tokenizers.ByteLevel.alphabet(),show_progress=False))
    for i,s in enumerate(SPECIAL):
        if tokenizer.token_to_id(s)!=i:raise ValueError('Tokenizer special IDs mismatch')
    return tokenizer


def select_records(records,split,budget,mix):
    selected=[];used=Counter()
    for source,weight in mix.items():
        target=int(budget*weight/100)
        for row in records:
            if row['source']!=source or row['split']!=split:continue
            if used[source]>=target:break
            selected.append(row);used[source]+=row['utf8Bytes']
        if used[source]<target*.95:raise ValueError('Insufficient saved source bytes: '+split+'/'+source)
    return selected,dict(used)


def prepare(hub,state,source,saved,config):
    from tokenizers import Tokenizer
    if not state.get('tokenizer'):raise ValueError('Inherit V28 tokenizer; do not retrain BPE')
    tokenizer=Tokenizer.from_str(hub.read_entry(state['tokenizer']).decode())
    if state.get('dataReady'):return state,tokenizer
    records,audit=load_index(source,saved)
    pools={}
    for split in ['train','validation']:
        pool=object.__new__(RemotePool);pool.hub=source;pool.entries=saved['corpus'][split];pool.cache=OrderedDict();pools[split]=pool
    selected={}
    for split,budget in [('train',config['trainBytes']),('validation',config['validationBytes'])]:
        selected[split],_=select_records(records,split,budget,config['sourceMix'])
    # Cleaning can make previously different documents identical. Validation is processed first.
    # Its cleaned hashes are reserved before any training document is accepted.
    valid_hashes=set();train_hashes=set();reports={};ranges={};raw_counts={};clean_counts={}
    for split in ['validation','train']:
        counts=Counter();edits=Counter();sources=Counter();original_sources=Counter();hashes=[];original_hashes=[]
        chunks=[];offset=0;split_ranges={}
        for i,row in enumerate(selected[split]):
            _,text=document(pools[split],row)
            value,detail=clean_text(text)
            counts['documentsScanned']+=1;original_sources[row['source']]+=row['utf8Bytes']
            edits.update(detail['edits']);counts['encodingRepaired']+=int(detail['encodingRepaired'])
            if value is None:counts['rejected/'+detail['reason']]+=1;continue
            if any(marker in value for marker in SPECIAL):counts['rejected/reserved-marker']+=1;continue
            h=detail['normalizedHash'];seen=valid_hashes if split=='validation' else train_hashes
            if h in seen or (split=='train' and h in valid_hashes):counts['rejected/cleaned-duplicate']+=1;continue
            seen.add(h);hashes.append(h);original_hashes.append(row['hash']);counts['accepted']+=1
            ids=[BOS]+tokenizer.encode(value,add_special_tokens=False).ids+[EOS]
            chunks.append(np.asarray(ids,dtype='<u2'));key=row['source']
            split_ranges.setdefault(key,[offset,offset]);offset+=len(ids);split_ranges[key][1]=offset
            sources[key]+=len(value.encode())
            if (i+1)%2000==0:emit(v29Cleaning=split,documents=i+1,accepted=counts['accepted'],total=len(selected[split]))
        values=np.concatenate(chunks) if chunks else np.asarray([],dtype='<u2');del chunks
        if len(values)<=config['context']+1:raise ValueError('Not enough cleaned text')
        raw_counts[split]=dict(original_sources);clean_counts[split]=dict(sources);ranges[split]=split_ranges
        reports[split]=dict(counts=dict(counts),edits=dict(edits),cleanedHashes=hashes,originalHashes=original_hashes)
        state=hub.publish({**state,'tokenRanges':ranges},{split+'Tokens':(split+'-clean-bpe-u16.bin',values.tobytes())})
        del values
    if valid_hashes&train_hashes:raise ValueError('Cleaned train/validation overlap')
    report=dict(format='nebula-v29-clean-data-1',originalIndexAudit=audit,sourceRepo=config['repo'],sourceRun=config['rawRun'],
        sourceRevision=config['rawRevision'],sourceMixRequestedOriginalBytes=config['sourceMix'],originalSelectedUtf8Bytes=raw_counts,
        cleanedUtf8Bytes=clean_counts,cleaning=reports,tokenRanges=ranges,
        tokenCounts={k:state[k+'Tokens']['bytes']//2 for k in ['train','validation']},
        sourceReferences={k:SOURCES[k] for k in config['sourceMix']},originalIndexReferences=saved['corpus']['index'],
        tokenizerInherited=True,cleanedHashesDisjoint=True,
        notice='Cleaned version of the same selected original V28 documents. Exact normalized dedup after repair; no fuzzy dedup or factual verification. Partial preparation may rebuild in RAM.')
    blobs={'dataReport':('clean-data-report.json',json.dumps(report,indent=2).encode())}
    for key in config['sourceMix']:
        spec=SOURCES[key];blobs['sourceCard_'+key]=(key+'-source-README.md',source.fetch(spec['dataset'],'README.md',spec['revision'],dataset=True))
    state=hub.publish({**state,'dataReady':True},blobs)
    emit(v29DataReady=True,tokenCounts=report['tokenCounts'],cleanedUtf8Bytes=clean_counts,
        cleaning={k:{'counts':v['counts'],'edits':v['edits']} for k,v in reports.items()})
    return state,tokenizer


def raw_batch(values,step,batch,context,seed):
    rng=np.random.default_rng(seed+step*7919)
    starts=rng.integers(0,len(values)-context,size=batch)
    import torch
    return [(torch.tensor(np.array(values[s:s+context],dtype=np.int64)),
             torch.tensor(np.array(values[s+1:s+context+1],dtype=np.int64))) for s in starts]


def public_windows(rows,tokenizer,context):
    train=[];valid=[];excluded=0
    for row in rows:
        try:pair=chat_window(tokenizer,row['messages'],context)
        except ValueError:excluded+=1;continue
        (valid if int(row['id'][:8],16)%20==0 else train).append(pair)
    if len(train)<100 or len(valid)<16:raise ValueError('Insufficient public SFT split')
    return train,valid[:64],dict(trainConversations=len(train),validationConversations=len(valid),excluded=excluded,
        assistantOnly=True,fullConversations=True,synthetic=True,humanVerified=False)
