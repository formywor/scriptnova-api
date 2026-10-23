"""Re-tokenize selected indexed public V18 documents in RAM, preserving splits."""
import json
from collections import OrderedDict,Counter
import numpy as np
from v18_stream import RemotePool,sha,emit,SOURCES
from v18_foundation_control import load_index,document
from v27_subword_model import SPECIAL,BOS,EOS,chat_window


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
    if state.get('dataReady'):
        tokenizer=Tokenizer.from_str(hub.read_entry(state['tokenizer']).decode())
        return state,tokenizer
    if not state.get('tokenizer'):raise ValueError('V28 requires the inherited V27 tokenizer; never retrain it')
    records,audit=load_index(source,saved)
    pools={}
    for split in ['train','validation']:
        pool=object.__new__(RemotePool);pool.hub=source;pool.entries=saved['corpus'][split];pool.cache=OrderedDict();pools[split]=pool
    selected={};sizes={}
    for split,budget in [('train',config['trainBytes']),('validation',config['validationBytes'])]:
        selected[split],sizes[split]=select_records(records,split,budget,config['sourceMix'])
    if {r['hash'] for r in selected['train']}&{r['hash'] for r in selected['validation']}:raise ValueError('Document split overlap')
    def text(row):
        _,result=document(pools[row['split']],row)
        if any(marker in result for marker in SPECIAL):raise ValueError('Reserved marker in corpus')
        return result
    # Learn BPE merges from train only; balanced byte budget per source. No validation text.
    samples=[];sample_bytes=Counter()
    if state.get('tokenizer'):
        tokenizer=Tokenizer.from_str(hub.read_entry(state['tokenizer']).decode())
        sample_bytes.update(state.get('tokenizerSampleBytes',{}))
    else:
        for row in selected['train']:
            key=row['source'];target=int(config['tokenizerBytes']*config['sourceMix'][key]/100)
            if sample_bytes[key]>=target:continue
            value=text(row);samples.append(value);sample_bytes[key]+=len(value.encode())
        tokenizer=train_tokenizer(iter(samples),config['vocab']);del samples
        tokenizer_json=tokenizer.to_str().encode()
        if tokenizer.get_vocab_size()>65535:raise ValueError('uint16 vocabulary exceeded')
        state=hub.publish({**state,'tokenizerSampleBytes':dict(sample_bytes)},
            {'tokenizer':('tokenizer.json',tokenizer_json)})
    token_counts={};ranges=state.get('tokenRanges',{})
    for split in ['train','validation']:
        if state.get(split+'Tokens'):continue
        chunks=[];offset=0;split_ranges={}
        for i,row in enumerate(selected[split]):
            ids=[BOS]+tokenizer.encode(text(row),add_special_tokens=False).ids+[EOS]
            chunks.append(np.asarray(ids,dtype='<u2'))
            key=row['source'];split_ranges.setdefault(key,[offset,offset]);offset+=len(ids);split_ranges[key][1]=offset
            if (i+1)%1000==0:emit(v28Tokenizing=split,documents=i+1,total=len(selected[split]))
        values=np.concatenate(chunks);del chunks
        if len(values)<=config['context']+1:raise ValueError('Token stream too short')
        token_counts[split]=len(values)
        ranges[split]=split_ranges
        state=hub.publish({**state,'tokenRanges':ranges},{split+'Tokens':(split+'-bpe-u16.bin',values.tobytes())})
        del values
    report=dict(format='nebula-v28-data-1',sourceRepo=config['repo'],sourceRun=config['rawRun'],sourceRevision=config['rawRevision'],
        sourceManifestSha256=sha(json.dumps(saved,sort_keys=True).encode()),indexAudit=audit,
        sourceMixRequestedUtf8Percent=config['sourceMix'],selectedUtf8Bytes=sizes,tokenizerTrainSampleBytes=dict(sample_bytes),
        documentHashes={k:[r['hash'] for r in rows] for k,rows in selected.items()},
        tokenCounts={k:state[k+'Tokens']['bytes']//2 for k in ['train','validation']},
        tokenRanges=ranges,
        sources={k:SOURCES[k] for k in config['sourceMix']},
        originalIndexReferences=saved['corpus']['index'],
        notice='Public source text only. Source URLs/attribution retained in pinned original index. Byte and subword losses are not directly comparable.')
    cards={}
    for key in config['sourceMix']:
        spec=SOURCES[key]
        cards['sourceCard_'+key]=(key+'-source-README.md',source.fetch(spec['dataset'],'README.md',spec['revision'],dataset=True))
    cards['dataReport']=('data-report.json',json.dumps(report,indent=2).encode())
    state=hub.publish({**state,'dataReady':True},cards)
    emit(v28DataReady=True,vocab=tokenizer.get_vocab_size(),tokenCounts=report['tokenCounts'],selectedUtf8Bytes=sizes)
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
