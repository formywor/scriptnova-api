"""Complete public conversations, scoped for the current small owned model."""
import argparse,hashlib,json,re,time
from collections import Counter
from pathlib import Path
import requests
from dataflow import read_jsonl,write_jsonl,example_id
from v9_data import canonical,prompts,normalize,parquet_file,digest
from v10_data import rejection

DATASET='HuggingFaceTB/smol-smoltalk'
ALLOWED={'smol-magpie-ultra-short','everyday-conversations','smollm-rewrite-30k','explore-instruct-rewrite'}
REWRITE_SYSTEM="You're an AI assistant for text re-writing. Rewrite the input text to make it more concise while preserving its core meaning."
EXCLUDE=re.compile(r'```|\b(?:python|javascript|typescript|sql|html|css|function|algorithm|tuple|dictionary|dataframe|dataset|stock|investment|diagnos\w*|medicat\w*|step.by.step|bullet points|forbidden.words)\b|\[ender\]|<think>',re.I)
ROLEPLAY=re.compile(r'\b(?:pretend|role.?play|act as|playing the (?:part|role)|you are (?:an? )?(?:\d+|person|human|woman|man|baker|time traveler|expert|reporter|detective))\b|\b(?:my childhood|my husband|my wife|my children|when i was a child|i visited|i have visited|i run (?:a|my) shop)\b',re.I)

def convert(item,index,shard):
    subset=item.get('source')
    if subset not in ALLOWED:return None,'out_of_scope_subset'
    raw=item.get('messages')
    if not isinstance(raw,list) or not 2<=len(raw)<=13 or any(not isinstance(m,dict) or not isinstance(m.get('content'),str) for m in raw):return None,'structure'
    original=json.dumps(raw,sort_keys=True);source_id=hashlib.sha256(original.encode()).hexdigest();turns=[dict(m) for m in raw];transform=[]
    if turns[0].get('role')=='system':
        if normalize(turns[0]['content'])!=normalize(REWRITE_SYSTEM):return None,'unsupported_system_instruction'
        turns=turns[1:]
        if not turns or turns[0].get('role')!='user':return None,'structure'
        turns[0]['content']='Rewrite this text more concisely while keeping its meaning: '+turns[0]['content'];transform.append('Moved the complete known rewriting instruction into the user request')
    if len(turns)%2 or any(m.get('role')!=('user' if i%2==0 else 'assistant') for i,m in enumerate(turns)):return None,'roles'
    messages=[{'role':m['role'],'content':normalize(m['content'])} for m in turns]
    if any(EXCLUDE.search(m['content']) for m in messages):return None,'specialist_or_format_task'
    if any(ROLEPLAY.search(m['content']) for m in messages):return None,'roleplay_or_human_biography'
    if any(m['content'].endswith(('...', '\u2026')) or '\ufffd' in m['content'] for m in messages):return None,'truncated_or_malformed'
    row={'id':example_id(messages),'reviewStatus':'approved','approvalMethod':'public-structural-filter-not-individually-fact-checked','splitGroup':'smol-record-'+source_id,
        'source':{'kind':'public','dataset':DATASET,'subset':'default','component':subset,'license':'apache-2.0','originalSplit':'train','recordId':source_id,'rowIndex':index,'parquetShard':shard,'url':'https://huggingface.co/datasets/'+DATASET,'curriculum':'v12-conversation','transformations':transform+['Normalized whitespace and typographic punctuation; no answer or conversation was shortened']},'messages':messages}
    reason=rejection(row)
    return (None,reason) if reason else (row,None)

def acquire(directory,cache,target=5000,max_scan=230000):
    """Use only the public training split; verify and reuse complete cached shards."""
    import pyarrow.parquet as pq
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True);output=directory/'conversations.jsonl'
    rows=[];seen=set();counts=Counter();scanned=0;shards=[]
    for shard in range(4):
        path=parquet_file('chat','train',shard,cache);shards.append({'index':shard,'sha256':digest(path),'bytes':path.stat().st_size})
        for batch in pq.ParquetFile(path).iter_batches(batch_size=512):
            for item in batch.to_pylist():
                scanned+=1;row,reason=convert(item,scanned,shard)
                if row:
                    key=canonical(row['messages'])
                    if key in seen:counts['duplicate']+=1
                    else:seen.add(key);rows.append(row)
                else:counts[reason]+=1
                if scanned%10000==0:print(json.dumps({'publicExamplesScanned':scanned,'completeExamplesAccepted':len(rows)}),flush=True)
                if len(rows)>=target or scanned>=max_scan:break
            if len(rows)>=target or scanned>=max_scan:break
        if len(rows)>=target or scanned>=max_scan:break
    if len(rows)<500:raise ValueError('Too few complete examples; existing model and data were not changed')
    write_jsonl(output,rows)
    # Stable JSONL bytes when moving a Windows-built seed to Linux/Kaggle.
    output.write_bytes(output.read_text(encoding='utf-8').encode('utf-8'))
    summary={'format':'nebula-v12-public-1','dataset':DATASET,'license':'apache-2.0','target':target,'accepted':len(rows),'scanned':scanned,'sha256':digest(output),'sourceShards':shards,'rejected':dict(counts),'components':dict(Counter(r['source']['component'] for r in rows)),'multiTurn':sum(len(r['messages'])>2 for r in rows),'answersTruncated':False,'individuallyFactChecked':False}
    (directory/'manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return summary

def merge(base,validation,seed,output,require_review=False):
    """Keep fixed validation untouched and exclude existing train/held-out prompts."""
    old=read_jsonl(base);fixed=read_jsonl(validation);new=read_jsonl(seed)
    blocked=set().union(*(prompts(r) for r in old+fixed));groups={r.get('splitGroup') for r in old+fixed if r.get('splitGroup')};seen={canonical(r['messages']) for r in old+fixed};records={r['source'].get('recordId') for r in old+fixed if r.get('source',{}).get('dataset')==DATASET};added=[];removed=Counter()
    for row in new:
        reason=rejection(row)
        if any(ROLEPLAY.search(m['content']) for m in row['messages']):reason='roleplay_or_human_biography'
        if require_review:
            from v12_review import PROTOCOL
            if row.get('source',{}).get('publicReviewProtocol')!=PROTOCOL:reason='public_review_required'
        if row.get('source',{}).get('dataset')!=DATASET or row.get('source',{}).get('originalSplit')!='train':reason='invalid_origin'
        if row.get('splitGroup') in groups or row.get('source',{}).get('recordId') in records:reason='existing_source_record'
        if prompts(row)&blocked:reason='existing_or_heldout_prompt'
        key=canonical(row['messages'])
        if key in seen:reason='duplicate'
        if reason:removed[reason]+=1;continue
        added.append(row);seen.add(key);blocked.update(prompts(row));groups.add(row['splitGroup']);records.add(row['source']['recordId'])
    if len(added)<200:raise ValueError('Fewer than 200 genuinely new examples survived exclusions; no training run initialized')
    write_jsonl(output,old+added)
    summary={'previousTrainingRows':len(old),'newCompleteConversations':len(added),'newMultiTurnConversations':sum(len(r['messages'])>2 for r in added),'trainingRows':len(old)+len(added),'excluded':dict(removed),'validationUnchanged':True,'validationSha256':digest(validation),'trainingSha256':digest(output),'publicSeedSha256':digest(seed),'conversationPercent':80,'mixedPercent':20,'maxAssistantCharacters':220,'maxContextBytes':768,'noAnswerTruncation':True}
    Path(output).with_suffix('.manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cache',type=Path,required=True);parser.add_argument('--target',type=int,default=5000)
    args=parser.parse_args();print(json.dumps(acquire(args.output,args.cache,args.target)),flush=True)
