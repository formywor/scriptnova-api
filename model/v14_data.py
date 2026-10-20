"""Separate raw-language and assistant-training corpora for the owned byte model."""
import hashlib,json,random
from collections import Counter
from pathlib import Path
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from v9_data import canonical,prompts,digest
from v13_data import HeldoutMatcher,rejection,atomic_json

FORMAT='nebula-v14-data-1'

def held(group):return int(hashlib.sha256(('v14:'+group).encode()).hexdigest()[:8],16)%10==0

def practice(scenarios=1000):
    """All questions about one scenario share a split; values/order/query phrasing vary."""
    rows=[];rng=random.Random(14014)
    for i in range(scenarios):
        name=rng.choice(['Vela','Korin','Nessa','Dorin','Elva','Runa','Iven','Olin'])
        color=rng.choice(['coral','navy','cream','teal','gold','maroon'])
        place=rng.choice(['drawer','cabinet','basket','shelf','cupboard','crate'])
        number=rng.randint(2,18);new_color=rng.choice([c for c in ['coral','navy','cream','teal','gold','maroon'] if c!=color])
        fields=[f'The person is named {name}.',f'The favorite color is {color}.',f'The notebook is in the {place}.',f'There are {number} pencils.']
        rng.shuffle(fields);context=' '.join(fields)
        group='profile-'+hashlib.sha256(json.dumps([name,color,place,number]).encode()).hexdigest()
        tasks=[('name',name,['What is the person called?','Which name is given?','What is the name?']),
               ('color',color,['What is the favorite color?','Which color does the person prefer?','Give the preferred color.']),
               ('place',place,['Where is the notebook?','Which location holds the notebook?','Name the notebook location.']),
               ('quantity',str(number),['How many pencils are there?','What is the pencil count?','Give the number of pencils.'])]
        for skill,answer,questions in tasks:
            q=rng.choice(questions);mode=i%3
            if mode==0:messages=[{'role':'user','content':context+' '+q+' Answer with only the value.'},{'role':'assistant','content':answer}]
            else:messages=[{'role':'user','content':context},{'role':'assistant','content':'Understood.'},{'role':'user','content':q+' Reply with only the value.'},{'role':'assistant','content':answer}]
            rows.append(make_owned(messages,group,skill))
        messages=[{'role':'user','content':context},{'role':'assistant','content':'Understood.'},{'role':'user','content':f'The favorite color changes to {new_color}. What is the favorite color now? Answer with only the color.'},{'role':'assistant','content':new_color}]
        rows.append(make_owned(messages,group,'updated-color'))
        messages=[{'role':'user','content':context},{'role':'assistant','content':'Understood.'},{'role':'user','content':f'Two pencils are given away. How many pencils remain? Answer with only the number.'},{'role':'assistant','content':str(number-2)}]
        rows.append(make_owned(messages,group,'changed-quantity'))
    return rows

def make_owned(messages,group,skill):
    return {'id':example_id(messages),'reviewStatus':'approved','approvalMethod':'owned-programmatically-checked-context-answer',
      'splitGroup':'v14-owned-'+group,'source':{'kind':'seed','curriculum':'v14-context','skill':skill,'pool':'context'},'messages':messages}

def prepare(base,old_validation,old_public_holdout,public_texts,folder,scenarios=1000):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    old=read_jsonl(base);prior_public_holdout=read_jsonl(old_public_holdout);fixed=read_jsonl(old_validation)+prior_public_holdout
    previously_trained_texts={hashlib.sha256(' '.join(r['messages'][1]['content'].casefold().split()).encode()).hexdigest() for r in old if r.get('source',{}).get('curriculum')=='v13-language'}
    from v14_eval import blocked_prompts
    blocked=set().union(*(prompts(r) for r in fixed))|blocked_prompts();matcher=HeldoutMatcher(blocked)
    excluded_records={(r.get('source',{}).get('dataset'),r.get('source',{}).get('recordId')) for r in fixed}
    seen=set();train=[];valid=[];counts=Counter();excluded=Counter()
    print(json.dumps({'v14DataPhase':'raw-language','candidatePassages':len(public_texts)}),flush=True)
    for i,row in enumerate(public_texts,1):
        source=row.get('source',{});text=row['messages'][1]['content'];key=hashlib.sha256(' '.join(text.casefold().split()).encode()).hexdigest()
        record=(source.get('dataset'),source.get('recordId'))
        reason=rejection(row)
        if source.get('curriculum')!='v13-language':reason='not-raw-language'
        if key in seen:reason='duplicate-text'
        if record in excluded_records or matcher.contains(' '.join(text.casefold().split())):reason='heldout-overlap'
        if reason:excluded[reason]+=1;continue
        seen.add(key);row={**row,'splitGroup':'v14-text-'+key}
        (valid if key not in previously_trained_texts and held(row['splitGroup']) else train).append(row);counts[source['dataset']]+=1
        if i%1000==0:print(json.dumps({'v14RawPassagesProcessed':i,'train':len(train),'heldout':len(valid)}),flush=True)
    if len(counts)!=3 or len(train)<100 or len(valid)<10:raise ValueError('V14 requires independent raw train/held-out data from all three text sources')
    foundation=folder/'foundation.jsonl';foundation_valid=folder/'foundation-valid.jsonl';write_jsonl(foundation,train);write_jsonl(foundation_valid,valid)
    # Keep old fixed validation untouched. Fresh public SFT holdouts were reserved by V13.
    public=[];history=[];sft_valid=[];seen=set();rewrite_count=0
    for row in old:
        if not eligible(row) or row['source'].get('curriculum')=='v13-language':continue
        src=row['source'];key=canonical(row['messages'])
        if key in seen or prompts(row)&blocked:continue
        if src.get('curriculum')=='v13-conversation':
            if rejection(row):continue
            if 'rewrite' in src.get('component',''):
                # A bounded minority, not the whole public pool.
                if rewrite_count>=1000:continue
                rewrite_count+=1
            pool='public'
        elif src.get('curriculum') in ['v7-conversation','v9-conversation','v5-conversation','v6-conversation']:
            if rejection(row):continue
            pool='historical'
        else:continue
        seen.add(key);row={**row,'source':{**src,'pool':pool}}
        (public if pool=='public' else history).append(row)
    # Reuse the reserved public holdout rather than relabeling already-trained chats as unseen.
    fixed_only=set().union(*(prompts(r) for r in read_jsonl(old_validation)))|blocked_prompts()
    for row in prior_public_holdout:
        if row.get('source',{}).get('curriculum')!='v13-conversation' or rejection(row) or prompts(row)&fixed_only:continue
        sft_valid.append({**row,'source':{**row['source'],'pool':'public'}})
    for row in practice(scenarios):
        key=canonical(row['messages'])
        if not eligible(row) or prompts(row)&blocked or key in seen:continue
        seen.add(key)
        (sft_valid if held(row['splitGroup']) else public).append(row)
    if not history:raise ValueError('V14 requires a small eligible historical pool')
    if not any(r['source']['pool']=='public' for r in public) or not any(r['source']['pool']=='context' for r in public):raise ValueError('V14 SFT requires diverse public conversations and context practice')
    conversation=folder/'conversation.jsonl';conversation_valid=folder/'conversation-valid.jsonl';write_jsonl(conversation,public+history);write_jsonl(conversation_valid,sft_valid)
    if not any(r['source']['pool']=='public' for r in sft_valid):raise ValueError('V14 requires conversation validation')
    foundation_stats={'trainingPassages':len(train),'heldoutPassages':len(valid),'uniqueTrainingBytes':sum(len(r['messages'][1]['content'].encode()) for r in train),'sources':dict(counts),'excluded':dict(excluded)}
    summary={'format':FORMAT,'foundation':foundation_stats,'conversation':{'trainingRows':len(public)+len(history),'heldoutRows':len(sft_valid),'poolRows':dict(Counter(r['source']['pool'] for r in public+history)),'publicUpdatesPercent':70,'contextUpdatesPercent':20,'historicalUpdatesPercent':10,'syntheticScenarios':scenarios},'tokenizer':'unchanged-byte-262','oldModelImitationPenalty':0,'externalTeacherCalls':0,'publicWebsiteUpdated':False,'oldValidationSha256':digest(old_validation),
      'files':{p.name:{'sha256':digest(p),'bytes':p.stat().st_size} for p in [foundation,foundation_valid,conversation,conversation_valid]}}
    atomic_json(folder/'manifest.json',summary);print(json.dumps({'v14DataPrepared':summary}),flush=True)
    return summary
