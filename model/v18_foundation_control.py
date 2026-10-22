"""Audit actual saved raw batches and run a bounded story foundation experiment."""
import copy
import gc
import gzip
import json
import math
import os
import random
import time
import unicodedata
from pathlib import Path

import numpy as np
import requests
import torch
import torch.nn.functional as F
from nebula import BOS,EOS
from v18_stream import Hub,RemotePool,deserialize,serialize,sha,digest,emit,PROBES
from v18_decode_probe import compare

SOURCE_REVISION='e167fff3bb27c36c25460fcd4c61915a5b7016ed'
DEFAULT={'sourceRepo':'iiidevv/nebula-raw-training','sourceRun':'nebula-v18-raw-1gb',
         'sourceRevision':SOURCE_REVISION,'expectedUpdates':10102,'updates':1000,
         'trainUtf8Bytes':8_000_000,'validationUtf8Bytes':500_000,'seed':19021,
         'saveEvery':100,'maxSessionHours':2}


def code_signature():
    root=Path(__file__).parent
    return sha(''.join((root/n).read_text(encoding='utf-8') for n in
               ['v18_foundation_control.py','nebula.py','v18_stream.py','v18_decode_probe.py']).encode())


def read_source(repo,run,revision,token):
    from huggingface_hub import HfApi
    hub=object.__new__(Hub);hub.repo=repo;hub.prefix='experiments/'+run+'/'
    hub.api=HfApi(token=token);hub.token=token;hub.session=requests.Session()
    hub.revision=hub.api.model_info(repo,revision=revision).sha
    state=hub.state()
    if not state or not state.get('working') or not state.get('corpusComplete'):
        raise ValueError('The pinned source needs a working checkpoint and completed corpus.')
    return hub,state


def load_index(hub,state):
    records=[];seen=set();counts={};sizes={};split_counts={'train':0,'validation':0}
    spans={};previous={}
    for entry in state['corpus']['index']:
        for line in gzip.decompress(hub.read_entry(entry)).splitlines():
            record=json.loads(line);identifier=record['hash'];split=record['split']
            if split not in split_counts:raise ValueError('Invalid document split')
            if identifier in seen:raise ValueError('Duplicate normalized document hash or split overlap')
            if ('validation' if int(identifier[:8],16)%100<state['config']['validationPercent'] else 'train')!=split:
                raise ValueError('Document hash split differs from the training preparation rule')
            shard=record['shard'];start=record['startToken'];end=record['endToken']
            if not 0<=shard<len(state['corpus'][split]):raise ValueError('Invalid shard index')
            if not 0<=start<end<=state['corpus'][split][shard]['bytes']//2:
                raise ValueError('Document range outside its saved shard')
            if end-start!=record['utf8Bytes']+2:raise ValueError('Document length differs from byte count plus markers')
            key=(split,shard)
            if previous.get(key,0)!=start:raise ValueError('Gap or overlap in indexed packed documents')
            previous[key]=end;spans[key]=end
            seen.add(identifier);source=record['source'];counts[source]=counts.get(source,0)+1
            sizes[source]=sizes.get(source,0)+record['utf8Bytes'];split_counts[split]+=1;records.append(record)
        emit(controlAuditIndexDocuments=len(records))
    for split in split_counts:
        for i,entry in enumerate(state['corpus'][split]):
            if spans.get((split,i),0)!=entry['bytes']//2:raise ValueError('Index does not cover the entire saved shard')
    if sum(sizes.values())!=state['uniqueTextBytes'] or sizes!=state['sourceBytes']:
        raise ValueError('Indexed source totals differ from the saved corpus manifest')
    if len(records)!=state['documents']:raise ValueError('Indexed document count differs from manifest')
    return records,{'documents':len(records),'sourceDocuments':counts,'sourceUtf8Bytes':sizes,
        'splitDocuments':split_counts,'uniqueNormalizedHashes':len(seen),
        'indexCoverageComplete':True,'trainValidationHashesDisjoint':True,
        'scope':'All index metadata checked; payload integrity/UTF-8/content checked on samples and selected story documents.'}


def document(pool,record):
    # Pool entries must retain original order: constructor filters undersized shards.
    values=pool.data(record['shard'])[record['startToken']:record['endToken']]
    if len(values)!=record['utf8Bytes']+2 or values[0]!=BOS or values[-1]!=EOS:
        raise ValueError('Saved document boundary/length mismatch')
    interior=values[1:-1]
    if np.any(interior>255):raise ValueError('Unexpected role/special token inside raw document')
    content=interior.astype(np.uint8).tobytes();text=content.decode('utf-8',errors='strict')
    identifier=sha(' '.join(unicodedata.normalize('NFKC',text).casefold().split()).encode())
    if identifier!=record['hash']:raise ValueError('Payload document hash differs from source index')
    return values,text


def audit_payloads(hub,state,records,context):
    # No shard filtering here: an end shard can be shorter than context.
    pools={}
    for split in ['train','validation']:
        pool=object.__new__(RemotePool);pool.hub=hub;pool.entries=state['corpus'][split]
        from collections import OrderedDict
        pool.cache=OrderedDict();pools[split]=pool
    samples=[]
    for source in sorted(state['sourceBytes']):
        for split in ['train','validation']:
            rows=sorted((r for r in records if r['source']==source and r['split']==split),key=lambda r:r['hash'])[:4]
            for row in rows:
                _,text=document(pools[split],row)
                samples.append({'source':source,'split':split,'hash':row['hash'],'utf8Bytes':row['utf8Bytes'],
                                'textBeginning':text[:500]})
    # Reconstruct the real V18 random batch at the saved optimizer update.
    original=RemotePool(hub,state['corpus']['train'],context,state['config']['shardHoldSteps'])
    step=state['updates'];seed=state['config']['seed'];batch=state['config']['batch']
    chosen=random.Random(seed+step//original.hold).choices(range(len(original.entries)),weights=original.weights,k=1)[0]
    data=original.data(chosen);rng=random.Random(seed+step*7919)
    pairs=original.batch(step,batch,seed);windows=[]
    for x,y in pairs:
        start=rng.randrange(len(data)-context)
        expected=torch.tensor(np.array(data[start:start+context+1],dtype=np.int64))
        if not torch.equal(x,expected[:-1]) or not torch.equal(y,expected[1:]) or not torch.equal(x[1:],y[:-1]):
            raise ValueError('Actual V18 input/target alignment failed')
        if int(x.min())<0 or int(y.min())<0 or int(x.max())>EOS or int(y.max())>EOS:
            raise ValueError('Unexpected token in raw training batch')
        windows.append({'startToken':start,'inputLength':len(x),'targetLength':len(y),
                        'bosTargets':int((y==BOS).sum()),'eosTargets':int((y==EOS).sum()),
                        'decodedBeginning':bytes(int(v) for v in x[:300] if v<256).decode('utf-8',errors='replace')})
    result={'payloadSamplesChecked':len(samples),'samples':samples,'actualV18Batch':{
        'reconstructedUpdate':step,'batch':batch,'context':context,'targetShiftCorrect':True,'windows':windows},
        'notice':'A window beginning mid-word or cutting a UTF-8 character is expected in byte-level packed training. Samples are not a full semantic/PII audit.'}
    del original,data
    for pool in pools.values():pool.cache.clear()
    gc.collect()
    return pools,result


def select_stories(pools,records,train_limit,valid_limit):
    arrays={};selected={};prefixes=[]
    for split,limit in [('train',train_limit),('validation',valid_limit)]:
        packed=bytearray();hashes=[];total=0
        rows=sorted((r for r in records if r['source']=='stories' and r['split']==split),key=lambda r:r['hash'])
        # Read selected records in shard order to avoid re-downloading the same shard for each hash.
        chosen=[]
        for r in rows:
            if total+r['utf8Bytes']>limit:continue
            chosen.append(r);total+=r['utf8Bytes']
            if total>=limit*.995:break
        for r in sorted(chosen,key=lambda r:(r['shard'],r['startToken'])):
            values,text=document(pools[split],r);packed.extend(values.tobytes());hashes.append(r['hash'])
            if split=='validation' and len(prefixes)<2:
                prefix=text[:85].rsplit(' ',1)[0]
                if prefix:prefixes.append(prefix)
        if not packed:raise ValueError('No indexed TinyStories documents available in '+split)
        arrays[split]=np.frombuffer(packed,dtype='<u2')
        selected[split]={'documents':len(hashes),'utf8Bytes':total,'packedSha256':sha(packed),'hashes':hashes}
        pools[split].cache.clear()
    if set(selected['train']['hashes'])&set(selected['validation']['hashes']):raise ValueError('Story split leakage')
    return arrays,selected,prefixes


def pairs_from_array(data,context,batch,seed):
    if len(data)<=context:raise ValueError('Story pool too short for full context')
    rng=random.Random(seed);pairs=[]
    for _ in range(batch):
        start=rng.randrange(len(data)-context)
        values=torch.tensor(np.array(data[start:start+context+1],dtype=np.int64))
        pairs.append((values[:-1],values[1:]))
    return pairs


@torch.inference_mode()
def heldout(model,pairs):
    model.eval();device=next(model.parameters()).device;total=0.;targets=0
    for i,(x,y) in enumerate(pairs):
        loss=F.cross_entropy(model(x[None].to(device)).float().flatten(0,1),y.to(device),reduction='sum')
        if not torch.isfinite(loss):raise ValueError('Non-finite held-out loss')
        total+=float(loss);targets+=len(y)
        if (i+1)%8==0:emit(controlHeldoutBlocks=i+1,total=len(pairs))
    return {'loss':total/targets,'targets':targets}


@torch.inference_mode()
def audit_forward(model,pair):
    model.eval();device=next(model.parameters()).device
    x,y=(v[:96].to(device) for v in pair)
    before=model(x[None]).float()
    changed=x.clone();cut=len(x)//2;changed[cut:]=(changed[cut:]+17)%256
    after=model(changed[None]).float()
    if not torch.isfinite(before).all() or not torch.isfinite(after).all():raise ValueError('Non-finite source logits')
    delta=float((before[:,:cut]-after[:,:cut]).abs().max())
    if not torch.allclose(before[:,:cut],after[:,:cut],rtol=1e-4,atol=1e-4):
        raise ValueError('Future-token changes affected earlier logits on a real saved batch')
    batched=F.cross_entropy(before.flatten(0,1),y)
    reference=-torch.log_softmax(before[0],-1)[torch.arange(len(y),device=device),y].mean()
    if not torch.allclose(batched,reference,rtol=1e-5,atol=1e-5):raise ValueError('Reference causal loss mismatch')
    return {'futureChangeMaxPastLogitDelta':delta,'causalPrefixInvariant':True,
            'manualNextTokenLossMatches':True,'sampleLoss':float(batched),'positions':len(y)}


def run_control(output_run='nebula-v18-foundation-control',config=None,device='cuda',clock=None):
    clock=time.monotonic if clock is None else clock
    config=copy.deepcopy(DEFAULT if config is None else config)
    if set(config)!=set(DEFAULT) or not 1<=config['updates']<=5000 or not 0<config['maxSessionHours']<=8:
        raise ValueError('Invalid controlled experiment configuration')
    if output_run==config['sourceRun']:raise ValueError('Use a different run; the source must be preserved')
    if device=='cuda' and not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle NVIDIA GPU')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise RuntimeError('Enable Kaggle secret NEBULA_HF_TOKEN')
    source,source_state=read_source(config['sourceRepo'],config['sourceRun'],config['sourceRevision'],token)
    if source_state['updates']!=config['expectedUpdates']:raise ValueError('Pinned source step mismatch')
    output=Hub(config['sourceRepo'],token,output_run);state=output.state();signature=digest({'config':config,'code':code_signature()})
    if state and state.get('signature')!=signature:raise ValueError('Keep the original experiment settings/code to resume; otherwise choose a NEW output run')
    if state and state.get('complete'):
        emit(controlAlreadyComplete=True,updates=state['updates'],publicWebsiteUpdated=False)
        return json.loads(output.read_entry(state['finalReport']))
    if state is None:
        state={'format':'nebula-v18-foundation-control-1','signature':signature,'config':config,
            'sourceRevision':source.revision,'sourceWeightSha256':source_state['working']['sha256'],
            'sourceUpdates':source_state['updates'],'updates':0,'complete':False,'qualityApproved':False,'publicWebsiteUpdated':False}
    records,index_audit=load_index(source,source_state)
    model,payload=deserialize(output.read_entry(state['working']) if state.get('working') else source.read_entry(source_state['working']))
    context=model.config.context
    pools,payload_audit=audit_payloads(source,source_state,records,context)
    arrays,selection,extra_prefixes=select_stories(pools,records,config['trainUtf8Bytes'],config['validationUtf8Bytes'])
    selection_hash=digest(selection)
    if state.get('selectionHash') and state['selectionHash']!=selection_hash:raise ValueError('Reconstructed story selection changed')
    model.to(device);torch.set_num_threads(2)
    if not state.get('audit'):
        actual_pair=RemotePool(source,source_state['corpus']['train'],context,source_state['config']['shardHoldSteps']).batch(
            source_state['updates'],1,source_state['config']['seed'])[0]
        forward_audit=audit_forward(model,actual_pair)
    else:forward_audit={'notice':'Original source forward audit already saved with this experiment.'}
    audit={'index':index_audit,'payload':payload_audit,'storySelection':selection,'forward':forward_audit,
           'passed':True,'humanVerified':False,'scope':'Packing/alignment/integrity checks, not proof of semantic correctness or full model architecture.'}
    emit(controlAuditSummary=index_audit,forwardAudit=forward_audit,
         actualBatchChecks={k:v for k,v in payload_audit['actualV18Batch'].items() if k!='windows'})
    seen_samples=set()
    for sample in payload_audit['samples']:
        key=(sample['source'],sample['split'])
        if key not in seen_samples:
            emit(controlPublicDocumentSample=sample);seen_samples.add(key)
    for window in payload_audit['actualV18Batch']['windows'][:2]:emit(controlActualWindow=window)
    if not state.get('audit'):
        state=output.publish({**state,'selectionHash':selection_hash},{'audit':('audit.json',json.dumps(audit,indent=2).encode())})
    emit(controlAuditPassed=True,storyTrainBytes=selection['train']['utf8Bytes'],storyValidationBytes=selection['validation']['utf8Bytes'])
    del records,pools,audit,payload_audit;gc.collect()
    amp=device=='cuda';native_bf16=amp and torch.cuda.get_device_capability(0)[0]>=8 and torch.cuda.is_bf16_supported()
    dtype=torch.bfloat16 if native_bf16 else torch.float16
    scaler=torch.amp.GradScaler('cuda',enabled=amp and not native_bf16,init_scale=1024)
    optimizer=torch.optim.AdamW(model.parameters(),lr=source_state['config']['learningRate'],weight_decay=.01)
    training=payload['trainingState'];optimizer.load_state_dict(training['optimizer'])
    if state.get('working'):
        if training.get('controlSignature')!=signature:raise ValueError('Controlled checkpoint signature mismatch')
        if training['updates']!=state['updates']:raise ValueError('Controlled checkpoint step mismatch')
    if scaler.is_enabled() and training.get('scaler'):scaler.load_state_dict(training['scaler'])
    del payload,training;gc.collect()
    mixed=RemotePool(source,source_state['corpus']['validation'],context,1)
    mixed_pairs=[mixed.batch(i,1,880019)[0] for i in range(16)]
    story_pairs=pairs_from_array(arrays['validation'],context,16,config['seed']+1)
    del mixed;gc.collect()
    modes=[dict(name='greedy',temperature=0.,top_p=1.,seeds=[0]),
           dict(name='sample-0.7',temperature=.7,top_p=.9,seeds=[17,43])]
    def evaluate(label):
        emit(controlEvaluation=label)
        report={'stage':label,'additionalUpdates':state['updates'],
                'heldoutMixed':heldout(model,mixed_pairs),'heldoutStories':heldout(model,story_pairs),
                **compare(model,128,modes=modes,raw=PROBES+extra_prefixes)}
        # compare's generic inference-only flag refers to the probe, not this whole experiment.
        report['trainingStarted']=state['updates']>0
        return report
    if not state.get('baselineReport'):
        baseline=evaluate('baseline-10102')
        state=output.publish(state,{'baselineReport':('baseline.json',json.dumps(baseline,indent=2).encode())})
    started=clock();bad=0;last_saved=state['updates'];interrupted=False
    source_config=source_state['config'];batch=source_config['batch'];microbatch=source_config['microbatch']
    emit(controlTraining=True,startingStep=source_state['updates'],additionalUpdateBudget=config['updates'],
         optimizerRestored=True,precision=str(dtype) if amp else 'float32',trainingGPUs=1,
         change='Train only on a deterministic public TinyStories subset; retain model, batch and original learning-rate schedule.',
         limitedChange='T4 uses native FP16 AMP instead of emulated BF16 when inherited source used it.',publicWebsiteUpdated=False)
    def save():
        nonlocal state,last_saved
        stream=serialize(model,{'experimental':True,'qualityApproved':False,'sourceUpdates':source_state['updates'],
                     'additionalUpdates':state['updates']},
            {'controlSignature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict(),'updates':state['updates']})
        try:state=output.publish(state,{'working':('working.pt',stream.getbuffer())})
        finally:stream.close()
        last_saved=state['updates']
        emit(controlCheckpointConfirmed=True,additionalUpdates=last_saved,publicWebsiteUpdated=False)
    try:
        while state['updates']<config['updates'] and clock()-started<config['maxSessionHours']*3600:
            step=state['updates'];absolute=source_state['updates']+step
            rate=source_config['learningRate']*min(1.,(absolute+1)/source_config['warmup'])*(.1+.9*.5*(1+math.cos(math.pi*absolute/source_config['steps'])))
            for group in optimizer.param_groups:group['lr']=rate
            model.train();optimizer.zero_grad(set_to_none=True);loss_value=0.
            pairs=pairs_from_array(arrays['train'],context,batch,config['seed']+step*7919)
            for offset in range(0,batch,microbatch):
                micro=pairs[offset:offset+microbatch]
                x=torch.stack([p[0] for p in micro]).to(device);y=torch.stack([p[1] for p in micro]).to(device)
                with torch.autocast('cuda',dtype=dtype,enabled=amp):
                    loss=F.cross_entropy(model(x).flatten(0,1),y.flatten(),reduction='sum')/(batch*context)
                if not torch.isfinite(loss):raise ValueError('Non-finite loss; keep the last confirmed control checkpoint')
                loss_value+=float(loss.detach());scaler.scale(loss).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            if not torch.isfinite(norm):
                bad+=1
                if not scaler.is_enabled() or bad>12:raise ValueError('Non-finite gradients')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();bad=0;state['updates']+=1
            if state['updates']%25==0:
                emit(controlUpdate=state['updates'],budget=config['updates'],loss=round(loss_value,4),
                     learningRate=rate,trainingBytePositions=state['updates']*batch*context)
            if state['updates']%config['saveEvery']==0:save()
    except KeyboardInterrupt:interrupted=True
    if state['updates']!=last_saved:save()
    if interrupted or state['updates']<config['updates']:
        emit(controlPaused=True,updatesSaved=last_saved,runAgainWithSameSettings=True)
        return state
    final=evaluate('story-foundation-final')
    baseline=json.loads(output.read_entry(state['baselineReport']))
    report={'format':'nebula-foundation-control-comparison-1','sourceRevision':source.revision,
            'sourceWeightSha256':source_state['working']['sha256'],'baseline':baseline,'final':final,
            'additionalUpdates':state['updates'],'additionalTrainingPositions':state['updates']*batch*context,
            'qualityApproved':False,'humanVerified':False,'publicWebsiteUpdated':False,
            'interpretation':'Compare actual completions and both held-out losses. Repetition reductions alone do not establish coherence. No automatic promotion or source replacement.'}
    state=output.publish({**state,'complete':True},{'finalReport':('comparison.json',json.dumps(report,indent=2).encode())})
    emit(controlFinished=True,updatesSaved=state['updates'],sourceWeightsPreserved=True,publicWebsiteUpdated=False,
         reportParts=[p['path'] for p in state['finalReport']['parts']])
    del optimizer,model;gc.collect()
    if amp:torch.cuda.empty_cache()
    return report
