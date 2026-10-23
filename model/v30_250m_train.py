"""Depth expansion of V28 weights with cleaned V29 corpus; RAM-only HF persistence."""
import copy
import gc
import json
import math
import os
import random
import re
import time
from pathlib import Path
import numpy as np
import requests
import torch
import torch.nn.functional as F
from v18_stream import sha,digest,emit
from v30_store import Hub
from v18_foundation_control import read_source
from v30_expanded_model import Config,Model,PAD,checkpoint,restore,generate,expand_parent
from v29_clean_data import prepare,raw_batch,public_windows
from v28_decode import decode_report
from v30_device_audit import audit as device_audit

DEFAULT=dict(repo='iiidevv/nebula-raw-training',rawRun='nebula-v18-raw-1gb',
    rawRevision='e167fff3bb27c36c25460fcd4c61915a5b7016ed',
    publicRun='nebula-v23-longrun',publicRevision='c21aafa220d33b9787791fcaf7aebf413bc62cf8',
    parentRun='nebula-v28-longrun',parentRevision='9cfc225eae2fefe1fee5e01d77690487172d6dce',expectedParentUpdates=30000,
    cleanRun='nebula-v29-clean-foundation',cleanRevision='6eec7e5076a6e1c29d8055395179c397287094f8',
    trainBytes=384_000_000,validationBytes=8_000_000,tokenizerBytes=16_000_000,
    sourceMix={'fineweb':55,'cosmopedia':30,'textbooks':10,'stories':5},
    vocab=8192,width=768,heads=12,layers=34,context=1024,seed=270221,
    foundationUpdates=10000,conversationUpdates=1000,batch=8,microbatch=1,
    foundationLR=.00003,conversationLR=.00003,warmup=100,saveEvery=100,evaluateEvery=1000)
RAW_PROBES=['The rain stopped, and the neighbors opened their windows.',
    'Ice changes from a solid to a liquid when',
    'A student wanted to learn how plants grow. First,']
CHAT_PROBES=['I have a notebook and ten minutes. How can I start practicing drawing?',
    'Write a short note thanking Mila for watering my plants.',
    'Ravi has a red bag. Sora has a blue bag. Which color is Sora\'s bag?']

class Store(Hub):
    def __init__(self,repo,token,run):
        from huggingface_hub import HfApi
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'nebula-v30-[\w-]{1,45}',run):raise ValueError('Use a separate V30 output run')
        self.repo=repo;self.token=token;self.prefix='experiments/'+run+'/'
        self.api=HfApi(token=token);self.session=requests.Session()
        if self.api.whoami()['name']!=repo.split('/')[0]:raise ValueError('Use your own namespace')
        info=self.api.model_info(repo)
        if info.private is not False:raise ValueError('Output repository must be public')
        self.revision=info.sha


def read_parent(config,token):
    from huggingface_hub import HfApi
    hub=object.__new__(Hub);hub.repo=config['repo'];hub.token=token
    hub.prefix='experiments/'+config['parentRun']+'/'
    hub.api=HfApi(token=token);hub.session=requests.Session()
    hub.revision=hub.api.model_info(config['repo'],revision=config['parentRevision']).sha
    state=hub.state()
    if not state or not state.get('foundationComplete') or state.get('steps',{}).get('foundation')!=config['expectedParentUpdates']:
        raise ValueError('Pinned V28 foundation checkpoint must be complete at expected updates')
    if not state.get('foundationWorking') or not state.get('tokenizer'):raise ValueError('Parent weights/tokenizer missing')
    return hub,state


def prepared_clean_data(hub,state,config,token):
    from huggingface_hub import HfApi
    from tokenizers import Tokenizer
    source=object.__new__(Hub);source.repo=config['repo'];source.token=token
    source.prefix='experiments/'+config['cleanRun']+'/'
    source.api=HfApi(token=token);source.session=requests.Session()
    source.revision=source.api.model_info(config['repo'],revision=config['cleanRevision']).sha
    saved=source.state()
    if not saved or not saved.get('dataReady'):raise ValueError('Pinned V29 cleaned corpus is not complete')
    if saved['tokenizer']['sha256']!=state['tokenizer']['sha256']:raise ValueError('Cleaned data tokenizer mismatch')
    for key in ['rawRun','rawRevision','trainBytes','validationBytes','sourceMix']:
        if saved.get('config',{}).get(key)!=config[key]:raise ValueError('Cleaned corpus configuration mismatch: '+key)
    state=hub.publish({**state,'cleanDataReference':dict(run=config['cleanRun'],revision=config['cleanRevision']),
        'tokenRanges':saved['tokenRanges']}, {'dataReport':('inherited-clean-data-report.json',source.read_entry(saved['dataReport']))})
    # Content-addressed uploads can deduplicate existing objects; no source is modified.
    for key in ['trainTokens','validationTokens']:
        state=hub.publish(state,{key:(key+'.bin',source.read_entry(saved[key]))})
    state=hub.publish({**state,'dataReady':True})
    return state,Tokenizer.from_str(hub.read_entry(state['tokenizer']).decode())


def signature(config):
    import tokenizers,ftfy
    root=Path(__file__).parent
    names=['v30_expanded_model.py','v29_clean_data.py','v30_250m_train.py','v30_store.py',
        'v28_decode.py','v29_clean_text.py','v30_device_audit.py','v18_stream.py','v18_foundation_control.py']
    return digest(dict(config=config,code=sha(''.join((root/n).read_text(encoding='utf-8') for n in names).encode()),
                       tokenizersVersion=tokenizers.__version__,ftfyVersion=ftfy.__version__))


def validate(config,stage):
    if set(config)!=set(DEFAULT) or stage not in ['foundation','conversation']:raise ValueError('Unknown settings/stage')
    for k in ['trainBytes','validationBytes','tokenizerBytes','vocab','width','heads','layers','context','foundationUpdates','conversationUpdates','batch','microbatch','warmup','saveEvery','evaluateEvery']:
        if type(config[k]) is not int or config[k]<1:raise ValueError('Invalid '+k)
    if not 262<=config['vocab']<=32000 or config['width']%config['heads'] or not 64<=config['context']<=2048:raise ValueError('Invalid architecture')
    if config['microbatch']>config['batch'] or config['batch']>32:raise ValueError('Invalid batch')
    if config['trainBytes']>512_000_000 or config['validationBytes']>16_000_000 or config['tokenizerBytes']>config['trainBytes']:raise ValueError('RAM preparation budget exceeded')
    if set(config['sourceMix'])!={'fineweb','cosmopedia','textbooks','stories'} or sum(config['sourceMix'].values())!=100 or any(v<=0 for v in config['sourceMix'].values()):raise ValueError('Invalid source mix')
    for k in ['foundationLR','conversationLR']:
        if not math.isfinite(config[k]) or not 0<config[k]<=.001:raise ValueError('Invalid LR')
    return config


def collate(pairs):
    n=max(len(x) for x,y in pairs)
    x=torch.full((len(pairs),n),PAD,dtype=torch.long);y=torch.full_like(x,-100)
    for i,(a,b) in enumerate(pairs):x[i,:len(a)]=a;y[i,:len(b)]=b
    return x,y


def make_optimizer(model,lr):
    groups=[dict(params=[p for p in model.parameters() if p.ndim>=2],weight_decay=.1),
            dict(params=[p for p in model.parameters() if p.ndim<2],weight_decay=0.)]
    return torch.optim.AdamW(groups,lr=lr,betas=(.9,.95))


@torch.inference_mode()
def loss_on(model,pairs):
    model.eval();device=next(model.parameters()).device;total=0.;targets=0
    for pair in pairs:
        x,y=collate([pair]);count=int((y!=-100).sum())
        loss=F.cross_entropy(model(x.to(device)).float().flatten(0,1),y.to(device).flatten(),reduction='sum')
        if not torch.isfinite(loss):raise ValueError('Nonfinite heldout loss')
        total+=float(loss);targets+=count
    return dict(loss=total/targets,targets=targets)


def evaluate(model,tokenizer,valid,stage,step,public_valid=None,ranges=None):
    pairs=raw_batch(valid,0,16,model.config.context,991027)
    report=dict(stage=stage,updates=step,heldoutLanguage=loss_on(model,pairs),
        rawCompletions=decode_report(model,tokenizer,RAW_PROBES),
        qualityApproved=False,humanVerified=False,publicWebsiteUpdated=False,
        notice='Subword loss is not comparable to byte-model loss. These are development probes, not certification.')
    if ranges:
        report['heldoutBySource']={}
        for source,(start,end) in ranges.items():
            if end-start>model.config.context:
                report['heldoutBySource'][source]=loss_on(model,raw_batch(valid[start:end],0,4,model.config.context,991028))
    if stage=='conversation':
        report['heldoutPublic']=loss_on(model,public_valid)
        report['openReplies']=[dict(prompt=p,reply=generate(model,tokenizer,p,chat=True,limit=96),grade='pending-human-review') for p in CHAT_PROBES]
    emit(v30Evaluation=report)
    return report


def run(run_name='nebula-v30-250m',config=None,stage='foundation',hours=6.5,reserve_minutes=10.,prepare_only=False,device='cuda',clock=None):
    config=copy.deepcopy(DEFAULT if config is None else config);validate(config,stage)
    if not 0<hours<=7.5:raise ValueError('Invalid session hours')
    if not 0<=reserve_minutes<=60 or hours*3600<=reserve_minutes*60:raise ValueError('Reserve must leave positive training time')
    clock=time.monotonic if clock is None else clock;deadline=clock()+hours*3600-reserve_minutes*60
    if not prepare_only and device=='cuda' and not torch.cuda.is_available():raise ValueError('Enable NVIDIA GPU')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise ValueError('Enable NEBULA_HF_TOKEN')
    hub=Store(config['repo'],token,run_name);state=hub.state();sig=signature(config)
    if state and state.get('signature')!=sig:raise ValueError('Settings/code changed; use original notebook or a NEW V30 run name')
    if state is None:state=hub.publish(dict(format='nebula-v30-subword-1',signature=sig,config=config,steps={},targets={},
        initializedFrom='V28 weights expanded in depth with initially identity residual layers; cleaned V29 corpus',qualityApproved=False,publicWebsiteUpdated=False))
    parent,parent_state=read_parent(config,token)
    if not state.get('tokenizer'):
        state=hub.publish({**state,'parentReference':dict(repo=config['repo'],run=config['parentRun'],revision=config['parentRevision'],
            updates=parent_state['steps']['foundation'],supervisedSubwordTokens=parent_state.get('targets',{}).get('foundation',0),weightSha256=parent_state['foundationWorking']['sha256'],
            tokenizerSha256=parent_state['tokenizer']['sha256']),
            'tokenizerSampleBytes':parent_state.get('tokenizerSampleBytes',{})},
            {'tokenizer':('tokenizer.json',parent.read_entry(parent_state['tokenizer']))})
    if state['tokenizer']['sha256']!=parent_state['tokenizer']['sha256']:raise ValueError('Parent tokenizer mismatch')
    if stage=='conversation' and not state.get('foundationComplete'):raise ValueError('Finish foundation stage and inspect raw completions before selecting conversation')
    if state.get(stage+'Complete'):
        report=json.loads(hub.read_entry(state[stage+'Final']))
        emit(v30StageAlreadyComplete=stage,report=report);return report
    if not state.get('dataReady'):
        state,tokenizer=prepared_clean_data(hub,state,config,token)
    else:
        from tokenizers import Tokenizer
        tokenizer=Tokenizer.from_str(hub.read_entry(state['tokenizer']).decode())
    if tokenizer.get_vocab_size()!=config['vocab']:raise ValueError('Vocabulary must match inherited V28 tokenizer')
    if prepare_only:
        emit(v30Prepared=True,trainingStarted=False,enableGPUThenSetPrepareOnlyFalse=True)
        return state
    if clock()>=deadline:
        emit(v30Paused=True,reason='session-budget-used-by-preparation',runAgainWithSameSettings=True)
        return state
    train=np.frombuffer(hub.read_entry(state['trainTokens']),dtype='<u2')
    valid=np.frombuffer(hub.read_entry(state['validationTokens']),dtype='<u2')
    torch.set_float32_matmul_precision('highest')
    torch.set_num_threads(2);torch.manual_seed(config['seed'])
    working=stage+'Working';training={}
    if state.get(working):model,training=restore(hub.read_entry(state[working]),state['tokenizer']['sha256'])
    elif stage=='conversation':
        model,parent_training=restore(hub.read_entry(state['foundationWorking']),state['tokenizer']['sha256'])
        del parent_training;gc.collect()
    else:
        target=Config(vocab=config['vocab'],width=config['width'],heads=config['heads'],layers=config['layers'],context=config['context'])
        model,expansion=expand_parent(parent.read_entry(parent_state['foundationWorking']),state['tokenizer']['sha256'],target)
        state=hub.publish({**state,'expansion':expansion})
        emit(v30Expansion=expansion)
        gc.collect()
    expected=Config(vocab=tokenizer.get_vocab_size(),width=config['width'],heads=config['heads'],layers=config['layers'],context=config['context'])
    if model.config!=expected:raise ValueError('V30 checkpoint architecture mismatch')
    model.to(device)
    backend=state.get('attentionBackend','default');model.set_attention_backend(backend)
    audit_report=device_audit(model,train)
    if not audit_report['passed'] and backend=='default':
        initial=copy.deepcopy(audit_report)
        model.set_attention_backend('math');backend='math'
        emit(v30AuditRetry=True,reason='checking-explicit-math-backend-with-unchanged-tolerances')
        audit_report=copy.deepcopy(device_audit(model,train))
        audit_report['initialDefaultBackendAudit']=initial
    audit_report['selectedBackend']=backend
    state=hub.publish({**state,'attentionBackend':backend},{'deviceAudit':('device-audit.json',json.dumps(audit_report,indent=2).encode())})
    emit(v30DeviceAudit=audit_report)
    if not audit_report['passed']:raise RuntimeError('Device pipeline audit failed; no optimizer updates started')
    amp=device=='cuda';bf16=amp and torch.cuda.get_device_capability(0)[0]>=8 and torch.cuda.is_bf16_supported()
    dtype=torch.bfloat16 if bf16 else torch.float16
    scaler=torch.amp.GradScaler('cuda',enabled=amp and not bf16,init_scale=1024)
    lr=config['foundationLR'] if stage=='foundation' else config['conversationLR']
    optimizer=make_optimizer(model,lr)
    if training:
        if training['signature']!=sig or training['stage']!=stage or training['updates']!=state['steps'].get(stage,0):raise ValueError('Checkpoint stage/signature mismatch')
        optimizer.load_state_dict(training['optimizer'])
        if scaler.is_enabled():scaler.load_state_dict(training['scaler'])
        torch.set_rng_state(training['rng'])
    public_train=public_valid=None
    if stage=='conversation':
        source,saved=read_source(config['repo'],config['publicRun'],config['publicRevision'],token)
        rows=json.loads(source.read_entry(saved['publicRows']))
        public_train,public_valid,public_report=public_windows(rows,tokenizer,config['context'])
        public_report.update(sourceRepo=config['repo'],sourceRun=config['publicRun'],sourceRevision=config['publicRevision'],sourceSha256=saved['publicRows']['sha256'])
        state=hub.publish(state,{'sftDataReport':('sft-data-report.json',json.dumps(public_report,indent=2).encode())})
        emit(v30ConversationData=public_report)
    emit(v30TrainingSetup=True,stage=stage,parameters=sum(p.numel() for p in model.parameters()),vocab=tokenizer.get_vocab_size(),
        contextTokens=config['context'],trainingGPUs=1,precision=str(dtype) if amp else 'float32',
        optimizerRestored=bool(training),oldModelsUntouched=True,publicWebsiteUpdated=False)
    del training;gc.collect()
    updates=state['steps'].get(stage,0);targets=state['targets'].get(stage,0);last_saved=updates;last_saved_time=clock()
    budget=config['foundationUpdates'] if stage=='foundation' else config['conversationUpdates']
    warmup=min(config['warmup'],max(1,budget//10));bad=0;interrupted=False;started=clock();start_targets=targets
    def save():
        nonlocal state,last_saved,last_saved_time
        steps=dict(state['steps']);steps[stage]=updates;counts=dict(state['targets']);counts[stage]=targets
        stream=checkpoint(model,dict(signature=sig,stage=stage,updates=updates,optimizer=optimizer.state_dict(),scaler=scaler.state_dict(),rng=torch.get_rng_state()),state['tokenizer']['sha256'])
        emit(v30BackupStarting=True,stage=stage,updates=updates)
        view=stream.getbuffer()
        try:state=hub.publish({**state,'steps':steps,'targets':counts},{working:(stage+'-working.pt',view)})
        finally:
            view.release()
            stream.close()
        last_saved=updates;last_saved_time=clock();emit(v30CheckpointConfirmed=True,stage=stage,updates=updates)
    if not state.get(stage+'Baseline'):
        report=evaluate(model,tokenizer,valid,stage,updates,public_valid,state.get('tokenRanges',{}).get('validation'))
        state=hub.publish(state,{stage+'Baseline':(stage+'-baseline.json',json.dumps(report,indent=2).encode())})
    try:
        while updates<budget and clock()<deadline:
            if stage=='foundation':pairs=raw_batch(train,updates,config['batch'],config['context'],config['seed'])
            else:
                rng=random.Random(config['seed']+updates*7919)
                pairs=[public_train[rng.randrange(len(public_train))] for _ in range(config['batch'])]
            rate=lr*min(1.,(updates+1)/warmup) # Hold after warmup; avoid another early decay.
            for group in optimizer.param_groups:group['lr']=rate
            denominator=sum(int((y!=-100).sum()) for _,y in pairs)
            model.train();optimizer.zero_grad(set_to_none=True);loss_value=0.
            for offset in range(0,len(pairs),config['microbatch']):
                x,y=collate(pairs[offset:offset+config['microbatch']]);x=x.to(device);y=y.to(device)
                with torch.autocast('cuda',dtype=dtype,enabled=amp):
                    loss=F.cross_entropy(model(x).flatten(0,1),y.flatten(),reduction='sum')/denominator
                if not torch.isfinite(loss):raise ValueError('Nonfinite loss; previous backup retained')
                loss_value+=float(loss.detach());scaler.scale(loss).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            if not torch.isfinite(norm):
                bad+=1
                if not scaler.is_enabled() or bad>12:raise ValueError('Nonfinite gradients')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();bad=0;updates+=1;targets+=denominator
            if updates%25==0:emit(v30Update=updates,stage=stage,budget=budget,loss=round(loss_value,4),learningRate=rate,
                supervisedSubwordTokens=targets,tokensPerSecond=round((targets-start_targets)/max(.01,clock()-started)))
            if updates%config['saveEvery']==0 or clock()-last_saved_time>=300:save()
            if updates%config['evaluateEvery']==0 and updates<budget:
                if last_saved!=updates:save()
                report=evaluate(model,tokenizer,valid,stage,updates,public_valid,state.get('tokenRanges',{}).get('validation'))
                state=hub.publish(state,{stage+'LatestEvaluation':(stage+'-evaluation.json',json.dumps(report,indent=2).encode())})
    except KeyboardInterrupt:interrupted=True
    if last_saved!=updates or not state.get(working):save()
    if updates<budget or interrupted:
        emit(v30Paused=True,stage=stage,updatesSaved=updates,runAgainWithSameSettings=True,reserveMinutes=reserve_minutes);return state
    report=evaluate(model,tokenizer,valid,stage,updates,public_valid,state.get('tokenRanges',{}).get('validation'))
    report['supervisedSubwordTokens']=targets
    report['parentReference']=state.get('parentReference')
    state=hub.publish({**state,stage+'Complete':True},{stage+'Final':(stage+'-final.json',json.dumps(report,indent=2).encode())})
    emit(v30StageComplete=stage,updates=updates,nextStageRequiresExplicitSelection=True,publicWebsiteUpdated=False)
    return report
