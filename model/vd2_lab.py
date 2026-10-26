"""Coding-focused consolidation and conservative 1B training. Artifacts persist only in private HF."""
import copy,gzip,hashlib,io,json,math,os,random,time
from pathlib import Path
from vd2_data import candidates,Corpus,texts,sha,SPECIAL,parameter_count,source_split
from vd2_hub import Hub
MODEL=dict(vocab=8192,width=1536,heads=24,layers=35,context=2048)
DEFAULT=dict(model=MODEL,updates=10000,batch=8,microbatch=1,learningRate=0.0001,warmup=200,saveEvery=100,evaluateEvery=500,seed=31025,maxCorpusBytes=256_000_000,minCodeDocuments=5000)

def engine_hash():
    root=Path(__file__).parent
    names=['vd2_data.py','vd2_hub.py','vd2_lab.py','vd2_fsdp.py','v30_expanded_model.py','v30_device_audit.py']
    return sha(''.join((root/n).read_text(encoding='utf-8') for n in names).encode())

def inventory(repos,token=None):
    from huggingface_hub import HfApi
    import requests
    api=HfApi(token=token);entries=[];runs=[]
    for repo in repos:
        info=api.model_info(repo);revision=info.sha
        for name in api.list_repo_files(repo,revision=revision):
            if not name.startswith('experiments/') or not name.endswith('/state.json'):continue
            url=f'https://huggingface.co/{repo}/resolve/{revision}/{name}'
            r=requests.get(url,headers={'Authorization':'Bearer '+token} if token else {},timeout=60);r.raise_for_status()
            if len(r.content)>2_000_000:raise ValueError('Manifest too large')
            state=r.json();runs.append(dict(repo=repo,revision=revision,path=name));entries+=candidates(repo,revision,name,state)
    # Content duplicates share a candidate; source references remain recorded in the inventory.
    return dict(format='nebula-vd2-inventory-1',runs=runs,candidates=entries,notScanned=['Unconfigured GCS/S3 buckets','Private repositories not accessible to supplied token'],noObjectsMoved=True)

def prepare(repo,token,approved,config=DEFAULT):
    from tokenizers import Tokenizer,models,pre_tokenizers,decoders,trainers
    hub=Hub(repo,token);existing=hub.state()
    fingerprint=sha(json.dumps({'config':config,'sources':approved,'engine':engine_hash()},sort_keys=True).encode())
    if existing:
        if existing.get('signature')!=fingerprint:raise ValueError('Changed source/config: choose a new output repository/run, do not overwrite prior work')
        if existing.get('dataReady'):return existing
    if not approved or any(not x.get('approved') or not x.get('license') or x.get('origin') in ['historical-unreviewed','user-chat','review-feed'] for x in approved):raise ValueError('Review and approve explicit training provenance/licenses first; do not admit private chats')
    corpus=Corpus(config['maxCorpusBytes'])
    # Process historical validation first. Dedup moves any duplicated training record to validation.
    for source in sorted(approved,key=lambda x:source_split(x)!='validation'):
        blob=hub.read_entry(source['repo'],source['revision'],source['entry']);tokenizer=None
        if source['format']=='bpe-u16':
            if not source.get('tokenizer'):raise ValueError('Cannot decode subwords without their exact tokenizer')
            tokenizer=Tokenizer.from_str(hub.read_entry(source['repo'],source['revision'],source['tokenizer']).decode())
        for text in texts(blob,source['format'],tokenizer):corpus.add(text,source)
        print(json.dumps({'vd2Consolidating':source['key'],**corpus.summary()}),flush=True)
        del blob
    if corpus.summary()['counts'].get('train/code',0)<config['minCodeDocuments']:raise ValueError('Not enough distinct code documents for this coding experiment. Historical story/chat data is not an adequate coding corpus.')
    tokenizer=Tokenizer(models.BPE(unk_token=None));tokenizer.pre_tokenizer=pre_tokenizers.ByteLevel(add_prefix_space=False);tokenizer.decoder=decoders.ByteLevel()
    tokenizer.train_from_iterator((r['text'] for r in corpus.records.values() if r['split']=='train' and r['category'] in ['code','docs']),trainers.BpeTrainer(vocab_size=config['model']['vocab'],special_tokens=SPECIAL,initial_alphabet=pre_tokenizers.ByteLevel.alphabet()))
    if tokenizer.get_vocab_size()!=config['model']['vocab']:raise ValueError('Corpus too small to build the target vocabulary')
    state=dict(format='nebula-vd2-code-1',signature=fingerprint,engine=engine_hash(),config=config,dataReady=True,updates=0,qualityApproved=False,websiteUpdated=False,summary=corpus.summary(),sources=approved)
    return hub.publish(state,{'corpus':gzip.compress(corpus.payload()),'tokenizer':tokenizer.to_str().encode()})

def train(repo,token,hours=6.0,reserve_minutes=15,config=DEFAULT):
    import numpy as np
    import torch
    import torch.nn.functional as F
    from tokenizers import Tokenizer
    from v30_expanded_model import Model,Config
    from v30_device_audit import audit
    # Full-parameter AdamW needs much more than 16GB. Two visible T4s do not pool memory automatically.
    if not torch.cuda.is_available():raise ValueError('No CUDA GPU. Preparation/inventory can run on CPU; 1B training is not started.')
    props=torch.cuda.get_device_properties(0)
    if props.total_memory<38*1024**3:raise ValueError('This implementation requires one >=40GB GPU for full 1B AdamW training. 2xT4 is not one pooled GPU. Use a larger GPU or implement/test sharded training separately; no purchase is made.')
    if hours<=reserve_minutes/60:raise ValueError('Reserve exceeds session duration')
    hub=Hub(repo,token);state=hub.state()
    if not state or not state.get('dataReady') or state['config']!=config or state.get('engine')!=engine_hash():raise ValueError('Prepare and freeze the approved coding corpus/config first')
    deadline=time.monotonic()+hours*3600-reserve_minutes*60
    tokenizer_blob=hub.read_entry(repo,hub.revision,state['tokenizer']);tokenizer=Tokenizer.from_str(tokenizer_blob.decode())
    records=[json.loads(line) for line in gzip.decompress(hub.read_entry(repo,hub.revision,state['corpus'])).decode().splitlines()]
    pools={split:{kind:[] for kind in ['code','docs','general']} for split in ['train','validation']}
    for r in records:
        ids=tokenizer.encode(r['text'],add_special_tokens=False).ids+[2]
        pools[r['split']][r['category']].append(ids)
    if not pools['validation']['code']:raise ValueError('Independent coding validation documents required')
    torch.manual_seed(config['seed']);random.seed(config['seed']);model=Model(Config(**config['model'])).cuda()
    if sum(p.numel() for p in model.parameters())!=parameter_count(**{k:v for k,v in config['model'].items() if k!='heads'}):raise ValueError('Parameter count mismatch')
    bf16=torch.cuda.is_bf16_supported();dtype=torch.bfloat16 if bf16 else torch.float16
    optimizer=torch.optim.AdamW([{'params':[p for p in model.parameters() if p.ndim>=2],'weight_decay':.1},{'params':[p for p in model.parameters() if p.ndim<2],'weight_decay':0}],lr=config['learningRate'],betas=(.9,.95))
    scaler=torch.amp.GradScaler('cuda',enabled=not bf16);step=state['updates']
    if state.get('working'):
        saved=torch.load(io.BytesIO(hub.read_entry(repo,hub.revision,state['working'])),map_location='cpu',weights_only=True)
        if saved['signature']!=state['signature']:raise ValueError('Checkpoint configuration mismatch')
        model.load_state_dict(saved['model']);optimizer.load_state_dict(saved['optimizer']);scaler.load_state_dict(saved['scaler']);random.setstate(saved['random']);torch.set_rng_state(saved['torchRng']);torch.cuda.set_rng_state(saved['cudaRng']);del saved
    # Same causal implementation as V30; evaluate/train agreement is checked before updates.
    check_tokens=np.array((pools['train']['code'][0]*4)[:256],dtype=np.uint16)
    report=audit(model,check_tokens)
    if not report['passed']:
        model.set_attention_backend('math');report=audit(model,check_tokens)
        if not report['passed']:raise ValueError('Device audit failed. No optimizer updates started.')
    state['deviceAudit']=report
    def example(split,seed):
        rng=random.Random(seed);available=pools[split];kind=rng.choices(['code','docs','general'],[.75 if available['code'] else 0,.2 if available['docs'] else 0,.05 if available['general'] else 0])[0]
        data=[]
        while len(data)<config['model']['context']+1:
            ids=list(rng.choice(available[kind]))
            if kind=='code' and len(ids)>64 and rng.random()<.2:
                a,b=sorted(rng.sample(range(1,len(ids)-1),2));ids=[6]+ids[:a]+[7]+ids[b:]+[8]+ids[a:b]+[2]
            data.extend(ids)
        return torch.tensor(data[:config['model']['context']+1],device='cuda',dtype=torch.long)
    @torch.inference_mode()
    def evaluate():
        model.eval();losses=[]
        for i in range(16):
            ids=example('validation',config['seed']+900000+i)
            with torch.autocast('cuda',dtype=dtype):losses.append(float(F.cross_entropy(model(ids[:-1][None]).float().flatten(0,1),ids[1:])))
        return dict(loss=sum(losses)/len(losses),targets=16*config['model']['context'],qualityApproved=False,notice='Held-out coding loss is not proof of correct or secure code. Run separate sandboxed tests before serving.')
    def save():
        nonlocal state
        buffer=io.BytesIO();torch.save(dict(format='nebula-vd2-code-1',signature=state['signature'],model={k:v.detach().cpu() for k,v in model.state_dict().items()},optimizer=optimizer.state_dict(),scaler=scaler.state_dict(),random=random.getstate(),torchRng=torch.get_rng_state(),cudaRng=torch.cuda.get_rng_state()),buffer)
        state=hub.publish({**state,'updates':step,'supervisedTokens':step*config['batch']*config['model']['context']},{'working':buffer});buffer.close()
    last=time.monotonic();last_saved=step
    if not state.get('baseline'):state=hub.publish({**state,'baseline':evaluate()}, {})
    try:
        while step<config['updates'] and time.monotonic()<deadline:
            model.train();optimizer.zero_grad(set_to_none=True);lr=config['learningRate']*min(1,(step+1)/config['warmup'])*(.1+.9*.5*(1+math.cos(math.pi*step/config['updates'])))
            for g in optimizer.param_groups:g['lr']=lr
            losses=[]
            for micro in range(config['batch']):
                ids=example('train',config['seed']+step*config['batch']+micro)
                with torch.autocast('cuda',dtype=dtype):loss=F.cross_entropy(model(ids[:-1][None]).float().flatten(0,1),ids[1:])/config['batch']
                if not torch.isfinite(loss):raise ValueError('Nonfinite loss; no successful checkpoint is replaced')
                scaler.scale(loss).backward();losses.append(float(loss.detach()))
            scaler.unscale_(optimizer);torch.nn.utils.clip_grad_norm_(model.parameters(),1,error_if_nonfinite=True);scaler.step(optimizer);scaler.update();step+=1
            if step%25==0:print(json.dumps(dict(vd2Update=step,parameters=parameter_count(),loss=sum(losses),lr=lr)),flush=True)
            if step%config['evaluateEvery']==0:state['evaluation']=evaluate()
            if step%config['saveEvery']==0 or time.monotonic()-last>=180:
                save();last_saved=step;last=time.monotonic()
    except KeyboardInterrupt:print('Stop requested; saving this exact trajectory.',flush=True)
    # Upload errors propagate and stop the run; do not silently keep training without backups.
    if last_saved!=step:save()
    state=hub.publish({**state,'evaluation':evaluate()}, {})
    return dict(updatesSaved=step,parameters=parameter_count(),complete=step>=config['updates'],qualityApproved=False,websiteUpdated=False)
