"""V14 phase-specific training. No old-model anchor and no checkpoint rollback."""
import argparse,hashlib,json,math,os,random,time
from collections import Counter
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path
import torch
import torch.distributed as dist
from torch.nn import functional as F
from torch.nn.parallel import DistributedDataParallel
from nebula import PAD,load,save
from dataflow import eligible,read_jsonl
from v9_data import canonical,digest
from v13_windows import examples
from v10_train import summed_loss
from train import evaluate_loss,unique_windows
from rules import owner_instructions

FORMAT='nebula-v14-train-1'

def pools(rows,context,stage):
    result={}
    for row in rows:
        if not eligible(row) or row['source'].get('kind')=='user':raise ValueError('V14 accepts eligible public/owned data only')
        if stage=='foundation':
            if row['source'].get('curriculum')!='v13-language':raise ValueError('Foundation stage accepts raw language only')
            key=row['source']['dataset'];windows=examples([row],context,False)
        else:
            key=row['source'].get('pool')
            if key not in ['public','context','historical']:raise ValueError('Conversation stage accepts labeled assistant pools only')
            # Owned context examples use the same complete-response rolling mask as public chats.
            wrapped={**row,'source':{**row['source'],'curriculum':'v13-conversation'}}
            windows=examples([wrapped],context,True)
        if windows:result.setdefault(key,[]).append(windows)
    return result

def pick(pools,batch,step,seed,stage):
    rng=random.Random(seed+step)
    if stage=='foundation':
        order=['roneneldan/TinyStories','HuggingFaceTB/smollm-corpus','HuggingFaceFW/fineweb-edu','roneneldan/TinyStories','HuggingFaceTB/smollm-corpus','HuggingFaceFW/fineweb-edu','roneneldan/TinyStories','HuggingFaceTB/smollm-corpus','HuggingFaceFW/fineweb-edu','roneneldan/TinyStories']
        key=order[step%10]
    else:key='public' if step%10<7 else 'context' if step%10<9 else 'historical'
    if key not in pools or not pools[key]:raise ValueError('Missing required V14 source pool: '+key)
    # Uniform original-record sampling prevents long answers dominating just by window count.
    rows=pools[key];return [rng.choice(rng.choice(rows)) for _ in range(batch)],key

def language_sum(model,batch,device,amp,dtype):
    length=max(len(x) for x,_ in batch);x=torch.full((len(batch),length),PAD,dtype=torch.long,device=device);y=torch.full_like(x,-100)
    for i,(a,b) in enumerate(batch):x[i,:len(a)]=a.to(device);y[i,:len(b)]=b.to(device)
    with torch.autocast('cuda',dtype=dtype) if amp else nullcontext():
        logits=model(x);loss=F.cross_entropy(logits.reshape(-1,262),y.reshape(-1),ignore_index=-100,reduction='sum')
    return loss,int((y!=-100).sum())

def main(argv=None,allow_world_change=False):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['data','validation-data','resume','output']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--stage',choices=['foundation','conversation'],required=True)
    parser.add_argument('--steps',type=int,default=500);parser.add_argument('--stage-budget',type=int,required=True)
    parser.add_argument('--batch',type=int,default=16);parser.add_argument('--microbatch',type=int,default=1)
    parser.add_argument('--lr',type=float,required=True);parser.add_argument('--warmup',type=int,default=100)
    parser.add_argument('--save-every',type=int,default=100);parser.add_argument('--max-seconds',type=float,default=3600)
    parser.add_argument('--seed',type=int,default=14014);parser.add_argument('--device',choices=['cpu','cuda'],default='cuda');parser.add_argument('--rendezvous')
    args=parser.parse_args(argv)
    world=int(os.environ.get('WORLD_SIZE','1'));rank=int(os.environ.get('RANK','0'));local=int(os.environ.get('LOCAL_RANK','0'))
    if not 0<args.steps<=10000 or not 0<args.stage_budget<=100000 or args.batch<world or args.batch%world or args.microbatch<1 or not math.isfinite(args.lr) or args.lr<=0 or args.save_every<1 or args.warmup<1 or not 0<args.max_seconds<=7200:parser.error('Invalid bounded training configuration')
    torch.set_num_threads(2);torch.manual_seed(args.seed)
    amp=args.device=='cuda'
    if amp:torch.cuda.set_device(local)
    device=torch.device('cuda',local) if amp else torch.device('cpu')
    if world>1:
        options={'backend':'nccl' if amp else 'gloo','rank':rank,'world_size':world,'timeout':timedelta(minutes=10)}
        if args.rendezvous:options['init_method']=Path(args.rendezvous).resolve().as_uri()
        dist.init_process_group(**options)
    def barrier():
        if world>1:dist.barrier()
    try:
        model,metadata=load(args.resume);model.to(device);model._activation_checkpointing=True
        dtype=torch.bfloat16 if amp and torch.cuda.is_bf16_supported() else torch.float16
        model._amp_enabled=amp;model._amp_dtype=dtype
        rows=read_jsonl(args.data);valid_rows=read_jsonl(args.validation_data)
        groups={r['splitGroup'] for r in valid_rows}
        valid_hash={canonical(r['messages']) for r in valid_rows}
        if any(r.get('splitGroup') in groups or canonical(r['messages']) in valid_hash for r in rows):raise ValueError('V14 train/heldout groups or records overlap')
        data=pools(rows,model.config.context,args.stage);valid_pools=pools(valid_rows,model.config.context,args.stage)
        validation=[];rng=random.Random(14141)
        for key,grouped in sorted(valid_pools.items()):
            windows,_=unique_windows([w for record in grouped for w in record]);validation.extend(rng.sample(windows,min(24,len(windows))))
        if not validation:raise ValueError('Independent heldout windows required')
        optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=.01)
        scaler=torch.amp.GradScaler('cuda',enabled=amp and dtype==torch.float16,init_scale=1024)
        signature={'format':FORMAT,'stage':args.stage,'dataSha256':digest(args.data),'validationSha256':digest(args.validation_data),'config':vars(model.config),'world':world,'batch':args.batch,'lr':args.lr,'warmup':args.warmup,'budget':args.stage_budget,'seed':args.seed,'amp':str(dtype) if amp else 'none','ownerRulesSha256':hashlib.sha256(owner_instructions().encode()).hexdigest() if args.stage=='conversation' else None}
        previous=torch.load(args.resume,map_location='cpu',weights_only=True).get('trainingState',{})
        same_stage=metadata.get('v14Stage')==args.stage
        saved_signature=previous.get('signature',{})
        # DDP shards a global batch; Adam state is per model and can resume on 1 or 2 GPUs.
        world_changed=bool(same_stage and saved_signature.get('world')!=world)
        comparable=dict(saved_signature)
        if allow_world_change and saved_signature.get('world') in [1,2] and world in [1,2]:comparable['world']=world
        compatible=same_stage and comparable==signature
        if same_stage and not compatible:raise ValueError('V14 resume configuration changed; use a new isolated experiment')
        if compatible:optimizer.load_state_dict(previous['optimizer']);scaler.load_state_dict(previous['scaler'])
        start=int(metadata.get('stageSteps',0)) if same_stage else 0;counts=Counter(previous.get('poolUpdates',{}) if compatible else {})
        wrapped=DistributedDataParallel(model,device_ids=[local] if amp else None,broadcast_buffers=False) if world>1 else model
        completed=0;targets=0;started=time.monotonic();bad=0
        if rank==0:print(json.dumps({'v14TrainingStage':args.stage,'stageSteps':start,'budget':args.stage_budget,'optimizerRestored':compatible,'stageTransitionOptimizerReset':not same_stage,'anchorModelsLoaded':0,'poolRecords':{k:len(v) for k,v in data.items()},'poolWindows':{k:sum(len(r) for r in v) for k,v in data.items()},'worldSize':world,'parameters':sum(p.numel() for p in model.parameters())}),flush=True)
        def checkpoint():
            barrier()
            if rank==0:
                model.eval()
                with torch.inference_mode():loss=evaluate_loss(model,validation,1)
                if loss is None or not math.isfinite(loss):raise ValueError('Non-finite heldout loss')
                report={'steps':metadata.get('steps',0)+completed,'stepsThisRun':completed,'v14Stage':args.stage,'stageSteps':start+completed,'validationLoss':loss,'poolUpdates':dict(counts),'worldSize':world,'trainingStateIncluded':True,'optimizerStateRestored':compatible,'worldSizeChangedOnResume':world_changed and compatible,'experimental':True,'qualityApproved':False,'humanVerified':False,'objective':'raw-next-byte' if args.stage=='foundation' else 'assistant-only','anchorPenalty':0,'stageBudget':args.stage_budget,'dataSha256':signature['dataSha256'],'validationSha256':signature['validationSha256'],'ownerRulesSha256':signature['ownerRulesSha256'],'configuredLearningRate':args.lr}
                save(model,args.output,report,training_state={'signature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict(),'poolUpdates':dict(counts)})
                print(json.dumps({'v14Checkpoint':str(args.output),**report}),flush=True)
            barrier()
        while completed<min(args.steps,args.stage_budget-start):
            step=start+completed;global_batch,key=pick(data,args.batch,step,args.seed,args.stage)
            global_targets=sum(int((y!=-100).sum()) for _,y in global_batch)
            portion=args.batch//world;batch=global_batch[rank*portion:(rank+1)*portion]
            optimizer.zero_grad(set_to_none=True);wrapped.train()
            progress=min(1.,step/max(1,args.stage_budget));rate=args.lr*min(1.,(step+1)/args.warmup)*(.1+.9*.5*(1+math.cos(math.pi*progress)))
            for group in optimizer.param_groups:group['lr']=rate
            for offset in range(0,len(batch),args.microbatch):
                micro=batch[offset:offset+args.microbatch];synchronize=offset+args.microbatch>=len(batch)
                with wrapped.no_sync() if world>1 and not synchronize else nullcontext():
                    if args.stage=='foundation':value,n=language_sum(wrapped,micro,device,amp,dtype);objective=value*world/max(1,global_targets)
                    else:value,n,_=summed_loss(wrapped,micro,device,amp,dtype);objective=value*world/args.batch
                    finite=torch.tensor(int(torch.isfinite(objective)),device=device)
                    if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
                    if not finite.item():raise ValueError('Non-finite training loss; saved checkpoints remain intact')
                    scaler.scale(objective).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            finite=torch.tensor(int(torch.isfinite(norm)),device=device)
            if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
            if not finite.item():
                optimizer.zero_grad(set_to_none=True);bad+=1
                if not scaler.is_enabled() or bad>16:raise ValueError('Non-finite gradients')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();completed+=1;counts[key]+=1;targets+=global_targets
            if rank==0 and completed%25==0:print(json.dumps({'v14Progress':args.stage,'stageStep':start+completed,'chunkStep':completed,'learningRate':rate,'targetsPerSecond':round(targets/max(.001,time.monotonic()-started)),'poolUpdates':dict(counts)}),flush=True)
            if completed%args.save_every==0:checkpoint()
            stop=torch.tensor(int(time.monotonic()-started>=args.max_seconds),device=device)
            if world>1:dist.all_reduce(stop,op=dist.ReduceOp.MAX)
            if stop.item():break
        checkpoint()
    finally:
        if world>1 and dist.is_initialized():dist.destroy_process_group()

if __name__=='__main__':main()
