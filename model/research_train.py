"""Synchronized one/two-GPU rounds; a single writer owns checkpoint files."""
import argparse
from contextlib import nullcontext
from datetime import timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import random
import time

import torch
import torch.distributed as dist
from torch.nn import functional as F
from torch.nn.parallel import DistributedDataParallel
from nebula import PAD,load,save
from research_eval import research_rows,select_focus
from train import examples,partition_rows,evaluate_loss,unique_windows

def global_batch(data,size,step,seed=42):
    # Stateless, length-local sampling: every rank chooses the same global batch
    # then consumes a different slice. No rank can run out of batches early.
    rng=random.Random(seed+step);anchor=rng.randrange(len(data))
    return [data[(anchor+i)%len(data)] for i in range(size)]

def summed_loss(model,batch,device,amp,dtype):
    length=max(len(x) for x,_ in batch)
    x=torch.full((len(batch),length),PAD,dtype=torch.long,device=device)
    y=torch.full_like(x,-100)
    for i,(a,b) in enumerate(batch):x[i,:len(a)]=a.to(device);y[i,:len(b)]=b.to(device)
    with torch.autocast('cuda',dtype=dtype) if amp else nullcontext():
        value=F.cross_entropy(model(x).reshape(-1,262),y.reshape(-1),ignore_index=-100,reduction='sum')
    return value,int((y!=-100).sum())

def main(argv=None,on_progress=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,required=True);parser.add_argument('--resume',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--steps',type=int,default=2000)
    parser.add_argument('--batch',type=int,default=16,help='GLOBAL batch shared by all GPUs')
    parser.add_argument('--device',choices=['cpu','cuda'],default='cuda')
    parser.add_argument('--focus',choices=['balanced','identity','memory','math','language'],default='balanced')
    parser.add_argument('--lr',type=float,default=.00005)
    parser.add_argument('--max-seconds',type=float,default=3600)
    parser.add_argument('--benchmark',action='store_true')
    parser.add_argument('--rendezvous',help='File rendezvous for the local CPU distributed test')
    args=parser.parse_args(argv)
    world=int(os.environ.get('WORLD_SIZE','1'));rank=int(os.environ.get('RANK','0'));local=int(os.environ.get('LOCAL_RANK','0'))
    if rank==0 and not args.benchmark and on_progress is None and os.environ.get('NEBULA_JOB_LEASE'):
        from research_client import Client
        client=Client();job=os.environ['NEBULA_JOB_LEASE']
        on_progress=lambda step:client.call('heartbeat',{'lease':job})
    if args.steps<1 or args.steps>10000 or args.batch<world or args.batch%world or not math.isfinite(args.lr) or args.lr<=0 or not math.isfinite(args.max_seconds) or not 0<args.max_seconds<=7200:
        parser.error('Use positive steps (up to 10000), LR, and a global batch divisible by worker count')
    torch.set_num_threads(2);torch.manual_seed(42)
    if args.device=='cuda':torch.cuda.set_device(local);device=torch.device('cuda',local)
    else:device=torch.device('cpu')
    if world>1:
        options={'backend':'nccl' if args.device=='cuda' else 'gloo','timeout':timedelta(minutes=5),'rank':rank,'world_size':world}
        if args.rendezvous:options['init_method']=Path(args.rendezvous).resolve().as_uri()
        dist.init_process_group(**options)
    def barrier():
        if world>1:dist.barrier()
    try:
        model,metadata=load(args.resume);model.to(device)
        amp=args.device=='cuda';dtype=torch.bfloat16 if amp and torch.cuda.is_bf16_supported() else torch.float16
        model._amp_enabled=amp;model._amp_dtype=dtype
        training_rows,validation_rows=partition_rows(research_rows(args.data),42)
        training,seen=unique_windows(examples(training_rows,model.config.context,True,'assistant'))
        validation,_=unique_windows(examples(validation_rows,model.config.context,True,'assistant'),seen)
        if not training or not validation:raise ValueError('Training and held-out validation data are required')
        focused,_=unique_windows(examples(select_focus(training_rows,args.focus),model.config.context,True,'assistant'))
        training.sort(key=lambda pair:len(pair[0]));focused.sort(key=lambda pair:len(pair[0]))
        validation=random.Random(43).sample(validation,min(128,len(validation)))
        validation.sort(key=lambda pair:len(pair[0]))
        optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=.01)
        scaler=torch.amp.GradScaler('cuda',enabled=amp and dtype==torch.float16,init_scale=1024)
        signature={'format':'research-ddp-1','dataSha256':hashlib.sha256(args.data.read_bytes()).hexdigest(),
                   'world':world,'batch':args.batch,'focus':args.focus,'lr':args.lr,'amp':str(dtype) if amp else 'none'}
        state=torch.load(args.resume,map_location='cpu',weights_only=True).get('trainingState',{})
        if state.get('signature')==signature:
            optimizer.load_state_dict(state['optimizer']);scaler.load_state_dict(state['scaler'])
        inherited=metadata.get('steps',0)
        wrapped=DistributedDataParallel(model,device_ids=[local] if amp else None,broadcast_buffers=False) if world>1 else model
        completed=0;trained=0;started=time.monotonic();bad=0
        def checkpoint():
            barrier()
            if rank==0 and not args.benchmark:
                model.eval()
                with torch.no_grad():value=evaluate_loss(model,validation,8)
                if value is None or not math.isfinite(value):raise ValueError('Non-finite validation result')
                report={'steps':inherited+completed,'stepsThisRun':completed,'validationLoss':value,
                        'dataSha256':signature['dataSha256'],'objective':'assistant','experimental':True,
                        'qualityApproved':False,'trainingStateIncluded':True,'worldSize':world,'focus':args.focus}
                save(model,args.output,report,training_state={'signature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict()})
                print(json.dumps({'checkpoint':str(args.output),**report}),flush=True)
            barrier()
        while completed<args.steps:
            step=inherited+completed
            pool=focused if focused and args.focus!='balanced' and step%4==0 else training
            batch=global_batch(pool,args.batch,step)
            portion=args.batch//world;batch=batch[rank*portion:(rank+1)*portion]
            wrapped.train();optimizer.zero_grad(set_to_none=True)
            value,count=summed_loss(wrapped,batch,device,amp,dtype)
            counts=torch.tensor(count,device=device,dtype=torch.float64)
            if world>1:dist.all_reduce(counts)
            objective=value*world/counts
            finite=torch.tensor(int(torch.isfinite(objective)),device=device)
            if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
            if not finite.item():raise ValueError('Non-finite loss; round stopped')
            scaler.scale(objective).backward();scaler.unscale_(optimizer)
            norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.0)
            finite=torch.tensor(int(torch.isfinite(norm)),device=device)
            if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
            if not finite.item():
                optimizer.zero_grad(set_to_none=True);bad+=1
                if not scaler.is_enabled() or bad>16:raise ValueError('Non-finite gradients; round stopped')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();completed+=1;trained+=int(counts)
            if rank==0 and completed%100==0:
                if on_progress:on_progress(completed)
                print(json.dumps({'step':completed,'worldSize':world,'globalBatch':args.batch,
                                  'targetsPerSecond':round(trained/max(.001,time.monotonic()-started))}),flush=True)
            if completed%200==0:checkpoint()
            stop=torch.tensor(int(time.monotonic()-started>=args.max_seconds),device=device)
            if world>1:dist.all_reduce(stop,op=dist.ReduceOp.MAX)
            if stop.item():break
        checkpoint()
        if rank==0:
            result={'completedSteps':completed,'worldSize':world,'targetsPerSecond':round(trained/max(.001,time.monotonic()-started))}
            args.output.with_suffix('.performance.json').write_text(json.dumps(result),encoding='utf-8')
            print(json.dumps(result),flush=True)
    except KeyboardInterrupt:
        # Periodic checkpoints remain valid even if a worker is forcibly stopped.
        if rank==0:print('Interrupted. Use the last complete checkpoint; other ranks will stop.',flush=True)
        raise
    finally:
        if world>1 and dist.is_initialized():dist.destroy_process_group()

if __name__=='__main__':main()
