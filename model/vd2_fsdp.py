"""EXPERIMENTAL two-GPU FULL_SHARD trainer. Requires a real 2xT4 memory/resume smoke test.
Each rank's optimizer is saved separately; only rank 0 atomically advances the model manifest.
Artifacts remain in RAM -> private HF. Do not run two torchrun jobs for one output run.
"""
import argparse,gc,gzip,io,json,os,random,time
from datetime import timedelta
from functools import partial
from vd2_hub import Hub
from vd2_lab import DEFAULT,engine_hash

def run(repo,token,hours=6,reserve_minutes=15,max_session_updates=0):
    import numpy as np
    import torch
    import torch.distributed as dist
    import torch.nn.functional as F
    from tokenizers import Tokenizer
    from torch.distributed.fsdp import FullyShardedDataParallel as FSDP,ShardingStrategy,MixedPrecision,StateDictType,FullStateDictConfig
    from torch.distributed.fsdp.wrap import transformer_auto_wrap_policy
    from torch.distributed.fsdp.sharded_grad_scaler import ShardedGradScaler
    from v30_expanded_model import Model,Config,Block
    from v30_device_audit import audit
    rank=int(os.environ.get('RANK',-1));local=int(os.environ.get('LOCAL_RANK',-1));world=int(os.environ.get('WORLD_SIZE',0))
    if world!=2 or not torch.cuda.is_available() or torch.cuda.device_count()<2:raise ValueError('Launch with torchrun --standalone --nproc_per_node=2 vd2_fsdp.py; requires two actual CUDA GPUs')
    torch.cuda.set_device(local);device=torch.device('cuda',local);dist.init_process_group('nccl',device_id=device,timeout=timedelta(minutes=30))
    try:
        hub=Hub(repo,token);state=hub.state()
        if not state or not state.get('dataReady') or state.get('engine')!=engine_hash():raise ValueError('Prepare the frozen approved corpus first')
        config=state['config'];step=state.get('updates',0);session_target=min(config['updates'],step+max_session_updates) if max_session_updates else config['updates']
        if state.get('worldSize',2)!=2:raise ValueError('Cannot resume a single-GPU optimizer as two FSDP optimizers; use a separate deliberate weight-transfer experiment')
        if config['batch']%2:raise ValueError('Global batch must divide by two ranks')
        if not 0<reserve_minutes/60<hours:raise ValueError('Invalid session/reserve')
        deadline=time.monotonic()+hours*3600-reserve_minutes*60
        tokenizer=Tokenizer.from_str(hub.read_entry(repo,hub.revision,state['tokenizer']).decode())
        pools={s:{k:[] for k in ['code','docs','general']} for s in ['train','validation']}
        records=gzip.decompress(hub.read_entry(repo,hub.revision,state['corpus'])).decode()
        for line in records.splitlines():
            r=json.loads(line);pools[r['split']][r['category']].append(tokenizer.encode(r['text'],add_special_tokens=False).ids+[2])
        del records;gc.collect()
        if not pools['train']['code'] or not pools['validation']['code']:raise ValueError('Independent coding training and validation documents are required')
        torch.manual_seed(config['seed']);base=Model(Config(**config['model']))
        if state.get('working'):
            blob=hub.read_entry(repo,hub.revision,state['working']);saved=torch.load(io.BytesIO(blob),map_location='cpu',weights_only=True)
            if saved['signature']!=state['signature']:raise ValueError('Model signature mismatch')
            base.load_state_dict(saved['model']);del blob,saved;gc.collect()
        # Before optimizer allocation, audit the actual full model/device (small sequence).
        base.to(device);probe=np.array((pools['train']['code'][0]*4)[:128],dtype=np.uint16);report=audit(base,probe)
        if not report['passed']:
            base.set_attention_backend('math');report=audit(base,probe)
            if not report['passed']:raise ValueError('Device audit failed before FSDP updates')
        if rank==0:print(json.dumps(dict(vd2FSDPAudit=report,experimental=True)),flush=True)
        model=FSDP(base,auto_wrap_policy=partial(transformer_auto_wrap_policy,transformer_layer_cls={Block}),sharding_strategy=ShardingStrategy.FULL_SHARD,mixed_precision=MixedPrecision(param_dtype=torch.float16,reduce_dtype=torch.float32,buffer_dtype=torch.float16),device_id=device,use_orig_params=True,limit_all_gathers=True)
        optimizer=torch.optim.AdamW([{'params':[p for n,p in model.named_parameters() if not any(s in n for s in ['bias','norm'])],'weight_decay':.1},{'params':[p for n,p in model.named_parameters() if any(s in n for s in ['bias','norm'])],'weight_decay':0}],lr=config['learningRate'],betas=(.9,.95),foreach=False)
        scaler=ShardedGradScaler(enabled=True)
        opt_key='optimizer'+str(rank)
        if step:
            if not state.get(opt_key):raise ValueError('Missing rank optimizer; refuse an incomplete resume')
            saved=torch.load(io.BytesIO(hub.read_entry(repo,hub.revision,state[opt_key])),map_location='cpu',weights_only=True)
            if saved['step']!=step or saved['worldSize']!=2 or saved['torchVersion']!=str(torch.__version__):raise ValueError('Rank optimizer/version mismatch')
            optimizer.load_state_dict(saved['optimizer']);scaler.load_state_dict(saved['scaler']);random.setstate(saved['random']);torch.set_rng_state(saved['torchRng']);torch.cuda.set_rng_state(saved['cudaRng'],device);del saved;gc.collect()
        def example(split,seed):
            rng=random.Random(seed);p=pools[split];kind=rng.choices(['code','docs','general'],[.75 if p['code'] else 0,.2 if p['docs'] else 0,.05 if p['general'] else 0])[0];data=[]
            while len(data)<config['model']['context']+1:
                ids=list(rng.choice(p[kind]))
                if split=='train' and kind=='code' and len(ids)>64 and rng.random()<.2:
                    a,b=sorted(rng.sample(range(1,len(ids)-1),2));ids=[6]+ids[:a]+[7]+ids[b:]+[8]+ids[a:b]+[2]
                data.extend(ids)
            return torch.tensor(data[:config['model']['context']+1],device=device,dtype=torch.long)
        @torch.inference_mode()
        def evaluate():
            model.eval();total=torch.zeros(1,device=device)
            for i in range(4):
                ids=example('validation',config['seed']+900000+rank*4+i)
                with torch.autocast('cuda',dtype=torch.float16):total+=F.cross_entropy(model(ids[:-1][None]).float().flatten(0,1),ids[1:])
            dist.all_reduce(total);return dict(loss=float(total)/(4*world),targets=8*config['model']['context'],qualityApproved=False)
        def save():
            nonlocal state
            # Collect weights only: no rank ever gathers the full 8GB optimizer state.
            with FSDP.state_dict_type(model,StateDictType.FULL_STATE_DICT,FullStateDictConfig(offload_to_cpu=True,rank0_only=True)):weights=model.state_dict()
            opt=io.BytesIO();torch.save(dict(step=step,worldSize=2,torchVersion=str(torch.__version__),optimizer=optimizer.state_dict(),scaler=scaler.state_dict(),random=random.getstate(),torchRng=torch.get_rng_state(),cudaRng=torch.cuda.get_rng_state(device)),opt)
            # Rank 1 uses a separate manifest. It cannot accidentally advance the main run's step.
            metadata=[None]
            if rank==1:
                sibling=Hub(repo,token,run='nebula-vd2-1b-code-rank1');s=sibling.publish({'updates':step,'signature':state['signature']},{'optimizer1':opt});metadata[0]={'revision':sibling.revision,'entry':s['optimizer1']}
            dist.broadcast_object_list(metadata,src=1,device=device);opt1=metadata[0];opt.close() if rank==1 else None
            if rank==0:
                hub.revision=opt1['revision'];model_blob=io.BytesIO();torch.save(dict(format='nebula-vd2-code-1',signature=state['signature'],model=weights),model_blob)
                state=hub.publish({**state,'updates':step,'worldSize':2,'optimizer1':opt1['entry'],'supervisedTokens':step*config['batch']*config['model']['context'],'experimentalFSDP':True},{'working':model_blob,'optimizer0':opt});model_blob.close();opt.close()
            del weights;gc.collect()
            metadata=[{'revision':hub.revision,'state':state} if rank==0 else None];dist.broadcast_object_list(metadata,src=0,device=device);hub.revision=metadata[0]['revision'];state=metadata[0]['state'];dist.barrier(device_ids=[local])
        if rank==0:print(json.dumps(dict(vd2FSDP=True,worldSize=2,precision='fp16',fullShard=True,resumedUpdates=step,experimental=True)),flush=True)
        state['evaluation']=evaluate();last=time.monotonic();last_saved=step
        while step<session_target:
            keep=torch.tensor([time.monotonic()<deadline],device=device,dtype=torch.int32);dist.all_reduce(keep,op=dist.ReduceOp.MIN)
            if not int(keep):break
            model.train();optimizer.zero_grad(set_to_none=True)
            import math
            lr=config['learningRate']*min(1,(step+1)/config['warmup'])*(.1+.9*.5*(1+math.cos(math.pi*step/config['updates'])))
            for group in optimizer.param_groups:group['lr']=lr
            loss_sum=0.
            # Do not use no_sync(): it keeps full accumulated gradients and can defeat memory savings.
            for micro in range(config['batch']//world):
                ids=example('train',config['seed']+step*config['batch']+rank*(config['batch']//world)+micro)
                with torch.autocast('cuda',dtype=torch.float16):loss=F.cross_entropy(model(ids[:-1][None]).float().flatten(0,1),ids[1:])/(config['batch']//world)
                if not torch.isfinite(loss):raise ValueError('Nonfinite loss; previous confirmed snapshot remains intact')
                scaler.scale(loss).backward();loss_sum+=float(loss.detach())
            scaler.unscale_(optimizer);model.clip_grad_norm_(1.);old_scale=scaler.get_scale();scaler.step(optimizer);scaler.update()
            if scaler.get_scale()<old_scale:
                if rank==0:print(json.dumps(dict(vd2FSDPSkippedOverflow=True,scale=scaler.get_scale())),flush=True)
                continue
            step+=1
            if rank==0 and step%25==0:print(json.dumps(dict(vd2FSDPUpdate=step,lossRank0=loss_sum,worldSize=2,peakRank0GpuBytes=torch.cuda.max_memory_allocated(device))),flush=True)
            if step%config['evaluateEvery']==0:state['evaluation']=evaluate()
            should_save=torch.tensor([step%config['saveEvery']==0 or time.monotonic()-last>=180],device=device,dtype=torch.int32);dist.all_reduce(should_save,op=dist.ReduceOp.MAX)
            if int(should_save):save();last_saved=step;last=time.monotonic()
        if last_saved!=step:save()
        state['evaluation']=evaluate()
        if rank==0:hub.publish(state,{})
    finally:dist.destroy_process_group()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--hours',type=float,default=6);p.add_argument('--reserve-minutes',type=float,default=15);p.add_argument('--max-session-updates',type=int,default=0);args=p.parse_args();run(args.repo,os.environ['HF_TOKEN'],args.hours,args.reserve_minutes,args.max_session_updates)
