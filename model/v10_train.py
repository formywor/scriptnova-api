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
from v7_checks import touches_checks
from v9_data import prompts
from v10_data import rejection
from nebula import PAD,load,save
from research_eval import research_rows,select_focus
from train import examples,partition_rows,evaluate_loss,unique_windows

def global_batch(data,size,step,seed=42):
    # Length-neighbor batches in V6 often repeated near-identical templates.
    rng=random.Random(seed+step)
    return rng.sample(data,size) if len(data)>=size else [rng.choice(data) for _ in range(size)]

def turn_average(values,mask):
    # Equal assistant-turn weight prevents a long first reply from drowning out its follow-up.
    starts=mask & ~F.pad(mask[:,:-1],(1,0),value=False)
    groups=starts.long().cumsum(1)
    shape=(values.shape[0],values.shape[1]+1)
    sums=torch.zeros(shape,device=values.device,dtype=values.dtype).scatter_add(1,groups,values*mask)
    counts=torch.zeros(shape,device=values.device,dtype=values.dtype).scatter_add(1,groups,mask.to(values.dtype))
    present=counts>0
    return ((sums/counts.clamp_min(1))*present).sum(1)/present.sum(1).clamp_min(1)

def summed_loss(model,batch,device,amp,dtype,anchor=None,strength=0.):
    length=max(len(x) for x,_ in batch)
    x=torch.full((len(batch),length),PAD,dtype=torch.long,device=device);y=torch.full_like(x,-100)
    for i,(a,b) in enumerate(batch):x[i,:len(a)]=a.to(device);y[i,:len(b)]=b.to(device)
    with torch.autocast('cuda',dtype=dtype) if amp else nullcontext():
        logits=model(x);mask=y!=-100
        losses=F.cross_entropy(logits.reshape(-1,262),y.reshape(-1),ignore_index=-100,reduction='none').view_as(y)
        # Each example, including greetings and clarification requests, counts equally.
        per_example=turn_average(losses,mask)
        if anchor is not None and strength:
            with torch.no_grad():reference=anchor(x)
            kl=F.kl_div(F.log_softmax(logits.float(),dim=-1),F.softmax(reference.float(),dim=-1),reduction='none').sum(-1)
            per_example=per_example+strength*turn_average(kl,mask)
    return per_example.sum(),len(batch),int(mask.sum())

def main(argv=None,on_progress=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validation-data',type=Path,required=True)
    parser.add_argument('--data',type=Path,required=True);parser.add_argument('--resume',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--steps',type=int,default=2000)
    parser.add_argument('--batch',type=int,default=16,help='GLOBAL batch shared by all GPUs')
    parser.add_argument('--device',choices=['cpu','cuda'],default='cuda')
    parser.add_argument('--focus',choices=['balanced','identity','memory','math','language'],default='balanced')
    parser.add_argument('--lr',type=float,default=.00005)
    parser.add_argument('--max-seconds',type=float,default=3600)
    parser.add_argument('--benchmark',action='store_true')
    parser.add_argument('--save-every',type=int,default=200)
    parser.add_argument('--sampling-seed',type=int,default=42)
    parser.add_argument('--best-checkpoint',action='store_true',help='Also preserve the lowest validation-loss checkpoint')
    parser.add_argument('--conversation-mix',action='store_true',help='80% conversation updates; 20% mixed, including memory')
    parser.add_argument('--review-data',type=Path,help='Fresh consent-checked review feed, training only')
    parser.add_argument('--quality-anchor',type=Path,required=True)
    parser.add_argument('--teacher-data',type=Path)
    parser.add_argument('--microbatch',type=int,default=1)
    parser.add_argument('--rendezvous',help='File rendezvous for the local CPU distributed test')
    parser.add_argument('--expanded-public',action='store_true',help='V13 complete-answer rolling windows and four-source curriculum')
    args=parser.parse_args(argv)
    make_examples=examples;reject=rejection;quality_version=10
    if args.expanded_public:
        from v13_windows import examples as make_examples
        from v13_data import rejection as reject
        quality_version=13
    world=int(os.environ.get('WORLD_SIZE','1'));rank=int(os.environ.get('RANK','0'));local=int(os.environ.get('LOCAL_RANK','0'))
    if rank==0 and not args.benchmark and on_progress is None and os.environ.get('NEBULA_JOB_LEASE'):
        from research_client import Client
        client=Client();job=os.environ['NEBULA_JOB_LEASE']
        on_progress=lambda step:client.call('heartbeat',{'lease':job})
    if args.microbatch<1 or args.steps<1 or args.steps>10000 or args.save_every<1 or args.batch<world or args.batch%world or not math.isfinite(args.lr) or args.lr<=0 or not math.isfinite(args.max_seconds) or not 0<args.max_seconds<=7200:
        parser.error('Use positive steps (up to 10000), LR, and a global batch divisible by worker count')
    if not 0<=args.sampling_seed<2**31:parser.error('Sampling seed must fit a nonnegative 31-bit integer')
    torch.set_num_threads(2);torch.manual_seed(args.sampling_seed)
    if args.device=='cuda':torch.cuda.set_device(local);device=torch.device('cuda',local)
    else:device=torch.device('cpu')
    if world>1:
        options={'backend':'nccl' if args.device=='cuda' else 'gloo','timeout':timedelta(minutes=5),'rank':rank,'world_size':world}
        if args.rendezvous:options['init_method']=Path(args.rendezvous).resolve().as_uri()
        dist.init_process_group(**options)
    def barrier():
        if world>1:dist.barrier()
    try:
        model,metadata=load(args.resume);model.to(device);model._activation_checkpointing=True
        anchor,_=load(args.quality_anchor);anchor.to(device);anchor.eval();anchor.requires_grad_(False)
        amp=args.device=='cuda';dtype=torch.bfloat16 if amp and torch.cuda.is_bf16_supported() else torch.float16
        model._amp_enabled=amp;model._amp_dtype=dtype
        training_rows=research_rows(args.data);validation_rows=research_rows(args.validation_data)
        training_rows=[r for r in training_rows if r['source'].get('kind')!='public' or r['source'].get('curriculum') in ['v9-language','v13-language'] or reject(r) is None]
        protected_questions=set().union(*(prompts(row) for row in validation_rows))
        protected_groups={row.get('splitGroup') for row in validation_rows if row.get('splitGroup')}
        if any(prompts(row)&protected_questions or row.get('splitGroup') in protected_groups for row in training_rows):raise ValueError('Training overlaps held-out validation prompts or groups')
        training,seen=unique_windows(make_examples(training_rows,model.config.context,True,'assistant'))
        validation,all_seen=unique_windows(make_examples(validation_rows,model.config.context,True,'assistant'),seen)
        if not training or not validation:raise ValueError('Training and held-out validation data are required')
        focused,_=unique_windows(make_examples(select_focus(training_rows,args.focus),model.config.context,True,'assistant'))
        chat_pool=[];mixed_pool=[];memory_pool=[];review_pool=[];teacher_pool=[];identity_pool=[];math_pool=[];language_pool=[];public_pool=[];old_pool=[];repair_pool=[]
        if args.conversation_mix:
            from conversation_mix import mixed_lane
            from v7_data import is_conversation as conversational
            chat_rows=[r for r in training_rows if conversational(r)]
            public_rows=[r for r in chat_rows if r['source'].get('dataset')=='HuggingFaceTB/smol-smoltalk']
            old_rows=[r for r in chat_rows if r['source'].get('kind')!='public' and r['source'].get('focus')!='v10-repair']
            public_rows=[r for r in chat_rows if r['source'].get('kind')=='public']
            repair_pool,_=unique_windows(make_examples([r for r in chat_rows if r['source'].get('focus')=='v10-repair'],model.config.context,True,'assistant'))
            public_pool,_=unique_windows(make_examples(public_rows,model.config.context,True,'assistant'))
            old_pool,_=unique_windows(make_examples(old_rows,model.config.context,True,'assistant'))
            language_pool,_=unique_windows(make_examples([r for r in training_rows if r['source'].get('curriculum') in ['v9-language','v13-language']],model.config.context,True,'assistant'))
            mixed_rows=[r for r in training_rows if not conversational(r)]
            chat_pool,_=unique_windows(make_examples(chat_rows,model.config.context,True,'assistant'))
            mixed_focus=select_focus(mixed_rows,args.focus) if args.focus not in ['balanced','language'] else []
            mixed_pool,_=unique_windows(make_examples(mixed_focus or mixed_rows,model.config.context,True,'assistant'))
            memory_pool,_=unique_windows(make_examples(select_focus(mixed_rows,'memory'),model.config.context,True,'assistant'))
            if not chat_pool or not mixed_pool or not memory_pool:raise ValueError('80/20 training requires conversation, mixed and memory examples')
            if args.review_data and args.review_data.is_file():
                from review_feed import validated_rows
                from dataflow import read_jsonl
                rows=[r for r in validated_rows(read_jsonl(args.review_data)) if not touches_checks(r['messages']) and not bool(prompts(r)&protected_questions) and reject(r,protected_questions) is None]
                review_pool,_=unique_windows(make_examples(rows,model.config.context,True,'assistant'),all_seen)
            identity_pool,_=unique_windows(make_examples(select_focus(training_rows,'identity'),model.config.context,True,'assistant'))
            math_pool,_=unique_windows(make_examples(select_focus(mixed_rows,'math'),model.config.context,True,'assistant'))
            if args.teacher_data and args.teacher_data.is_file():
                teacher_rows=[r for r in research_rows(args.teacher_data) if r.get('source',{}).get('curriculum')=='v7-groq-teacher' and r.get('source',{}).get('validation')=='generated-dialogue-second-pass-v1' and not touches_checks(r['messages']) and not bool(prompts(r)&protected_questions) and reject(r,protected_questions) is None]
                teacher_pool,_=unique_windows(make_examples(teacher_rows,model.config.context,True,'assistant'),all_seen)
            for pool in [chat_pool,mixed_pool,memory_pool,review_pool,teacher_pool,identity_pool,math_pool,language_pool,public_pool,old_pool,repair_pool]:pool.sort(key=lambda pair:len(pair[0]))
            if rank==0:print(json.dumps({'conversationPercent':80,'mixedPercent':20,'memoryIncluded':True,'reviewedTrainingWindows':len(review_pool),'groqTeacherWindows':len(teacher_pool),'repairWindows':len(repair_pool),'newPublicWindows':len(public_pool),'languageWindows':len(language_pool),'qualityAnchor':True,'pastBestReplay':True,'protectedBestAnchor':True,'assistantTurnBalanced':True,'teacherAndHistoricalPractice':True,'mixMeasuredIn':'optimizer updates'}),flush=True)
        language_sources={}
        if args.expanded_public:
            for dataset in sorted({r['source']['dataset'] for r in training_rows if r['source'].get('curriculum')=='v13-language'}):
                language_sources[dataset]=unique_windows(make_examples([r for r in training_rows if r['source'].get('curriculum')=='v13-language' and r['source']['dataset']==dataset],model.config.context,True))[0]
        language_counts={dataset:0 for dataset in language_sources}
        training.sort(key=lambda pair:len(pair[0]));focused.sort(key=lambda pair:len(pair[0]))
        validation=random.Random(43).sample(validation,min(128,len(validation)))
        validation.sort(key=lambda pair:len(pair[0]))
        optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=.01)
        scaler=torch.amp.GradScaler('cuda',enabled=amp and dtype==torch.float16,init_scale=1024)
        signature={'format':'research-ddp-1','dataSha256':hashlib.sha256(args.data.read_bytes()).hexdigest(),
                   'world':world,'batch':args.batch,'focus':args.focus,'lr':args.lr,'amp':str(dtype) if amp else 'none','samplingSeed':args.sampling_seed,'conversationMix':args.conversation_mix,'qualityVersion':quality_version,'turnBalanced':True,'anchorSha256':hashlib.sha256(args.quality_anchor.read_bytes()).hexdigest(),'validationSha256':hashlib.sha256(args.validation_data.read_bytes()).hexdigest(),'reviewSha256':hashlib.sha256(args.review_data.read_bytes()).hexdigest() if args.review_data and args.review_data.is_file() else None}
        state=torch.load(args.resume,map_location='cpu',weights_only=True).get('trainingState',{})
        previous_signature=state.get('signature',{})
        compatible=previous_signature.get('turnBalanced') is True and previous_signature.get('qualityVersion')==quality_version and previous_signature.get('anchorSha256')==signature['anchorSha256'] and previous_signature.get('dataSha256')==signature['dataSha256'] and previous_signature.get('amp')==signature['amp'] and previous_signature.get('validationSha256')==signature['validationSha256']
        if compatible:
            optimizer.load_state_dict(state['optimizer']);scaler.load_state_dict(state['scaler'])
        if rank==0:print(json.dumps({'v10OptimizerStateRestored':compatible}),flush=True)
        inherited=metadata.get('steps',0)
        wrapped=DistributedDataParallel(model,device_ids=[local] if amp else None,broadcast_buffers=False) if world>1 else model
        mix_counts={'conversationUpdates':0,'mixedUpdates':0,'memoryUpdates':0,'reviewUpdates':0,'teacherUpdates':0,'repairUpdates':0,'identityUpdates':0,'mathUpdates':0,'pastBestReplayUpdates':0,'publicConversationUpdates':0,'languageUpdates':0};completed=0;trained=0;started=time.monotonic();bad=0;best_value=float('inf');best_step=0
        def checkpoint(candidate=False):
            nonlocal best_value,best_step
            barrier()
            if rank==0 and not args.benchmark:
                model.eval()
                with torch.no_grad():value=evaluate_loss(model,validation,1)
                if value is None or not math.isfinite(value):raise ValueError('Non-finite validation result')
                report={'steps':inherited+completed,'stepsThisRun':completed,'validationLoss':value,
                        'dataSha256':signature['dataSha256'],'objective':'assistant','experimental':True,
                        'qualityApproved':False,'trainingStateIncluded':True,'worldSize':world,'focus':args.focus,'conversationPercent':80 if args.conversation_mix else None,'reviewedTrainingWindows':len(review_pool),'groqTeacherWindows':len(teacher_pool),'qualityVersion':quality_version,'optimizerStateRestored':compatible,**({'languageSourceUpdates':dict(language_counts),'completeAnswerWindows':True,'modelContextBytes':model.config.context} if args.expanded_public else {}),**mix_counts}
                training_state={'signature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict(),'totalUpdates':state.get('totalUpdates',0)+completed if compatible else completed}
                save(model,args.output,report,training_state=training_state)
                if args.best_checkpoint and value<best_value:
                    best_value=value;best_step=completed
                    save(model,args.output.with_suffix('.best.pt'),report,training_state=training_state)
                if candidate and completed>0:save(model,args.output.with_name(args.output.stem+f'.step-{completed}.pt'),report,training_state=training_state)
                print(json.dumps({'checkpoint':str(args.output),**report}),flush=True)
            barrier()
        if args.best_checkpoint and not args.benchmark:checkpoint()
        while completed<args.steps:
            step=inherited+completed
            pool=focused if focused and args.focus!='balanced' and step%4==0 else training
            if args.conversation_mix:
                lane=mixed_lane(completed)
                pool=chat_pool if lane=='conversation' else memory_pool if lane=='memory' else mixed_pool
                chat_number=4*(completed//5)+completed%5
                if lane=='conversation':
                    slot=chat_number%10
                    pool=(old_pool or chat_pool) if slot<3 else repair_pool if slot<5 else teacher_pool if slot<7 else public_pool if slot<9 else public_pool
                    if pool is repair_pool and mix_counts['repairUpdates']>=max(1,math.ceil(len(repair_pool)*4/args.batch)):pool=old_pool or public_pool
                    if pool is teacher_pool and mix_counts['teacherUpdates']>=max(1,math.ceil(len(teacher_pool)*2/args.batch)):pool=public_pool or old_pool
                    if slot==9 and review_pool and mix_counts['reviewUpdates']<max(1,math.ceil(len(review_pool)*2/args.batch)):pool=review_pool
                    if not pool:pool=old_pool or public_pool or chat_pool
                if lane=='mixed':
                    block=completed//5%8
                    pool=((language_pool if block in [1,5] else identity_pool if block==3 else math_pool) if args.expanded_public else (identity_pool if block in [1,5] else language_pool if block==3 else math_pool)) or mixed_pool
            selection=pool
            if args.expanded_public and pool is language_pool and language_sources:
                dataset=sorted(language_sources)[mix_counts['languageUpdates']%len(language_sources)];selection=language_sources[dataset];language_counts[dataset]+=1
            batch=global_batch(selection,args.batch,step,args.sampling_seed)
            portion=args.batch//world;batch=batch[rank*portion:(rank+1)*portion]
            wrapped.train();optimizer.zero_grad(set_to_none=True)
            total_updates=(state.get('totalUpdates',0) if compatible else 0)+completed
            warmup=min(1.,(total_updates+1)/30);decay=max(.50,1-total_updates/10000)
            for group in optimizer.param_groups:group['lr']=args.lr*warmup*decay
            strength=(.25 if pool is old_pool else .10 if pool is public_pool else .04) if args.conversation_mix and lane=='conversation' else (2.0 if lane=='memory' else 1.0 if pool is identity_pool else .50) if args.conversation_mix else .20
            target_count=0
            for offset in range(0,len(batch),args.microbatch):
                micro=batch[offset:offset+args.microbatch]
                sync=offset+args.microbatch>=len(batch)
                context=wrapped.no_sync() if world>1 and not sync else nullcontext()
                with context:
                    value,count,targets=summed_loss(wrapped,micro,device,amp,dtype,anchor,strength)
                    objective=value*world/args.batch
                    finite=torch.tensor(int(torch.isfinite(objective)),device=device)
                    if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
                    if not finite.item():raise ValueError('Non-finite loss; round stopped')
                    scaler.scale(objective).backward();target_count+=targets
            scaler.unscale_(optimizer)
            norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.0)
            finite=torch.tensor(int(torch.isfinite(norm)),device=device)
            if world>1:dist.all_reduce(finite,op=dist.ReduceOp.MIN)
            if not finite.item():
                optimizer.zero_grad(set_to_none=True);bad+=1
                if not scaler.is_enabled() or bad>16:raise ValueError('Non-finite gradients; round stopped')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();completed+=1
            target_total=torch.tensor(target_count,device=device,dtype=torch.long)
            if world>1:dist.all_reduce(target_total)
            trained+=int(target_total)
            if args.conversation_mix:
                mix_counts['conversationUpdates' if lane=='conversation' else 'mixedUpdates']+=1
                if lane=='memory':mix_counts['memoryUpdates']+=1
                if pool is repair_pool:mix_counts['repairUpdates']+=1
                if pool is identity_pool:mix_counts['identityUpdates']+=1
                if pool is math_pool:mix_counts['mathUpdates']+=1
                if pool is review_pool:mix_counts['reviewUpdates']+=1
                if pool is teacher_pool:mix_counts['teacherUpdates']+=1
                if pool is chat_pool or pool is old_pool:mix_counts['pastBestReplayUpdates']+=1
                if pool is public_pool:mix_counts['publicConversationUpdates']+=1
                if pool is language_pool:mix_counts['languageUpdates']+=1
            if rank==0 and completed%10==0:
                if on_progress:on_progress(completed)
                print(json.dumps({'step':completed,'worldSize':world,'globalBatch':args.batch,
                                  'targetsPerSecond':round(trained/max(.001,time.monotonic()-started))}),flush=True)
            if completed%args.save_every==0:checkpoint(candidate=completed in [25,50])
            stop=torch.tensor(int(time.monotonic()-started>=args.max_seconds),device=device)
            if world>1:dist.all_reduce(stop,op=dist.ReduceOp.MAX)
            if stop.item():break
        checkpoint()
        if rank==0:
            result={'bestStep':best_step,'completedSteps':completed,'worldSize':world,'targetsPerSecond':round(trained/max(.001,time.monotonic()-started)),
                    'peakGpuMemoryBytes':torch.cuda.max_memory_allocated(device) if amp else 0}
            args.output.with_suffix('.performance.json').write_text(json.dumps(result),encoding='utf-8')
            print(json.dumps(result),flush=True)
    except KeyboardInterrupt:
        # Periodic checkpoints remain valid even if a worker is forcibly stopped.
        if rank==0:print('Interrupted. Use the last complete checkpoint; other ranks will stop.',flush=True)
        raise
    finally:
        if world>1 and dist.is_initialized():dist.destroy_process_group()

if __name__=='__main__':main()
