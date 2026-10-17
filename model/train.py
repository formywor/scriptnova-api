import argparse
import hashlib
import json
import random
import time
import itertools
import math
from contextlib import nullcontext
from pathlib import Path
import torch
from torch.nn import functional as F
from nebula import Config, Nebula, PAD, encode, load, save, config_for_preset
from dataflow import read_jsonl, eligible
from rules import with_owner_rules

class NumericalFailure(RuntimeError): pass

def examples(rows, context, include_owner_rules=False, objective='assistant'):
    result = []
    for row in rows:
        messages = row['messages']
        if objective == 'language':
            # Language pretraining uses continuous serialized text chunks, with no
            # invented end-of-answer tokens at chunk boundaries. Chat tuning below
            # uses complete replies instead.
            prefix=encode(with_owner_rules([]) if include_owner_rules else [])[0]
            body=encode(messages)[0][1:]
            room=context+1-len(prefix)
            if room<1: raise ValueError('Owner rules exceed model context')
            for offset in range(0,len(body),room):
                tokens=prefix+body[offset:offset+room]
                x=torch.tensor(tokens[:-1]); y=torch.tensor([-100]*(len(prefix)-1)+tokens[len(prefix):])
                result.append((x,y))
            continue
        wrapped = with_owner_rules(messages) if include_owner_rules else messages
        windows = [wrapped]
        if len(encode(wrapped)[0]) > context + 1:
            windows = []
            for end in range(2,len(messages)+1,2):
                for start in range(0,end,2):
                    candidate=with_owner_rules(messages[start:end]) if include_owner_rules else messages[start:end]
                    if len(encode(candidate)[0]) <= context+1:
                        windows.append(candidate); break
        for window in windows:
            tokens, learn = encode(window)
            x = torch.tensor(tokens[:-1]); y = torch.tensor([v if mask else -100 for v, mask in zip(tokens[1:], learn[1:])])
            if (y != -100).any(): result.append((x, y))
    return result

def partition_rows(rows, seed):
    """Split original dialogues before creating windows, keeping duplicates together."""
    training=[]; validation=[]
    for row in rows:
        identifier=hashlib.sha256(json.dumps(row['messages'],sort_keys=True).encode()).hexdigest()
        # Owned curriculum variants of one scenario stay in the same partition.
        group=row.get('splitGroup') if row.get('source',{}).get('kind')=='seed' else None
        split_key='group:'+group if isinstance(group,str) and group else identifier
        score=int(hashlib.sha256((str(seed)+':'+split_key).encode()).hexdigest()[:8],16)
        (validation if score%10==0 else training).append(row)
    if not training or not validation: raise ValueError('Grouped split requires enough distinct conversations')
    return training,validation

def bucket_batches(data,batch_size,rng):
    ordered=sorted(data,key=lambda pair:len(pair[0])); batches=[]
    for offset in range(0,len(ordered),max(batch_size*32,32)):
        bucket=ordered[offset:offset+max(batch_size*32,32)]; rng.shuffle(bucket)
        batches.extend(bucket[i:i+batch_size] for i in range(0,len(bucket),batch_size))
    rng.shuffle(batches)
    return batches

def unique_windows(data,excluded=None):
    seen=set(excluded or []); result=[]
    for x,y in data:
        identifier=hashlib.sha256(x.numpy().tobytes()+y.numpy().tobytes()).hexdigest()
        if identifier in seen: continue
        seen.add(identifier); result.append((x,y))
    return result,seen

def loss(model, batch):
    length = max(len(x) for x, _ in batch)
    x = torch.full((len(batch), length), PAD, dtype=torch.long); y = torch.full_like(x, -100)
    for i, (a, b) in enumerate(batch): x[i, :len(a)] = a; y[i, :len(b)] = b
    device=next(model.parameters()).device
    autocast=torch.autocast('cuda',dtype=model._amp_dtype) if getattr(model,'_amp_enabled',False) else nullcontext()
    with autocast:
        return F.cross_entropy(model(x.to(device)).reshape(-1, 262), y.to(device).reshape(-1), ignore_index=-100)

def evaluate_loss(model, data, batch_size):
    total = tokens = 0
    for offset in range(0, len(data), batch_size):
        batch = data[offset:offset+batch_size]
        count = sum(int((y != -100).sum()) for _, y in batch)
        total += float(loss(model, batch)) * count; tokens += count
    return total / tokens if tokens else None

def train(args):
    if args.steps < 1 or args.batch < 1 or args.threads < 1: raise ValueError('Positive steps, batch and threads required')
    if not math.isfinite(args.lr) or args.lr <= 0: raise ValueError('Learning rate must be finite and positive')
    continuous = getattr(args, 'continuous', False)
    save_every = getattr(args, 'save_every', 100)
    patience = getattr(args, 'patience', 0)
    if patience < 0: raise ValueError('Patience must be zero or positive')
    if save_every < 1: raise ValueError('Save interval must be positive')
    max_seconds=getattr(args,'max_seconds',0)
    if not math.isfinite(max_seconds) or max_seconds<0: raise ValueError('Time limit must be zero or positive')
    torch.set_num_threads(args.threads); torch.manual_seed(args.seed); rng = random.Random(args.seed)
    rows = read_jsonl(args.data)
    snapshot = json.loads(Path(args.snapshot).read_text(encoding='utf-8')) if args.snapshot else None
    if any(row.get('source', {}).get('kind') == 'user' for row in rows):
        if continuous: raise ValueError('Continuous runs require seed/teacher data; user consent must be refreshed between bounded runs')
        if not snapshot or not 0 <= time.time() * 1000 - snapshot.get('createdAt', 0) < 300000:
            raise ValueError('User examples require a fresh consent check. Use scripts/model-data.mjs train.')
    # User records always require a fresh Firebase consent snapshot supplied by the wrapper.
    rows = [row for row in rows if eligible(row, snapshot)]
    if args.resume: model,resume_metadata=load(args.resume)
    else: model,resume_metadata=Nebula(config_for_preset(args.preset)),{}
    inherited_steps=resume_metadata.get('steps',0)
    requested_device=getattr(args,'device','cpu')
    device='cuda' if requested_device=='auto' and torch.cuda.is_available() else 'cpu' if requested_device=='auto' else requested_device
    if device=='cuda' and not torch.cuda.is_available(): raise ValueError('CUDA GPU is unavailable in this PyTorch installation')
    model.to(device)
    model._amp_enabled=device=='cuda' and getattr(args,'amp',False)
    model._amp_dtype=torch.bfloat16 if device=='cuda' and torch.cuda.is_bf16_supported() else torch.float16
    scaler=torch.amp.GradScaler('cuda',enabled=model._amp_enabled and model._amp_dtype==torch.float16)
    objective=getattr(args,'objective','assistant')
    grouped=getattr(args,'grouped_split',False)
    if grouped:
        train_rows,validation_rows=partition_rows(rows,args.seed)
        training=examples(train_rows,model.config.context,True,objective)
        validation=examples(validation_rows,model.config.context,True,objective)
        training,seen_windows=unique_windows(training)
        validation,_=unique_windows(validation,seen_windows)
        data=training+validation
    else:
        data = examples(rows, model.config.context, include_owner_rules=True,objective=objective)
        rng.shuffle(data); split = max(1, int(len(data) * .9)); training, validation = data[:split], data[split:]
    if not training: raise ValueError('No approved training examples fit the model context')
    if grouped and not validation: raise ValueError('No validation conversations fit the model context')
    available_validation=len(validation)
    max_validation=getattr(args,'max_validation',0)
    if max_validation:
        validation_rng=random.Random(args.seed+1)
        validation=validation_rng.sample(validation,min(len(validation),max_validation))
    validation.sort(key=lambda pair:len(pair[0]))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=.01)
    with torch.no_grad(): initial = float(loss(model, training[:args.batch]))
    if not math.isfinite(initial): initial=None
    completed = 0
    data_hash = hashlib.sha256(Path(args.data).read_bytes()).hexdigest()
    best_path = Path(args.output).with_suffix('.best.pt')
    best_validation = float('inf')
    stale_checks = 0
    batches=[]; epoch=0; completed_total_before=0
    if best_path.exists():
        _, previous = load(best_path)
        if previous.get('dataSha256') == data_hash and previous.get('seed') == args.seed and previous.get('objective','assistant') == objective and previous.get('groupedSplit',False) == grouped and previous.get('maxValidation',0) == max_validation and previous.get('windowFormat',1)==2:
            previous_loss = previous.get('validationLoss')
            if isinstance(previous_loss, (int, float)): best_validation = previous_loss
    state_enabled=getattr(args,'save_training_state',False)
    if state_enabled and args.resume:
        saved_state=torch.load(args.resume,map_location='cpu',weights_only=True).get('trainingState')
        signature={'dataSha256':data_hash,'objective':objective,'seed':args.seed,
                   'batch':args.batch,'bucketed':getattr(args,'bucketed',False),
                   'groupedSplit':grouped,'windowFormat':2,'maxValidation':max_validation,
                   'amp':model._amp_enabled,'learningRate':args.lr}
        if saved_state and saved_state.get('signature')==signature:
            optimizer.load_state_dict(saved_state['optimizer'])
            scaler.load_state_dict(saved_state['scaler'])
            rng.setstate(saved_state['samplerRandom'])
            torch.set_rng_state(saved_state['torchRandom'])
            if device=='cuda' and saved_state.get('cudaRandom'):
                torch.cuda.set_rng_state_all(saved_state['cudaRandom'])
            batches=[[training[index] for index in batch] for batch in saved_state['remainingBatches']]
            epoch=saved_state['epoch']; stale_checks=saved_state['staleChecks']
            completed_total_before=saved_state.get('stageSteps',0)
            print(json.dumps({'trainingStateRestored':True,'previousStageSteps':completed_total_before}),flush=True)
        else:
            print(json.dumps({'trainingStateRestored':False,'reason':'legacy_checkpoint_or_new_training_configuration'}),flush=True)
    signature={'dataSha256':data_hash,'objective':objective,'seed':args.seed,
               'batch':args.batch,'bucketed':getattr(args,'bucketed',False),
               'groupedSplit':grouped,'windowFormat':2,'maxValidation':max_validation,
               'amp':model._amp_enabled,'learningRate':args.lr}
    training_indices={id(x):index for index,(x,_) in enumerate(training)}
    def checkpoint(stopped=False,validate=True,reason=None):
        nonlocal best_validation, stale_checks
        model.eval()
        current=validation_loss=None
        if validate:
            with torch.no_grad():
                current = float(loss(model, training[:args.batch]))
                validation_loss = evaluate_loss(model, validation, args.batch)
            if not math.isfinite(current) or validation_loss is not None and not math.isfinite(validation_loss):
                raise NumericalFailure('Non-finite checkpoint metric')
        report = {'parameters': sum(p.numel() for p in model.parameters()), 'steps': inherited_steps+completed,'stepsThisRun':completed, 'trainingExamples': len(training), 'validationExamples': len(validation),'availableValidationExamples':available_validation,'originalConversations':len(rows), 'skippedExamples': None if grouped else max(0,len(rows) - len(data)), 'initialLoss': initial, 'finalLoss': current, 'validationLoss': validation_loss, 'seed': args.seed, 'dataSha256': data_hash, 'experimental': True, 'qualityApproved': False, 'stopped': stopped,'objective':objective,'groupedSplit':grouped,'maxValidation':max_validation,'device':device,'windowFormat':2}
        if reason: report['stopReason']=reason
        improved=validation_loss is not None and validation_loss < best_validation
        if improved:
            best_validation = validation_loss
            stale_checks = 0
        elif validation_loss is not None:
            stale_checks += 1
            if validation_loss > best_validation * 1.2:
                print('Validation loss is worsening: this run is overfitting. More varied data is needed; Ctrl+C saves and stops.', flush=True)
        training_state=None
        if state_enabled:
            training_state={'signature':signature,'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict(),
                'samplerRandom':rng.getstate(),'torchRandom':torch.get_rng_state(),
                'cudaRandom':torch.cuda.get_rng_state_all() if device=='cuda' else [],
                'remainingBatches':[[training_indices[id(x)] for x,_ in batch] for batch in batches],
                'epoch':epoch,'staleChecks':stale_checks,'stageSteps':completed_total_before+completed}
            report['stageSteps']=completed_total_before+completed
            report['trainingStateIncluded']=True
        if state_enabled: save(model,args.output,report,training_state=training_state)
        else: save(model,args.output,report)
        if improved:
            if state_enabled: save(model,best_path,report,training_state=training_state)
            else: save(model,best_path,report)
            print(json.dumps({'bestCheckpoint': str(best_path), 'validationLoss': best_validation}), flush=True)
        print(json.dumps({'checkpoint': str(args.output), **report}), flush=True)
    # Save even before the first update, then periodically and on Ctrl+C.
    started=time.monotonic(); trained_tokens=0
    try:
        # Resume already has a verified checkpoint and optimizer state. Avoid an
        # extra validation check consuming patience before its first update.
        if not (state_enabled and completed_total_before): checkpoint()
        for step in itertools.count() if continuous else range(args.steps):
            if getattr(args,'bucketed',False):
                if not batches: batches=bucket_batches(training,args.batch,rng); epoch+=1
                batch=batches.pop()
            else: batch = [training[rng.randrange(len(training))] for _ in range(args.batch)]
            model.train()
            optimizer.zero_grad(set_to_none=True); value = loss(model, batch)
            if not torch.isfinite(value): raise NumericalFailure('Non-finite training loss')
            scaler.scale(value).backward(); scaler.unscale_(optimizer)
            gradient_norm=torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            if not torch.isfinite(gradient_norm): raise NumericalFailure('Non-finite gradients; optimizer update was blocked')
            scaler.step(optimizer); scaler.update()
            completed = step + 1
            trained_tokens+=sum(len(x) for x,_ in batch)
            if step == 0 or completed % 25 == 0: print(json.dumps({'step': completed, 'loss': round(float(value.detach()), 4),'epoch':epoch or None,'tokensPerSecond':round(trained_tokens/max(.001,time.monotonic()-started))}), flush=True)
            if max_seconds and time.monotonic()-started>=max_seconds:
                checkpoint(stopped=True,validate=False,reason='time_limit')
                return {'steps':completed,'stopped':True,'reason':'time_limit'}
            if completed % save_every == 0:
                checkpoint()
                if patience and stale_checks >= patience:
                    print(json.dumps({'stopped':'validation_not_improving','steps':completed,'bestCheckpoint':str(best_path),'note':'Latest weights and best validation weights are saved. Live website unchanged.'}),flush=True)
                    return {'steps':completed,'stopped':True,'reason':'validation_not_improving'}
    except KeyboardInterrupt:
        checkpoint(stopped=True,validate=False,reason='interrupted')
        print('Stopped. Latest weights saved; the live website was not changed.', flush=True)
        return {'steps': completed, 'stopped': True}
    except NumericalFailure:
        optimizer.zero_grad(set_to_none=True)
        try:
            checkpoint(stopped=True,validate=False,reason='non_finite_loss_or_gradient')
            message='Stopped for a numerical error. Finite current weights saved without validation; the best checkpoint is preserved.'
        except ValueError:
            message='Stopped for a numerical error. Invalid weights were not saved; existing checkpoints are preserved.'
        print(message+' Resume from a healthy best checkpoint with a lower learning rate.',flush=True)
        return {'steps':completed,'stopped':True,'reason':'non_finite_loss_or_gradient'}
    checkpoint()
    report=load(args.output)[1]
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train owned Nebula weights from scratch. CPU preset is experimental, not production quality.')
    parser.add_argument('--continuous', action='store_true'); parser.add_argument('--save-every', type=int, default=100)
    parser.add_argument('--save-training-state',action='store_true',help='Save and restore compatible optimizer, sampler and random states')
    parser.add_argument('--max-seconds',type=float,default=0,help='Stop and save after this many seconds; 0 disables')
    parser.add_argument('--patience', type=int, default=0, help='Stop after this many validation checks without improvement; 0 disables')
    parser.add_argument('--device',choices=['auto','cpu','cuda'],default='auto')
    parser.add_argument('--objective',choices=['assistant','language'],default='assistant')
    parser.add_argument('--grouped-split',action='store_true'); parser.add_argument('--bucketed',action='store_true'); parser.add_argument('--max-validation',type=int,default=0)
    parser.add_argument('--data', required=True); parser.add_argument('--output', required=True); parser.add_argument('--snapshot'); parser.add_argument('--resume'); parser.add_argument('--preset', choices=['cpu', 'smoke','cpu-medium','cpu-large','gpu'], default='cpu'); parser.add_argument('--steps', type=int, default=500); parser.add_argument('--batch', type=int, default=4); parser.add_argument('--threads', type=int, default=2); parser.add_argument('--seed', type=int, default=42); parser.add_argument('--lr', type=float, default=.0005)
    train(parser.parse_args())
