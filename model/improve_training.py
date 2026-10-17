"""Bounded language-first curriculum, preserving previous Colab weights and data."""
import argparse
import hashlib
import json
import random
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

from dataflow import eligible, example_id, prepare, read_jsonl, redact, write_jsonl
from nebula import encode, load
from public_data import fetch_page
from rules import with_owner_rules
from train import train

STORIES = {'dataset':'roneneldan/TinyStories','config':'default','split':'train',
           'license':'cdla-sharing-1.0','url':'https://huggingface.co/datasets/roneneldan/TinyStories'}

def story_row(text, index):
    if not isinstance(text,str) or not 100 <= len(text.encode('utf-8')) <= 8000:
        return None
    if '<|endoftext|>' in text: return None
    messages=[{'role':'user','content':'Tell a simple story.'},
              {'role':'assistant','content':redact(text.strip())}]
    identifier=example_id(messages)
    return {'id':identifier,'reviewStatus':'approved',
            'approvalMethod':'public-dataset-structural-filter-unverified',
            'messages':messages,'source':{'kind':'public',**STORIES,
                'subset':'default','recordId':identifier,'rowIndex':index}}

def download_stories(directory, limit=10000, transport=None):
    if not 1 <= limit <= 20000: raise ValueError('Story limit must be 1-20000')
    directory=Path(directory); rows=[]; seen=set(); offset=0
    destination=directory/'stories-approved.jsonl'; source_manifest=directory/'stories-sources.json'
    # Keep the training dataset stable across interrupted runs, even if the
    # original download was shortened by the public server's rate limit.
    if destination.exists() and source_manifest.exists():
        previous=json.loads(source_manifest.read_text(encoding='utf-8'))
        if previous.get('requestedRows')==limit and previous.get('sha256')==hashlib.sha256(destination.read_bytes()).hexdigest():
            print(json.dumps({'storiesReused':previous['accepted'],'downloadSkipped':True}),flush=True)
            return destination
    deferred=False
    while offset < limit:
        try:
            page=fetch_page(STORIES,offset,min(100,limit-offset),directory/'stories-cache',transport)
        except HTTPError as error:
            if error.code not in [429,500,502,503,504] or len(rows)<1000: raise
            deferred=True
            print(json.dumps({'storyDownloadDeferred':True,'httpStatus':error.code,
                              'usingCachedStories':len(rows),'trainingCanContinue':True}),flush=True)
            break
        entries=page['rows']
        if not entries: break
        for entry in entries:
            if entry.get('truncated_cells'): continue
            row=story_row(entry.get('row',{}).get('text'),entry.get('row_idx',offset))
            if row and row['id'] not in seen:
                seen.add(row['id']); rows.append(row)
        offset+=len(entries)
        print(json.dumps({'storiesScanned':offset,'storiesAccepted':len(rows)}),flush=True)
        if offset >= page.get('num_rows_total',limit): break
    if not rows: raise ValueError('No valid stories downloaded; no training started')
    write_jsonl(destination,rows)
    source_manifest.write_text(json.dumps({
        'source':STORIES,'scanned':offset,'accepted':len(rows),
        'requestedRows':limit,'downloadDeferred':deferred,
        'licenseURL':'https://cdla.dev/sharing-1-0/',
        'changes':['Wrapped stories in a synthetic story prompt','Redacted likely contacts and credentials',
                   'Excluded malformed, oversized, duplicate and truncated records'],
        'sha256':hashlib.sha256(destination.read_bytes()).hexdigest()},indent=2),encoding='utf-8')
    return destination

def foundation_rows():
    """Original, exact-answer exercises; never generated from account chats."""
    pairs=[]; rng=random.Random(177)
    problems=[(a,b) for a in range(50) for b in range(50)]
    rng.shuffle(problems)
    for i,(a,b) in enumerate(problems[:1600]):
        if i % 2:
            high,low=max(a,b),min(a,b)
            pairs.append((f'Subtract {low} from {high}.',f'{high} - {low} = {high-low}.'))
        else: pairs.append((f'Add {a} and {b}.',f'{a} + {b} = {a+b}.'))
    for name in ['Ari','Lena','Omar','Maya','Tess','Noah','Zoe','Iris','Ben','Nora']:
        for color in ['red','blue','green','yellow','purple','orange']:
            pairs.append((f'{name} has a {color} bag. What color is the bag?',f'The bag is {color}.'))
            pairs.append((f'I am {name}. Please repeat my name.',f'Your name is {name}.'))
    pairs += [('Who are you?','I am Nebula AI.'),
              ('Can you help?','Yes. What would you like help with?'),
              ('Thanks for helping.','You are welcome!'),
              ('I need help writing a message.','Who is the message for, and what should it say?'),
              ('Do you know everything?','No. I can make mistakes and may not know the answer.')]
    seen=set()
    for question,answer in pairs:
        messages=[{'role':'user','content':question},{'role':'assistant','content':answer}]
        identifier=example_id(messages)
        if identifier in seen: continue
        seen.add(identifier)
        yield {'id':identifier,'reviewStatus':'approved','messages':messages,
               'source':{'kind':'seed','curriculum':'nebula-foundations-v1'}}

def prepare_curriculum(project, story_path, context):
    project=Path(project); data=project/'model/data'
    foundations=data/'foundations-approved.jsonl'; write_jsonl(foundations,list(foundation_rows()))
    inputs=[data/'public-approved.jsonl',foundations]
    for name in ['conversations-approved.jsonl','conversations-teacher-accepted.jsonl','gemini-accepted.jsonl']:
        if (data/name).exists(): inputs.append(data/name)
    language=data/'improved-language.jsonl'
    prepare(inputs+[story_path],language)
    # Select whole conversations that fit. Never cut an answer or move a partial
    # version of an original conversation into another validation partition.
    short=[]; seen=set()
    for path in inputs:
        for row in read_jsonl(path):
            identifier=example_id(row['messages'])
            if eligible(row) and identifier not in seen and len(encode(with_owner_rules(row['messages']))[0]) <= context+1:
                seen.add(identifier); short.append(row)
    chat=data/'improved-chat.jsonl'; write_jsonl(chat,short)
    print(json.dumps({'languageConversations':len(read_jsonl(language)),
                      'completeChatConversations':len(short),'contextBytes':context}),flush=True)
    if len(short)<100: raise ValueError('Too few complete short conversations')
    return language,chat

def run_stage(data, output, resume, objective, steps, batch, max_validation=256):
    """Retry CUDA memory exhaustion with smaller batches, preserving saved updates."""
    import gc
    import torch
    while True:
        print(json.dumps({'trainingStage':objective,'batch':batch,'additionalSteps':steps,
                          'resume':str(resume),'output':str(output),'mixedPrecision':True}),flush=True)
        try:
            result=train(SimpleNamespace(data=data,output=output,resume=resume,preset='cpu-large',
                snapshot=None,steps=steps,batch=batch,threads=2,seed=42,lr=.0001,
                continuous=False,save_every=250,patience=8,device='cuda',amp=True,
                objective=objective,grouped_split=True,bucketed=True,max_validation=max_validation))
        except torch.cuda.OutOfMemoryError:
            if batch == 1: raise
        else: return result
        # This code runs outside the exception block so traceback tensors can be freed.
        batch=max(1,batch//2); gc.collect(); torch.cuda.empty_cache()
        if Path(output).exists(): resume=output
        # Retry a bounded budget after memory failure, rather than endlessly looping.
        print(json.dumps({'gpuMemoryRetry':True,'smallerBatch':batch}),flush=True)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--resume',type=Path,required=True)
    parser.add_argument('--stories',type=int,default=10000)
    parser.add_argument('--language-steps',type=int,default=6000)
    parser.add_argument('--chat-steps',type=int,default=3000)
    parser.add_argument('--batch',type=int,default=16)
    args=parser.parse_args(argv)
    if min(args.batch,args.language_steps,args.chat_steps)<1: parser.error('Positive batches and steps required')
    import os
    import torch
    if not torch.cuda.is_available(): raise RuntimeError('Select a GPU runtime before training')
    os.chdir(args.project)
    model,_=load(args.resume); context=model.config.context; del model
    story_path=download_stories(args.project/'model/data',args.stories)
    language,chat=prepare_curriculum(args.project,story_path,context)
    checkpoints=args.project/'model/checkpoints'; checkpoints.mkdir(parents=True,exist_ok=True)
    for stage,data,steps,objective in [('language',language,args.language_steps,'language'),
                                       ('chat',chat,args.chat_steps,'assistant')]:
        output=checkpoints/f'improved-{stage}.pt'; marker=checkpoints/f'improved-{stage}.done.json'
        data_hash=hashlib.sha256(data.read_bytes()).hexdigest()
        done=json.loads(marker.read_text()) if marker.exists() else None
        best=output.with_suffix('.best.pt')
        if done and done.get('dataSha256')==data_hash and best.exists():
            args.resume=best; continue
        resume=output if output.exists() else args.resume
        result=run_stage(data,output,resume,objective,steps,args.batch)
        if result.get('reason')=='non_finite_loss_or_gradient' or result.get('stopped') and result.get('reason')!='validation_not_improving':
            print('Stopped. Checkpoints preserved; the next stage was not started.',flush=True)
            return
        if not best.exists(): raise RuntimeError('No best checkpoint was saved; inspect validation output')
        marker.write_text(json.dumps({'dataSha256':data_hash,'report':result}),encoding='utf-8')
        args.resume=best
    print('Finished language and chat stages. Test improved-chat.best.pt before deployment.',flush=True)

if __name__=='__main__': main()
