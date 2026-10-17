"""V3: simple-language rehearsal, varied short tasks, and resumable GPU stages."""
import argparse
import hashlib
import json
import random
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

import torch
from dataflow import eligible,example_id,prepare,read_jsonl,write_jsonl
from nebula import encode,load
from rules import with_owner_rules
from train import train

def curriculum():
    """Original, exact-answer tasks with varied wording and bounded difficulty."""
    rows=[]; seen=set()
    def add(messages,group=None):
        identifier=example_id(messages)
        if identifier in seen: return
        seen.add(identifier)
        row={'id':identifier,'reviewStatus':'approved','source':{'kind':'seed','curriculum':'nebula-v3'},'messages':messages}
        if group: row['splitGroup']=group
        rows.append(row)
    def pair(q,a,group=None):
        add([{'role':'user','content':q},{'role':'assistant','content':a}],group)
    identities=['Introduce yourself.','Who am I speaking with?','Tell me who you are.',
                'What should I call you?','Please introduce yourself briefly.','Which assistant are you?',
                'Say your name.','Do you have a name?','Could you introduce yourself?',
                'Identify yourself.','What do people call you?','Who is helping me?']
    for question in identities: pair(question,'I am Nebula AI.')
    for question in ['Hello there!','Good morning!','Hey Nebula!','Hello, can we talk?',
                     'Good evening!','Hi there, Nebula.','Hey, are you there?','Greetings!']:
        pair(question,'Hello! How can I help you?')
    for question in ['Could you help me draft a message?','I need to write a note.',
                     'Help me write an email please.','Can we draft an email together?']:
        pair(question,'Yes. Who is it for, and what would you like to say?')
    for question in ['What if you do not know an answer?','Are your answers always right?',
                     'Can you make mistakes?','Will you admit when you are unsure?']:
        pair(question,'I can make mistakes. I should tell you when I am unsure.')
    # Hold out whole name families: no alternate wording for a held-out person's
    # scenario is allowed into training. These names differ from the old test Sam.
    names=['Alice','Amir','Bella','Cleo','Diego','Ella','Felix','Grace','Hana','Idris',
           'Jade','Kai','Leah','Luis','Mila','Nadia','Oscar','Priya','Quinn','Ravi',
           'Sara','Theo','Uma','Vera','Will','Xena','Yara','Zane','Ada','Eli',
           'Flora','Hugo','Ines','Jules','Kira','Luca','Mina','Owen','Rosa','Silas']
    colors=['red','green','blue','yellow','purple','orange']
    for i,name in enumerate(names):
        group='v3-person-'+name
        for question in [f'My name is {name}. Please repeat it.',
                         f'Please call me {name}. What should you call me?',
                         f'I am {name}. Which name did I give you?']:
            pair(question,f'Your name is {name}.',group)
        for color in colors:
            pair(f'{name} has a {color} bag. What color is the bag?',f'The bag is {color}.',group)
            pair(f'The ball is {color}. Tell me its color.',f'The ball is {color}.','v3-color-'+color)
            add([{'role':'user','content':f'Please call me {name}.'},
                 {'role':'assistant','content':f'Nice to meet you, {name}.'},
                 {'role':'user','content':f'My favorite color is {color}.'},
                 {'role':'assistant','content':f'I will keep that in mind in this conversation.'},
                 {'role':'user','content':'Which name and favorite color did I tell you?'},
                 {'role':'assistant','content':f'Your name is {name}, and your favorite color is {color}.'}],group)
        for animal in ['cat','dog','bird','fish']:
            pair(f'{name} has a pet {animal}. What pet does {name} have?',f'{name} has a {animal}.',group)
    rng=random.Random(20261017)
    operands=[(a,b) for a in range(31) for b in range(31)]
    rng.shuffle(operands)
    for i,(a,b) in enumerate(operands[:300]):
        group=f'v3-add-{min(a,b)}-{max(a,b)}'
        for question in [f'Calculate {a} + {b}.',f'Add {a} and {b}.',
                         f'I have {a} marbles and get {b} more. How many marbles do I have?']:
            pair(question,f'{a} + {b} = {a+b}.',group)
    facts=[('What does a plant need to grow?','Most plants need light, water, air, and nutrients.'),
           ('What is a noun?','A noun names a person, place, thing, or idea.'),
           ('What is a verb?','A verb describes an action or a state.'),
           ('What is ice made of?','Ice is frozen water.'),
           ('What happens when ice gets warm?','Ice melts into liquid water.'),
           ('Why do people need sleep?','Sleep helps the body and brain rest and recover.'),
           ('What is a sentence?','A sentence is a group of words that expresses a complete thought.'),
           ('How can I write a polite request?','Say what you need clearly and use polite words such as please.'),
           ('What can I do if a task feels too big?','Break it into smaller steps and start with one step.'),
           ('How can I check an answer?','Compare it with a reliable source or work through the steps again.')]
    for question,answer in facts: pair(question,answer)
    return rows

def datasets(project):
    data=Path(project)/'model/data'
    own=data/'v3-foundations.jsonl'; write_jsonl(own,curriculum())
    # The old language mix was dominated by long, complex instructions.
    # Rehearse simpler stories and complete short dialogues instead.
    dialogue=[]
    for row in read_jsonl(data/'improved-chat.jsonl'):
        if row.get('source',{}).get('curriculum')=='nebula-foundations-v1': continue
        if eligible(row) and len(encode(with_owner_rules(row['messages']))[0])<=1025:
            dialogue.append(row)
    conversations=data/'v3-conversations.jsonl'; write_jsonl(conversations,dialogue)
    language=data/'v3-language.jsonl'; chat=data/'v3-chat.jsonl'
    # Do not put the arithmetic curriculum into language rehearsal. It belongs
    # to the second stage; basic language gets the larger training budget.
    prepare([data/'stories-approved.jsonl',conversations],language)
    prepare([conversations,own],chat)
    print(json.dumps({'v3LanguageConversations':len(read_jsonl(language)),
                      'v3ChatConversations':len(read_jsonl(chat)),
                      'newOriginalExercises':len(curriculum()),'downloadsNeeded':False}),flush=True)
    return language,chat

def backup_data(project):
    """One downloadable data file, with checksums; no archive or credentials."""
    project=Path(project); entries={}; hashes={}
    names=['model/data/stories-approved.jsonl','model/data/improved-chat.jsonl',
           'model/data/v3-language.jsonl','model/data/v3-chat.jsonl',
           'model/data/v3-foundations.jsonl','model/data/v3-conversations.jsonl',
           'model/data/stories-sources.json','model/data/public-sources.json',
           'model/DATA_SOURCES.md','nebula-rules.json']
    for name in names:
        path=project/name
        if not path.exists(): continue
        raw=path.read_bytes(); hashes[name]=hashlib.sha256(raw).hexdigest()
        entries[name]=torch.frombuffer(bytearray(zlib.compress(raw)),dtype=torch.uint8)
    destination=project/'Nebula_V3_Data.pt'
    temporary=destination.with_suffix('.tmp')
    torch.save({'format':'nebula-v3-data-1','compression':'zlib','files':entries,'sha256':hashes},temporary)
    temporary.replace(destination)
    return destination

def compare(checkpoints,project,label):
    """Print actual replies on different questions; never fabricate a quality score."""
    prompts=['Hello Nebula, who are you?',
             'Calculate 13 + 9.',
             'Please call me Talia. Which name did I give you?',
             'Marta has a silver key. What color is her key?',
             'Please write a polite, short thank-you note.',
             'Tell a simple story about a lost puppy.']
    reports=[]
    for path in checkpoints:
        model,metadata=load(path); model.cuda()
        for prompt in prompts:
            answer=model.reply(with_owner_rules([{'role':'user','content':prompt}]),max_tokens=180,temperature=0)
            row={'comparison':label,'checkpoint':str(path),'steps':metadata.get('steps'),
                 'prompt':prompt,'reply':answer}
            print(json.dumps(row),flush=True); reports.append(row)
        del model; torch.cuda.empty_cache()
    target=Path(project)/'model/checkpoints'/f'{label}-replies.json'
    target.write_text(json.dumps(reports,indent=2),encoding='utf-8')

def main(argv=None,on_data_ready=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--hours',type=float,default=8)
    parser.add_argument('--batch',type=int,default=16)
    args=parser.parse_args(argv)
    if not 0<args.hours<=12 or args.batch<1: parser.error('Use 0-12 hours and a positive batch size')
    if not torch.cuda.is_available(): raise RuntimeError('A GPU runtime is required')
    project=args.project; checkpoints=project/'model/checkpoints'
    language,chat=datasets(project)
    if on_data_ready:
        backup=backup_data(project)
        try: on_data_ready(backup)
        except Exception as error:
            print(json.dumps({'dataBackupDownloadFailed':type(error).__name__,
                              'downloadManually':str(backup)}),flush=True)
    deadline=time.monotonic()+args.hours*3600
    # Preserve and inspect both previous stages. Continue language from its own
    # best weights, rather than repeatedly undoing the latest chat tuning.
    if not (checkpoints/'v3-baseline-replies.json').exists():
        compare([checkpoints/'previous-language.best.pt',checkpoints/'previous-chat.best.pt'],project,'v3-baseline')
    resume=checkpoints/'previous-language.best.pt'
    plan=[('language',language,20000,'language',.0001,deadline-args.hours*3600*.25),
          ('chat',chat,8000,'assistant',.00005,deadline)]
    for stage,data,limit,objective,lr,stage_deadline in plan:
        output=checkpoints/f'v3-{stage}.pt'; best=output.with_suffix('.best.pt')
        marker=output.with_suffix('.done.json')
        if marker.exists() and best.exists(): resume=best; continue
        done=0
        if output.exists():
            resume=output
            _,meta=load(output); done=meta.get('stageSteps',0)
        remaining=limit-done; seconds=stage_deadline-time.monotonic()
        if remaining<=0:
            if not best.exists(): raise RuntimeError('Best checkpoint missing')
            resume=best; continue
        if seconds<=0:
            print('Time budget reached. Saved checkpoints remain available.',flush=True)
            return
        batch=args.batch
        while True:
            print(json.dumps({'v3Stage':stage,'resume':str(resume),'additionalSteps':remaining,
                              'batch':batch,'maximumSeconds':round(seconds),'saveEvery':200}),flush=True)
            try:
                result=train(SimpleNamespace(data=data,output=output,resume=resume,snapshot=None,
                    steps=remaining,batch=batch,threads=2,seed=42,lr=lr,preset='cpu-large',
                    continuous=False,save_every=200,patience=10,device='cuda',amp=True,
                    objective=objective,grouped_split=True,bucketed=True,max_validation=256,
                    save_training_state=True,max_seconds=seconds))
            except torch.cuda.OutOfMemoryError:
                if batch==1: raise
            else: break
            import gc
            batch=max(1,batch//2); gc.collect(); torch.cuda.empty_cache()
            if output.exists(): resume=output
            seconds=stage_deadline-time.monotonic()
            if seconds<=0: return
        reason=result.get('reason')
        if result.get('stopped') and reason not in ['validation_not_improving','time_limit']:
            print('Stopped safely. Next stage was not started.',flush=True); return
        if not best.exists(): raise RuntimeError('No validated checkpoint saved')
        marker.write_text(json.dumps(result),encoding='utf-8')
        resume=best
        compare([best],project,f'v3-{stage}')
        if time.monotonic()>=deadline: break
    print('V3 run finished. Inspect v3-chat-replies.json and keep your previous model for comparison.',flush=True)

if __name__=='__main__': main()
