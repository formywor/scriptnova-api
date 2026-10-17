"""Broader owned exercises, bounded public additions, and frozen diagnostics."""
import hashlib
import json
from pathlib import Path
import random
import re
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from nebula import encode
from public_data import SOURCES,convert,fetch_page
from research_eval import CASES
from rules import with_owner_rules

VERSION='nebula-v4-1'
def digest(text):return hashlib.sha256(text.encode()).hexdigest()
def held(group):return int(digest(VERSION+':'+group)[:8],16)%10==0
RESERVED={name.casefold() for name in CASES['reservedNames']}
LOCKED_PAIRS={(37,48),(46,17),(58,29),(64,27)}

def exercises():
    rows=[];checks=[];seen=set()
    def add(q,a,group,category,expected=None,number=None,messages=None):
        messages=messages or [{'role':'user','content':q},{'role':'assistant','content':a}]
        identifier=example_id(messages)
        if identifier in seen:return
        seen.add(identifier)
        if held(group):
            case={'category':category,'messages':messages[:-1],'group':group}
            if expected is not None:case['expected']=expected
            if number is not None:case['number']=number
            checks.append(case)
        else:
            rows.append({'id':identifier,'reviewStatus':'approved','splitGroup':group,
                         'source':{'kind':'seed','curriculum':VERSION},'messages':messages})
    identities=['Who are you?','What is your name?','Introduce yourself.',
        'Which assistant am I chatting with?','What should I call this assistant?',
        'Tell me the name of this AI.','Can you tell me who you are?',
        'Name the assistant in this conversation.','How do you introduce yourself?',
        'What name do you use?','Who is answering my questions?',
        'Tell me your identity.','What is the assistant called?',
        'Please give your name.','Who am I speaking to?','What do people call you?',
        'Say the name you go by.','Identify yourself briefly.',
        'Can you introduce the assistant?','Tell me which AI this is.']
    for i,question in enumerate(identities):
        for prefix in ['', 'Hello. ', 'Hi there! ', 'Before we begin, ', 'Quick question: ']:
            for suffix in ['', ' Keep it short.', ' Please answer briefly.', ' One sentence is enough.']:
                add(prefix+question+suffix,'I am Nebula AI.','identity-'+str(i),'identity',expected='Nebula')
    rng=random.Random(20261017)
    syllables=['ba','be','bi','bo','bu','ca','ce','ci','co','cu','da','de','di','do','du',
               'fa','fe','fi','fo','fu','ga','ge','gi','go','gu','ha','he','hi','ho','hu',
               'ja','je','ji','jo','ju','ka','ke','ki','ko','ku','la','le','li','lo','lu',
               'ma','me','mi','mo','mu','na','ne','ni','no','nu','pa','pe','pi','po','pu',
               'ra','re','ri','ro','ru','sa','se','si','so','su','ta','te','ti','to','tu',
               'va','ve','vi','vo','vu','za','ze','zi','zo','zu']
    names=set()
    while len(names)<1200:
        name=''.join(rng.choice(syllables) for _ in range(rng.randint(2,5))).capitalize()
        if not any(reserved in name.casefold() for reserved in RESERVED):names.add(name)
    for name in sorted(names):
        group='name-'+name
        for q in [f'My name is {name}. What is my name?',f'Call me {name}. Repeat my name.',
                  f'I am {name}. Say my name back to me.',f'Remember this name: {name}. Which name did I say?',
                  f'Please address me as {name}. How should you address me?']:
            add(q,f'Your name is {name}.',group,'memory',expected=name)
        messages=[{'role':'user','content':f'My name is {name}.'},
                  {'role':'assistant','content':f'Hello, {name}.'},
                  {'role':'user','content':'What name did I give you?'},
                  {'role':'assistant','content':f'Your name is {name}.'}]
        add(None,None,group,'memory',expected=name,messages=messages)
    # Whole operand pairs are held out, including every wording for those pairs.
    pairs=[(a,b) for a in range(100) for b in range(100) if (a,b) not in LOCKED_PAIRS and (b,a) not in LOCKED_PAIRS]
    rng.shuffle(pairs)
    for a,b in pairs[:5000]:
        group=f'addition-{min(a,b)}-{max(a,b)}'
        for q in [f'What is {a} + {b}?',f'Add {a} and {b}.',f'Calculate the sum of {a} and {b}.']:
            add(q,f'{a} + {b} = {a+b}.',group,'math',number=a+b)
    colors=['red','green','blue','yellow','purple','orange','pink','white','black','gray',
            'silver','gold','brown','cyan','magenta','violet','indigo','navy','maroon','lime']
    objects=['kite','cup','hat','shoe','chair','table','button','basket','bottle','book',
             'jacket','flower','car','train','door','gate','plate','mug','pencil','lamp',
             'scarf','sock','coat','bicycle','boat','balloon','flag','bead','stone','shell']
    for item in objects:
        for color in colors:
            group=f'color-{item}-{color}'
            for q in [f'The {item} is {color}. What color is it?',
                      f'I have a {color} {item}. Tell me its color.',
                      f'Look at the {item}: it is {color}. Repeat its color.']:
                add(q,f'The {item} is {color}.',group,'extraction',expected=color)
    # Also practice exact unfamiliar strings, rather than a fixed vocabulary of names.
    for index in range(800):
        word=''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(rng.randint(2,12)))
        if any(name in word for name in RESERVED):continue
        add(f'Repeat this word exactly: {word}',word,'copy-'+word,'memory',expected=word)
    for i,(q,a) in enumerate([
        ('Hi','Hello! How can I help you?'),('Hello','Hello! How can I help you?'),
        ('Can you help me write an email?','Yes. Who is it for, and what would you like to say?'),
        ('I need help.','What would you like help with?'),
        ('What if you do not know?','I can say I am unsure and ask for more information.'),
        ('Do you make mistakes?','Yes. Please check important answers.'),
        ('Thanks!','You are welcome!')]):
        for prefix in ['', 'Hey, ', 'Hi there. ']:
            add(prefix+q,a,'small-chat-'+str(i),'chat',expected=None)
    # Check cases without exact validators are qualitative only, not used for selection.
    checks=[case for case in checks if 'expected' in case or 'number' in case]
    return rows,checks

def benchmark(checks):
    rng=random.Random(49317);result=[]
    for category,limit in [('identity',8),('math',20),('memory',16),('extraction',12)]:
        pool=[case for case in checks if case['category']==category]
        # Use one prompt per held-out scenario in the scored benchmark.
        by_group={case['group']:case for case in pool}
        # Identity has few distinct phrase families; allow several variants there.
        pool=list(by_group.values()) if category!='identity' else pool
        result.extend(rng.sample(pool,min(limit,len(pool))))
    return {'benchmark':VERSION,'cases':CASES['cases']+result,'legacyCaseCount':len(CASES['cases'])}

def blocked_questions(checks):
    blocked_questions={m['content'].casefold() for case in CASES['cases'] for m in case.get('messages',[{'role':'user','content':case.get('prompt','')}]) if m['role']=='user'}
    blocked_questions.update(m['content'].casefold() for case in checks for m in case.get('messages',[]) if m['role']=='user')
    return blocked_questions

def forbidden(row,checks,blocked=None):
    text=' '.join(m['content'].casefold() for m in row['messages'])
    if any(name in text for name in RESERVED):return True
    blocked=blocked_questions(checks) if blocked is None else blocked
    if any(m['content'].casefold() in blocked for m in row['messages'] if m['role']=='user'):return True
    # Avoid legacy public/teacher paraphrases of held arithmetic/name facts.
    for message in row['messages'][::2]:
        nums=re.findall(r'\b\d+\b',message['content'])
        if len(nums)==2:
            a,b=map(int,nums);group=f'addition-{min(a,b)}-{max(a,b)}'
            if (a,b) in LOCKED_PAIRS or (b,a) in LOCKED_PAIRS or held(group):return True
    return False

def public_additions(directory,limit=1000,transport=None):
    directory=Path(directory);source=SOURCES['magpie'];rows=[]
    for offset in range(5000,5000+limit,100):
        try:page=fetch_page(source,offset,min(100,5000+limit-offset),directory/'cache',transport)
        except Exception:
            print(json.dumps({'publicDownloadDeferred':True,'cachedAndOwnedDataStillAvailable':True}),flush=True);break
        for entry in page['rows']:
            if entry.get('truncated_cells'):continue
            row=convert(entry.get('row',{}),source,entry.get('row_idx',offset))
            if row:rows.append(row)
        print(json.dumps({'publicRowsScannedThrough':offset+len(page['rows'])}),flush=True)
    return rows

def prepare(project,extra_public=None):
    project=Path(project);directory=project/'model/data';directory.mkdir(parents=True,exist_ok=True)
    own,held_cases=exercises();cases=benchmark(held_cases)
    checks_path=directory/'v4-checks.json';checks_path.write_text(json.dumps(cases,indent=2),encoding='utf-8')
    rows=[];seen=set();counts={};max_bytes=0;blocked=blocked_questions(held_cases)
    def keep(row):
        nonlocal max_bytes
        if not eligible(row) or forbidden(row,held_cases,blocked):return
        size=len(encode(with_owner_rules(row['messages']))[0])
        if size>1024:return
        identifier=example_id(row['messages'])
        if identifier in seen:return
        seen.add(identifier);rows.append({**row,'id':identifier});max_bytes=max(max_bytes,size)
        category=row.get('source',{}).get('curriculum',row['source']['kind'])
        counts[category]=counts.get(category,0)+1
    for row in own:keep(row)
    legacy=directory/'v3-chat.jsonl'
    for row in (read_jsonl(legacy) if legacy.exists() else [])+(extra_public or []):
        # Rehearse complete short public/teacher turns; do not copy raw user chats.
        if row.get('source',{}).get('kind') not in ['public','teacher']:continue
        for i in range(0,len(row['messages'])-1,2):
            pair=row['messages'][i:i+2]
            if len(pair[0]['content'].encode())>240 or len(pair[1]['content'].encode())>400:continue
            value={**row,'messages':pair,'splitGroup':'source-'+str(row['source'].get('recordId',row.get('id','')))}
            keep(value)
    data=directory/'v4-chat.jsonl';write_jsonl(data,rows)
    manifest={'version':VERSION,'conversations':len(rows),'counts':counts,'maximumContextBytes':max_bytes,
              'dataSha256':hashlib.sha256(data.read_bytes()).hexdigest(),'diagnosticCases':len(cases['cases']),
              'checksSha256':hashlib.sha256(checks_path.read_bytes()).hexdigest(),
              'sources':[{'dataset':'HuggingFaceTB/smoltalk','subset':'smol-magpie-ultra','license':'apache-2.0','url':'https://huggingface.co/datasets/HuggingFaceTB/smoltalk'},
                         {'dataset':'HuggingFaceTB/everyday-conversations-llama3.1-2k','license':'apache-2.0'},
                         {'kind':'original verified exercises','version':VERSION}],
              'note':'Public/teacher replies are structurally filtered, not independently verified. Owned arithmetic and copying targets are generated exactly. Legacy weights cannot be decontaminated retroactively.'}
    (directory/'v4-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'v4Data':manifest}),flush=True)
    return data,checks_path,manifest
