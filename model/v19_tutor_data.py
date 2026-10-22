"""Original, deterministic tutor lessons; benchmark prompts never enter practice."""
import hashlib
import json
import random
import re
from collections import Counter

import torch
from nebula import encode,PAD

SYSTEM={'role':'system','content':'You are Nebula AI.'}
NAMES=['Ada','Ben','Cleo','Dario','Evan','Faye','Hugo','Mina','Noah','Omar','Rosa','Tess']
COLORS=['red','blue','green','white','black','yellow','pink','gold']
NEW_NAMES=['Iris','Juno','Kai','Lina','Talia','Marta']
NEW_COLORS=['purple','orange','silver','brown']
MEANINGS=[('cold','having a low temperature','The water is cold.'),
 ('hot','having a high temperature','The soup is hot.'),
 ('empty','containing nothing','The cup is empty.'),('full','filled to capacity','The cup is full.'),
 ('quiet','making little noise','The room is quiet.'),('loud','making a lot of noise','The music is loud.'),
 ('wet','covered with water','The towel is wet.'),('dry','not wet','The towel is dry.'),
 ('before','earlier than','Breakfast comes before lunch.'),('after','later than','Dinner comes after lunch.'),
 ('above','higher than','The lamp is above the table.'),('below','lower than','The floor is below the table.'),
 ('near','not far away','The chair is near the desk.'),('far','a long distance away','The town is far away.'),
 ('borrow','use something temporarily and return it','I borrow a book and return it.'),
 ('return','give something back','I return the book to its owner.')]
FACTS=[('Why does ice melt?','Ice melts when it absorbs enough heat to change from solid water to liquid water.'),
 ('What is ice?','Ice is water in its solid form.'),
 ('What do roots do for a plant?','Roots take in water and help hold the plant in the ground.'),
 ('Why do we use an umbrella?','An umbrella can help keep rain off us.'),
 ('What does a thermometer measure?','A thermometer measures temperature.'),
 ('What is a sentence?','A sentence is a group of words that expresses a complete thought.'),
 ('What is a question?','A question asks for information.'),
 ('What is a noun?','A noun names a person, place, thing, or idea.'),
 ('What is a verb?','A verb can describe an action or a state.'),
 ('What does a map show?','A map shows where places are and how they are arranged.'),
 ('Why should we check an answer?','Checking can help us find and correct mistakes.'),
 ('What should you do if a question is unclear?','Ask a question to find out what the person means.')]
CHATS=[('Hello!','Hello! How can I help?'),('Hi there.','Hi! What would you like to work on?'),
 ('What is your name?','I am Nebula AI.'),('Who are you?','I am Nebula AI, an AI assistant.'),
 ('Can you help me write an email?','Yes. Who is the email for, and what would you like it to say?'),
 ('Which should I choose?','What options are you choosing between, and what matters most to you?'),
 ('Can you explain this?','What would you like me to explain?'),
 ('Help me plan something.','What are you planning, and when does it need to happen?'),
 ('Thank you for helping.','You are welcome!'),('I made a mistake.','We can work through it. What happened?'),
 ('I do not understand the question.','Share the question, and we can break it into smaller parts.'),
 ('Tell me a short story.','A child found a lost dog near the park. She checked its tag and helped it get home.'),
 ('Write a short thank-you note to a neighbor.','Thank you for your help. I appreciate your kindness and am glad we are neighbors.'),
 ('Can you read my mind?','No. I only know what is available in the conversation and any information provided to me.'),
 ('What is inside my closed box?','I do not know. Can you describe what is inside it?'),
 ('Can you be certain without enough information?','No. I should explain what is uncertain and ask for the missing information.')]


def pair(question,answer):return [dict(SYSTEM),{'role':'user','content':question},{'role':'assistant','content':answer}]
def key(messages):return hashlib.sha256(json.dumps(messages,sort_keys=True).encode()).hexdigest()
def norm(text):return ' '.join(text.casefold().split())


def benchmarks(seed=190221):
    rng=random.Random(seed);cases=[]
    def add(axis,messages,expected):cases.append({'axis':axis,'messages':messages,'expected':str(expected)})
    for i in range(12):
        name=NEW_NAMES[i%6];color=NEW_COLORS[i%4]
        ask='name' if i%2==0 else 'color'
        fields=[f'Name = {name}',f'Scarf color = {color}',f'Number = {21+i}'];rng.shuffle(fields)
        q='; '.join(fields)+f'. Read this record and return the {ask} alone.'
        add('new-values',pair(q,'')[:-1],name if ask=='name' else color)
    for i in range(12):
        name=NAMES[i];color=COLORS[(i*3)%len(COLORS)];ask='name' if i%2==0 else 'color'
        q=f'The person is {name}; their scarf is {color}. Extract just the '+('person\'s name.' if ask=='name' else 'scarf color.')
        add('new-wording',pair(q,'')[:-1],name if ask=='name' else color)
    for i in range(16):
        name=NEW_NAMES[i%6];old=COLORS[i%8];new=NEW_COLORS[i%4];ask_name=i%4==0
        messages=pair(f'My name is {name}. My scarf is {old}.',f'Your name is {name}, and your scarf is {old}.')
        messages.extend([{'role':'user','content':f'Update: my scarf is now {new}, not {old}.'},
                         {'role':'assistant','content':'Understood. I will use the updated color.'},
                         {'role':'user','content':'Give only '+('my name.' if ask_name else 'the current scarf color.')}])
        add('updated-multi-turn',messages,name if ask_name else new)
    for i in range(8):
        a=NEW_NAMES[i%6];b=NEW_COLORS[i%4];c=str(31+i)
        add('instruction',pair(f'Items in order: {a}, {b}, {c}. Return only the final item.','')[:-1],c)
    for i in range(8):
        a=17+i;b=3+i
        add('arithmetic',pair(f'Calculate {a} + {b}. Output the number alone.','')[:-1],a+b)
    for word,definition,_ in MEANINGS[:8]:
        add('meaning',pair(f'Which word means "{definition}"? Return one word.','')[:-1],word)
    return cases


def lessons(seed=190221,dynamic=1600):
    rng=random.Random(seed);rows=[];seen=set();tests=benchmarks(seed)
    banned={norm(m['content']) for c in tests for m in c['messages'] if m['role']=='user'}
    def add(family,messages):
        identifier=key(messages)
        if identifier in seen or any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        seen.add(identifier);rows.append({'family':family,'messages':messages,'id':identifier,'origin':'original-synthetic-tutor'})
    for word,definition,sentence in MEANINGS:
        for question,answer in [(f'What does {word} mean?',f'{word.capitalize()} means {definition}.'),
          (f'Explain the word "{word}" and use it in a sentence.',f'It means {definition}. For example: {sentence}'),
          (f'Give a sentence using {word}.',sentence),
          (f'Explain this sentence: {sentence}',f'The word "{word}" means {definition} here.')]:
            add('meaning',pair(question,answer))
    for question,answer in FACTS:
        for lead in ['', 'Please explain simply: ', 'Help me understand: ']:add('explanation',pair(lead+question,answer))
    for question,answer in CHATS:
        for lead in ['', 'Please help. ']:add('conversation',pair(lead+question,answer))
    for i in range(dynamic):
        name=rng.choice(NAMES);color=rng.choice(COLORS);old=rng.choice([c for c in COLORS if c!=color]);number=rng.randrange(21)
        family=i%5
        if family==0:
            ask=rng.choice(['name','color','number']);fields=[f'Name: {name}',f'Color: {color}',f'Number: {number}'];rng.shuffle(fields)
            instruction=rng.choice([f'Reply with only the {ask}.',f'What is the {ask}? Give only its value.',f'Find the {ask}. Answer with its value only.'])
            answer={'name':name,'color':color,'number':str(number)}[ask]
            add('context',pair('. '.join(fields)+'. '+instruction,answer))
        elif family==1:
            messages=pair(f'I am {name}. My scarf is {old}.',f'Hello, {name}. Your scarf is {old}.')
            ask_name=rng.randrange(4)==0
            if rng.randrange(2):
                messages.extend([{'role':'user','content':f'My scarf is {color} now.'},
                                 {'role':'assistant','content':f'Your current scarf color is {color}.'}])
            else:color=old
            q='What is my name?' if ask_name else 'What color is my scarf now?'
            answer=name if ask_name else color
            if rng.randrange(2):q+=' Reply with just the answer.'
            else:answer=f'Your name is {name}.' if ask_name else f'Your scarf is {color}.'
            messages.extend([{'role':'user','content':q},{'role':'assistant','content':answer}]);add('multi-turn',messages)
        elif family==2:
            kind=rng.randrange(3)
            if kind==0:q=f'Fix capitalization and punctuation: i like {color}';a=f'I like {color}.'
            elif kind==1:q=f'Return only the last word in: {name} {color} {number}';a=str(number)
            else:q=f'Put these on separate lines, without adding words: {name}, {color}, {number}';a=f'{name}\n{color}\n{number}'
            add('instruction',pair(q,a))
        elif family==3:
            a=rng.randrange(16);b=rng.randrange(16);op=rng.choice(['+','-'])
            if op=='-':a,b=max(a,b),min(a,b)
            answer=a+b if op=='+' else a-b
            q=rng.choice([f'What is {a} {op} {b}?',f'Work out {a} {op} {b}.'])
            if rng.randrange(2):q+=' Give only the number.';reply=str(answer)
            else:reply=f'{a} {op} {b} = {answer}.'
            add('arithmetic',pair(q,reply))
        else:
            attribute=rng.choice(['empty','full','wet','dry','hot','cold']);obj=rng.choice(['cup','bowl','glass'])
            yes=rng.randrange(2)==0
            properties={'empty':('contains nothing','contains something'),'full':('is filled to the top','contains nothing'),
                        'wet':('has water on it','has no water on it'),'dry':('has no water on it','has water on it'),
                        'hot':('has a high temperature','has a low temperature'),'cold':('has a low temperature','has a high temperature')}
            statement=properties[attribute][0 if yes else 1]
            q=f'{name} has a {obj} that {statement}. Is the {obj} {attribute}?'
            if rng.randrange(2):q+=' Reply yes or no.';a='Yes' if yes else 'No'
            else:a=('Yes' if yes else 'No')+f'. The {obj} {statement}.'
            add('application',pair(q,a))
    # Practice is sampled equally by family, so a large template family cannot dominate updates.
    counts=dict(Counter(r['family'] for r in rows))
    return rows,tests,{'examples':len(rows),'familyExamples':counts,'practiceSampling':'equal probability per family',
        'trainingNames':NAMES,'trainingColors':COLORS,'benchmarkOnlyNames':NEW_NAMES,'benchmarkOnlyColors':NEW_COLORS,
        'heldoutScope':'New relative to generated tutor practice, not guaranteed unseen in all historical public pretraining.',
        'benchmarkPromptsExcluded':True,'teacherCalls':0}


def window(messages,context):
    tokens,mask=encode(messages)
    if len(tokens)>context+1:raise ValueError('Tutor example exceeds context; do not truncate lessons silently')
    x=torch.tensor(tokens[:-1]);y=torch.tensor([v if learn else -100 for v,learn in zip(tokens[1:],mask[1:])])
    if not (y!=-100).any():raise ValueError('Tutor example has no assistant targets')
    return x,y


def collate(pairs):
    length=max(len(x) for x,_ in pairs)
    x=torch.full((len(pairs),length),PAD,dtype=torch.long);y=torch.full((len(pairs),length),-100,dtype=torch.long)
    for i,(a,b) in enumerate(pairs):x[i,:len(a)]=a;y[i,:len(b)]=b
    return x,y


def exact_grade(reply,expected):
    # Strict full-answer match: mentioning the right word inside an incorrect story never passes.
    return reply.strip().rstrip('.!?').strip().casefold()==expected.strip().casefold()
