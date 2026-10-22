"""Progressive paired context practice; no teacher calls or user-chat imports."""
import random
from collections import Counter
from v20_generalize_data import (lessons as previous_lessons, inventory, profile, context,
    QUESTIONS, held_math, pair, norm, key, window, collate, exact_grade, grade_content,
    benchmarks)


def lessons(seed=210221,groups=1800):
    rng=random.Random(seed);values=inventory(seed)
    old,cases,_=previous_lessons(seed,groups)
    banned={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
    rows=[];seen=set()
    def add(family,messages):
        identifier=key(messages)
        if identifier in seen or any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        seen.add(identifier)
        rows.append(dict(family=family,messages=messages,id=identifier,origin='original-synthetic-v21'))
    for row in old:
        if row['family'] in ['updates','instructions']:continue
        messages=row['messages']
        # Arithmetic gets sum supervision only: do not reward copying either operand in this family.
        if row['family']=='arithmetic':messages=messages[:3]
        add(row['family'],messages)
    for i in range(groups):
        p=profile(rng,values);fields=rng.sample(['name','color','place'],3)
        for field in fields:
            label={'name':'Name','color':'Scarf color','place':'Location'}[field]
            add('single',pair(f'{label}: {p[field]}. '+rng.choice(QUESTIONS[field])+' Only the value.',p[field]))
        text=context(rng,p)
        # Each question is trained alone AND after another, correct answer.
        first,second=fields[:2]
        for field in [first,second]:
            add('contrast',pair(text+' '+rng.choice(QUESTIONS[field])+' Only the value.',p[field]))
        messages=pair(text+' '+rng.choice(QUESTIONS[first])+' Only the value.',p[first])
        messages += [{'role':'user','content':rng.choice(QUESTIONS[second])+' Only the value.'},
                     {'role':'assistant','content':p[second]}]
        add('contrast',messages)
        # Rotate values and positions so first-item selection is not a useful shortcut.
        items=[p['name'],p['color'],p['place']];rng.shuffle(items)
        for index in range(3):
            q=rng.choice([f'List: {" / ".join(items)}. Give item {index+1} only.',
                          f'From {", ".join(items)}, return the '+['first','second','third'][index]+' item only.'])
            add('instructions',pair(q,items[index]))
        new=rng.choice([c for c in values['colors'] if c!=p['color']])
        # Identical history, independently supervised final queries; no "current color" assistant template.
        history=pair(f'My name is {p["name"]}. My scarf is {p["color"]}.','Understood.')
        history += [{'role':'user','content':f'Correction: my scarf is {new} now.'},
                    {'role':'assistant','content':'Understood.'}]
        for field,value in [('name',p['name']),('color',new)]:
            add('updates',history+[{'role':'user','content':rng.choice(QUESTIONS[field])+' Only the value.'},
                                   {'role':'assistant','content':value}])
        a=rng.randrange(31);b=rng.randrange(31)
        if not held_math(a,b):
            add('arithmetic',pair(rng.choice([f'Add {a} and {b}.',f'What is {a} + {b}?',
                f'Compute the sum of {a} and {b}.'])+' Return a number only.',str(a+b)))
    # Ordinary requests include useful follow-ups, with varied topics and user-supplied facts.
    topics=[('drawing','Choose a simple object, sketch its outline, and add a few details.'),
            ('gardening','Choose a suitable plant, check its light needs, and keep the soil appropriately moist.'),
            ('cooking','Pick an easy recipe, read it first, and prepare the ingredients.'),
            ('reading','Choose a short book that interests you and set aside a little time each day.'),
            ('writing','Choose an idea, write a short draft, and revise it for clarity.'),
            ('walking','Choose a comfortable route and begin with a short walk.'),
            ('organizing','Choose one small area, sort the items, and put away what you want to keep.'),
            ('studying','Choose one topic, review the basics, and try a short practice exercise.')]
    for topic,advice in topics:
        for ask in [f'I want to start {topic}. Can you help?',f'How can I begin {topic}?',
                    f'I am new to {topic}. Give me a simple first step.']:
            messages=pair(ask,advice)
            messages += [{'role':'user','content':'I only have ten minutes today.'},
                {'role':'assistant','content':f'Start with one small {topic} task that fits into ten minutes. You can continue another day.'}]
            add('conversation',messages)
    for ask in ['Hi!','Hello! What can you help me with?','What can you do?', 'Can you help me?']:
        add('conversation',pair(ask,'I can help explain ideas, write and edit text, make plans, and practice questions. What would you like help with?'))
    for item in ['a laptop','a book','a class','a gift','a game','a recipe','a place to visit']:
        add('conversation',pair(f'Help me choose {item}.','What options are you considering, and what matters most to you?'))
    return rows,cases,dict(examples=len(rows),familyExamples=dict(Counter(r['family'] for r in rows)),
        teacherCalls=0,benchmarkPromptsExcluded=True,heldoutScope='V21 synthetic practice only; historical public exposure unknown.',
        curriculum='0-399: single facts; 400-999: contrasting queries; 1000+: people and updates; ordinary conversation throughout',
        practiceSampling='70% tutor updates / 30% raw updates; 15% V19 replay within tutor examples',
        arithmeticOperandFollowups=False)


def curriculum(step):
    names=['copy','single','contrast','binding','entities','updates','instructions','arithmetic','meaning','conversation']
    if step<400:weights=[15,25,10,5,2,2,10,6,5,20]
    elif step<1000:weights=[8,10,22,10,8,8,10,6,5,13]
    else:weights=[5,5,15,10,15,15,10,6,5,14]
    return names,weights
