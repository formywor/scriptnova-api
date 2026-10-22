"""Paired questions, varied copying and fact updates; original synthetic practice."""
import hashlib
import json
import random
import re
from collections import Counter
from v19_tutor_data import pair,key,norm,window,collate,exact_grade as relaxed_word_grade,MEANINGS,FACTS,lessons as old_lessons


def exact_grade(reply,expected,case_sensitive=False):
    # Codes are identifiers: case, leading/trailing whitespace and punctuation must be preserved exactly.
    return reply==expected if case_sensitive else relaxed_word_grade(reply,expected)


def inventory(seed):
    rng=random.Random(seed)
    syllables=[a+b for a in 'bdfgklmnprstvz' for b in 'aeio']
    names=[]
    while len(names)<340:
        name=''.join(rng.choices(syllables,k=rng.randrange(2,5))).capitalize()
        if name not in names:names.append(name)
    codes=[]
    while len(codes)<1200:
        code=''.join(rng.choices('abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789',k=rng.randrange(5,13)))
        if code not in codes:codes.append(code)
    return {'names':names[:300],'heldNames':names[300:], 'codes':codes[:1100],'heldCodes':codes[1100:],
      'colors':['red','blue','green','white','black','yellow','pink','gold','purple','orange','silver','brown',
                'cyan','magenta','lime','olive','plum','amber','tan','peach','mint','violet'],
      'heldColors':['teal','maroon','beige','coral','navy','ivory'],
      'places':['kitchen','bedroom','garden','park','school','library','hall','office','shed','shop'],
      'heldPlaces':['attic','garage','balcony','basement']}


def profile(rng,values,held=False):
    return {field:rng.choice(values[('held'+keyname if held else keyname)]) for field,keyname in
            [('name','Names' if held else 'names'),('color','Colors' if held else 'colors'),
             ('code','Codes' if held else 'codes'),('place','Places' if held else 'places')]}


def context(rng,p,style=None):
    style=rng.randrange(3) if style is None else style
    if style==0:
        fields=[f'Name: {p["name"]}',f'Color: {p["color"]}',f'Code: {p["code"]}',f'Place: {p["place"]}']
        rng.shuffle(fields);return '; '.join(fields)+'.'
    if style==1:
        sentences=[f'{p["name"]} has a {p["color"]} scarf.',f'The scarf is in the {p["place"]}.',f'The label code is {p["code"]}.']
        rng.shuffle(sentences);return ' '.join(sentences)
    fields=[f'PERSON={p["name"]}',f'SCARF={p["color"]}',f'TAG={p["code"]}',f'LOCATION={p["place"]}']
    rng.shuffle(fields);return 'Record: '+' | '.join(fields)+'.'


QUESTIONS={
 'name':['What is the name?','Who is this person?','Find the person\'s name.','What name was provided?',
         'Read out the name.','Give the name from the record.'],
 'color':['What color is the scarf?','Find the scarf color.','What is the color?','Which color was given?',
          'Give the color from the record.','Read out the scarf color.'],
 'code':['What is the code?','Copy the label code.','Find the tag code.','What code was provided?',
         'Give the code from the record.','Read out the label.'],
 'place':['Where is the scarf?','What is the place?','Find the location.','Which place was given?',
          'Give the location from the record.','Read out the place.']}
TEST_QUESTIONS={'name':'Identify the person by name.','color':'Which scarf color is recorded?',
                'code':'What exact tag text belongs to this record?','place':'Identify the stored location.'}


def held_math(a,b):return int(hashlib.sha256(f'{a}+{b}'.encode()).hexdigest()[:8],16)%5==0


def benchmarks(seed):
    values=inventory(seed);rng=random.Random(seed+8501);cases=[]
    def add(axis,messages,expected,field='value'):
        cases.append({'axis':axis,'messages':messages,'expected':str(expected),'field':field})
    for i in range(12):
        value=values['heldCodes'][i]
        add('verbatim-copy',pair(f'Text inside brackets: [{value}]. Output exactly the bracket contents.','')[:-1],value,'code')
    for axis,held in [('unseen-values',True),('unseen-wording',False)]:
        for i in range(12):
            p=profile(rng,values,held);field=['name','color','code','place'][i%4]
            q=context(rng,p)+' '+TEST_QUESTIONS[field]+' Return the value and nothing else.'
            add(axis,pair(q,'')[:-1],p[field],field)
    for i in range(12):
        p=profile(rng,values,True);other=profile(rng,values)
        while other['name']==p['name']:other=profile(rng,values)
        text=f'{p["name"]} has a {p["color"]} scarf. {other["name"]} has a {other["color"]} scarf.'
        add('entity-binding',pair(text+f' State only the scarf color belonging to {p["name"]}.','')[:-1],p['color'],'color')
    for i in range(12):
        p=profile(rng,values,True);old=rng.choice(values['colors']);field='name' if i%3==0 else 'color'
        messages=pair(f'My name is {p["name"]}. My scarf is {old}.','I understand.')
        messages.extend([{'role':'user','content':f'Correction: the scarf is {p["color"]} now.'},
            {'role':'assistant','content':'I will use the updated information.'},
            {'role':'user','content':('Identify me by name.' if field=='name' else 'State the scarf color after my correction.')+' Return just the value.'}])
        add('updated-facts',messages,p[field],field)
    for i in range(12):
        p=profile(rng,values,True);items=[p['name'],p['color'],p['code']];index=i%3
        add('instruction-selection',pair('Sequence: '+' / '.join(items)+f'. Return item {index+1} alone.','')[:-1],items[index],['name','color','code'][index])
    pairs=[(a,b) for a in range(16,31) for b in range(1,31) if held_math(a,b)];rng.shuffle(pairs)
    for a,b in pairs[:12]:add('arithmetic-combinations',pair(f'Compute the sum of {a} and {b}. Return a number only.','')[:-1],a+b,'number')
    for word,definition,_ in MEANINGS[:12]:
        add('meaning-transfer',pair(f'Name the word described by this definition: {definition}. One word only.','')[:-1],word)
    return cases


def lessons(seed=200221,groups=1800):
    rng=random.Random(seed);values=inventory(seed);cases=benchmarks(seed);rows=[];seen=set()
    banned={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
    def add(family,messages,origin='original-synthetic-v20'):
        identifier=key(messages)
        if identifier in seen or any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        seen.add(identifier);rows.append({'family':family,'messages':messages,'id':identifier,'origin':origin})
    for i in range(groups):
        p=profile(rng,values);text=context(rng,p);fields=rng.sample(['name','color','code','place'],3)
        # A single context supports several different answers. Query order varies independently of field order.
        for field in fields:
            add('binding',pair(text+' '+rng.choice(QUESTIONS[field])+' Answer with only the value.',p[field]))
        messages=pair(text+' '+rng.choice(QUESTIONS[fields[0]])+' Only the value.',p[fields[0]])
        for field in fields[1:]:
            messages.extend([{'role':'user','content':rng.choice(QUESTIONS[field])+' Only the value.'},
                             {'role':'assistant','content':p[field]}])
        add('binding',messages)
        value=rng.choice([p['name'],p['code'],p['color'],str(rng.randrange(1000))])
        for q in [f'Copy exactly: {value}',f'Repeat only the text between quotes: "{value}"']:
            add('copy',pair(q,value))
        other=profile(rng,values)
        while other['name']==p['name']:other=profile(rng,values)
        text=f'{p["name"]} has a {p["color"]} scarf. {other["name"]} has a {other["color"]} scarf.'
        for person in [p,other]:
            add('entities',pair(text+f' What color is {person["name"]}\'s scarf? Reply only with the color.',person['color']))
        new=rng.choice([c for c in values['colors'] if c!=p['color']])
        messages=pair(f'I am {p["name"]}. My scarf is {p["color"]}.','Understood.')
        messages.extend([{'role':'user','content':rng.choice([f'My scarf is {new} now.',f'Change the scarf color to {new}.',f'The old color is wrong. It is {new}.'])},
                         {'role':'assistant','content':f'The current color is {new}.'},
                         {'role':'user','content':'What color is my scarf now? Answer only with the color.'},
                         {'role':'assistant','content':new},
                         {'role':'user','content':'What is my name? Reply with only the name.'},
                         {'role':'assistant','content':p['name']}])
        add('updates',messages)
        items=[p['name'],p['color'],p['code']]
        for index in range(3):
            q=rng.choice([f'Return only item {index+1} from: ',f'Give the '+['first','second','third'][index]+' value only: '])
            add('instructions',pair(q+', '.join(items),items[index]))
        a=rng.randrange(31);b=rng.randrange(31)
        if not held_math(a,b):
            q=rng.choice([f'What is {a} + {b}?',f'Add {a} and {b}.',f'Find the sum: {a} + {b}.'])+' Give only the number.'
            messages=pair(q,str(a+b))
            messages.extend([{'role':'user','content':'What was the first number? Give only that number.'},
                             {'role':'assistant','content':str(a)},
                             {'role':'user','content':'What was the second number? Give only that number.'},
                             {'role':'assistant','content':str(b)}])
            add('arithmetic',messages)
    for word,definition,sentence in MEANINGS:
        for q,a in [(f'What word means {definition}? Answer with one word.',word),
                    (f'Give only the word for this meaning: {definition}.',word),
                    (f'What does {word} mean?',f'{word.capitalize()} means {definition}.'),
                    (f'Use {word} in a sentence.',sentence)]:add('meaning',pair(q,a))
    for q,a in FACTS:
        for lead in ['', 'Explain simply: ', 'Please help me understand: ']:add('meaning',pair(lead+q,a))
    favors=['watering my plants','the book','helping me move','checking on my cat','your advice','helping with my homework']
    for name in values['names'][:100]:
        favor=rng.choice(favors)
        messages=pair(f'Write a short note to {name} thanking them for {favor}.',f'{name}, thank you for {favor}. I appreciate it.')
        messages.extend([{'role':'user','content':'Make the note shorter.'},
                         {'role':'assistant','content':f'Thank you for {favor}, {name}.'}]);add('conversation',messages)
        add('conversation',pair(f'I am choosing between {name}\'s plan and another plan. What information do you need?',
                              'What are the plans, and what matters most to you?'))
    # Retain useful V19 responses, but cap replay at 20% of tutor examples during sampling.
    old,_,_=old_lessons(190221)
    for row in old:add('replay/'+row['family'],row['messages'],'v19-practice-replay')
    return rows,cases,{'examples':len(rows),'familyExamples':dict(Counter(r['family'] for r in rows)),
        'sameContextMultipleQuestions':True,'fieldAndQueryOrderIndependent':True,
        'heldoutNames':values['heldNames'],'heldoutColors':values['heldColors'],
        'practiceSampling':'80% new curriculum / 20% V19 replay within tutor updates; copying emphasis in first 200 updates',
        'benchmarkPromptsExcluded':True,'teacherCalls':0,'holdoutScope':'Held out of V20 synthetic practice; historical public exposure is unknown.'}


def grade_content(reply,expected,field='value'):
    """Conservative full-answer parsing, never keyword containment or a semantic judge."""
    sensitive=field=='code'
    if exact_grade(reply,expected,sensitive):return {'verifiedContentCorrect':True,'strictFormatCorrect':True,'method':'exact'}
    text=reply.strip();parsed=None
    patterns={'name':[r'(?:Your|The) name is (.+?)[.!]?'],
      'color':[r'(?:Your|The) scarf is (.+?)[.!]?',r'(?:Your|The) (?:scarf color|color) is (.+?)[.!]?'],
      'code':[r'(?:Your|The) code is (.+?)[.!]?'],
      'place':[r'(?:Your|The) (?:place|location) is (.+?)[.!]?'],
      'number':[r'(?:Your|The) (?:number|sum) is (.+?)[.!]?']}
    for pattern in patterns.get(field,[])+[r'The answer is (.+?)[.!]?',r'It is (.+?)[.!]?']:
        match=re.fullmatch(pattern,text,flags=re.I)
        if match:parsed=match.group(1);break
    if parsed is not None:
        return {'verifiedContentCorrect':exact_grade(parsed,expected,sensitive),'strictFormatCorrect':False,'method':'complete-sentence-pattern'}
    if re.fullmatch(r'[A-Za-z0-9_-]+[.!]?',text):
        return {'verifiedContentCorrect':False,'strictFormatCorrect':False,'method':'wrong-single-value'}
    return {'verifiedContentCorrect':None,'strictFormatCorrect':False,'method':'pending-human-review'}
