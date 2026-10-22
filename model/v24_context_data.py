"""Original, varied context practice; fixed V23 benchmark values stay held out."""
import json
import random
from collections import Counter
from nebula import encode
from v20_generalize_data import inventory, profile, pair, key, norm
from v18_foundation_control import read_source
from v23_public_chat import convert


def context_lessons(seed, cases, groups=2400, context=1024):
    rng=random.Random(seed+240024);values=inventory(seed);rows=[];seen=set()
    banned={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
    def add(messages,kind):
        identifier=key(messages)
        if identifier in seen or len(encode(messages)[0])>context+1:return
        if any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        seen.add(identifier);rows.append(dict(id=identifier,family='context/'+kind,messages=messages,
            origin='original-synthetic-v24',humanVerified=False))
    objects=['cup','bag','coat','scarf','notebook','bottle','hat','box']
    for i in range(groups):
        a=profile(rng,values);b=profile(rng,values)
        while a['name']==b['name'] or a['color']==b['color']:b=profile(rng,values)
        obj=rng.choice(objects);people=[a,b];rng.shuffle(people)
        facts=[f'{p["name"]} has a {p["color"]} {obj} in the {p["place"]}.' for p in people]
        for p in people:
            question=rng.choice([f'What color is {p["name"]}\'s {obj}?',
                f'Give the {obj} color belonging to {p["name"]}.',f'For {p["name"]}, which {obj} color was mentioned?'])
            add(pair(' '.join(facts)+' '+question+' Give only the color.',p['color']),'ownership')
            add(pair(' '.join(facts)+f' Where is {p["name"]}\'s {obj}? Reply with only the place.',p['place']),'location')
        first,second=people
        dialogue=pair(' '.join(facts)+f' Which color belongs to {first["name"]}?',first['color'])
        dialogue+=pair(f'And the {obj} owned by {second["name"]}? Give its color.',second['color'])[1:]
        add(dialogue,'multi-turn')
        updated=rng.choice([c for c in values['colors'] if c not in [a['color'],b['color']]])
        dialogue=pair(' '.join(facts),'I understand the two descriptions.')
        correction=rng.choice([f'{a["name"]}\'s {obj} is {updated} now. The other person\'s {obj} stays the same.',
            f'Correction: change only {a["name"]}\'s {obj} color to {updated}.'])
        dialogue+=pair(correction,'Thanks for the correction.')[1:]
        queries=[(a['name'],updated),(b['name'],b['color'])];rng.shuffle(queries)
        for name,color in queries:dialogue+=pair(f'What is the current color of {name}\'s {obj}? Only the color.',color)[1:]
        add(dialogue,'correction')
        fields=[('person',a['name']),('color',a['color']),('location',a['place']),('tag',a['code'])]
        rng.shuffle(fields);record='; '.join(f'{k}: {v}' for k,v in fields)
        for field,value in rng.sample(fields,2):
            add(pair(record+f'. Read the {field} field. Return its value only.',value),'field-order')
        dialogue=pair(f'My name is {a["name"]}. My {obj} is {a["color"]}.','Thanks for telling me.')
        dialogue+=pair(f'What color is my {obj}? Only the color.',a['color'])[1:]
        dialogue+=pair('Which name did I provide? Only the name.',a['name'])[1:]
        add(dialogue,'query-switch')
        # Copy arbitrary training strings rather than choosing answers from a tiny list.
        add(pair(f'The label reads "{a["code"]}". Copy the label text without quotation marks.',a['code']),'copy')
    return rows,dict(examples=len(rows),families=dict(Counter(r['family'] for r in rows)),
        templateGenerated=True,heldoutValuesExcluded=True,benchmarkPromptsExcluded=True,
        notice='Synthetic context practice; success on these templates does not establish open conversation ability.')


def prepare_public(hub,state,config,context,banned):
    """Read the saved V23 public snapshot in RAM; never train from V23 weights."""
    source,saved=read_source(config['sourceRepo'],config['publicSourceRun'],config['publicSourceRevision'],hub.token)
    if not saved.get('publicPreparation',{}).get('complete') or not saved.get('publicRows'):
        raise ValueError('Pinned V23 public preparation is not complete')
    original=json.loads(source.read_entry(saved['publicRows']))
    rows=[];excluded=Counter()
    for row in original:
        checked,reason=convert({'messages':row['messages']},context,banned)
        if reason:excluded[reason]+=1
        else:rows.append(row)
    if len(rows)<256:raise ValueError('Too few reusable public conversations')
    # Retain provenance and an immutable pointer, not duplicate data or weights.
    reference=dict(repo=config['sourceRepo'],run=config['publicSourceRun'],revision=source.revision,
        sha256=saved['publicRows']['sha256'],accepted=len(rows),excluded=dict(excluded))
    if state.get('publicReference')!=reference:
        state=hub.publish({**state,'publicReference':reference})
    return state,rows
