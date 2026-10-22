"""Answer questions, acknowledge statements, and practice grounded short dialogues."""
import random
from collections import Counter
from v21_curriculum_data import lessons as previous_lessons
from v20_generalize_data import (inventory, profile, benchmarks, QUESTIONS, pair, norm, key,
    window, collate, exact_grade, grade_content, held_math)


def lessons(seed=220221,groups=1800):
    rng=random.Random(seed);values=inventory(seed);cases=benchmarks(seed)
    banned={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
    rows=[];seen=set()
    def add(family,messages,origin='original-synthetic-v22'):
        identifier=key(messages)
        if identifier in seen or any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        seen.add(identifier);rows.append(dict(family=family,messages=messages,id=identifier,origin=origin))
    # Practice that V21 learned is a minority replay source, rather than the main curriculum.
    old,_,_=previous_lessons(seed,groups)
    for row in old:add('replay/'+row['family'],row['messages'],'historical-synthetic-replay')
    asks={
        'name':['What is my name?','Which name did I give you?','Tell me my name.'],
        'color':['What color is my scarf?','Which scarf color did I mention?','Tell me the color of my scarf.'],
        'place':['Where is my scarf?','Which location did I give for the scarf?','Tell me where I put my scarf.']}
    topics=[
        ('drawing','sketch a cup','Draw the outline first, then add the handle and a few shadows.'),
        ('writing','draft a short paragraph','Choose one idea, write a few sentences, and read them back.'),
        ('reading','read a short chapter','Pick a book that interests you and read a few pages without rushing.'),
        ('organizing','clear one shelf','Take the items off, decide what to keep, and put them back neatly.'),
        ('studying','practice one topic','Review an example, try a similar question, and check your answer.'),
        ('gardening','check a plant','Read its light and watering needs before choosing where to put it.'),
        ('walking','take a short walk','Choose a comfortable route and begin at an easy pace.'),
        ('cooking','choose an easy recipe','Read the recipe first, gather the ingredients, and follow the steps.'),
        ('photography','photograph an object','Use good light, check the background, and try two different angles.'),
        ('learning a language','practice a few words','Learn their meanings, say them aloud, and use them in short sentences.'),
        ('planning','write a short task list','List what needs doing, choose a priority, and start with one task.'),
        ('editing','revise a paragraph','Check the meaning first, then improve unclear wording and spelling.')]
    for i in range(groups):
        p=profile(rng,values)
        facts=f'My name is {p["name"]}. My scarf is {p["color"]}. It is in the {p["place"]}.'
        # Identical facts with and without a query. Acknowledgment is correct ONLY for the statement.
        add('direct',pair(facts,'Thanks for telling me.'))
        for field in ['name','color','place']:
            q=rng.choice(asks[field]);answer=p[field]
            add('direct',pair(facts+' '+q,answer))
            history=pair(facts,'Thanks for telling me.')
            history += [{'role':'user','content':q},{'role':'assistant','content':answer}]
            add('direct',history)
        other=profile(rng,values)
        while other['name']==p['name'] or other['color']==p['color']:other=profile(rng,values)
        people=[p,other];rng.shuffle(people)
        record=' '.join(f'{person["name"]} has a {person["color"]} scarf.' for person in people)
        for person in people:
            q=rng.choice([f'What color is {person["name"]}\'s scarf?',
                          f'Which scarf color belongs to {person["name"]}?',
                          f'Give the scarf color for {person["name"]}.'])
            add('ownership',pair(record+' '+q,person['color']))
        dialogue=pair(record+f' What color is {people[0]["name"]}\'s scarf?',people[0]['color'])
        dialogue += [{'role':'user','content':f'And what color is {people[1]["name"]}\'s scarf?'},
                     {'role':'assistant','content':people[1]['color']}]
        add('ownership',dialogue)
        topic,task,advice=topics[i%len(topics)]
        minutes=rng.choice([10,15,20,30]);name=p['name']
        question=rng.choice([f'I want to start {topic}. What should I do?',
            f'Can you help me with {topic}? I am a beginner.',f'Give me an easy way to begin {topic}.'])
        answer=f'You could {task}. {advice}'
        dialogue=pair(question,answer)
        dialogue += [{'role':'user','content':f'I have {minutes} minutes today. Make a short plan.'},
            {'role':'assistant','content':f'Use your {minutes} minutes to {task}. Keep the task small and continue another day if needed.'},
            {'role':'user','content':'What topic are we working on?'},
            {'role':'assistant','content':f'We are working on {topic}.'}]
        add('dialogue',dialogue)
        favor=rng.choice(['watering my plants','lending me a book','helping me move','feeding my cat','your advice'])
        dialogue=pair(f'Write a short thank-you message to {name} for {favor}.',
                      f'Hi {name}, thank you for {favor}. I really appreciate your help.')
        dialogue += [{'role':'user','content':'Make it shorter, but keep the name and reason.'},
            {'role':'assistant','content':f'Thank you for {favor}, {name}.'},
            {'role':'user','content':'Who is the message for?'},{'role':'assistant','content':name}]
        add('dialogue',dialogue)
        event=rng.choice(['a picnic','a study session','a birthday lunch','a book club meeting'])
        day=rng.choice(['Monday','Tuesday','Friday','Saturday']);place=p['place']
        people=rng.choice([2,3,4,6,8]);hour=rng.randrange(9,18)
        start=f'{hour}:00';field=rng.choice(['day','time','people'])
        followup={'day':('Which day did I choose?',day),'time':('What time are we starting?',start),
                  'people':('How many people are coming?',str(people))}[field]
        dialogue=pair(f'Help me plan {event}.','When will it happen, where will it be, and how many people are coming?')
        dialogue += [{'role':'user','content':f'{day} at {start}, in the {place}, with {people} people.'},
            {'role':'assistant','content':f'For {event} on {day} at {start} in the {place}, prepare space for {people} people and a short list of what to bring.'},
            {'role':'user','content':followup[0]},{'role':'assistant','content':followup[1]}]
        add('dialogue',dialogue)
        a=rng.randrange(31);b=rng.randrange(31)
        if not held_math(a,b):add('arithmetic',pair(f'What is {a} + {b}? Give only the sum.',str(a+b)))
    return rows,cases,dict(examples=len(rows),familyExamples=dict(Counter(r['family'] for r in rows)),
        teacherCalls=0,benchmarkPromptsExcluded=True,
        heldoutScope='V22 synthetic benchmark prompts/values excluded from V22 practice; historical public exposure unknown.',
        practiceSampling='70% tutor updates / 30% raw updates. Within tutor: 15% previous synthetic practice replay; 85% new lessons.',
        newFamilySampling='45% dialogue, 30% direct answers versus acknowledgments, 20% ownership, 5% arithmetic',
        naturalPublicConversationsAdded=False,
        notice='Original template-generated multi-turn lessons; variety is limited and this is not proof of conversational ability.')


def curriculum(step):
    return ['dialogue','direct','ownership','arithmetic'],[45,30,20,5]
