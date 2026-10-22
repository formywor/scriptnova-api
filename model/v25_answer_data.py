"""Target answer turns, not intermediate acknowledgments; preserve all context."""
import random
from collections import Counter
from nebula import encode,ASSISTANT
from v24_context_data import context_lessons,prepare_public
from v20_generalize_data import inventory,pair,key,norm
from v19_tutor_data import window


def training_window(row,context):
    x,y=window(row['messages'],context)
    if row.get('finalAnswerOnly'):
        if row['messages'][-1]['role']!='assistant':raise ValueError('A final assistant answer is required')
        tokens,_=encode(row['messages']);last=max(i for i,t in enumerate(tokens) if t==ASSISTANT)
        y[:last]=-100
        if not (y!=-100).any():raise ValueError('No final answer targets')
    return x,y


def repair_lessons(seed,cases,groups=1800,context=1024):
    base,_=context_lessons(seed,cases,groups,context);rows=[];seen=set()
    banned={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
    def add(messages,family):
        if len(encode(messages)[0])>context+1 or any(norm(m['content']) in banned for m in messages if m['role']=='user'):return
        identifier=key(messages)
        if identifier in seen:return
        seen.add(identifier);rows.append(dict(id=identifier,family='repair/'+family,messages=messages,
            finalAnswerOnly=True,origin='original-synthetic-v25',humanVerified=False))
    acknowledgments={'I understand the two descriptions.','Thanks for the correction.','Thanks for telling me.'}
    # Each actual answer becomes its own complete context -> final-answer training example.
    # Earlier assistant text remains visible but receives no loss for these examples.
    for row in base:
        family=row['family'].split('/',1)[1]
        for i,m in enumerate(row['messages']):
            if m['role']=='assistant' and m['content'] not in acknowledgments:
                add(row['messages'][:i+1],family)
    rng=random.Random(seed+250025);values=inventory(seed)
    topics=[('drawing','sketch a simple object','draw its outline, then add one detail'),
        ('writing','draft a few sentences','choose one idea and write about it'),
        ('reading','read a few pages','choose a short passage and read it slowly'),
        ('organizing','clear a small space','choose one shelf and sort its contents'),
        ('studying','practice one example','review a worked example, then try one yourself'),
        ('cooking','prepare a simple dish','choose a recipe and gather the ingredients'),
        ('gardening','check one plant','check its soil and light before watering'),
        ('photography','photograph a nearby object','use clear light and try two angles')]
    favors=[('watered my plants','watering my plants'),('lent me a book','lending me a book'),
        ('helped me move','helping me move'),('fed my cat','feeding my cat'),('shared their notes','sharing your notes')]
    for i in range(groups):
        name=rng.choice(values['names']);topic,task,advice=topics[i%len(topics)];minutes=rng.randrange(5,46)
        request=rng.choice([f'I am a beginner at {topic}. Can you suggest a small task?',f'Help me start {topic} with something simple.',f'I want to practice {topic}. Please help me begin.'])
        messages=pair(request,'How much time do you have?')
        question=rng.choice([f'I have {minutes} minutes. Give me a simple first step.',f'There are {minutes} minutes available. What should I try first?',f'Just {minutes} minutes today. Suggest a short activity.'])
        answer=rng.choice([f'Use your {minutes} minutes to {task}. First, {advice}.',f'Try to {task} during your {minutes} minutes. Start by taking this step: {advice}.'])
        messages+=pair(question,answer)[1:]
        add(messages,'practical')
        messages+=pair('Which activity did I ask about? Give only the activity.',topic)[1:];add(messages,'practical')
        past,thanks=rng.choice(favors)
        messages=pair('Help me write a friendly thank-you message.','Who is it for, and what did they do?')
        messages+=pair(f'The message is for {name}. They {past}.',f'Hi {name}, thank you for {thanks}. I appreciate your help.')[1:]
        add(messages,'writing')
        messages+=pair('Keep only the name and the reason in a shorter message.',f'{name}, thank you for {thanks}.')[1:];add(messages,'writing')
    return rows,dict(examples=len(rows),families=dict(Counter(r['family'] for r in rows)),
        objective='Final assistant answer only on repair records; full preceding context retained',
        intermediateAcknowledgmentTargets=0,templateGenerated=True,benchmarkPromptsExcluded=True,
        notice='Synthetic repair curriculum. Existing 96 questions are a development comparison, not an independent certification of intelligence.')
