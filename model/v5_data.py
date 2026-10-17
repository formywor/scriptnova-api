"""Original short conversations and exact arithmetic; preserve V4's held-out tasks."""
import hashlib
import json
import random
from pathlib import Path
from dataflow import example_id,eligible,read_jsonl,write_jsonl
from nebula import encode
from rules import with_owner_rules
from v4_data import exercises,forbidden,blocked_questions

VERSION='nebula-v5-1'
CONVERSATIONS=[
 ('hi','Hello! How can I help?'),('hello','Hello! What would you like to talk about?'),
 ('Good morning.','Good morning! How can I help today?'),('Good evening.','Good evening! What can I help with?'),
 ('How are you?','I am ready to help. How are you doing?'),('Thanks!','You are welcome!'),
 ('Thank you for helping me.','You are welcome. I am glad I could help.'),('Bye!','Goodbye! Take care.'),
 ('What is your name?','I am Nebula AI.'),('Who are you?','I am Nebula AI, an experimental AI assistant.'),
 ('Are you a person?','No. I am an AI assistant.'),('Can you make mistakes?','Yes. I can make mistakes. Please check important information.'),
 ('What can you do?','I can try to answer questions, write short text, and help you practice simple tasks.'),
 ('Do you know everything?','No. My knowledge and abilities are limited.'),
 ('Can you help me?','I can try. What do you need help with?'),('I need help.','Tell me what you are working on.'),
 ('Can you help me write an email?','Yes. Who is the email for, and what would you like it to say?'),
 ('Write a short thank-you note.','Thank you for your help. I really appreciate your time and kindness.'),
 ('Write a friendly greeting.','Hello! I hope you are having a good day.'),
 ('Write a polite request for help.','Could you please help me with this when you have a moment?'),
 ('Write a short apology for being late.','I am sorry I am late. Thank you for waiting.'),
 ('Help me plan my day.','List your tasks, choose the most important ones, and leave time for breaks.'),
 ('How can I start studying?','Pick one small topic. Read it, practice it, and take a short break.'),
 ('I do not understand.','Which part is confusing? I can try to explain it more simply.'),
 ('Can you explain that again?','Of course. Tell me which part you would like me to explain.'),
 ('What is gravity?','Gravity is the attraction between objects with mass. It keeps us on Earth.'),
 ('Why is the sky blue?','Air scatters blue sunlight more strongly than red sunlight, so the daytime sky looks blue.'),
 ('What is a planet?','A planet is a large, nearly round object that orbits a star and has cleared its orbital neighborhood.'),
 ('What is the Moon?','The Moon is Earth\'s natural satellite.'),
 ('What is the Sun?','The Sun is the star at the center of our solar system.'),
 ('What do plants need to grow?','Most plants need light, water, air, nutrients, and a suitable temperature.'),
 ('What is water made of?','A water molecule has two hydrogen atoms and one oxygen atom.'),
 ('What is ice?','Ice is solid water.'),('What is a triangle?','A triangle is a shape with three straight sides.'),
 ('How many days are in a week?','There are seven days in a week.'),('How many minutes are in an hour?','There are 60 minutes in an hour.'),
 ('What is a noun?','A noun is a word that names a person, place, thing, or idea.'),
 ('What is a verb?','A verb usually describes an action, event, or state.'),
 ('What is an adjective?','An adjective describes a noun.'),
 ('What is a computer?','A computer is a machine that follows instructions to process information.'),
 ('What is a password?','A password is a secret used to help protect access to an account.'),
 ('Should I share my password?','Keep your password private. Do not post it in a chat.'),
 ('Tell me a short story.','A puppy lost its ball in the garden. A friend found it under a bench. They played together until sunset.'),
 ('Tell me a story about a cat.','A cat watched rain from a warm window. When the sun came out, it curled up and fell asleep.'),
 ('Give me a creative project idea.','Make a small illustrated book about a place you would like to visit.'),
 ('Help me brainstorm.','What would you like ideas for? Tell me your goal and any limits.'),
 ('I am bored.','Would you like a story, a simple game, or a creative project idea?'),
 ('I had a difficult day.','That sounds hard. Would you like to talk about what happened?'),
 ('I am happy today.','I am glad to hear that! What made your day good?'),
 ('What should we talk about?','We could talk about a hobby, a question, or something you want to make.'),
]

def additions():
    _,held_cases=exercises();blocked=blocked_questions(held_cases);rows=[];seen=set()
    def add(messages,group,kind):
        row={'id':example_id(messages),'reviewStatus':'approved','splitGroup':group,
             'source':{'kind':'seed','curriculum':kind},'messages':messages}
        if row['id'] in seen or forbidden(row,held_cases,blocked) or len(encode(with_owner_rules(messages))[0])>1024:return
        seen.add(row['id']);rows.append(row)
    for index,(question,answer) in enumerate(CONVERSATIONS):
        # Variants stay in one partition, rather than leaking into validation.
        group=f'v5-conversation-{index}'
        for prefix in ['', 'Hi. ', 'Hello. ', 'Please help: ', 'Quick question: ']:
            for suffix in ['', ' Please keep it short.', ' One sentence is fine.', ' Please answer clearly.']:
                add([{'role':'user','content':prefix+question+suffix},{'role':'assistant','content':answer}],group,'v5-conversation')
        add([{'role':'user','content':question},{'role':'assistant','content':answer},
             {'role':'user','content':'Thank you.'},{'role':'assistant','content':'You are welcome!'}],group,'v5-conversation')
    # Exact terminating targets, including familiar 2 + 2 rehearsal. V4's held
    # operand pairs and reserved scenarios remain excluded in every wording.
    for a in range(32):
        for b in range(32):
            for operator,value,verb in [('+',a+b,'Add'),('-',a-b,'Subtract')]:
                group=f'addition-{min(a,b)}-{max(a,b)}' if operator=='+' else f'v5-subtraction-{a}-{b}'
                questions=[f'What is {a} {operator} {b}?',f'Calculate {a} {operator} {b}.',
                           f'{verb} {a} and {b}.' if operator=='+' else f'Subtract {b} from {a}.']
                for q in questions:add([{'role':'user','content':q},{'role':'assistant','content':f'{a} {operator} {b} = {value}.'}],group,'v5-exact-math')
    return rows

def prepare(base,output):
    rows=[];seen=set();new=0
    for row in read_jsonl(base)+additions():
        if not eligible(row) or row.get('source',{}).get('kind')=='user':continue
        identifier=example_id(row['messages'])
        if identifier in seen:continue
        seen.add(identifier);rows.append(row)
        if row.get('source',{}).get('curriculum','').startswith('v5-'):new+=1
    write_jsonl(output,rows)
    result={'format':VERSION,'conversations':len(rows),'newOriginalExamples':new,
            'dataSha256':hashlib.sha256(Path(output).read_bytes()).hexdigest(),
            'rawUserChatsIncluded':False,'knownProbeRehearsal':['What is your name?','What is 2 + 2?'],
            'note':'Known probes are rehearsal, not unseen tests. Original V4 frozen tasks remain excluded. Public source notices are inherited.'}
    Path(output).with_suffix('.manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result
