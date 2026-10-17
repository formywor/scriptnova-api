"""Owned multi-turn tasks with explicit context, revisions and complete answers."""
import hashlib
import json
from pathlib import Path
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from nebula import encode
from rules import with_owner_rules
from v4_data import exercises,forbidden,blocked_questions
VERSION='nebula-v6-conversation-1'

def additions():
    _,checks=exercises();blocked=blocked_questions(checks);rows=[];seen=set()
    def add(turns,group):
        messages=[{'role':'user' if i%2==0 else 'assistant','content':text} for i,text in enumerate(turns)]
        row={'id':example_id(messages),'reviewStatus':'approved','splitGroup':group,'source':{'kind':'seed','curriculum':'v6-conversation'},'messages':messages}
        if row['id'] in seen or forbidden(row,checks,blocked) or len(encode(with_owner_rules(messages))[0])>1024:return
        seen.add(row['id']);rows.append(row)
    # Details are synthetic task inputs, not facts about real users.
    for hobby in ['drawing','gardening','reading','painting','baking','running','chess','music','photography','writing','cycling','origami']:
        for minutes in [10,15,20,25,30,40]:
            group=f'v6-plan-{hobby}-{minutes}'
            turns=[f'I want to practice {hobby}.','How much time do you have?',f'I have {minutes} minutes.',f'Set aside {minutes} minutes for one small {hobby} activity. Start with something easy.',
                   'What hobby did I choose?',f'You chose {hobby}.','How much time did I say?',f'You said {minutes} minutes.']
            add(turns,group)
            add(turns[:4]+['Make that shorter.',f'Practice {hobby} for {minutes} minutes.'],group)
            add(turns[:4]+['Actually, I have five more minutes.',f'Then you have {minutes+5} minutes for {hobby}.'],group)
    for item in ['notebook','backpack','umbrella','bowl','helmet','wallet','folder','shirt']:
        for color in ['red','green','blue','yellow','purple','orange']:
            group=f'v6-context-{item}-{color}'
            turns=[f'I have a {color} {item}.',f'You have a {color} {item}.','What color is it?',f'Your {item} is {color}.']
            add(turns,group)
            add(turns+[f'I changed it to white.','Your '+item+' is white now.','What was the first color?',f'The first color was {color}.'],group)
            add(turns+['Thanks for remembering.','You are welcome! I used the details in this conversation.'],group)
    for recipient in ['teacher','friend','coach','neighbor','classmate','teammate','club leader','tutor']:
        for reason in ['helping me study','explaining the project','sharing useful advice','helping me practice','answering my questions','giving me extra time']:
            group=f'v6-note-{recipient}-{reason}'
            turns=['Help me write a thank-you message.','Who is it for, and what are you thanking them for?',f'My {recipient}, for {reason}.',f'Thank you for {reason}. I appreciate your help!']
            add(turns,group)
            add(turns+['Make it more casual.',f'Thanks for {reason}! I really appreciate it.'],group)
            add(turns+['Make it one sentence.',f'Thank you for {reason}; I appreciate your help.'],group)
    for topic,explanation in [('ice','Ice is solid water.'),('a square','A square has four equal sides and four right angles.'),('a triangle','A triangle has three straight sides.'),('a week','A week has seven days.'),('an hour','An hour has 60 minutes.'),('a noun','A noun names a person, place, thing, or idea.'),('a verb','A verb usually describes an action, event, or state.'),('plants','Most plants need light, water, air, nutrients, and a suitable temperature.')]:
        for intro in ['Can you help me learn something?','I want to understand a topic.','Please explain something simply.','I need a simple explanation.']:
            group='v6-explain-'+topic
            add([intro,'What would you like to understand?',f'Explain {topic}.',explanation,'Thank you.','You are welcome! Would you like to ask another question?'],group)
    for animal in ['puppy','kitten','rabbit','duck','turtle','fox']:
        for place in ['garden','park','forest','village','meadow','yard']:
            story=f'A little {animal} found a lost ball in the {place}. A friend came to look for it. They shared the ball and played together.'
            group=f'v6-story-{animal}-{place}'
            add(['Tell me a short story.','What animal should the story be about?',f'A {animal} in a {place}.',story,'Where did the story happen?',f'It happened in the {place}.'],group)
            add([f'Tell a short story about a {animal} in a {place}.',story,'Make it shorter.',f'A {animal} found a lost ball in the {place} and shared it with a friend.'],group)
    return rows

def prepare(base,output):
    rows=[];seen=set();new=0
    for row in read_jsonl(base)+additions():
        if not eligible(row) or row.get('source',{}).get('kind')=='user':continue
        identifier=example_id(row['messages'])
        if identifier in seen:continue
        seen.add(identifier);rows.append(row)
        if row.get('source',{}).get('curriculum')=='v6-conversation':new+=1
    write_jsonl(output,rows)
    result={'format':VERSION,'conversations':len(rows),'newMultiTurnExamples':new,'conversationUpdatePercent':80,'mixedUpdatePercent':20,'memoryIncluded':True,'dataSha256':hashlib.sha256(Path(output).read_bytes()).hexdigest()}
    Path(output).with_suffix('.manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8');return result
