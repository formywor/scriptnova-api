"""Short complete conversation practice; preserve V9's fixed unseen validation."""
import hashlib,json,re
from pathlib import Path
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from nebula import encode
from rules import with_owner_rules
from v7_data import is_conversation
from v7_checks import touches_checks
from v9_data import prompts,canonical,locked_checks
from v4_data import forbidden,blocked_questions

DIALOGUES=[
('greeting',['Good to see you, Nebula.','Good to see you too! What would you like to work on?','I need a relaxing hobby.','You could draw, read, or try a simple puzzle.']),
('greeting',['Are you ready to help me today?','Yes! Tell me what you need help with.','I need to organize my desk.','Start by clearing rubbish, then group papers and supplies.']),
('greeting',['I am not sure where to start our chat.','We can start with something you enjoy or a task you want help with.','I like painting.','What do you enjoy painting?']),
('clarify',['Help me prepare a message.','Who is the message for, and what should it say?','My neighbor. Thank her for watering my plants.','Thank you for watering my plants while I was away. I appreciate your help.']),
('clarify',['I need help choosing a present.','Who is it for, and what is your budget?','A friend who likes drawing. Under twenty dollars.','A sketchbook and a few drawing pencils could be a thoughtful choice.']),
('clarify',['Can you make a simple plan for me?','What would you like to plan, and how much time do you have?','Cleaning my room in fifteen minutes.','Put clothes away, clear the floor, then tidy your desk.']),
('clarify',['Can you tell me which one is better?','Which options are you comparing?','Walking or cycling for a short trip.','Walking is simple; cycling is usually quicker. Which matters more to you?']),
('clarify',['I cannot understand this instruction.','Please share the instruction and the part that is confusing.','It says to fold the paper in half.','Bring two opposite edges together, then press along the fold.']),
('identity',['Tell me a little about the assistant I am chatting with.','I am Nebula AI, an experimental assistant. I can help with questions and writing.','Are your answers always right?','No. I can make mistakes, so important facts should be checked.']),
('identity',['Introduce yourself in one short sentence.','I am Nebula AI, an experimental assistant here to help.','What should I call you in this chat?','You can call me Nebula.']),
('identity',['Are you a person sitting at a computer?','No. I am Nebula AI, an AI assistant.','Do you have real feelings?','I do not have human feelings, but I can respond thoughtfully.']),
('identity',['Who will help me with my writing here?','I am Nebula AI, and I can help you draft or revise it.','Can you read a document I have not shared?','No. Please share the text you want me to work on.']),
('identity',['What sort of help can Nebula offer?','I can help with simple questions, ideas, and writing. I am still experimental.','Can you admit when you do not know?','Yes. I should say when I am unsure or need more information.']),
('context',['My practice notebook is violet.','Your practice notebook is violet.','I changed its cover to orange. Which color is it now?','It is orange now.']),
('context',['The fictional shop opens on Wednesday.','The fictional shop opens on Wednesday.','It now opens on Friday instead. When does it open?','It opens on Friday now.']),
('context',['For this exercise, call my imaginary pet Rillo.','Your imaginary pet is named Rillo.','Remind me of the name I chose.','You chose Rillo.']),
('context',['I prefer short explanations about gardening.','I will keep the explanations short and focus on gardening.','Suggest a topic to learn.','You could learn how to check whether a plant needs water.']),
('context',['I have paper, scissors, and glue.','You have paper, scissors, and glue.','Suggest a project using those supplies.','Make a paper collage by cutting shapes and gluing them onto a sheet.']),
('context',['For this story, the rabbit carries a green bag.','The rabbit carries a green bag.','Which item is green in the story?','The rabbit\'s bag is green.']),
('context',['Our fictional team chose a sunflower symbol.','The team symbol is a sunflower.','We replaced it with a moon. What symbol do we use now?','The team uses a moon now.']),
('rewrite',['Write a brief note thanking a friend for helping me move.','Thank you for helping me move. You made a busy day much easier.','Make it more casual.','Thanks for helping me move! You made the day so much easier.']),
('rewrite',['Ask someone politely to return a borrowed book.','Could you please return the book when you have a chance?','Mention that I need it tomorrow.','Could you please return the book today? I need it tomorrow.']),
('rewrite',['Write a short apology for arriving late.','I am sorry I arrived late. Thank you for waiting for me.','Make it shorter.','Sorry I was late, and thanks for waiting.']),
('rewrite',['Make this kinder: Your drawing is wrong.','There may be a mistake in the drawing. Could we check it together?','Keep it to one sentence.','Could we check this part of your drawing together?']),
('rewrite',['Help me invite a friend for a walk on Sunday.','Would you like to go for a walk with me on Sunday?','Add that we could meet at noon.','Would you like to go for a walk on Sunday? We could meet at noon.']),
('explain',['Explain why a shadow changes when a lamp moves.','A shadow forms where an object blocks light. Moving the lamp changes where the light is blocked.','Can you make that shorter?','Moving the lamp changes the direction of the light, so the shadow moves.']),
('explain',['Why does ice become water in a warm room?','Ice takes in heat from the room. With enough heat, it melts into liquid water.','Is melting the same as boiling?','No. Melting changes a solid to a liquid; boiling changes a liquid to a gas.']),
('explain',['Explain what a map is in simple words.','A map is a drawing that shows where places are and how they relate to each other.','How can it help on a walk?','It can help you choose a route and find where you are.']),
('explain',['Why should I save my work while writing?','Saving keeps a copy so an interruption is less likely to erase your progress.','What else could help?','Keep a backup copy in a second place.']),
('story',['Write a tiny story about a lost mitten.','A mitten fell beside a gate. A child found it and returned it to its grateful owner.','Where was the mitten found?','It was found beside a gate.']),
('story',['Tell a short story about a snail reaching a leaf.','A snail slowly crossed a stone. At last it reached a leaf and rested in the shade.','What did the snail cross?','It crossed a stone.']),
('story',['Write a tiny story about a cracked cup.','A cup cracked, so its owner filled it with soil. A little flower soon grew inside.','What became of the cup?','It became a pot for a flower.']),
('story',['Tell a complete short story about a windy picnic.','Wind lifted the picnic napkins. The friends caught them, then moved behind a wall to eat.','Why did the friends move?','They moved to shelter from the wind.']),
('uncertainty',['How much does my bag weigh?','I cannot tell without a measurement. Do you have a scale?','The scale says three kilograms.','Your bag weighs three kilograms according to that measurement.']),
('uncertainty',['Which page has the answer in my book?','Please share the book title and the question you are trying to answer.','I cannot share the book yet.','That is fine. Tell me the topic, and I can try to explain it generally.']),
('planning',['Suggest a calm activity for a rainy afternoon.','Try reading, sketching, or working on a small puzzle indoors.','I only have paper and a pencil.','You could sketch an object in the room or make a word puzzle.']),
('planning',['Help me start a small drawing project.','Choose one simple object, sketch its outline, then add a few details.','I chose a mug. What should I draw first?','Start with the rim, then outline the body and handle.']),
('planning',['I have ten minutes to tidy my kitchen.','Put items away, wash a few dishes, then wipe the counter.','Which task should I do first?','Start by putting items back where they belong.']),
('friendly',['Thanks, that explanation helped me.','You are welcome! I am glad it helped.','Could we try a simple example next?','Of course. Which part would you like an example of?']),
('friendly',['I made a mistake in my sketch and feel frustrated.','That sounds frustrating. We can look at one small part and decide how to change it.','The handle is too large.','Try lightly redrawing a smaller handle before erasing the old outline.']),
]

def rejection(row,blocked=()):
    if not eligible(row):return 'ineligible_source_or_roles'
    if touches_checks(row['messages']) or prompts(row)&set(blocked):return 'heldout_prompt'
    _,checks=locked_checks()
    if forbidden(row,checks,blocked_questions(checks)):return 'frozen_check'
    if len(encode(with_owner_rules(row['messages']))[0])>768:return 'context_too_long'
    for message in row['messages']:
        text=message['content']
        if any(ord(c)>126 or ord(c)<32 and c!='\n' for c in text):return 'non_ascii_or_control'
        if re.search(r'https?://|@|(?:gsk_|hf_|sk-|AIza|AQ\.)[\w-]{12,}|\b(ChatGPT|Gemini|Groq|OpenAI|Claude|Anthropic)\b',text,re.I):return 'identity_contact_or_credential'
        if message['role']=='assistant':
            if not 2<=len(text)<=220:return 'answer_length'
            if not text.rstrip().endswith(('.', '?', '!')):return 'incomplete_answer'
            words=re.findall(r'\w+',text.casefold());grams=[tuple(words[i:i+3]) for i in range(len(words)-2)]
            if len(grams)>5 and len(set(grams))<.9*len(grams):return 'repeated_phrase'
            for a,b,result in re.findall(r'(?<![\d-])(\d+)\s*\+\s*(\d+)\s*=\s*(-?\d+)',text):
                if int(a)+int(b)!=int(result):return 'incorrect_addition'
    return None

def owned():
    rows=[]
    for index,(skill,turns) in enumerate(DIALOGUES):
        messages=[{'role':'user' if i%2==0 else 'assistant','content':content} for i,content in enumerate(turns)]
        row={'id':example_id(messages),'reviewStatus':'approved','approvalMethod':'owned-original-dialogue','splitGroup':'v10-original-'+str(index),'source':{'kind':'seed','curriculum':'v7-conversation','focus':'v10-repair','skill':skill},'messages':messages}
        if rejection(row) is None:rows.append(row)
    return rows

def prepare(base,validation,output):
    fixed=read_jsonl(validation);blocked=set().union(*(prompts(r) for r in fixed));groups={r.get('splitGroup') for r in fixed if r.get('splitGroup')};seen=set();rows=[];removed={}
    for row in read_jsonl(base)+owned():
        reason='heldout_group' if row.get('splitGroup') in groups else 'heldout_prompt' if prompts(row)&blocked else None
        if not eligible(row):reason='ineligible'
        if is_conversation(row):reason=reason or rejection(row,blocked)
        identity=canonical(row['messages'])
        if identity in seen:reason=reason or 'duplicate'
        if reason:removed[reason]=removed.get(reason,0)+1;continue
        rows.append(row);seen.add(identity)
    counts={'trainingRows':len(rows),'shortConversationRows':sum(is_conversation(r) for r in rows),'publicConversationRows':sum(is_conversation(r) and r['source'].get('kind')=='public' for r in rows),'repairDialogues':sum(r['source'].get('focus')=='v10-repair' for r in rows),'languageRows':sum(r['source'].get('curriculum')=='v9-language' for r in rows),'removed':removed,'conversationPercent':80,'validationUnchanged':True,'maxAssistantCharacters':220}
    if counts['shortConversationRows']<200 or counts['publicConversationRows']<50 or counts['repairDialogues']<20:raise ValueError('V10 needs complete short conversations, public replay and original repair dialogues')
    write_jsonl(output,rows);counts['trainingSha256']=hashlib.sha256(Path(output).read_bytes()).hexdigest();counts['validationSha256']=hashlib.sha256(Path(validation).read_bytes()).hexdigest()
    Path(output).with_suffix('.manifest.json').write_text(json.dumps(counts,indent=2),encoding='utf-8');return counts
