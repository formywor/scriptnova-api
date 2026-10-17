"""Conversation-focused data with complete, short answers and retained mixed rehearsal."""
import hashlib
import json
from pathlib import Path
import re
from dataflow import eligible,example_id,read_jsonl,write_jsonl
from nebula import encode
from rules import with_owner_rules
from conversation_mix import conversational
from v7_checks import touches_checks
from v6_data import additions as multi_turn
from v4_data import exercises,forbidden,blocked_questions
VERSION='nebula-v7-quality-1'

def is_conversation(row):return conversational(row) or row.get('source',{}).get('curriculum')=='v7-conversation'

def short_complete(row):
    if not eligible(row) or row.get('source',{}).get('kind')=='user' or touches_checks(row.get('messages',[])):return False
    if not is_conversation(row):return True
    if len(encode(with_owner_rules(row['messages']))[0])>1024:return False
    for message in row['messages']:
        text=message['content']
        if re.search(r'\b(ChatGPT|Gemini|Groq|Claude|OpenAI|Anthropic)\b|https?://|@',text,re.I):return False
        if any(ord(c)>126 for c in text):return False
        if message['role']=='assistant' and (len(text)>220 or not text.rstrip().endswith(('.', '?', '!'))):return False
    return True

def additions():
    rows=multi_turn();_,checks=exercises();blocked=blocked_questions(checks)
    questions=['What kind of assistant are you?','Could you introduce yourself briefly?','Who is helping me here?','Tell me what you are.']
    for q in questions:
        for task,answer in [('Help me get started.','Tell me your goal, and we can choose a first step.'),('Can you ask a question?','What would you like help with?'),('Do you know everything?','No. I can make mistakes and may need more information.'),('Thank you.','You are welcome!')]:
            messages=[{'role':'user','content':q},{'role':'assistant','content':'I am Nebula AI, an experimental AI assistant.'},{'role':'user','content':task},{'role':'assistant','content':answer}]
            row={'id':example_id(messages),'reviewStatus':'approved','splitGroup':'v7-identity-'+q,'source':{'kind':'seed','curriculum':'v7-conversation'},'messages':messages}
            if not forbidden(row,checks,blocked):rows.append(row)
    return rows

def prepare(base,output):
    seen=set();rows=[];dropped=0
    for row in read_jsonl(base)+additions():
        if not short_complete(row):dropped+=1;continue
        identifier=example_id(row['messages'])
        if identifier in seen:continue
        seen.add(identifier);rows.append(row)
    chats=sum(is_conversation(r) for r in rows)
    if chats<200:raise ValueError('V7 requires enough complete conversation examples')
    write_jsonl(output,rows)
    summary={'format':VERSION,'conversations':len(rows),'completeConversationExamples':chats,'droppedLongIncompleteOrForeignExamples':dropped,'conversationPercent':80,'mixedPercent':20,'memoryIncluded':True,'teacherGeneratedSeparately':True,'dataSha256':hashlib.sha256(Path(output).read_bytes()).hexdigest()}
    Path(output).with_suffix('.manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');return summary
