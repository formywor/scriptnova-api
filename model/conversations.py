"""Owned short dialogues and bounded parallel teacher collection."""
import concurrent.futures
import hashlib
import json
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from dataflow import generate_teacher, read_jsonl, write_jsonl, redact
from nebula import encode
from rules import with_owner_rules
from teacher_http import TeacherRequestError

def curriculum():
    """Original synthetic curriculum: no user chats or outside datasets."""
    rows = []
    def add(pairs):
        messages = [{'role': role, 'content': text} for pair in pairs for role, text in zip(['user', 'assistant'], pair)]
        rows.append({'reviewStatus': 'approved', 'source': {'kind': 'seed'}, 'messages': messages})
    for name in ['Sam','Mia','Alex','Noah','Ava','Liam','Zoe','Leo','Emma','Omar','Ivy','Max']:
        for color in ['blue','green','red','purple']:
            add([(f'My name is {name}.',f'Hi, {name}!'), (f'I like {color}.',f'I will remember that in this chat.'), ('What is my name and favorite color?',f'Your name is {name} and you like {color}.')])
    for a in range(1,13):
        for b in range(1,9):
            add([(f'What is {a} + {b}?',f'{a} + {b} = {a+b}.'), ('Add 2 to that.',f'{a+b} + 2 = {a+b+2}.'), ('Now subtract 1.',f'{a+b+2} - 1 = {a+b+1}.')])
    for item in ['apples','books','coins','pens','cups','balls','cards','bags']:
        for n in range(2,10):
            add([(f'I have {n} {item}.',f'You have {n} {item}.'), ('I get 3 more.',f'Now you have {n+3} {item}.'), ('I give away 2. How many remain?',f'You have {n+1} {item} left.')])
    for greeting in ['hi','hello','hey','good morning','good evening']:
        add([(greeting,'Hi! How can I help?'), ('What is your name?','I am Nebula AI.'), ('Nice to meet you.','Nice to meet you too!')])
    add([('I need an email.','Who is it for?'), ('My teacher. I was absent.','What do you need to ask?'), ('Ask what work I missed.','Hi, could you please tell me what work I missed? Thank you.')])
    add([('Tell me about gravity.','Gravity pulls objects toward each other.'), ('Give an example.','Gravity makes a dropped ball fall to the ground.'), ('What about the Moon?','Gravity keeps the Moon in orbit around Earth.')])
    add([('Help me plan my homework.','List the tasks and their deadlines.'), ('Math tomorrow, essay Friday.','Start with math because it is due sooner.'), ('What next?','Work on your essay after finishing math.')])
    add([('I have a question.','Go ahead!'), ('Do you know everything?','No. I can make mistakes and have limited knowledge.'), ('What if you are unsure?','I should tell you I am unsure instead of guessing.')])
    return rows

def teacher_job_id(config, row):
    value = {'teacher': config.get('name', 'custom'), 'model': config['model'], 'users': [m['content'] for m in row['messages'] if m['role'] == 'user'], 'format': 1}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def collect(configs, prompts, output, limit=32, workers=2, context=512, transport=None, interval=15, retry_delay=60, clock=time.monotonic, sleep=time.sleep):
    if not 1 <= workers <= 3 or not 1 <= limit <= 100: raise ValueError('Use 1-3 workers and a total budget of 1-100 calls')
    if not configs or len(configs) > 3: raise ValueError('Choose one to three teacher configurations')
    if any(c.get('trainingAllowed') is not True for c in configs): raise ValueError('Each teacher configuration must explicitly enable trainingAllowed')
    # Assign each original dialogue to one teacher; never submit account conversations.
    if any(r.get('source', {}).get('kind') != 'seed' for r in prompts): raise ValueError('Only original seed dialogues can be sent to teachers')
    output = Path(output)
    rows = read_jsonl(output) if output.exists() else []
    done = {r.get('promptId') for r in rows}
    queues = [[] for _ in configs]
    for index, row in enumerate(prompts):
        config = configs[index % len(configs)]
        identifier = teacher_job_id(config, row)
        if identifier not in done:
            queues[index % len(configs)].append((config, row, identifier))
    def task(job):
        config, row, identifier = job
        users = [m['content'] for m in row['messages'] if m['role'] == 'user']
        prompt = 'Write assistant replies for this original conversation. User messages in order: ' + json.dumps(users) + '. Return ONLY a JSON array of exactly ' + str(len(users)) + ' strings, one reply per user message. Each reply must be under 65 UTF-8 bytes. Remember earlier turns, calculate carefully, answer directly. No markdown.'
        # The scheduler handles retries so waiting on one API never occupies a worker.
        settings = {**config, 'maxTokens': 1024, 'httpRetries':0, 'instructions': 'Output only the requested JSON array. No reasoning text.'}
        with tempfile.TemporaryDirectory(dir=output.parent) as directory:
            path = Path(directory)/'reply.jsonl'
            generate_teacher(settings, [{'source':'original','prompt':prompt}], path, 1, transport)
            answer = read_jsonl(path)[0]['messages'][1]['content'].strip()
        if answer.startswith('```'):
            answer = answer.split('\n',1)[-1].rsplit('```',1)[0].strip()
        answers = json.loads(answer)
        if not isinstance(answers,list) or len(answers) != len(users) or any(not isinstance(a,str) or not a.strip() or len(a.encode('utf-8'))>65 for a in answers):
            raise ValueError('Teacher dialogue format invalid')
        messages = [{'role':role,'content':redact(text)} for pair in zip(users,answers) for role,text in zip(['user','assistant'],pair)]
        if len(encode(with_owner_rules(messages))[0]) > context+1: raise ValueError('Teacher dialogue exceeds context')
        return {'promptId':identifier, 'reviewStatus':'pending', 'messages':messages, 'source':{'kind':'teacher','provider':config.get('name','custom'),'model':config['model'],'trainingAllowed':True}}
    output.parent.mkdir(parents=True, exist_ok=True)
    accepted = failed = attempts = 0
    next_ready = [0.0 for _ in configs]
    failures = [0 for _ in configs]
    retries = {}
    cursor = 0
    # One outstanding call per provider. The coordinator writes each result immediately.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        while futures or (attempts < limit and any(queues)):
            busy = {index for index,_ in futures.values()}
            for turn in range(len(configs)):
                index = (cursor + turn) % len(configs)
                if len(futures) >= workers or attempts >= limit: break
                if index in busy or not queues[index] or clock() < next_ready[index]: continue
                job = queues[index].pop(0)
                attempts += 1
                print(json.dumps({'teacherRequestStarted':True,'provider':configs[index].get('name','custom'),'attempt':attempts,'maximumAttempts':limit}),flush=True)
                futures[pool.submit(task,job)] = (index,job)
                busy.add(index)
            cursor = (cursor + 1) % len(configs)
            if not futures:
                if attempts >= limit: break
                waiting = [max(0,next_ready[i]-clock()) for i,q in enumerate(queues) if q]
                if waiting: sleep(min(1,max(.001,min(waiting))))
                continue
            finished,_ = concurrent.futures.wait(futures,timeout=.1,return_when=concurrent.futures.FIRST_COMPLETED)
            for future in finished:
                index,job = futures.pop(future)
                provider = configs[index].get('name','custom')
                try:
                    row = future.result()
                    failures[index] = 0
                    next_ready[index] = clock() + (interval if not transport else 0)
                    # Filesystem failures must stop the run, rather than masquerading as API failures.
                except Exception as error:
                    failed += 1; failures[index] += 1
                    status = error.code if isinstance(error,HTTPError) else getattr(error,'status',None)
                    reason = ('authentication' if status == 401 else 'permission_or_gateway' if status == 403 else 'rate_or_quota' if status == 429 else 'http_error' if status else 'network' if isinstance(error,(URLError,TimeoutError)) else 'invalid_json' if isinstance(error,json.JSONDecodeError) else 'context_too_long' if str(error)=='Teacher dialogue exceeds context' else 'invalid_reply')
                    print(json.dumps({'teacherDialogueFailed':failed,'provider':provider,'httpStatus':status,'reason':reason}),flush=True)
                    transient = status in [408,429,500,502,503,504] or isinstance(error,(URLError,TimeoutError)) and not isinstance(error,HTTPError)
                    if isinstance(error,TeacherRequestError): transient = error.retryable
                    count = retries.get(job[2],0)
                    if transient and count < 2:
                        retries[job[2]] = count + 1
                        delay = max(retry_delay * (2 ** min(failures[index]-1,3)),getattr(error,'retry_after',0))
                        next_ready[index] = clock() + delay
                        queues[index].insert(0,job)
                        print(json.dumps({'teacherRetryLater':True,'provider':provider,'retryInSeconds':delay,'otherTeacherContinues':True}),flush=True)
                    elif transient or status in [401,403] or isinstance(error,TeacherRequestError):
                        # Keep unfinished jobs eligible on the next invocation; do not hammer bad keys/quotas.
                        queues[index].clear()
                        print(json.dumps({'teacherPausedForRun':True,'provider':provider,'retryOnNextRun':True}),flush=True)
                    else:
                        next_ready[index] = clock() + (interval if not transport else 0)
                    continue
                rows.append(row); write_jsonl(output, rows); accepted += 1
                print(json.dumps({'teacherDialogueSaved':accepted,'provider':row['source']['provider'],'messages':len(row['messages'])}),flush=True)
    return {'attempts':attempts,'saved':accepted,'failed':failed,'workers':workers,'configuredTeachers':len(configs)}
