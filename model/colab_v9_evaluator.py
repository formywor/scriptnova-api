"""Read-only Colab companion: compare saved V9 snapshots without changing training."""
import argparse,gc,hashlib,json,math,os,re,time
from pathlib import Path
import torch
from dataflow import read_jsonl
from kaggle_migrate import restore_data
from nebula import load
from research_client import ResearchError,digests
from research_eval import healthy
from rules import with_owner_rules,owner_instructions
from v8_store import Store
from v9_eval import evaluate

class ReadOnlyStore(Store):
    def publish(self,*args,**kwargs):raise ResearchError('COLAB_EVALUATOR_IS_READ_ONLY')

def normalized(text):return ' '.join(text.casefold().split())

def fresh_cases(blocked):
    candidates=[
        ('context','The model kite in this exercise is amber. Remember its color.','The model kite is amber.','What color is the model kite in this exercise?','amber'),
        ('context','A fictional explorer is named Velko. Keep that name for this task.','The fictional explorer is Velko.','Which name did this exercise give the explorer?','velko'),
        ('context','The rehearsal was on Tuesday.','The rehearsal was on Tuesday.','Move it to Saturday. What day is the rehearsal now?','saturday'),
    ]
    cases=[]
    for category,a,b,c,expected in candidates:
        cases.append({'category':category,'messages':[{'role':'user','content':a},{'role':'assistant','content':b},{'role':'user','content':c}],'expected':expected})
    for a,b in [(26,15),(18,24),(32,9)]:cases.append({'category':'arithmetic','messages':[{'role':'user','content':f'For this exercise, add {a} and {b}. Give the total.'}],'number':a+b})
    for category,prompt in [
        ('clarification','Help me prepare an invitation, but first ask who it is for.'),
        ('writing','Write two friendly sentences thanking someone for feeding my rabbit.'),
        ('explanation','In two simple sentences, explain why a wet towel dries outside.'),
        ('story','Write a tiny complete story about a paper boat crossing a puddle.'),
        ('editing','Make this request polite: Send the drawing today.'),
        ('planning','Suggest one quiet indoor hobby that needs only paper and a pencil.')]:cases.append({'category':category,'messages':[{'role':'user','content':prompt}],'humanReviewRequired':True})
    return [case for case in cases if not any(normalized(m['content']) in blocked for m in case['messages'] if m['role']=='user')]

def generated_checks(checkpoint,cases,device):
    model,metadata=load(checkpoint);model.to(device);model.eval();answers=[]
    try:
        with torch.no_grad():
            for case in cases:
                reply=model.reply(with_owner_rules(case['messages']),max_tokens=220,temperature=0)
                passed=None
                if 'expected' in case:passed=healthy(reply) and bool(re.search(r'(?<!\w)'+re.escape(case['expected'])+r'(?!\w)',reply.casefold()))
                if 'number' in case:
                    numbers=re.findall(r'-?\d+',reply);passed=healthy(reply) and bool(numbers) and numbers[-1]==str(case['number'])
                answers.append({**case,'reply':reply,'healthy':healthy(reply),'passed':passed})
    finally:
        del model;gc.collect()
        if device=='cuda':torch.cuda.empty_cache()
    exact=[answer for answer in answers if answer['passed'] is not None]
    return {'steps':metadata.get('steps'),'exactChecksPassed':sum(answer['passed'] for answer in exact),'exactChecks':len(exact),'manualReviewCases':sum(answer.get('humanReviewRequired',False) for answer in answers),'answers':answers}

def questions(paths):
    return {normalized(m['content']) for path in paths for row in read_jsonl(path) for m in row['messages'] if m['role']=='user'}

def comparison(results):
    if not all(name in results for name in ['best','latest']):return {'note':'Only a protected best checkpoint is available so far.'}
    first=results['best']['metrics'];last=results['latest']['metrics']
    keys=['correct','chatChecks','memory','chatLoss','publicChatLoss','languageLoss']
    return {key:{'best':first[key],'latest':last[key],'latestMinusBest':last[key]-first[key]} for key in keys}

def evaluate_snapshot(store,state,project,device='cuda',evaluator=evaluate,generate=generated_checks):
    if state.get('format')!='nebula-v9-curriculum-1':raise ResearchError('COLAB_REQUIRES_V9_SNAPSHOT')
    project=Path(project);project.mkdir(parents=True,exist_ok=True)
    source=store.download(state['sourceData'],project/'source-data.pt');restore_data(source,project)
    os.environ['NEBULA_RULES_FILE']=str((project/'nebula-rules.json').resolve());owner_instructions()
    data={key:store.download(state[key],project/(key+'.jsonl' if key!='checks' else 'checks.json')) for key in ['data','validationData','evaluationData','checks']}
    blocked_paths=[data['data'],data['validationData'],data['evaluationData']]
    if state.get('teacherData'):blocked_paths.append(store.download(state['teacherData'],project/'teachers.jsonl'))
    blocked=questions(blocked_paths)
    frozen=json.loads(data['checks'].read_text(encoding='utf-8'))
    for case in frozen.get('cases',[]):
        if case.get('prompt'):blocked.add(normalized(case['prompt']))
        blocked.update(normalized(m['content']) for m in case.get('messages',[]) if m['role']=='user')
    probes=fresh_cases(blocked)
    if not probes:raise ResearchError('COLAB_NO_FRESH_CHECKS_AVAILABLE')
    signature=hashlib.sha256(json.dumps({'validation':state['validationData']['sha256'],'legacy':state['evaluationData']['sha256'],'checks':state['checks']['sha256'],'rules':owner_instructions(),'probes':probes,'format':'colab-v9-1'},sort_keys=True).encode()).hexdigest()
    reports=project/'reports';reports.mkdir(exist_ok=True);cache=project/'evaluation-cache';cache.mkdir(exist_ok=True)
    results={}
    for label in ['best','latest']:
        ref=state.get(label)
        if not ref:continue
        key=hashlib.sha256((ref['sha256']+signature).encode()).hexdigest();cached=cache/(key+'.json')
        if cached.is_file():result=json.loads(cached.read_text(encoding='utf-8'))
        else:
            checkpoint=store.download(ref,project/(label+'.pt'))
            metrics=evaluator(checkpoint,data['evaluationData'],data['checks'],data['validationData'],project/(label+'-details.json'),device=device)
            if not all(isinstance(v,(int,float)) and math.isfinite(v) for v in metrics.values()):raise ResearchError('COLAB_NONFINITE_METRICS')
            result={'checkpointSha256':ref['sha256'],'metrics':metrics,'freshConversationChecks':generate(checkpoint,probes,device)}
            temporary=cached.with_suffix('.tmp');temporary.write_text(json.dumps(result,indent=2),encoding='utf-8');temporary.replace(cached)
        results[label]=result
    report={'format':'nebula-colab-v9-evaluation-1','sourceRevision':store.revision,'sourceRound':state['round'],'checkpointWrites':False,'trainingChanges':False,'websiteUpdated':False,'freshCasesExcludedFromKnownData':True,'comparison':comparison(results),'results':results}
    path=reports/f"round-{state['round']:04d}-{store.revision[:12]}.json";path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    markdown=['# Nebula V9 Colab evaluation',f"Saved Kaggle round: {state['round']}",'','These reports do not change training or publish a model. Lower loss is better; generated text still needs human inspection.','']
    for label,result in results.items():
        markdown.extend([f'## {label.title()} snapshot','',json.dumps(result['metrics']), ''])
        for answer in result['freshConversationChecks']['answers']:
            for message in answer['messages']:
                markdown.extend(['**'+('User' if message['role']=='user' else 'Earlier assistant')+':** '+message['content'],''])
            markdown.extend(['**Nebula:** '+answer['reply'],''])
    human=path.with_suffix('.md');human.write_text('\n'.join(markdown),encoding='utf-8')
    print(json.dumps({'colabEvaluationSaved':True,'sourceRound':state['round'],'report':str(path),'comparison':report['comparison'],'trainingChanged':False,'publicWebsiteUpdated':False}),flush=True)
    return path,human

def watch(project,repo,token,hours=8,max_rounds=20,poll_seconds=60,device='cuda',on_report=None,store_factory=ReadOnlyStore,clock=time.monotonic,sleep=time.sleep,run_evaluation=evaluate_snapshot):
    if not 0<hours<=8 or not 1<=max_rounds<=20 or not 15<=poll_seconds<=300:raise ValueError('Use at most eight hours/twenty reports and a 15-300 second poll interval')
    if device=='cuda' and not torch.cuda.is_available():raise ResearchError('COLAB_GPU_REQUIRED')
    torch.set_num_threads(2);project=Path(project);project.mkdir(parents=True,exist_ok=True)
    record=project/'seen-snapshots.json';seen=set(json.loads(record.read_text(encoding='utf-8'))) if record.exists() else set()
    deadline=clock()+hours*3600;completed=0
    try:
        while clock()<deadline and completed<max_rounds:
            if (project/'STOP_EVALUATING').exists():break
            try:
                store=store_factory(repo,token,'nebula-v9-curriculum');state=store.state()
                if state is None:print(json.dumps({'colabWaitingFor':'V9_FIRST_BACKUP'}),flush=True)
                else:
                    key=hashlib.sha256(json.dumps({'round':state['round'],'best':state.get('best',{}).get('sha256'),'latest':state.get('latest',{}).get('sha256')},sort_keys=True).encode()).hexdigest()
                    if key not in seen:
                        paths=run_evaluation(store,state,project,device=device);seen.add(key);completed+=1
                        record.write_text(json.dumps(sorted(seen)),encoding='utf-8')
                        if on_report:on_report(*paths)
                    else:print(json.dumps({'colabWaitingFor':'NEW_KAGGLE_CHECKPOINT','lastSavedRound':state['round']}),flush=True)
            except ResearchError as error:
                if error.code in ['V4_STORAGE_CONFIGURATION_MISSING','V4_STORAGE_ACCESS_FAILED','HF_REPOSITORY_MUST_BE_PRIVATE','COLAB_REQUIRES_V9_SNAPSHOT']:raise
                print(json.dumps({'colabEvaluationDeferred':True,'reason':error.code,'trainingUnaffected':True}),flush=True)
            if completed>=max_rounds:break
            remaining=min(poll_seconds,max(0,deadline-clock()))
            # Short sleeps keep notebook interrupt and graceful-stop controls responsive.
            for _ in range(math.ceil(remaining)):
                if clock()>=deadline or (project/'STOP_EVALUATING').exists():break
                sleep(min(1,max(0,deadline-clock())))
    except KeyboardInterrupt:print('Evaluator stopped. Kaggle training continues.',flush=True)
    print(json.dumps({'colabEvaluatorFinished':True,'reportsThisSession':completed,'trainingChanged':False}),flush=True)
    return completed
