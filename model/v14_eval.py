"""Small fixed/rotating diagnostics, with complete answers and unknown grades preserved."""
import json,random,time
from pathlib import Path
import torch
from nebula import BOS,EOS,load
from rules import with_owner_rules
from verified_grading import local_grade,readable
from v13_data import atomic_json

FIXED=[
 {'category':'open','prompt':'Hello! What can you help me with?'},
 {'category':'identity','prompt':'Tell me your name and what you are.','expected':'Nebula'},
 {'category':'math','prompt':'What is 16 + 27?','number':43},
 {'category':'math','prompt':'I have 5 apples and give 2 away. How many apples do I have left?','number':3},
 {'category':'extraction','prompt':'My name is Keira and my favorite color is amber. What is my favorite color?','expected':'amber'},
 {'category':'open','prompt':'Write a short thank-you note to my neighbor for feeding my cat.'},
 {'category':'open','prompt':'Explain in one sentence why ice melts in a warm room.'},
 {'category':'open','prompt':'Give me two ideas for a quiet indoor hobby.'},
 {'category':'open','prompt':'Which should I choose?'},
 {'category':'open','prompt':'Rewrite this politely: Give me my notebook back now.'},
 {'category':'open','prompt':'What is inside my closed backpack?'},
 {'category':'extraction','messages':[{'role':'user','content':'For this exercise, I put a blue scarf in the green box.'},{'role':'assistant','content':'Understood.'},{'role':'user','content':'Which box holds the scarf?'}],'expected':'green'}]
PREFIXES=['A child found a small wooden boat beside the pond.','The rain stopped, and the neighbors opened their windows.','Ice melts when it takes in heat.','A notebook helps a writer keep track of ideas.']

def rotating(seed):
    rng=random.Random(140000+seed);result=[]
    for i in range(3):
        mark=rng.choice(['ochre','indigo','ivory','bronze']);place=rng.choice(['attic','locker','studio','porch']);number=rng.randrange(30,90)
        context=f'Exercise {seed}-{i}: the badge is {mark}, the folder is in the {place}, and the code is {number}.'
        # Two actual turns: the second question follows the model's first generated answer.
        result.append({'category':'extraction','messages':[{'role':'user','content':context+' What color is the badge? Answer with only the color.'}],'expected':mark,'followup':{'content':'Where is the folder? Answer with only the location.','expected':place}})
    return result

@torch.inference_mode()
def completion(model,prefix,maximum=120):
    encoded=[BOS]+list(prefix.encode());device=next(model.parameters()).device;tokens=torch.tensor([encoded],device=device);result=[];ended=False
    for _ in range(min(maximum,model.config.context-len(encoded))):
        logits=model(tokens)[:,-1,:].clone();end=logits[:,EOS].clone();logits[:,BOS:]=float('-inf');logits[:,EOS]=end;value=int(logits.argmax(-1).item())
        if value==EOS:ended=True;break
        result.append(value);tokens=torch.cat([tokens,torch.tensor([[value]],device=device)],dim=1)
    return {'prefix':prefix,'continuation':bytes(result).decode('utf-8',errors='replace'),'endedNaturally':ended,'requiresSemanticReview':True}

def evaluate(path,output,stage,seed=0,device=None):
    started=time.monotonic();torch.set_num_threads(2);model,metadata=load(path)
    device=device or ('cuda' if torch.cuda.is_available() else 'cpu');model.to(device);model.eval();answers=[];raw=[]
    with torch.inference_mode():
        for prefix in PREFIXES:
            raw.append(completion(model,prefix))
            print(json.dumps({'v14ProbeProgress':'raw-completion','completed':len(raw),'total':len(PREFIXES)}),flush=True)
        for index,case in enumerate(FIXED+rotating(seed),1):
            messages=case.get('messages') or [{'role':'user','content':case['prompt']}]
            reply=model.reply(with_owner_rules(messages),max_tokens=192,temperature=0)
            grade=local_grade(case,reply)
            answers.append({'suite':'fixed' if index<=len(FIXED) else 'rotating','case':case,'messages':messages,'reply':reply,'grade':grade})
            if case.get('followup'):
                next_case={'category':'extraction','messages':messages+[{'role':'assistant','content':reply},{'role':'user','content':case['followup']['content']}],'expected':case['followup']['expected']}
                follow=model.reply(with_owner_rules(next_case['messages']),max_tokens=192,temperature=0)
                answers.append({'suite':'rotating-followup','case':next_case,'messages':next_case['messages'],'reply':follow,'grade':local_grade(next_case,follow)})
            print(json.dumps({'v14ProbeProgress':'questions','completed':index,'total':len(FIXED)+3}),flush=True)
    summary={'stage':stage,'stageSteps':metadata.get('stageSteps',0),'generationCases':len(answers),'localPass':sum(r['grade']['passed'] is True for r in answers),'localFail':sum(r['grade']['passed'] is False for r in answers),'pendingSemanticReview':sum(r['grade']['passed'] is None for r in answers),'readableReplies':sum(readable(r['reply']) for r in answers),'rawCompletions':len(raw),'humanVerified':False,'qualityApproved':False,'externalReviewCalls':0,'seconds':round(time.monotonic()-started,1),'notice':'Exact local checks are limited; unknown replies remain pending. Raw continuation quality requires inspection. Probe answers never enter training.'}
    atomic_json(output,{'report':summary,'answers':answers,'rawCompletions':raw,'checkpointMetadata':metadata})
    print(json.dumps({'v14ProbeReport':summary,'report':str(output)}),flush=True)
    del model
    if torch.cuda.is_available():torch.cuda.empty_cache()
    return summary

def blocked_prompts():
    return {m['content'].casefold() for case in FIXED for m in case.get('messages',[{'role':'user','content':case.get('prompt','')}]) if m['role']=='user'}
