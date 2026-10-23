"""Read-only inspection of an immutable V28 checkpoint; only reports are written."""
import gc
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
import requests
import torch
from v18_stream import Hub,sha,digest,emit
from v27_subword_model import restore,PAD,BOS,EOS,SYSTEM,USER,ASSISTANT

REPO='iiidevv/nebula-raw-training'
SOURCE_RUN='nebula-v28-longrun'
REVISION='9cfc225eae2fefe1fee5e01d77690487172d6dce'
PROMPTS=[
 ('everyday','Mara put her wet coat beside the heater. After a few hours, the coat'),
 ('everyday','Jon forgot his umbrella, so he checked the sky before'),
 ('science','Water turns into ice when'),
 ('science','A plant needs sunlight because'),
 ('practical','To wash your hands, first'),
 ('practical','Before crossing a busy road, you should'),
 ('context','Leena has a yellow notebook. Tomas has a blue notebook. Tomas owns the'),
 ('context','The package label reads Q7M4. Copying the label onto the receipt, she wrote'),
 ('explanation','A bicycle moves when the rider pushes the pedals, which'),
 ('explanation','The kitchen floor was slippery because someone had spilled water. To make it safe,'),
 ('dialogue','"I have only ten minutes to practice drawing," said Nia. Her teacher replied, "'),
 ('story','A small dog found a lost glove beside a park bench. Its owner')]

class ReportStore(Hub):
    def __init__(self,repo,token,run):
        from huggingface_hub import HfApi
        if not re.fullmatch(r'nebula-v28-inspect-[\w-]{1,35}',run):raise ValueError('Use a separate inspection output prefix')
        self.repo=repo;self.token=token;self.prefix='experiments/'+run+'/'
        self.api=HfApi(token=token);self.session=requests.Session()
        if self.api.whoami()['name']!=repo.split('/')[0]:raise ValueError('Use your own namespace')
        info=self.api.model_info(repo)
        if info.private is not False:raise ValueError('Reports use the existing public repository')
        self.revision=info.sha
    def publish(self,state,blobs=None,root_readme=None):
        if root_readme or any(k not in ['report'] for k in (blobs or {})):raise ValueError('Inspection may save reports only')
        if any(k in state for k in ['working','foundationWorking','conversationWorking','tokenizer','corpus']):raise ValueError('No model/data writes in inspection state')
        return super().publish(state,blobs)


def read_source(token):
    from huggingface_hub import HfApi
    source=object.__new__(Hub);source.repo=REPO;source.token=token
    source.prefix='experiments/'+SOURCE_RUN+'/'
    source.api=HfApi(token=token);source.session=requests.Session();source.revision=REVISION
    state=source.state()
    if not state or not state.get('foundationComplete') or state.get('steps',{}).get('foundation')!=30000:
        raise ValueError('Pinned V28 foundation stage must be complete at 30000 updates')
    return source,state


@torch.inference_mode()
def continuation(model,tokenizer,prompt,temperature,seed,limit,deadline,clock):
    device=next(model.parameters()).device;ids=[BOS]+tokenizer.encode(prompt,add_special_tokens=False).ids;out=[]
    if len(ids)>=model.config.context:raise ValueError('Prompt exceeds context')
    generator=torch.Generator(device=device).manual_seed(seed);stop='context-budget' if model.config.context-len(ids)<limit else 'token-budget'
    for _ in range(min(limit,model.config.context-len(ids))):
        if clock()>=deadline:stop='time-budget';break
        logits=model(torch.tensor([ids+out],device=device))[0,-1].float()
        logits[[PAD,BOS,SYSTEM,USER,ASSISTANT]]=-float('inf')
        if temperature==0:token=int(logits.argmax())
        else:
            probabilities=(logits/temperature).softmax(-1)
            values,index=probabilities.sort(descending=True)
            values[values.cumsum(-1)-values>.9]=0;values/=values.sum()
            token=int(index[torch.multinomial(values,1,generator=generator)])
        if token==EOS:stop='eos';break
        out.append(token)
    reply=tokenizer.decode(out,skip_special_tokens=True)
    words=reply.casefold().split();grams=[tuple(words[i:i+3]) for i in range(max(0,len(words)-2))]
    repeated=sum(n-1 for n in Counter(grams).values())/max(1,len(grams))
    return dict(continuation=reply,generatedSubwordTokens=len(out),stopReason=stop,
        repeatedTrigramFraction=round(repeated,4),replacementCharacters=reply.count('\ufffd'),grade='pending-human-review')


def run(output_run='nebula-v28-inspect-1',device='cuda',seconds=900,limit=48,prompts=None,clock=None):
    if not 60<=seconds<=1800 or not 8<=limit<=96:raise ValueError('Use a bounded inspection budget')
    clock=time.monotonic if clock is None else clock;deadline=clock()+seconds
    prompts=PROMPTS if prompts is None else prompts
    if device=='cuda' and not torch.cuda.is_available():raise ValueError('Enable an NVIDIA GPU for this short inspection')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise ValueError('Enable NEBULA_HF_TOKEN for report saving')
    source,state=read_source(token);destination=ReportStore(REPO,token,output_run)
    settings=dict(sourceRevision=REVISION,weightSha256=state['foundationWorking']['sha256'],tokenizerSha256=state['tokenizer']['sha256'],
        prompts=prompts,limit=limit,seed=28117,modes=[0.,.7],topP=.9,precision='float32',
        engine=sha(Path(__file__).read_bytes()+Path(__file__).with_name('v27_subword_model.py').read_bytes()))
    sig=digest(settings);saved=destination.state()
    if saved and saved.get('signature')!=sig:raise ValueError('Settings changed; choose a new inspection output name')
    report=json.loads(destination.read_entry(saved['report'])) if saved else dict(format='nebula-v28-inspection-1',settings=settings,answers=[],
        complete=False,qualityApproved=False,humanVerified=False,trainingStarted=False,publicWebsiteUpdated=False,
        rubric='Read every reply for relevance, correctness, coherent meaning and repetition. No automatic semantic pass; all replies remain pending.',
        notice='Plain-text continuation probes of a foundation model, not a trained assistant benchmark. Historical public exposure is unknown. Outputs never enter training.')
    if report['complete']:
        emit(v28InspectionAlreadyComplete=True,report=report);return report
    from tokenizers import Tokenizer
    tokenizer=Tokenizer.from_str(source.read_entry(state['tokenizer']).decode())
    emit(v28InspectionLoading=True,trainingStarted=False,sourceUpdates=30000,weightSha256=state['foundationWorking']['sha256'])
    model,training=restore(source.read_entry(state['foundationWorking']),state['tokenizer']['sha256'])
    del training;gc.collect();model.to(device);model.eval();torch.set_num_threads(2)
    last_saved=len(report['answers']);interrupted=False
    def save():
        nonlocal saved,last_saved
        saved=destination.publish(dict(signature=sig,trainingStarted=False,publicWebsiteUpdated=False),
            {'report':('inspection.json',json.dumps(report,indent=2).encode())})
        last_saved=len(report['answers']);emit(v28InspectionReportSaved=True,answers=last_saved,complete=report['complete'])
    tasks=[(category,prompt,temperature) for category,prompt in prompts for temperature in [0.,.7]]
    try:
        for index in range(len(report['answers']),len(tasks)):
            if clock()>=deadline:break
            category,prompt,temperature=tasks[index]
            result=continuation(model,tokenizer,prompt,temperature,28117,limit,deadline,clock)
            if result['stopReason']=='time-budget':break # retry incomplete probe on resume
            row=dict(category=category,prefix=prompt,mode='greedy' if temperature==0 else 'sample-0.7',**result)
            report['answers'].append(row);emit(v28InspectionAnswer=row,completed=len(report['answers']),total=len(tasks))
            if len(report['answers'])%4==0:save()
    except KeyboardInterrupt:interrupted=True
    report['complete']=len(report['answers'])==len(tasks)
    if len(report['answers'])!=last_saved or not saved or report['complete']:save()
    emit(v28InspectionFinished=report['complete'],answers=len(report['answers']),total=len(tasks),interrupted=interrupted,
        trainingStarted=False,publicWebsiteUpdated=False)
    return report
