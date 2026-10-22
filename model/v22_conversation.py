"""Bounded tutor SFT plus general-language replay, with protected V18 control."""
import copy
import gc
import json
import math
import os
import random
import re
import time
from collections import Counter
from pathlib import Path

import numpy as np
import requests
import torch
import torch.nn.functional as F
from v18_stream import Hub,RemotePool,deserialize,serialize,sha,digest,emit,PROBES
from v18_foundation_control import read_source,heldout,SOURCE_REVISION
from v18_decode_probe import generate,compare
from v22_conversation_data import lessons,window,collate,exact_grade,grade_content,curriculum

DEFAULT={'sourceRepo':'iiidevv/nebula-raw-training','sourceRun':'nebula-v21-curriculum',
 'sourceRevision':'47cba3a6b8af6554af78c986900c7936eac50062','expectedSourceUpdates':2400,
 'rawCorpusRun':'nebula-v18-raw-1gb','rawCorpusRevision':SOURCE_REVISION,'updates':4000,'seed':220221,
 'learningRate':.000015,'warmup':60,'batch':8,'microbatch':1,'saveEvery':100,
 'maxSessionHours':4}
MOJIBAKE=('\ufffd','\u00e2\u20ac','\u00c3\u00a2','\u00ef\u00bf\u00bd','\u00f0\u0178')
OPEN=['Hello! What can you help me with?','Explain why ice melts.',
      'Write a thank-you note to a neighbor.','Which should I choose?',
      'My name is Iris. My scarf is purple. What color is my scarf?',
      'I want to learn something new. Can you help me get started?',
      'I have ten minutes to learn drawing. Suggest a first step.',
      "Nora has a green cup. Omar has a white cup. What color is Omar's cup?",
      'Write a friendly message thanking Luis for fixing my bicycle.']


class TutorStore(Hub):
    def __init__(self,repo,token,run):
        from huggingface_hub import HfApi
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'nebula-v22-[\w-]{1,45}',run):
            raise ValueError('Use a separate nebula-v22 output run')
        self.repo=repo;self.token=token;self.prefix='experiments/'+run+'/'
        self.api=HfApi(token=token);self.session=requests.Session()
        if self.api.whoami()['name']!=repo.split('/')[0]:raise ValueError('Use your own output namespace')
        info=self.api.model_info(repo)
        if info.private is not False:raise ValueError('The configured output repository must be public')
        self.revision=info.sha


def signature(config):
    root=Path(__file__).parent
    code=''.join((root/name).read_text(encoding='utf-8') for name in
                 ['v22_conversation.py','v22_conversation_data.py','v21_curriculum_data.py','v20_generalize_data.py','v19_tutor_data.py','nebula.py','v18_stream.py','v18_decode_probe.py','v18_foundation_control.py'])
    return digest({'config':config,'codeSha256':sha(code.encode())})


def raw_clean(pool,step,batch,seed):
    result=[];rejected=0
    for attempt in range(32):
        for x,y in pool.batch(step,batch-len(result),seed+attempt*100003):
            # Inspect text without changing the actual packed token stream. A window may cut a UTF-8 character.
            text=bytes(int(v) for v in x if v<256).decode('utf-8',errors='ignore')
            if any(pattern in text for pattern in MOJIBAKE):rejected+=1;continue
            result.append((x,y))
        if len(result)==batch:return result,rejected
    raise ValueError('Could not sample a clean raw batch; last confirmed checkpoint remains saved')


def tutor_batch(rows,windows,step,batch,seed):
    families={}
    for i,row in enumerate(rows):families.setdefault(row['family'],[]).append(i)
    rng=random.Random(seed+step*7919);pairs=[];counts=Counter()
    names,weights=curriculum(step)
    replay=sorted(n for n in families if n.startswith('replay/'))
    for _ in range(batch):
        family=rng.choice(replay) if rng.random()<.15 else rng.choices(names,weights=weights,k=1)[0]
        index=rng.choice(families[family]);pairs.append(windows[index]);counts[family]+=1
    return pairs,dict(counts)


@torch.inference_mode()
def tutor_loss(model,windows):
    total=0.;targets=0;device=next(model.parameters()).device;model.eval()
    for pair in windows:
        x,y=collate([pair]);count=int((y!=-100).sum())
        loss=F.cross_entropy(model(x.to(device)).float().flatten(0,1),y.to(device).flatten(),reduction='sum')
        if not torch.isfinite(loss):raise ValueError('Non-finite held-out tutor loss')
        total+=float(loss);targets+=count
    return {'loss':total/targets,'assistantTargets':targets}


def evaluate(model,cases,mixed_pairs,label,updates,full=True):
    emit(v22EvaluationStarted=label,additionalUpdates=updates)
    validations=[window(c['messages']+[{'role':'assistant','content':c['expected']}],model.config.context) for c in cases]
    losses={'heldoutMixed':heldout(model,mixed_pairs),'heldoutTutor':tutor_loss(model,validations)}
    answers=[];axes={}
    for i,case in enumerate(cases):
        # Greedy, strict full-answer checks. Correct words inside an unrelated paragraph do not pass.
        prompt=case['messages'][-1]['content']
        if len(case['messages'])==2:
            answer=generate(model,prompt,'chat',0,1,0,48)
        else:
            # Nebula.reply preserves the full multi-turn history and uses the same special-token convention.
            text=model.reply(case['messages'],max_tokens=48,temperature=0)
            answer={'reply':text,'stopReason':'see-generated-text'}
        correct=exact_grade(answer['reply'],case['expected'],case.get('field')=='code')
        content=grade_content(answer['reply'],case['expected'],case.get('field','value'))
        axis=axes.setdefault(case['axis'],{'correct':0,'cases':0,'contentVerifiedCorrect':0,'contentPendingReview':0})
        axis['cases']+=1;axis['correct']+=int(correct)
        axis['contentVerifiedCorrect']+=int(content['verifiedContentCorrect'] is True)
        axis['contentPendingReview']+=int(content['verifiedContentCorrect'] is None)
        answers.append({**case,**answer,'exactCorrect':correct,'contentCheck':content})
        if (i+1)%8==0:emit(v22ExactProgress=i+1,total=len(cases))
    report={'stage':label,'additionalUpdates':updates,**losses,'exactCorrect':sum(a['exactCorrect'] for a in answers),
            'exactCases':len(cases),'byAxis':axes,'exactAnswers':answers,
            'contentVerifiedCorrect':sum(a['contentCheck']['verifiedContentCorrect'] is True for a in answers),
            'contentVerifiedIncorrect':sum(a['contentCheck']['verifiedContentCorrect'] is False for a in answers),
            'contentPendingReview':sum(a['contentCheck']['verifiedContentCorrect'] is None for a in answers),
            'contentRubric':'Only exact values or explicitly recognized complete sentence forms; arbitrary prose stays pending.',
            'qualityApproved':False,'humanVerified':False}
    if full:
        report['generation']=compare(model,128,modes=[dict(name='greedy',temperature=0.,top_p=1.,seeds=[0]),
            dict(name='sample-0.7',temperature=.7,top_p=.9,seeds=[17])],raw=PROBES,questions=OPEN)
    emit(v22EvaluationSummary={k:v for k,v in report.items() if k not in ['exactAnswers','generation']})
    return report


def run_tutor(output_run='nebula-v22-conversation',config=None,device='cuda',clock=None):
    clock=time.monotonic if clock is None else clock;config=copy.deepcopy(DEFAULT if config is None else config)
    if set(config)!=set(DEFAULT) or not 1<=config['updates']<=5000 or not 0<config['maxSessionHours']<=8:
        raise ValueError('Invalid tutor experiment settings')
    for name in ['batch','microbatch','saveEvery','warmup']:
        if type(config[name]) is not int or config[name]<1:raise ValueError('Invalid '+name)
    if config['microbatch']>config['batch'] or not 0<config['learningRate']<=.001:raise ValueError('Invalid batch/learning rate')
    if device=='cuda' and not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle NVIDIA GPU')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise RuntimeError('Enable Kaggle secret NEBULA_HF_TOKEN')
    source,source_state=read_source(config['sourceRepo'],config['sourceRun'],config['sourceRevision'],token)
    if source_state['updates']!=config['expectedSourceUpdates']:raise ValueError('Pinned source checkpoint step mismatch')
    corpus_source,corpus_state=read_source(config['sourceRepo'],config['rawCorpusRun'],config['rawCorpusRevision'],token)
    output=TutorStore(config['sourceRepo'],token,output_run);state=output.state();run_signature=signature(config)
    if state and state.get('signature')!=run_signature:raise ValueError('Use identical notebook/settings to resume, or choose a NEW output run')
    if state and state.get('complete'):
        emit(v22AlreadyComplete=True,additionalUpdates=state['updates'])
        return json.loads(output.read_entry(state['finalReport']))
    rows,cases,data_report=lessons(config['seed'])
    if state is None:
        state={'format':'nebula-v22-conversation-1','signature':run_signature,'config':config,'updates':0,
             'sourceRevision':source.revision,'sourceWeightSha256':source_state['working']['sha256'],
             'sourceUpdates':source_state['updates'],'complete':False,'qualityApproved':False,'publicWebsiteUpdated':False,
             'uniqueTextBytes':corpus_state['uniqueTextBytes'],'corpusComplete':True,
             'rawCorpusRevision':corpus_source.revision,'rawCorpusRun':config['rawCorpusRun'],
             'corpusNotice':'References the existing pinned V18 corpus; the original data is not duplicated.',
             'counters':{'tutorUpdates':0,'rawUpdates':0,'assistantTargets':0,'rawTargets':0,'filteredRawWindows':0,'familyExamples':{}}}
        state=output.publish(state,{
            'practice':('tutor-practice.jsonl',b'\n'.join(json.dumps(row).encode() for row in rows)),
            'benchmark':('heldout-benchmark.json',json.dumps(cases,indent=2).encode()),
            'dataReport':('data-report.json',json.dumps(data_report,indent=2).encode())})
    emit(v22Data=data_report,practiceMix={'tutorUpdatesPercent':70,'rawUpdatesPercent':30},
         sourceCheckpoint=source_state['updates'],sourceRun=config['sourceRun'],
         evaluationPolicy='baseline-and-final-only',sourceIsStoryControl=False,sourceModelResized=False,publicWebsiteUpdated=False)
    model,payload=deserialize(output.read_entry(state['working']) if state.get('working') else source.read_entry(source_state['working']))
    windows=[window(r['messages'],model.config.context) for r in rows]
    model.to(device);torch.set_num_threads(2)
    amp=device=='cuda';bf16=amp and torch.cuda.get_device_capability(0)[0]>=8 and torch.cuda.is_bf16_supported()
    dtype=torch.bfloat16 if bf16 else torch.float16
    scaler=torch.amp.GradScaler('cuda',enabled=amp and not bf16,init_scale=1024)
    optimizer=torch.optim.AdamW(model.parameters(),lr=config['learningRate'],weight_decay=.01)
    if state.get('working'):
        training=payload['trainingState']
        if training['signature']!=run_signature or training['updates']!=state['updates']:raise ValueError('Tutor checkpoint mismatch')
        optimizer.load_state_dict(training['optimizer'])
        if scaler.is_enabled() and training.get('scaler'):scaler.load_state_dict(training['scaler'])
        del training
    del payload;gc.collect()
    raw=RemotePool(corpus_source,corpus_state['corpus']['train'],model.config.context,64)
    valid=RemotePool(corpus_source,corpus_state['corpus']['validation'],model.config.context,1)
    mixed_pairs=[valid.batch(i,1,880019)[0] for i in range(16)]
    del valid;gc.collect()
    emit(v22TrainingSetup=True,parameters=sum(p.numel() for p in model.parameters()),trainingGPUs=1,
         precision=str(dtype) if amp else 'float32',optimizerRestored=bool(state.get('working')),
         optimizerResetReason=None if state.get('working') else 'Changed generalization curriculum; V21 weights reused with a lower peak learning rate.',
         originalWeightsPreserved=True)
    if not state.get('baselineReport'):
        baseline=evaluate(model,cases,mixed_pairs,'baseline-v21-final',0)
        state=output.publish(state,{'baselineReport':('baseline.json',json.dumps(baseline,indent=2).encode())})
    baseline=json.loads(output.read_entry(state['baselineReport']))
    started=clock();last_saved=state['updates'];bad=0;interrupted=False
    def save():
        nonlocal state,last_saved
        stream=serialize(model,{'experimental':True,'qualityApproved':False,'sourceUpdates':source_state['updates'],
            'additionalUpdates':state['updates']},{'signature':run_signature,'updates':state['updates'],
            'optimizer':optimizer.state_dict(),'scaler':scaler.state_dict()})
        try:state=output.publish(state,{'working':('working.pt',stream.getbuffer())})
        finally:stream.close()
        last_saved=state['updates'];emit(v22CheckpointConfirmed=True,additionalUpdates=last_saved)
    try:
        while state['updates']<config['updates'] and clock()-started<config['maxSessionHours']*3600:
            step=state['updates'];is_tutor=step%10<7
            if is_tutor:pairs,families=tutor_batch(rows,windows,step,config['batch'],config['seed']);rejected=0
            else:pairs,rejected=raw_clean(raw,step,config['batch'],config['seed']);families={}
            rate=config['learningRate']*min(1.,(step+1)/config['warmup'])*(.2+.8*.5*(1+math.cos(math.pi*step/config['updates'])))
            for group in optimizer.param_groups:group['lr']=rate
            denominator=sum(int((y!=-100).sum()) for _,y in pairs)
            model.train();optimizer.zero_grad(set_to_none=True);loss_value=0.
            for offset in range(0,len(pairs),config['microbatch']):
                x,y=collate(pairs[offset:offset+config['microbatch']]);x=x.to(device);y=y.to(device)
                with torch.autocast('cuda',dtype=dtype,enabled=amp):
                    loss=F.cross_entropy(model(x).flatten(0,1),y.flatten(),reduction='sum')/denominator
                if not torch.isfinite(loss):raise ValueError('Non-finite loss; previous confirmed checkpoint preserved')
                loss_value+=float(loss.detach());scaler.scale(loss).backward()
            scaler.unscale_(optimizer);norm=torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
            if not torch.isfinite(norm):
                bad+=1
                if not scaler.is_enabled() or bad>12:raise ValueError('Non-finite gradients')
                scaler.update(new_scale=scaler.get_scale()/2);continue
            scaler.step(optimizer);scaler.update();bad=0;state['updates']+=1
            counters=state['counters'];counters['tutorUpdates' if is_tutor else 'rawUpdates']+=1
            counters['assistantTargets' if is_tutor else 'rawTargets']+=denominator;counters['filteredRawWindows']+=rejected
            for family,n in families.items():counters['familyExamples'][family]=counters['familyExamples'].get(family,0)+n
            if state['updates']%25==0:
                emit(v22Update=state['updates'],budget=config['updates'],objective='assistant-only' if is_tutor else 'raw-language',
                     loss=round(loss_value,4),learningRate=rate,counters=counters)
            if state['updates']%config['saveEvery']==0:save()
    except KeyboardInterrupt:interrupted=True
    if state['updates']!=last_saved:save()
    if interrupted or state['updates']<config['updates']:
        emit(v22Paused=True,updatesSaved=last_saved,runAgainWithSameSettings=True)
        return state
    final=evaluate(model,cases,mixed_pairs,'tutor-final',state['updates'])
    report={'format':'nebula-v22-conversation-comparison-1','baseline':baseline,'final':final,'counters':state['counters'],
            'sourceRevision':source.revision,'sourceWeightSha256':source_state['working']['sha256'],
            'mixedLossRatioToBaseline':final['heldoutMixed']['loss']/baseline['heldoutMixed']['loss'],
            'qualityApproved':False,'humanVerified':False,'publicWebsiteUpdated':False,
            'interpretation':'Compare complete replies, per-axis strict answers and held-out mixed loss. No automatic promotion. Synthetic tests do not establish broad intelligence.'}
    report['mixedLossRegressionFlag']=report['mixedLossRatioToBaseline']>1.10
    state=output.publish({**state,'complete':True},{'finalReport':('comparison.json',json.dumps(report,indent=2).encode())})
    emit(v22Finished=True,additionalUpdates=state['updates'],exactCorrect=final['exactCorrect'],exactCases=final['exactCases'],
         mixedLossRegressionFlag=report['mixedLossRegressionFlag'],originalWeightsPreserved=True,publicWebsiteUpdated=False,
         reportParts=[p['path'] for p in state['finalReport']['parts']])
    del model,optimizer;gc.collect()
    if amp:torch.cuda.empty_cache()
    return report
