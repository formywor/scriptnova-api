"""Inference-only comparison; never updates V18 weights, optimizer or manifest."""
import gc
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone

import requests
import torch
from nebula import BOS, EOS, pack_prompt
from v18_stream import Hub, deserialize, PROBES

MODES = [dict(name='greedy', temperature=0., top_p=1., seeds=[0]),
         dict(name='sample-0.7', temperature=.7, top_p=.9, seeds=[17,43]),
         dict(name='sample-1.0', temperature=1., top_p=.95, seeds=[17,43])]
QUESTIONS = ['Hello! What can you help me with?', 'Explain why ice melts.',
             'Write a thank-you note to a neighbor.', 'Which should I choose?',
             'My name is Iris. My scarf is purple. What color is my scarf?']


def repetition(text):
    words = re.findall(r"\w+",text.casefold())
    grams = [tuple(words[i:i+3]) for i in range(max(0,len(words)-2))]
    counts = Counter(grams)
    return {'words':len(words), 'repeatedTrigramFraction':
            round(sum(n-1 for n in counts.values())/len(grams),4) if grams else 0.,
            'utf8ReplacementCharacters':text.count('\ufffd')}


@torch.inference_mode()
def generate(model, prompt, kind, temperature, top_p, seed, max_bytes=128):
    if kind not in ['raw','chat'] or not 0<=temperature<=2 or not 0<top_p<=1:
        raise ValueError('Invalid generation configuration')
    prefix = ([BOS]+list(prompt.encode('utf-8'))) if kind=='raw' else pack_prompt(
        [{'role':'system','content':'You are Nebula AI.'},{'role':'user','content':prompt}],model.config.context)
    if len(prefix)>=model.config.context:raise ValueError('Prompt leaves no context for generation')
    device=next(model.parameters()).device
    rng=torch.Generator(device=device).manual_seed(seed)
    tokens=torch.tensor([prefix],dtype=torch.long,device=device)
    generated=[];stop='byte-budget';model.eval()
    limit=min(max_bytes,model.config.context-len(prefix))
    for _ in range(limit):
        logits=model(tokens)[0,-1].float().clone()
        # Match the original V18 raw probe's stop-on-any-marker rule.
        # Chat follows Nebula.reply: only EOS may be generated among markers.
        if kind=='chat':
            end=logits[EOS].clone();logits[BOS:]=float('-inf');logits[EOS]=end
        if temperature==0:
            value=int(logits.argmax())
        else:
            values,indices=torch.sort(logits/temperature,descending=True)
            probs=torch.softmax(values,dim=-1)
            remove=probs.cumsum(-1)-probs>=top_p
            values[remove]=float('-inf')
            sampled=torch.multinomial(torch.softmax(values,dim=-1),1,generator=rng)
            value=int(indices[sampled].item())
        if value>=256:
            stop='eos' if value==EOS else 'special-marker';break
        generated.append(value)
        tokens=torch.cat([tokens,torch.tensor([[value]],device=device)],dim=1)
    else:
        if limit<max_bytes:stop='context-limit'
    text=bytes(generated).decode('utf-8',errors='replace')
    return {'reply':text,'generatedBytes':len(generated),'stopReason':stop,
            **repetition(text),'relevanceGrade':'pending-human-review'}


def compare(model, max_bytes=128, modes=MODES, raw=PROBES, questions=QUESTIONS):
    answers=[]
    total=(len(raw)+len(questions))*sum(len(m['seeds']) for m in modes)
    for kind,prompts in [('raw',raw),('chat',questions)]:
        for prompt in prompts:
            for mode in modes:
                for seed in mode['seeds']:
                    result=generate(model,prompt,kind,mode['temperature'],mode['top_p'],seed,max_bytes)
                    answer={'kind':kind,'prompt':prompt,'mode':mode['name'],'seed':seed,
                            'temperature':mode['temperature'],'topP':mode['top_p'],**result}
                    answers.append(answer)
                    print(json.dumps({'decodeProbeProgress':len(answers),'total':total,**answer}),flush=True)
    summaries=[]
    for kind in ['raw','chat']:
        for mode in modes:
            rows=[a for a in answers if a['kind']==kind and a['mode']==mode['name']]
            if rows:summaries.append({'kind':kind,'mode':mode['name'],'cases':len(rows),
                'meanRepeatedTrigramFraction':sum(a['repeatedTrigramFraction'] for a in rows)/len(rows),
                'emptyReplies':sum(not a['reply'].strip() for a in rows),
                'notice':'Less repetition does not establish correctness or relevance.'})
    return {'answers':answers,'summary':summaries,'qualityApproved':False,'humanVerified':False,
            'trainingStarted':False,'publicWebsiteUpdated':False}


def run_probe(repo='iiidevv/nebula-raw-training',run_name='nebula-v18-raw-1gb',
              revision='e167fff3bb27c36c25460fcd4c61915a5b7016ed',expected_updates=10102,
              save_report=True,max_bytes=128):
    if not torch.cuda.is_available():raise RuntimeError('Enable a Kaggle NVIDIA GPU before running this probe.')
    if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'nebula-v18-[\w-]{1,45}',run_name):
        raise ValueError('Invalid repository/run')
    token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
    if not token:raise RuntimeError('Enable Kaggle secret NEBULA_HF_TOKEN.')
    from huggingface_hub import HfApi,CommitOperationAdd
    # Construct a reader without Hub.__init__: no repository creation or manifest writes.
    hub=object.__new__(Hub);hub.repo=repo;hub.token=token;hub.prefix='experiments/'+run_name+'/'
    hub.api=HfApi(token=token);hub.session=requests.Session()
    hub.revision=hub.api.model_info(repo,revision=revision or None).sha
    state=hub.state()
    if not state or not state.get('working'):raise RuntimeError('Saved working checkpoint is missing.')
    if expected_updates is not None and state.get('updates')!=expected_updates:
        raise RuntimeError('Checkpoint step differs from EXPECTED_UPDATES; verify the revision before testing.')
    model,payload=deserialize(hub.read_entry(state['working']))
    del payload;gc.collect()
    torch.set_num_threads(2);model.to('cuda').eval()
    print(json.dumps({'decodeProbeCheckpoint':state['updates'],'revision':hub.revision,
        'weightObjectSha256':state['working']['sha256'],'GPU':torch.cuda.get_device_name(0),
        'precision':'float32','trainingStarted':False}),flush=True)
    report=compare(model,max_bytes)
    report.update(format='nebula-v18-decoding-comparison-1',checkpointUpdates=state['updates'],
        checkpointRevision=hub.revision,weightObjectSha256=state['working']['sha256'],
        generatedAt=datetime.now(timezone.utc).isoformat(),maxGeneratedBytes=max_bytes,
        notice='Synthetic inference probes only. No weight/optimizer updates. No byte repetition penalty applied.')
    if save_report:
        name='decode-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]+'.json'
        path='experiments/'+run_name+'/decode-reports/'+name
        commit=hub.api.create_commit(repo_id=repo,operations=[CommitOperationAdd(
            path_in_repo=path,path_or_fileobj=json.dumps(report,indent=2).encode())],
            commit_message='Save inference-only decoding comparison')
        report['savedReportUrl']='https://huggingface.co/'+repo+'/blob/'+commit.oid+'/'+path
        print(json.dumps({'decodeReportSaved':True,'url':report['savedReportUrl'],
                          'trainingManifestModified':False}),flush=True)
    del model;gc.collect();torch.cuda.empty_cache();hub.session.close()
    return report
