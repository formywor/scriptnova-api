"""Inference-only greedy/sampled development probes, without repetition penalties."""
from collections import Counter
import torch
from v27_subword_model import PAD,BOS,EOS,SYSTEM,USER,ASSISTANT

@torch.inference_mode()
def complete(model,tokenizer,prompt,temperature=0.,top_p=.9,seed=28,limit=80):
    model.eval();device=next(model.parameters()).device
    ids=[BOS]+tokenizer.encode(prompt,add_special_tokens=False).ids;out=[]
    if len(ids)>=model.config.context:raise ValueError('Probe exceeds context')
    generator=torch.Generator(device=device).manual_seed(seed)
    for _ in range(min(limit,model.config.context-len(ids))):
        logits=model(torch.tensor([ids+out],device=device))[0,-1].float()
        logits[[PAD,BOS,SYSTEM,USER,ASSISTANT]]=-float('inf')
        if temperature==0:token=int(logits.argmax())
        else:
            probabilities=(logits/temperature).softmax(-1)
            values,index=probabilities.sort(descending=True)
            mask=values.cumsum(-1)-values>top_p;values[mask]=0
            values/=values.sum()
            token=int(index[torch.multinomial(values,1,generator=generator)])
        if token==EOS:break
        out.append(token)
    return tokenizer.decode(out,skip_special_tokens=True),len(out)


def decode_report(model,tokenizer,prompts):
    results=[]
    for prompt in prompts:
        for name,temperature in [('greedy',0.),('sample-0.7',.7)]:
            reply,count=complete(model,tokenizer,prompt,temperature=temperature)
            words=reply.casefold().split();grams=[tuple(words[i:i+3]) for i in range(max(0,len(words)-2))]
            repeated=sum(n-1 for n in Counter(grams).values())/max(1,len(grams))
            results.append(dict(prefix=prompt,continuation=reply,mode=name,temperature=temperature,topP=.9,
                seed=28,generatedSubwordTokens=count,repeatedTrigramFraction=round(repeated,4),
                grade='pending-human-review',notice='Sampled fluency and lower repetition do not establish correctness.'))
    return results
