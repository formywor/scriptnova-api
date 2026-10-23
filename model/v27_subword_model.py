"""New randomly initialized subword model; byte checkpoints are incompatible."""
import io
import math
from dataclasses import dataclass,asdict
import torch
from torch import nn

SPECIAL=['<|n27_pad|>','<|n27_bos|>','<|n27_eos|>','<|n27_system|>','<|n27_user|>','<|n27_assistant|>']
PAD,BOS,EOS,SYSTEM,USER,ASSISTANT=range(6)
ROLES={'system':SYSTEM,'user':USER,'assistant':ASSISTANT}
@dataclass
class Config:
    vocab:int=8192
    width:int=768
    heads:int=12
    layers:int=13
    context:int=1024

class Model(nn.Module):
    def __init__(self,config):
        super().__init__();self.config=config
        self.token=nn.Embedding(config.vocab,config.width)
        self.position=nn.Embedding(config.context,config.width)
        self.blocks=nn.ModuleList(nn.TransformerEncoderLayer(config.width,config.heads,config.width*4,
            dropout=0.,activation='gelu',batch_first=True,norm_first=True) for _ in range(config.layers))
        self.norm=nn.LayerNorm(config.width)
        self.output=nn.Linear(config.width,config.vocab,bias=False);self.output.weight=self.token.weight
        self.register_buffer('mask',torch.ones(config.context,config.context,dtype=torch.bool).triu(1),persistent=False)
        self.apply(self.initialize)
        for block in self.blocks:
            nn.init.normal_(block.self_attn.out_proj.weight,std=.02/math.sqrt(2*config.layers))
            nn.init.normal_(block.linear2.weight,std=.02/math.sqrt(2*config.layers))
    @staticmethod
    def initialize(module):
        if isinstance(module,(nn.Linear,nn.Embedding)):
            nn.init.normal_(module.weight,std=.02)
            if getattr(module,'bias',None) is not None:nn.init.zeros_(module.bias)
    def forward(self,tokens):
        n=tokens.shape[1]
        if n>self.config.context:raise ValueError('Context exceeded')
        x=self.token(tokens)+self.position(torch.arange(n,device=tokens.device))
        for block in self.blocks:x=block(x,src_mask=self.mask[:n,:n])
        return self.output(self.norm(x))


def encode_chat(tokenizer,messages,answer_prefix=False):
    tokens=[BOS];learn=[False]
    for message in messages:
        role=message['role'];text=message['content']
        if role not in ROLES or any(s in text for s in SPECIAL):raise ValueError('Invalid chat role or reserved marker')
        ids=tokenizer.encode(text,add_special_tokens=False).ids
        tokens+=[ROLES[role]]+ids+[EOS]
        learn+=[False]+[role=='assistant']*(len(ids)+1)
    if answer_prefix:tokens+=[ASSISTANT];learn+=[False]
    return tokens,learn


def chat_window(tokenizer,messages,context):
    tokens,learn=encode_chat(tokenizer,messages)
    if len(tokens)>context+1:raise ValueError('Complete conversation does not fit')
    x=torch.tensor(tokens[:-1],dtype=torch.long)
    y=torch.tensor([v if flag else -100 for v,flag in zip(tokens[1:],learn[1:])],dtype=torch.long)
    if not (y!=-100).any():raise ValueError('No assistant targets')
    return x,y


def checkpoint(model,training,tokenizer_sha):
    if any(not torch.isfinite(p).all() for p in model.parameters()):raise ValueError('Nonfinite checkpoint')
    stream=io.BytesIO()
    torch.save({'format':'nebula-v27-subword-1','config':asdict(model.config),'model':model.state_dict(),
        'tokenizerSha256':tokenizer_sha,'training':training},stream)
    return stream


def restore(blob,tokenizer_sha):
    value=torch.load(io.BytesIO(blob),map_location='cpu',weights_only=True)
    if value.get('format')!='nebula-v27-subword-1' or value['tokenizerSha256']!=tokenizer_sha:
        raise ValueError('Incompatible model/tokenizer; no byte checkpoint conversion')
    model=Model(Config(**value['config']));model.load_state_dict(value['model'])
    return model,value['training']


@torch.inference_mode()
def generate(model,tokenizer,prompt,chat=False,limit=96):
    model.eval()
    ids=encode_chat(tokenizer,[{'role':'user','content':prompt}],True)[0] if chat else [BOS]+tokenizer.encode(prompt).ids
    if len(ids)>=model.config.context:raise ValueError('Probe too long')
    device=next(model.parameters()).device;out=[]
    for _ in range(min(limit,model.config.context-len(ids))):
        x=torch.tensor([ids+out],device=device)
        logits=model(x)[0,-1].float();logits[[PAD,BOS,SYSTEM,USER,ASSISTANT]]=-float('inf')
        token=int(logits.argmax())
        if token==EOS:break
        out.append(token)
    return tokenizer.decode(out,skip_special_tokens=True)
