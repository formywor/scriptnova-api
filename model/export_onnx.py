"""Export owned weights to an incremental CPU graph; no external provider needed."""
import argparse,hashlib,json,math
from dataclasses import asdict
from pathlib import Path
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
from nebula import load,pack_prompt,EOS
from rules import with_owner_rules

class CachedNebula(nn.Module):
    def __init__(self,model):super().__init__();self.model=model
    def forward(self,tokens,past_k,past_v):
        m=self.model;c=m.config;n=tokens.shape[1];start=past_k.shape[3]
        positions=torch.arange(n,device=tokens.device)+start
        x=m.token(tokens)+m.position(positions)
        keys=[];values=[]
        allowed=torch.arange(start+n,device=tokens.device)[None,:]<=positions[:,None]
        for i,block in enumerate(m.blocks):
            z=block.norm1(x)
            qkv=F.linear(z,block.self_attn.in_proj_weight,block.self_attn.in_proj_bias).reshape(1,n,3,c.heads,c.width//c.heads).permute(2,0,3,1,4)
            q=qkv[0];k=torch.cat([past_k[i],qkv[1]],dim=2);v=torch.cat([past_v[i],qkv[2]],dim=2)
            scores=torch.matmul(q,k.transpose(-1,-2))/math.sqrt(c.width//c.heads)
            scores=scores.masked_fill(~allowed,-10000.)
            attention=torch.matmul(torch.softmax(scores,dim=-1),v).transpose(1,2).reshape(1,n,c.width)
            x=x+block.self_attn.out_proj(attention)
            x=x+block.linear2(F.gelu(block.linear1(block.norm2(x))))
            keys.append(k);values.append(v)
        return m.output(m.norm(x))[:,-1,:],torch.stack(keys),torch.stack(values)

def session(path):
    import onnxruntime as ort
    options=ort.SessionOptions();options.intra_op_num_threads=1;options.inter_op_num_threads=1
    return ort.InferenceSession(str(path),sess_options=options,providers=['CPUExecutionProvider'])

def reply(runtime,config,messages,max_tokens=256):
    tokens=pack_prompt(messages,config['context']);shape=(config['layers'],1,config['heads'],0,config['width']//config['heads'])
    k=np.empty(shape,dtype=np.float32);v=np.empty(shape,dtype=np.float32);ids=np.array([tokens],dtype=np.int64);out=[]
    for _ in range(min(max_tokens,config['context']-len(tokens))):
        logits,k,v=runtime.run(None,{'tokens':ids,'past_k':k,'past_v':v});scores=logits[0].copy();scores[256:]=-np.inf;scores[EOS]=logits[0,EOS];token=int(scores.argmax())
        if token==EOS:break
        out.append(token);ids=np.array([[token]],dtype=np.int64)
    return bytes(out).decode('utf-8',errors='replace').strip()

def export(checkpoint,output,model_id):
    import onnx
    from onnxruntime.quantization import quantize_dynamic,QuantType
    torch.set_num_threads(2);model,meta=load(checkpoint);wrapper=CachedNebula(model).eval();c=model.config
    destination=Path(output);destination.mkdir(parents=True,exist_ok=True)
    raw=destination/'unquantized.onnx';quant=destination/'quantized.onnx'
    ids=torch.tensor([[256,259,104,105,257,260]]);empty=torch.empty((c.layers,1,c.heads,0,c.width//c.heads))
    with torch.no_grad():
        full=model(ids)[:,-1,:];actual,keys,values=wrapper(ids,empty,empty)
        torch.testing.assert_close(actual,full,rtol=2e-4,atol=2e-5)
        more=torch.tensor([[42]])
        cached,_,_=wrapper(more,keys,values)
        torch.testing.assert_close(cached,model(torch.cat([ids,more],1))[:,-1,:],rtol=2e-4,atol=2e-5)
        torch.onnx.export(wrapper,(ids,empty,empty),str(raw),input_names=['tokens','past_k','past_v'],output_names=['logits','present_k','present_v'],dynamic_axes={'tokens':{1:'sequence'},'past_k':{3:'past'},'past_v':{3:'past'},'present_k':{3:'total'},'present_v':{3:'total'}},opset_version=17,dynamo=False)
    onnx.checker.check_model(str(raw))
    quantize_dynamic(str(raw),str(quant),weight_type=QuantType.QInt8,per_channel=True,op_types_to_quantize=['MatMul'],extra_options={'MatMulConstBOnly':True})
    runtime=session(quant);got=runtime.run(None,{'tokens':ids.numpy(),'past_k':empty.numpy(),'past_v':empty.numpy()})[0]
    error=float(np.max(np.abs(got-full.numpy())))
    if not np.isfinite(got).all() or error>1.:raise ValueError('Quantized logits drifted too far')
    data=quant.read_bytes();parts=[]
    for i,offset in enumerate(range(0,len(data),8*1024*1024)):
        name=model_id+'-'+str(i+1).zfill(2)+'.part';chunk=data[offset:offset+8*1024*1024];(destination/name).write_bytes(chunk);parts.append({'name':name,'bytes':len(chunk),'sha256':hashlib.sha256(chunk).hexdigest()})
    release={'format':'nebula-onnx-1','id':model_id,'config':asdict(c),'parameters':sum(p.numel() for p in model.parameters()),'trainingSteps':meta.get('steps',0),'sourceSha256':hashlib.sha256(Path(checkpoint).read_bytes()).hexdigest(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'parts':parts,'quantized':True,'experimental':True,'probeMaxLogitError':error}
    (destination/'release.json').write_text(json.dumps(release,indent=2),encoding='utf-8')
    print(json.dumps(release),flush=True)
    return release

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--checkpoint',required=True);parser.add_argument('--output',required=True);parser.add_argument('--model-id',required=True);args=parser.parse_args();export(args.checkpoint,args.output,args.model_id)
