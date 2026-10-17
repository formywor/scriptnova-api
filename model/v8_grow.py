"""Widen repeated channels and append zero-residual blocks, retaining owned weights."""
from dataclasses import asdict
import torch
from nebula import Config,Nebula,load,save

TARGET=Config(width=768,heads=24,layers=14,context=1024)

def grow_model(original,target=TARGET):
    old=original.config
    factor=target.width//old.width
    if factor<1 or target.width!=old.width*factor or target.heads!=old.heads*factor or target.context!=old.context or target.layers<old.layers:
        raise ValueError('Expansion requires repeated channels/heads, the same context, and retained depth')
    original=original.cpu().eval()
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(20261018);grown=Nebula(target)
    with torch.no_grad():
        grown.token.weight.copy_(original.token.weight.repeat(1,factor))
        grown.position.weight.copy_(original.position.weight.repeat(1,factor))
        for before,after in zip(original.blocks,grown.blocks):
            for name in ['norm1','norm2']:
                src=getattr(before,name);dst=getattr(after,name)
                dst.weight.copy_(src.weight.repeat(factor));dst.bias.copy_(src.bias.repeat(factor))
            q,k,v=before.self_attn.in_proj_weight.chunk(3,0)
            after.self_attn.in_proj_weight.copy_(torch.cat([part.repeat(factor,factor)/factor for part in [q,k,v]],0))
            after.self_attn.in_proj_bias.copy_(torch.cat([part.repeat(factor) for part in before.self_attn.in_proj_bias.chunk(3,0)],0))
            for src,dst in [(before.self_attn.out_proj,after.self_attn.out_proj),(before.linear1,after.linear1),(before.linear2,after.linear2)]:
                dst.weight.copy_(src.weight.repeat(factor,factor)/factor);dst.bias.copy_(src.bias.repeat(factor))
        for block in grown.blocks[old.layers:]:
            block.self_attn.out_proj.weight.zero_();block.self_attn.out_proj.bias.zero_();block.linear2.weight.zero_();block.linear2.bias.zero_()
        # Tied embeddings sum across the copied channels; compensate at final norm.
        grown.norm.weight.copy_(original.norm.weight.repeat(factor)/factor)
        grown.norm.bias.copy_(original.norm.bias.repeat(factor)/factor)
    grown.eval()
    probe=torch.randint(0,256,(1,min(16,old.context)),generator=torch.Generator().manual_seed(72))
    with torch.no_grad():torch.testing.assert_close(grown(probe),original(probe),rtol=2e-4,atol=2e-5)
    return grown

def grow_checkpoint(source,destination):
    original,meta=load(source);grown=grow_model(original)
    details={'originalConfig':asdict(original.config),'config':asdict(TARGET),'parameters':sum(p.numel() for p in grown.parameters()),'forwardPreservedWithinTolerance':True}
    save(grown,destination,{**meta,'growth100M':details,'trainingStateIncluded':False,'qualityApproved':False,'experimental':True})
    return details
