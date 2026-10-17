"""Increase owned model depth while initially preserving its forward function."""
from dataclasses import asdict
import torch
from nebula import Config,Nebula,load,save

def grow_model(model,layers):
    if not model.config.layers<=layers<=model.config.layers+8:raise ValueError('Growth must add at most eight layers')
    config=asdict(model.config);config['layers']=layers
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(49317);grown=Nebula(Config(**config))
    missing,unexpected=grown.load_state_dict(model.state_dict(),strict=False)
    if unexpected or any(not name.startswith('blocks.') or int(name.split('.')[1])<model.config.layers for name in missing):
        raise ValueError('Unexpected architecture mismatch')
    with torch.no_grad():
        for block in grown.blocks[model.config.layers:]:
            block.self_attn.out_proj.weight.zero_();block.self_attn.out_proj.bias.zero_()
            block.linear2.weight.zero_();block.linear2.bias.zero_()
    grown.eval();model.eval()
    # New residual blocks initially add zero; this must hold numerically.
    generator=torch.Generator().manual_seed(49317)
    probe=torch.randint(0,256,(1,min(64,model.config.context)),generator=generator)
    with torch.no_grad():
        torch.testing.assert_close(grown(probe),model.cpu()(probe),rtol=0,atol=0)
    return grown

def grow_checkpoint(source,destination,layers):
    original,metadata=load(source);grown=grow_model(original,layers)
    info={**metadata,'growth':{'originalLayers':original.config.layers,'layers':layers,
          'parameters':sum(p.numel() for p in grown.parameters()),'initialFunctionPreserved':True},
          'trainingStateIncluded':False,'qualityApproved':False,'experimental':True}
    save(grown,destination,info)
    return info
