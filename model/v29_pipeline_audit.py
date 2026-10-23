"""Check actual device/model masking and train/eval consistency before updates."""
import numpy as np
import torch

@torch.inference_mode()
def audit(model,values):
    original_mode=model.training;tf32=torch.backends.cuda.matmul.allow_tf32
    device=next(model.parameters()).device;checks={};errors={}
    try:
        torch.backends.cuda.matmul.allow_tf32=False
        n=min(64,model.config.context,len(values)-1)
        seq=torch.tensor(np.array(values[:n],dtype=np.int64),device=device)[None]
        target=torch.tensor(np.array(values[1:n+1],dtype=np.int64),device=device)[None]
        checks['one_token_shift']=torch.equal(seq[:,1:],target[:,:-1])
        model.eval();full=model(seq).float()
        model.train();training=model(seq).float()
        errors['trainEvalMaxAbs']=float((full-training).abs().max())
        checks['train_eval_agree']=torch.allclose(full,training,atol=1e-3,rtol=1e-4)
        model.eval();cut=n//2;changed=seq.clone();changed[:,cut:]=(changed[:,cut:]+7)%model.config.vocab
        altered=model(changed).float()
        errors['futureMaxAbs']=float((full[:,:cut]-altered[:,:cut]).abs().max())
        checks['future_cannot_change_past']=torch.allclose(full[:,:cut],altered[:,:cut],atol=1e-3,rtol=1e-4)
        prefix=model(seq[:,:cut]).float()
        errors['prefixMaxAbs']=float((full[:,cut-1]-prefix[:,-1]).abs().max())
        checks['prefix_and_teacher_forced_agree']=torch.allclose(full[:,cut-1],prefix[:,-1],atol=1e-3,rtol=1e-4)
        checks['finite_logits']=bool(torch.isfinite(full).all())
        return dict(format='nebula-v29-device-audit-1',passed=all(checks.values()),checks=checks,maxErrors=errors,
            device=str(device),scope='Small actual checkpoint/device sample; does not certify factual knowledge or all training behavior.')
    finally:
        model.train(original_mode);torch.backends.cuda.matmul.allow_tf32=tf32
