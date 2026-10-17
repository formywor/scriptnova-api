import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import torch
from nebula import Nebula,config_for_preset,save,load
from train import train,loss

class NumericalSafety(unittest.TestCase):
    def args(self,root):
        data=root/'data.jsonl'
        row={'reviewStatus':'approved','source':{'kind':'seed'},'messages':[{'role':'user','content':'Hi'},{'role':'assistant','content':'Hello'}]}
        data.write_text(json.dumps(row)+'\n'+json.dumps(row)+'\n',encoding='utf-8')
        return SimpleNamespace(data=data,output=root/'weights.pt',steps=1,batch=1,threads=1,seed=42,lr=.0001,resume=None,snapshot=None,preset='smoke',continuous=False,save_every=1)

    def test_nan_loss_stops_before_optimizer_update(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            args=self.args(Path(folder))
            def broken(model,batch):
                return torch.tensor(float('nan'),requires_grad=True) if torch.is_grad_enabled() else loss(model,batch)
            with patch('train.loss',broken),patch.object(torch.optim.AdamW,'step') as step:
                result=train(args)
            step.assert_not_called()
            self.assertEqual(result['reason'],'non_finite_loss_or_gradient')
            model,metadata=load(args.output)
            self.assertEqual(metadata['stopReason'],'non_finite_loss_or_gradient')
            self.assertIsNone(metadata['validationLoss'])
            self.assertTrue(all(torch.isfinite(p).all() for p in model.parameters()))

    def test_interrupt_during_validation_saves_without_repeating_validation(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            args=self.args(Path(folder))
            with patch('train.evaluate_loss',side_effect=KeyboardInterrupt) as validate:
                result=train(args)
            self.assertTrue(result['stopped']); self.assertEqual(validate.call_count,1)
            _,metadata=load(args.output)
            self.assertEqual(metadata['stopReason'],'interrupted')

    def test_invalid_weights_cannot_replace_saved_checkpoint(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path=Path(folder)/'weights.pt'; model=Nebula(config_for_preset('smoke'))
            save(model,path,{})
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            with torch.no_grad(): next(model.parameters()).flatten()[0]=float('nan')
            with self.assertRaisesRegex(ValueError,'non-finite'): save(model,path,{})
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest)
            load(path)

    def test_non_finite_gradients_block_optimizer_update(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            args=self.args(Path(folder))
            def broken(model,batch):
                value=loss(model,batch)
                if torch.is_grad_enabled(): value.register_hook(lambda gradient:gradient*float('nan'))
                return value
            with patch('train.loss',broken),patch.object(torch.optim.AdamW,'step') as step:
                result=train(args)
            step.assert_not_called(); self.assertEqual(result['reason'],'non_finite_loss_or_gradient')

if __name__=='__main__':unittest.main()
