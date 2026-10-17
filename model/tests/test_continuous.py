import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import torch
from train import train
from nebula import load

class Continuous(unittest.TestCase):
    def test_patience_stops_continuous_training_and_preserves_best(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); data=root/'data.jsonl'
            row={'reviewStatus':'approved','source':{'kind':'seed'},'messages':[{'role':'user','content':'Hi'},{'role':'assistant','content':'Hello'}]}
            data.write_text(json.dumps(row)+'\n'+json.dumps(row)+'\n',encoding='utf-8')
            args=SimpleNamespace(data=data,output=root/'weights.pt',steps=1,batch=1,threads=1,seed=42,lr=.0005,resume=None,snapshot=None,preset='smoke',continuous=True,save_every=1,patience=2)
            with patch('train.evaluate_loss',side_effect=[.1,1.,2.]): result=train(args)
            self.assertEqual(result['reason'],'validation_not_improving'); self.assertEqual(result['steps'],2)
            _,best=load(root/'weights.best.pt'); self.assertEqual(best['steps'],0)
            _,latest=load(root/'weights.pt'); self.assertEqual(latest['steps'],2)

    def test_interrupt_saves_completed_weights_and_periodic_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory)
            data = root / 'data.jsonl'
            data.write_text(json.dumps({'reviewStatus': 'approved', 'source': {'kind': 'seed'}, 'messages': [{'role': 'user', 'content': 'Hi'}, {'role': 'assistant', 'content': 'Hello'}]}) + '\n', encoding='utf-8')
            args = SimpleNamespace(data=data, output=root/'weights.pt', steps=1, batch=1, threads=1, seed=42, lr=.0005, resume=None, snapshot=None, preset='smoke', continuous=True, save_every=1)
            original = torch.optim.AdamW.step
            calls = []
            def step(optimizer, *a, **kw):
                if calls: raise KeyboardInterrupt()
                calls.append(True)
                return original(optimizer, *a, **kw)
            with patch.object(torch.optim.AdamW, 'step', step):
                result = train(args)
            model, metadata = load(args.output)
            self.assertEqual(result, {'steps': 1, 'stopped': True})
            self.assertEqual(metadata['steps'], 1)
            self.assertTrue(metadata['stopped'])
            self.assertEqual(model.config.width, 64)

    def test_worse_validation_keeps_earlier_best_weights(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory); data = root/'data.jsonl'
            rows = [{'reviewStatus':'approved', 'source':{'kind':'seed'}, 'messages':[{'role':'user','content':q},{'role':'assistant','content':'Hi'}]} for q in ['Hello','Hey']]
            data.write_text(''.join(json.dumps(r)+'\n' for r in rows), encoding='utf-8')
            args = SimpleNamespace(data=data, output=root/'weights.pt', steps=1, batch=1, threads=1, seed=42, lr=.0005, resume=None, snapshot=None, preset='smoke', continuous=False, save_every=1)
            from train import loss as actual_loss
            validations = []
            def measured(model, batch):
                if not torch.is_grad_enabled():
                    validations.append(True)
                    # The initial checkpoint wins; later checkpoint metrics worsen.
                    return torch.tensor(float(len(validations)))
                return actual_loss(model,batch)
            with patch('train.loss', measured): train(args)
            _, best = load(root/'weights.best.pt')
            _, latest = load(args.output)
            self.assertEqual(best['steps'], 0)
            self.assertEqual(latest['steps'], 1)

if __name__ == '__main__': unittest.main()
