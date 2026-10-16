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

if __name__ == '__main__': unittest.main()
