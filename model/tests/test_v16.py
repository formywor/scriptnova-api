import ast
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import torch
from nebula import Nebula, Config, load, save
from v16_diagnostic import audit, suite, training_windows, fit, assess


class V16Tests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(2)

    def test_pipeline_invariants_and_disjoint_exercises(self):
        checks = audit()
        self.assertTrue(checks['passed'])
        self.assertGreaterEqual(len(checks['checks']), 10)
        train, held, opens = suite()
        self.assertEqual((len(train), len(held), len(opens)), (24, 12, 4))
        self.assertFalse({json.dumps(x[:-1]) for x in train} & {json.dumps(x[:-1]) for x in held})
        self.assertTrue(all(len(training_windows([row], 256)) == 1 for row in train))

    def test_causal_audit_detects_future_information_leak(self):
        original = Nebula.forward
        def leaking(model, tokens):
            return original(model, tokens) + tokens.float().sum(1)[:, None, None]
        with patch.object(Nebula, 'forward', leaking):
            with self.assertRaisesRegex(AssertionError, 'future_tokens'):
                audit()

    def test_resume_keeps_adam_and_token_counters_and_rejects_changed_data(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder, contextlib.redirect_stdout(io.StringIO()):
            root = Path(folder); torch.manual_seed(42)
            source = Nebula(Config(width=32, heads=2, layers=1, context=128))
            save(source, root / 'initial.pt', {})
            train = suite()[0][:4]
            full, _ = load(root / 'initial.pt')
            full_meta = fit(full, train, root / 'full.pt', steps=4, batch=2, checkpoint_every=2)
            class Pause(Exception): pass
            def pause(*args): raise Pause()
            half, _ = load(root / 'initial.pt')
            with self.assertRaises(Pause):
                fit(half, train, root / 'half.pt', steps=4, batch=2, checkpoint_every=2, checkpoint_callback=pause)
            resumed, _ = load(root / 'half.pt')
            meta = fit(resumed, train, root / 'continued.pt', steps=4, batch=2, checkpoint_every=2, resume=root / 'half.pt')
            for key in ['updates', 'inputPositions', 'supervisedTokens']:
                self.assertEqual(meta[key], full_meta[key])
            for expected, actual in zip(full.parameters(), resumed.parameters()):
                self.assertTrue(torch.equal(expected, actual))
            with self.assertRaisesRegex(ValueError, 'CONFIGURATION_CHANGED'):
                fit(resumed, train[:-1], root / 'bad.pt', steps=4, batch=2, resume=root / 'half.pt')
            self.assertFalse((root / 'bad.pt').exists())

    def test_exact_grades_do_not_approve_keyword_only_or_open_answers(self):
        class Model:
            def reply(self, messages, **kwargs): return 'Nebula nonsense'
        result = assess(Model(), [suite()[0][1]], suite()[2][:1])
        self.assertEqual(result['exactCorrect'], 0)
        self.assertEqual(result['openAnswers'][0]['grade'], 'pending-human-review')
        self.assertFalse(result['qualityApproved'])

    def test_new_notebook_embeds_current_sources_with_native_colab_secrets(self):
        from build_v16_colab import build
        root = Path(__file__).parents[1]
        nb = json.loads(build().read_text(encoding='utf-8'))
        setup, run = [''.join(c['source']) for c in nb['cells'] if c['cell_type'] == 'code']
        self.assertIn("userdata.get('NEBULA_HF_TOKEN')", setup)
        self.assertNotIn('drive.mount', setup)
        self.assertIn('HOURS = 2', setup)
        sources = ast.literal_eval(ast.parse(run).body[0].value)
        self.assertIn('model/v16_diagnostic.py', sources)
        for name, text in sources.items():
            self.assertEqual(text, (root.parent / name).read_text(encoding='utf-8'))
            if name.endswith('.py'): ast.parse(text)
        for c in nb['cells']:
            if c['cell_type'] == 'code':
                self.assertEqual(c['outputs'], []); ast.parse(''.join(c['source']))


if __name__ == '__main__': unittest.main()
