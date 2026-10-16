import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import torch
from dataflow import eligible, generate_teacher, prepare, read_jsonl, write_jsonl, redact
from nebula import ASSISTANT, BOS, EOS, USER, Config, Nebula, encode, save, load, pack_prompt
from rules import with_owner_rules
from train import examples, loss
from serve import make_server

class Pipeline(unittest.TestCase):
    def setUp(self): torch.set_num_threads(1); torch.manual_seed(7)
    def row(self): return {'reviewStatus': 'approved', 'messages': [{'role': 'user', 'content': 'Hello'}, {'role': 'assistant', 'content': 'Hi'}], 'source': {'kind': 'seed'}}
    def test_tokenizer_keeps_role_like_text_as_data(self):
        values, masks = encode([{'role': 'user', 'content': '<assistant>\u2603'}, {'role': 'assistant', 'content': 'Hi'}])
        self.assertEqual(values.count(ASSISTANT), 1); self.assertEqual(values.count(USER), 1)
        self.assertEqual(sum(masks), 3); self.assertFalse(masks[1])
    def test_causal_mask_blocks_future_information(self):
        model = Nebula(Config(width=32, heads=2, layers=1, context=32)).eval()
        with torch.no_grad():
            a = model(torch.tensor([[BOS, USER, 65, 66]])); b = model(torch.tensor([[BOS, USER, 65, 99]]))
        torch.testing.assert_close(a[:, :3], b[:, :3])
    def test_long_history_keeps_owner_rules_and_latest_question(self):
        messages=[{'role':'system','content':'OWNER RULE'}, {'role':'user','content':'old history '*100}, {'role':'assistant','content':'old reply'}, {'role':'user','content':'Latest question'}]
        packed=pack_prompt(messages,80);self.assertEqual(packed[:len(encode([messages[0]])[0])],encode([messages[0]])[0]);self.assertIn(b'Latest question',bytes(v for v in packed if v<256));self.assertLess(len(packed),80)
        with self.assertRaises(ValueError):pack_prompt([{'role':'system','content':'x'*100},{'role':'user','content':'Hello'}],80)
    def test_private_server_rule_prefix_is_not_duplicated(self):
        once=with_owner_rules(self.row()['messages']);self.assertEqual(with_owner_rules(once),once)
    def test_training_only_targets_assistant(self):
        batch = examples([self.row()], 32); self.assertEqual(int((batch[0][1] != -100).sum()), 3)
    def test_gradient_training_reduces_loss_and_checkpoint_roundtrips(self):
        model = Nebula(Config(width=32, heads=2, layers=1, context=32)); batch = examples([self.row()], 32)
        optimizer = torch.optim.AdamW(model.parameters(), lr=.01); initial = float(loss(model, batch).detach())
        for _ in range(25):
            optimizer.zero_grad(); value = loss(model, batch); value.backward(); optimizer.step()
        self.assertLess(float(loss(model, batch).detach()), initial / 2)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder)/'model.pt'; save(model, path, {'experimental': True}); other, metadata = load(path)
            torch.testing.assert_close(model(batch[0][0][None]), other(batch[0][0][None])); self.assertTrue(metadata['experimental'])
    def test_prepare_filters_pending_and_duplicate_data(self):
        row = self.row()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            source, target = Path(folder)/'input.jsonl', Path(folder)/'out.jsonl'
            write_jsonl(source, [row, row, {**row, 'reviewStatus': 'pending'}]); self.assertEqual(prepare([source], target), 1)
    def test_user_requires_current_consent_and_generation(self):
        row = self.row(); row['source'] = {'kind': 'user', 'accountKey': 'account', 'owner': 'owner', 'generation': 0, 'chatId': 'chat', 'turnId': 'turn'}
        state = {'accounts': {'account': {'improve': True, 'trainingGeneration': 0}}, 'training': {'owner': {'samples': {'chat': {'turn': {'consentVersion': 1, 'messages': row['messages']}}}}}}
        self.assertFalse(eligible(row)); self.assertTrue(eligible(row, state)); state['accounts']['account']['improve'] = False; self.assertFalse(eligible(row, state)); state['accounts']['account']['improve'] = True; state['training']['owner']['revoked'] = True; self.assertFalse(eligible(row, state))
    def test_teacher_budget_resume_and_original_prompts_only(self):
        config = {'url': 'http://127.0.0.1:11434/v1/chat/completions', 'model': 'teacher', 'trainingAllowed': True}
        prompts = [{'source': 'original', 'prompt': 'Explain '+str(i)} for i in range(3)]; sent = []
        def transport(request): sent.append(json.loads(request.data)); return {'choices': [{'message': {'content': 'A concise answer.'}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder)/'pending.jsonl'; self.assertEqual(generate_teacher(config, prompts, path, 1, transport), 1); self.assertEqual(generate_teacher(config, prompts, path, 1, transport), 1)
            self.assertEqual(len(sent), 2); self.assertTrue(all(r['reviewStatus'] == 'pending' for r in read_jsonl(path)))
            with self.assertRaises(ValueError): generate_teacher(config, [{'source': 'user', 'prompt': 'Private chat'}], path, 1, transport)
            with self.assertRaises(ValueError): generate_teacher({**config, 'trainingAllowed': False}, prompts, path, 1, transport)
    def test_redaction_removes_credentials_contacts(self):
        text = redact('me@example.com +1 202 555 0123 sk-abcdefghijklmnopqrstuvwxyz')
        self.assertNotIn('example.com', text); self.assertNotIn('555', text); self.assertNotIn('abcdefghijklmnopqrstuvwxyz', text)
    def test_private_inference_requires_key_and_valid_input(self):
        class Model:
            def reply(self, messages): return 'Nebula response'
        key = 'x'*40; server = make_server(Model(), key, port=0); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def request(data, auth=key): return urlopen(Request(f'http://127.0.0.1:{server.server_port}/chat', json.dumps(data).encode(), {'Content-Type': 'application/json', 'Authorization': 'Bearer '+auth}), timeout=5)
        try:
            body = {'messages': [{'role': 'user', 'content': 'Hello'}]}
            with request(body) as response: self.assertEqual(json.load(response)['reply'], 'Nebula response')
            with self.assertRaises(HTTPError) as wrong: request(body, 'invalid')
            self.assertEqual(wrong.exception.code, 401)
            with self.assertRaises(HTTPError) as bad: request({'messages': [{'role': 'admin', 'content': 'x'}]})
            self.assertEqual(bad.exception.code, 400)
        finally: server.shutdown(); server.server_close(); thread.join()

if __name__ == '__main__': unittest.main()
