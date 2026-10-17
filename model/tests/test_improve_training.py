import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from unittest.mock import patch
import torch
from dataflow import eligible,read_jsonl,write_jsonl
from improve_training import download_stories,foundation_rows,prepare_curriculum,story_row,run_stage
from nebula import Config,Nebula,encode,EOS
from train import examples,loss

class ImprovedTraining(unittest.TestCase):
    def test_rate_limit_keeps_cached_stories_and_does_not_redownload(self):
        def transport(url):
            from urllib.parse import parse_qs,urlparse
            offset=int(parse_qs(urlparse(url).query)['offset'][0])
            if offset>=1000: raise HTTPError(url,429,'Too many requests',{},None)
            return {'num_rows_total':20000,'rows':[
                {'row_idx':i,'row':{'text':f'A child called Number {i} found a little dog. '*6}}
                for i in range(offset,offset+100)]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            target=download_stories(directory,2000,transport)
            self.assertEqual(len(read_jsonl(target)),1000)
            self.assertTrue(json.loads(target.with_name('stories-sources.json').read_text())['downloadDeferred'])
            download_stories(directory,2000,lambda _:self.fail('Stable dataset should be reused'))

    def test_story_filter_license_and_cache(self):
        row=story_row('Once a child found a little dog. '*8,0)
        self.assertTrue(eligible(row))
        self.assertFalse(eligible({**row,'source':{**row['source'],'license':'unknown'}}))
        self.assertIsNone(story_row('too short',0))
        def transport(url):
            return {'num_rows_total':2,'rows':[{'row_idx':0,'row':{'text':'Once a child found a little dog. '*8}},
                {'row_idx':1,'truncated_cells':['text'],'row':{'text':'Once a child found a little dog. '*8}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            target=download_stories(directory,2,transport)
            self.assertEqual(len(read_jsonl(target)),1)
            download_stories(directory,2,lambda _:self.fail('Expected cached page'))

    def test_foundations_are_eligible_unique_and_exact(self):
        rows=list(foundation_rows())
        self.assertGreater(len(rows),1000)
        self.assertEqual(len(rows),len({r['id'] for r in rows}))
        for row in rows:
            self.assertTrue(eligible(row))
            q,a=[m['content'] for m in row['messages']]
            if q.startswith('Add '):
                parts=q.rstrip('.').split(); self.assertEqual(a,f'{parts[1]} + {parts[3]} = {int(parts[1])+int(parts[3])}.')

    def test_chat_keeps_complete_answers_and_excludes_stories(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); data=root/'model/data'; data.mkdir(parents=True)
            original=list(foundation_rows())[:20]
            write_jsonl(data/'public-approved.jsonl',original)
            story=data/'stories-approved.jsonl'; write_jsonl(story,[story_row('Once a child found a little dog. '*8,0)])
            language,chat=prepare_curriculum(root,story,1024)
            self.assertTrue(any(r['source'].get('dataset')=='roneneldan/TinyStories' for r in read_jsonl(language)))
            for row in read_jsonl(chat):
                self.assertNotEqual(row['source'].get('dataset'),'roneneldan/TinyStories')
            self.assertEqual(len(read_jsonl(data/'public-approved.jsonl')),20)

    def test_attention_cannot_see_future_tokens_in_train_or_eval(self):
        torch.set_num_threads(1); torch.manual_seed(42)
        model=Nebula(Config(width=32,heads=2,layers=1,context=64))
        a=torch.tensor([[256,259,65,66,67,68]])
        b=a.clone(); b[:,4:]=torch.tensor([90,91])
        for training in [True,False]:
            model.train(training)
            with torch.no_grad():
                torch.testing.assert_close(model(a)[:,:4],model(b)[:,:4],rtol=0,atol=1e-6)

    def test_training_and_generation_can_learn_a_tiny_pair(self):
        torch.set_num_threads(1); torch.manual_seed(42)
        model=Nebula(Config(width=32,heads=2,layers=1,context=64))
        messages=[{'role':'user','content':'Hello'},{'role':'assistant','content':'Hi!'}]
        batch=examples([{'messages':messages}],64)
        optimizer=torch.optim.AdamW(model.parameters(),lr=.01)
        before=float(loss(model,batch).detach())
        for _ in range(100):
            model.train(); optimizer.zero_grad(); value=loss(model,batch); value.backward(); optimizer.step()
        self.assertLess(float(loss(model,batch).detach()),before*.1)
        self.assertEqual(model.reply(messages[:1],max_tokens=10,temperature=0),'Hi!')

    def test_gpu_memory_retry_and_interrupt_do_not_start_endless_training(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory)
            with patch('improve_training.train',side_effect=[torch.cuda.OutOfMemoryError(),{'stopped':True}]) as trainer:
                result=run_stage(root/'data',root/'out.pt',root/'prior.pt','language',100,16)
            self.assertTrue(result['stopped'])
            self.assertEqual([c.args[0].batch for c in trainer.call_args_list],[16,8])
            self.assertTrue(all(not c.args[0].continuous for c in trainer.call_args_list))

if __name__=='__main__': unittest.main()
