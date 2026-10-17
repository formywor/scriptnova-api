import json
from pathlib import Path
import random
import tempfile
import unittest
import torch
from dataflow import eligible,read_jsonl
from nebula import Nebula,config_for_preset,encode
from public_data import SOURCES,convert,download
from train import examples,partition_rows,bucket_batches,unique_windows
from train_conversations import configured_teachers

class PublicTraining(unittest.TestCase):
    def test_language_pretraining_keeps_long_text_without_fake_end_tokens(self):
        from nebula import EOS
        row={'messages':[{'role':'user','content':'Question?'},{'role':'assistant','content':'long answer '*200}]}
        data=examples([row],512,True,objective='language')
        targets=[int(v) for _,y in data for v in y if v!=-100]
        original=encode(row['messages'])[0][1:]
        self.assertEqual(targets,original)
        self.assertEqual(targets.count(EOS),2)
        self.assertGreater(len(data),2)
        self.assertTrue(all(len(x)<=512 for x,_ in data))

    def test_duplicate_windows_never_leak_into_validation(self):
        pair=(torch.tensor([1,2,3]),torch.tensor([-100,2,3]))
        different=(torch.tensor([1,2,4]),torch.tensor([-100,2,4]))
        training,seen=unique_windows([pair,pair])
        validation,_=unique_windows([pair,different],seen)
        self.assertEqual(len(training),1); self.assertEqual(len(validation),1)
        self.assertEqual(validation[0][0].tolist(),[1,2,4])

    def test_optional_teacher_is_skipped_without_removing_required_teachers(self):
        configs=json.loads((Path(__file__).resolve().parents[1]/'teachers.gemini-groq.json').read_text(encoding='utf-8'))
        self.assertEqual([c['name'] for c in configured_teachers(configs,{})],['gemini','groq'])
        self.assertEqual(len(configured_teachers(configs,{'GEMINI_SECOND_API_KEY':'test'})),3)
        self.assertEqual(len(configured_teachers(configs,{'GEMINI_SECOND_API_KEY':'  '})),2)

    def test_public_import_preserves_source_and_cache_and_filters(self):
        sent=[]
        def transport(url):
            sent.append(url)
            return {'num_rows_total':2,'rows':[{'row_idx':0,'row':{'messages':[{'role':'user','content':'Hi'},{'role':'assistant','content':'Hello'}]}},{'row_idx':1,'truncated_cells':['messages'],'row':{'messages':[]}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            manifest=download(directory,everyday=2,magpie=0,transport=transport)
            rows=read_jsonl(Path(directory)/'public-conversations.jsonl')
            self.assertEqual(manifest['conversations'],1); self.assertTrue(eligible(rows[0]))
            self.assertEqual(rows[0]['source']['license'],'apache-2.0')
            download(directory,everyday=2,magpie=0,transport=lambda _:self.fail('Cache should be reused'))
            self.assertEqual(len(sent),1)
        self.assertIsNone(convert({'messages':[{'role':'user','content':'Hi'},{'role':'assistant','content':'I am ChatGPT.'}]},SOURCES['everyday'],0))

    def test_long_dialogue_windows_preserve_complete_answers_and_rules(self):
        from rules import owner_instructions
        text='answer '*10
        messages=[{'role':role,'content':value} for _ in range(6) for role,value in [('user','question '*6),('assistant',text)]]
        row={'messages':messages}
        result=examples([row],512,True)
        self.assertGreater(len(result),1)
        for x,y in result:
            self.assertLessEqual(len(x),512)
            self.assertIn(owner_instructions().encode(),bytes(i for i in x.tolist() if i<256))
            self.assertEqual(int(y[-1]),257)

    def test_partition_never_splits_a_duplicate_original_dialogue(self):
        rows=[{'messages':[{'role':'user','content':str(i)},{'role':'assistant','content':'Example.'}]} for i in range(100)]
        training,validation=partition_rows(rows+rows[:10],42)
        identifiers=lambda values:{json.dumps(r['messages']) for r in values}
        self.assertFalse(identifiers(training)&identifiers(validation))
        self.assertEqual(partition_rows(rows,42)[1],partition_rows(rows,42)[1])

    def test_bucket_sampler_covers_each_example_once(self):
        data=[(torch.zeros(n,dtype=torch.long),torch.ones(n,dtype=torch.long)) for n in range(1,80)]
        batches=bucket_batches(data,4,random.Random(42))
        self.assertEqual(sorted(len(x) for b in batches for x,_ in b),list(range(1,80)))
        self.assertTrue(all(len(b)<=4 for b in batches))

    def test_larger_preset_is_larger_and_has_finite_gradients(self):
        torch.set_num_threads(1)
        model=Nebula(config_for_preset('cpu-large'))
        count=sum(p.numel() for p in model.parameters())
        self.assertGreater(count,4_900_000); self.assertLess(count,6_000_000)
        value=model(torch.tensor([[256,259,72,105,257,260,72,105]]))
        value.square().mean().backward()
        self.assertTrue(all(p.grad is None or torch.isfinite(p.grad).all() for p in model.parameters()))

if __name__=='__main__':unittest.main()
