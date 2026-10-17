import ast
from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import torch
from conversation_mix import mixed_lane,conversational
from v6_data import additions,VERSION
from v6_experiment import research_improves,initial
from v4_data import exercises,forbidden
from dataflow import read_jsonl,write_jsonl
from review_feed import refresh_reviews,validated_rows
from research_client import ResearchError
from nebula import Nebula,config_for_preset,save,load
from research_train import main as train

def reviewed():
    return {'id':'example','reviewStatus':'approved','source':{'kind':'teacher','trainingAllowed':True,'curriculum':'v6-reviewed','validation':'two-pass-review-v1'},'messages':[{'role':'user','content':'Explain a peaceful afternoon.'},{'role':'assistant','content':'Read a book, take a break, and enjoy some quiet time.'}]}

def report(**kw):return {'loss':.6,'correct':54,'cases':76,'health':1.,'identity':.8,'math':.65,'memory':.8,'extraction':.93,'conversation':0.,**kw}

class V6Tests(unittest.TestCase):
    def test_exact_mix_includes_memory_and_conversation_sources(self):
        self.assertEqual(Counter(mixed_lane(i) for i in range(500)),{'conversation':400,'memory':50,'mixed':50})
        self.assertTrue(conversational(reviewed()))
        self.assertFalse(conversational({'source':{'kind':'public','dataset':'roneneldan/TinyStories'}}))
    def test_new_multiturn_examples_do_not_leak_frozen_tasks(self):
        rows=additions();self.assertGreater(len(rows),400);_,checks=exercises()
        for row in rows:self.assertGreaterEqual(len(row['messages']),4);self.assertFalse(forbidden(row,checks))
        self.assertTrue(any('What color is it?' in [m['content'] for m in r['messages']] for r in rows))
        self.assertTrue(any('Make it more casual.' in [m['content'] for m in r['messages']] for r in rows))
    def test_stale_review_feed_is_erased_on_network_error_or_optout(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'feed.jsonl';write_jsonl(path,[reviewed()]);client=Mock()
            client.call.side_effect=ResearchError('OFFLINE');self.assertEqual(refresh_reviews(client,path),0);self.assertEqual(read_jsonl(path),[])
            client.call.side_effect=None;client.call.return_value={'format':'nebula-reviewed-training-1','requiresFreshConsent':True,'rows':[reviewed()]}
            self.assertEqual(refresh_reviews(client,path),1)
            client.call.return_value={'format':'nebula-reviewed-training-1','requiresFreshConsent':True,'rows':[]}
            self.assertEqual(refresh_reviews(client,path),0);self.assertEqual(read_jsonl(path),[])
    def test_unchecked_reviews_and_locked_probes_cannot_enter_the_feed(self):
        wrong=reviewed();wrong['source']['validation']='unchecked'
        locked=reviewed();locked['messages'][0]['content']='Compute 37 + 48.'
        self.assertEqual(validated_rows([wrong,locked]),[])
    def test_selection_prioritizes_chat_gain_but_protects_memory(self):
        base=report()
        self.assertTrue(research_improves(base,report(correct=53,conversation=1/6)))
        self.assertFalse(research_improves(base,report(correct=53,conversation=1/6,memory=.1)))
        self.assertFalse(research_improves(base,report(correct=60,conversation=-.1)))
        self.assertFalse(research_improves(base,report(correct=60,conversation=float('nan'))))
    def test_missing_v5_progress_fails_instead_of_reinitializing_weights(self):
        previous=Mock();previous.state.return_value=None
        with patch('v6_experiment.Store',return_value=previous):
            with self.assertRaisesRegex(ResearchError,'V5_BEST_CHECKPOINT_REQUIRED'):initial(Mock(),Path('.'))
    def test_real_cpu_updates_use_both_pools_and_checked_reviews_without_resetting_steps(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);rows=[]
            for i in range(60):
                for kind in ['v6-conversation','mixed']:
                    rows.append({'reviewStatus':'approved','splitGroup':f'{kind}-{i}','source':{'kind':'seed','curriculum':kind},'messages':[{'role':'user','content':f'Practice item {i}.' if kind=='v6-conversation' else f'Remember word {i}.'},{'role':'assistant','content':f'Here is practice {i}.' if kind=='v6-conversation' else f'Your name is Test{i}.'}]})
            write_jsonl(root/'data.jsonl',rows);write_jsonl(root/'reviews.jsonl',[reviewed()]);model=Nebula(config_for_preset('smoke'));save(model,root/'start.pt',{'steps':17})
            train(['--data',str(root/'data.jsonl'),'--resume',str(root/'start.pt'),'--output',str(root/'end.pt'),'--steps','15','--batch','2','--device','cpu','--conversation-mix','--review-data',str(root/'reviews.jsonl')])
            trained,meta=load(root/'end.pt');self.assertEqual(meta['steps'],32);self.assertEqual(meta['conversationUpdates'],12);self.assertEqual(meta['mixedUpdates'],3);self.assertEqual(meta['memoryUpdates'],2);self.assertEqual(meta['reviewUpdates'],1)
            self.assertTrue(any(not torch.equal(v,trained.state_dict()[k]) for k,v in model.state_dict().items()))
    def test_notebook_embeds_current_code_and_no_secrets(self):
        from build_v6_notebook import build
        value=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(value)
        self.assertNotRegex(text,r'hf_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}')
        self.assertIn('nebula-v6',text);self.assertIn('v6_experiment',text)
        for cell in value['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))

if __name__=='__main__':unittest.main()
