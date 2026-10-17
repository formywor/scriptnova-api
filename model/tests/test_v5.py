import ast
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock,patch
import torch
from nebula import Nebula,config_for_preset,save,load
from v5_data import additions,prepare,VERSION
from v5_experiment import research_improves,topic_focus,compact,main
from v4_data import exercises,forbidden
from research_eval import select_focus
from research_client import ResearchError
from train import partition_rows
from dataflow import write_jsonl,read_jsonl

ROOT=Path(__file__).resolve().parents[1]
def report(**values):return {'loss':1.,'correct':35,'cases':76,'health':.98,'identity':1.,'math':.04,'memory':.47,'extraction':.92,'familiar':.66,'conversation':.2,**values}

class V5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(1);cls.rows=additions()
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_new_targets_are_exact_and_exclude_frozen_v4_scenarios(self):
        self.assertGreater(len(self.rows),5000);_,checks=exercises()
        for row in self.rows:
            self.assertFalse(forbidden(row,checks))
            if row['source']['curriculum']=='v5-exact-math':
                match=re.fullmatch(r'(\d+) ([+-]) (\d+) = (-?\d+)\.',row['messages'][-1]['content'])
                self.assertIsNotNone(match);a,operator,b,total=match.groups();a,b,total=map(int,[a,b,total])
                self.assertEqual(total,a+b if operator=='+' else a-b)
        train,valid=partition_rows(self.rows,42)
        self.assertTrue(any(row['messages'][0]['content']=='What is 2 + 2?' for row in train))
        self.assertTrue({r['splitGroup'] for r in train}.isdisjoint({r['splitGroup'] for r in valid}))
        self.assertTrue(any(r['source']['curriculum']=='v5-conversation' for r in select_focus(self.rows,'language')))
    def test_preparation_never_relabels_private_user_chats_as_original_data(self):
        with self.temporary() as folder:
            root=Path(folder);source=root/'base.jsonl';target=root/'new.jsonl'
            write_jsonl(source,[{'reviewStatus':'approved','source':{'kind':'user'},'messages':[{'role':'user','content':'PRIVATE DATA'},{'role':'assistant','content':'Private reply'}]}])
            result=prepare(source,target);self.assertGreater(result['newOriginalExamples'],5000)
            self.assertNotIn('PRIVATE DATA',target.read_text());self.assertFalse(result['rawUserChatsIncluded'])
    def test_working_head_allows_broader_gains_but_rejects_collapse_or_loss_only_regression(self):
        base=report()
        self.assertTrue(research_improves(base,report(correct=40,identity=.9,math=.3)))
        self.assertFalse(research_improves(base,report(correct=30,loss=.5)))
        self.assertFalse(research_improves(base,report(correct=40,health=.5)))
        self.assertFalse(research_improves(base,report(correct=40,loss=float('nan'))))
        self.assertFalse(research_improves(base,report(correct=40,conversation=float('nan'))))
    def test_chat_topics_have_bounded_influence_on_actual_training_focus(self):
        topics={'counts':{'identity':100,'language':5,'unknown':999999}}
        self.assertEqual(topic_focus(report(),0,4,topics),'identity')
        self.assertEqual(topic_focus(report(),0,1,topics),'language')
        self.assertNotEqual(topic_focus(report(),0,4,{'counts':{'unknown':100}}),'unknown')
    def test_compact_backup_contains_real_model_weights_without_optimizer(self):
        with self.temporary() as folder:
            source=Path(folder)/'full.pt';target=Path(folder)/'weights.pt'
            original=Nebula(config_for_preset('smoke'));save(original,source,{'steps':5},training_state={'optimizer':{'large':torch.ones(100)}})
            compact(source,target);saved=torch.load(target,weights_only=True)
            self.assertNotIn('trainingState',saved);actual,meta=load(target);self.assertEqual(meta['steps'],5)
            for name,value in original.state_dict().items():torch.testing.assert_close(value,actual.state_dict()[name],rtol=0,atol=0)
    def test_rejected_rounds_continue_from_best_and_back_up_without_public_promotion(self):
        with self.temporary() as folder:
            project=Path(folder);store=Mock();state={'format':VERSION,'round':3,'rejected':3,'bestReport':report(),
                'sourceData':{},'data':{},'evaluationData':{},'checks':{},'best':{},'profile':{'gpus':1},'dataSummary':{}}
            store.state.return_value=state
            def download(value,destination):
                destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(b'old-best');return destination
            store.download.side_effect=download
            def train(project,resume,output,*args,**kwargs):output.write_bytes(b'new');output.with_suffix('.best.pt').write_bytes(b'new')
            def evaluate(checkpoint,data,checks,output):output.write_text('{}');return report(correct=20)
            def backup(state,files,project):return {**state,**{key:{} for key in files}}
            store.publish.side_effect=backup
            def copy(source,destination):destination.write_bytes(source.read_bytes());return destination
            with patch('v5_experiment.Store',return_value=store),patch('v5_experiment.torch.cuda.is_available',return_value=True),\
                 patch('v5_experiment.torch.cuda.empty_cache'),patch('v5_experiment.restore_data'),patch('v5_experiment.configure_rules'),\
                 patch('v5_experiment.launch',side_effect=train) as launch,patch('v5_experiment.evaluate',side_effect=evaluate),\
                 patch('v5_experiment.compact',side_effect=copy),patch('v5_experiment.Client') as client:
                client.return_value.call.side_effect=ResearchError('NOT_DEPLOYED_YET')
                main(['--project',str(project),'--rounds','1','--hours','.01'])
            launch.assert_called_once();value,files,_=store.publish.call_args.args
            self.assertEqual(launch.call_args.kwargs['sampling_seed'],20261021)
            self.assertEqual(value['round'],4);self.assertEqual(value['rejected'],4);self.assertEqual(value['bestReport']['correct'],35)
            self.assertNotIn('best',files);self.assertIn('latest',files)
            self.assertEqual(client.return_value.call.call_args.args,('curriculum',))
    def test_notebook_sources_parse_and_contain_no_credentials(self):
        from build_v5_notebook import build
        notebook=json.loads(build().read_text())
        text=json.dumps(notebook);self.assertNotRegex(text,r'hf_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}')
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))

if __name__=='__main__':unittest.main()
