import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import torch
from nebula import Nebula,config_for_preset,load,save
from dataflow import write_jsonl
from train import partition_rows
from v4_data import exercises,benchmark,prepare,LOCKED_PAIRS
from v4_eval import improves
from v4_experiment import size_model,main as experiment
from v4_data import VERSION
from v4_grow import grow_model
from v4_store import Store
from research_client import ResearchError
from research_eval import select_focus

ROOT=Path(__file__).resolve().parents[1]

class V4Experiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1);cls.rows,cls.checks=exercises()
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_growth_preserves_logits_and_original_weights(self):
        torch.manual_seed(42);original=Nebula(config_for_preset('smoke')).eval()
        before={key:value.clone() for key,value in original.state_dict().items()}
        grown=grow_model(original,3)
        tokens=torch.randint(0,256,(2,70))
        with torch.no_grad():torch.testing.assert_close(grown(tokens),original(tokens),rtol=0,atol=0)
        self.assertGreater(sum(p.numel() for p in grown.parameters()),sum(p.numel() for p in original.parameters()))
        for key,value in before.items():torch.testing.assert_close(value,original.state_dict()[key],rtol=0,atol=0)
    def test_all_scenario_variants_are_held_out_together_and_targets_are_correct(self):
        groups={row['splitGroup'] for row in self.rows}
        self.assertTrue(groups.isdisjoint({case['group'] for case in self.checks}))
        self.assertGreater(len(self.rows),15000)
        for row in self.rows:
            if row['splitGroup'].startswith('addition-'):
                answer=row['messages'][-1]['content'];a,b,total=map(int,re.findall(r'\d+',answer))
                self.assertEqual(a+b,total);self.assertNotIn((a,b),LOCKED_PAIRS);self.assertNotIn((b,a),LOCKED_PAIRS)
        cases=benchmark(self.checks)
        self.assertGreaterEqual(len(cases['cases']),60)
        self.assertEqual(cases,benchmark(self.checks))
    def test_prepare_rejects_user_data_and_keeps_complete_short_public_turns(self):
        with self.temporary() as folder,patch.dict(os.environ):
            root=Path(folder);rules=root/'nebula-rules.json';rules.write_text(json.dumps({'instructions':['You are Nebula AI.']}))
            os.environ['NEBULA_RULES_FILE']=str(rules)
            public={'id':'public-origin','reviewStatus':'approved','source':{'kind':'public','dataset':'HuggingFaceTB/smoltalk','subset':'smol-magpie-ultra','license':'apache-2.0','recordId':'public-origin'},'messages':[
                {'role':'user','content':'Say hello kindly.'},{'role':'assistant','content':'Hello! I hope your day is going well.'},
                {'role':'user','content':'Can we talk?'},{'role':'assistant','content':'Of course. What would you like to talk about?'}]}
            user={'reviewStatus':'approved','source':{'kind':'user'},'messages':[{'role':'user','content':'PRIVATE USER MESSAGE'},{'role':'assistant','content':'SECRET RESPONSE'}]}
            write_jsonl(root/'model/data/v3-chat.jsonl',[public,user])
            data,checks,manifest=prepare(root)
            text=data.read_text();self.assertNotIn('PRIVATE USER MESSAGE',text)
            self.assertIn('Hello! I hope your day is going well.',text)
            self.assertLessEqual(manifest['maximumContextBytes'],1024)
            rows=[json.loads(line) for line in text.splitlines()]
            public_rows=[row for row in rows if row['source']['kind']=='public']
            train,valid=partition_rows(public_rows+self.rows,42)
            self.assertTrue(all(row in train for row in public_rows) or all(row in valid for row in public_rows))
    def test_gpu_sizing_falls_back_when_largest_model_is_too_slow(self):
        with self.temporary() as folder:
            root=Path(folder);baseline=root/'baseline.pt';save(Nebula(config_for_preset('smoke')),baseline,{'steps':12})
            profiles=[{'targetsPerSecond':100,'gpus':1},{'targetsPerSecond':40,'gpus':1},{'targetsPerSecond':60,'gpus':1}]
            with patch('v4_experiment.profile',side_effect=profiles):path,measurement,growth=size_model(root,baseline,root/'data.jsonl')
            self.assertEqual(growth['layers'],3);self.assertEqual(measurement['targetsPerSecond'],60)
            self.assertTrue(path.exists())
    def test_lower_loss_cannot_hide_a_task_regression(self):
        base={'loss':1,'correct':5,'health':1,'identity':.5,'math':.5,'memory':.5,'extraction':.5,'familiar':1}
        self.assertFalse(improves(base,{**base,'loss':.7,'math':.25}))
        self.assertTrue(improves(base,{**base,'loss':.98}))
        self.assertTrue(improves(base,{**base,'loss':1.02,'correct':6,'math':.75}))
        self.assertFalse(improves(base,{**base,'loss':float('nan')}))
    def test_memory_practice_includes_exact_copying_and_color_extraction(self):
        focused=select_focus(self.rows,'memory')
        self.assertTrue(any(row['splitGroup'].startswith('copy-') for row in focused))
        self.assertTrue(any(row['splitGroup'].startswith('color-') for row in focused))
    def test_atomic_snapshot_binds_resume_manifest_to_file_hash_and_repository_revision(self):
        api=Mock();api.model_info.return_value=SimpleNamespace(private=True,sha='b'*40)
        api.create_commit.return_value=SimpleNamespace(oid='c'*40)
        module=SimpleNamespace(HfApi=Mock(return_value=api),CommitOperationAdd=lambda **kw:SimpleNamespace(**kw))
        with self.temporary() as folder,patch.dict(sys.modules,{'huggingface_hub':module}):
            root=Path(folder);file=root/'weights.pt';file.write_bytes(b'weights')
            store=Store('owner/private','hf_fake_test_only','test-v4')
            result=store.publish({'round':0},{'best':(file,'best.pt')},root)
            self.assertEqual(result['best']['sha256'],hashlib.sha256(b'weights').hexdigest())
            self.assertEqual(api.create_commit.call_args.kwargs['parent_commit'],'b'*40)
            self.assertTrue(api.create_commit.call_args.kwargs['operations'][-1].path_in_repo.endswith('state.json'))
            self.assertEqual(store.revision,'c'*40)
            api.create_commit.side_effect=RuntimeError('sensitive upstream message')
            with self.assertRaisesRegex(ResearchError,'V4_BACKUP_FAILED_OR_CONCURRENT_RUN'):store.publish(result,{},root)
    def test_best_validation_checkpoint_is_retained_by_real_training(self):
        with self.temporary() as folder:
            root=Path(folder);data=root/'data.jsonl';source=root/'source.pt';output=root/'result.pt'
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':f'Say {i}.'},{'role':'assistant','content':f'Answer {i}.'}]} for i in range(50)]
            write_jsonl(data,rows);save(Nebula(config_for_preset('smoke')),source,{'steps':12})
            result=subprocess.run([sys.executable,str(ROOT/'research_train.py'),'--data',str(data),'--resume',str(source),
                '--output',str(output),'--device','cpu','--steps','3','--batch','4','--save-every','1','--best-checkpoint'],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-2000:])
            losses=[json.loads(line)['validationLoss'] for line in result.stdout.splitlines() if line.startswith('{') and 'validationLoss' in line]
            _,best=load(output.with_suffix('.best.pt'));self.assertAlmostEqual(best['validationLoss'],min(losses))
            self.assertTrue(best['trainingStateIncluded'])
    def test_resumed_experiment_uses_saved_data_and_never_resets_or_promotes_api_campaign(self):
        base={'loss':1,'correct':5,'health':1,'identity':.5,'math':.5,'memory':.5,'extraction':.5,'familiar':1}
        state={'format':VERSION,'status':'ready','round':2,'rejected':0,'bestReport':base,
               'profile':{'gpus':1},**{key:{'path':key} for key in ['sourceData','data','checks','best','baseline']}}
        with self.temporary() as folder,patch.dict(os.environ,{'NEBULA_HF_REPO':'owner/private','NEBULA_HF_TOKEN':'hf_fake_test_only'}):
            root=Path(folder);store=Mock();store.state.return_value=state
            def download(file,destination):
                path=Path(destination);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'weights');return path
            def train(project,resume,output,*args,**kwargs):
                output.write_bytes(b'new-weights');output.with_suffix('.best.pt').write_bytes(b'new-weights')
            def evaluate(path,data,checks,output):Path(output).write_text('{}');return {**base,'loss':.98}
            def publish(value,files,project):
                return {**value,**{key:{'path':name} for key,(path,name) in files.items()}}
            store.download.side_effect=download;store.publish.side_effect=publish
            with patch('v4_experiment.Store',return_value=store),patch('v4_experiment.torch.cuda.is_available',return_value=True),\
                 patch('v4_experiment.torch.cuda.empty_cache'),patch('v4_experiment.restore_data'),patch('v4_experiment.configure_rules'),\
                 patch('v4_experiment.Client') as client,patch('v4_experiment.public_additions') as public,\
                 patch('v4_experiment.launch',side_effect=train),patch('v4_experiment.evaluate',side_effect=evaluate):
                experiment(['--project',str(root),'--rounds','1'])
            client.assert_not_called();public.assert_not_called()
            saved=store.publish.call_args.args[0]
            self.assertEqual(saved['round'],3);self.assertTrue(saved['lastRoundAccepted']);self.assertEqual(saved['rejected'],0)
            self.assertIn('best',store.publish.call_args.args[1])
    def test_paused_v4_state_is_preserved_without_starting_gpu_training(self):
        store=Mock();store.state.return_value={'format':VERSION,'status':'paused'}
        with self.temporary() as folder,patch('v4_experiment.Store',return_value=store),\
             patch('v4_experiment.torch.cuda.is_available',return_value=True),patch('v4_experiment.launch') as train:
            experiment(['--project',folder])
        train.assert_not_called();store.publish.assert_not_called()

if __name__=='__main__':unittest.main()
