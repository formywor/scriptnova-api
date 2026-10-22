import ast,hashlib,io,json,os,shutil,subprocess,sys,tempfile,unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock,patch
import torch
from nebula import Nebula,config_for_preset,save
from dataflow import write_jsonl
from research_client import ResearchError
import colab_v9_evaluator as companion

class ColabV9Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_write_operations_are_explicitly_disabled(self):
        store=object.__new__(companion.ReadOnlyStore)
        with self.assertRaisesRegex(ResearchError,'READ_ONLY'):store.publish({}, {}, None)
    def test_fresh_probes_exclude_known_prompts(self):
        cases=companion.fresh_cases(set());self.assertEqual(len(cases),12)
        banned=companion.normalized(cases[0]['messages'][0]['content'])
        filtered=companion.fresh_cases({banned});self.assertEqual(len(filtered),11)
        self.assertFalse(any(companion.normalized(m['content'])==banned for c in filtered for m in c['messages']))
    def test_generated_probes_use_owned_model_and_distinguish_manual_checks(self):
        torch.set_num_threads(1)
        with self.temporary() as folder:
            path=Path(folder)/'small.pt';save(Nebula(config_for_preset('smoke')),path,{'steps':123})
            cases=[{'category':'context','messages':[{'role':'user','content':'Which color?'}],'expected':'amber'},{'category':'writing','messages':[{'role':'user','content':'Write a kind note.'}],'humanReviewRequired':True}]
            with patch('nebula.Nebula.reply',side_effect=['It is amber.','Thank you for helping.']):report=companion.generated_checks(path,cases,'cpu')
            self.assertEqual(report['steps'],123);self.assertEqual(report['exactChecksPassed'],1);self.assertEqual(report['manualReviewCases'],1);self.assertIsNone(report['answers'][1]['passed'])
    def test_snapshot_is_pinned_cached_and_never_published(self):
        with self.temporary() as folder,patch.dict(os.environ,{},clear=False):
            root=Path(folder);remote=root/'remote';remote.mkdir();project=root/'project';project.mkdir()
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[{'role':'user','content':'Practice unseen object QZ.'},{'role':'assistant','content':'A useful reply.'}]}]
            for name in ['data','validationData','evaluationData','teacherData']:write_jsonl(remote/(name+'.jsonl'),rows)
            (remote/'checks.json').write_text(json.dumps({'cases':[]}));(remote/'source.pt').write_bytes(b'source');(remote/'model.pt').write_bytes(b'weights')
            def ref(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            state={'format':'nebula-v9-curriculum-1','round':2,'sourceData':ref(remote/'source.pt'),'checks':ref(remote/'checks.json'),'best':ref(remote/'model.pt'),'latest':ref(remote/'model.pt')}
            state.update({key:ref(remote/(key+'.jsonl')) for key in ['data','validationData','evaluationData','teacherData']})
            store=Mock();store.revision='pinned-revision'
            def download(value,target):shutil.copyfile(value['path'],target);return target
            store.download.side_effect=download
            def restore(source,project):(project/'nebula-rules.json').write_text(json.dumps({'instructions':['You are Nebula AI.']}))
            metrics={'correct':57,'cases':76,'chatChecks':5,'chatCases':20,'memory':1.,'chatLoss':1.2,'publicChatLoss':1.6,'languageLoss':1.1}
            evaluator=Mock(return_value=metrics);generate=Mock(return_value={'exactChecksPassed':2,'exactChecks':6,'answers':[]})
            with patch.object(companion,'restore_data',side_effect=restore),redirect_stdout(io.StringIO()):
                result=companion.evaluate_snapshot(store,state,project,'cpu',evaluator,generate)
                companion.evaluate_snapshot(store,state,project,'cpu',evaluator,generate)
            evaluator.assert_called_once();generate.assert_called_once();store.publish.assert_not_called()
            report=json.loads(result[0].read_text());self.assertEqual(report['sourceRevision'],'pinned-revision');self.assertFalse(report['trainingChanges']);self.assertEqual(report['comparison']['correct']['latestMinusBest'],0)
            self.assertTrue(result[1].is_file())
    def test_monitor_waits_for_new_rounds_and_does_not_repeat_unchanged_snapshots(self):
        with self.temporary() as folder:
            root=Path(folder);clock=[0.];stores=[]
            states=[None,{'round':0,'best':{'sha256':'a'}},{'round':0,'best':{'sha256':'a'}},{'round':1,'best':{'sha256':'a'},'latest':{'sha256':'b'}}]
            def factory(*args):
                store=Mock();store.state.return_value=states[min(len(stores),3)];stores.append(store);return store
            run=Mock(return_value=(root/'report.json',root/'report.md'));callback=Mock()
            with redirect_stdout(io.StringIO()):count=companion.watch(root,'private/test','unused',hours=.03,max_rounds=2,poll_seconds=15,device='cpu',on_report=callback,store_factory=factory,clock=lambda:clock[0],sleep=lambda delay:clock.__setitem__(0,clock[0]+delay),run_evaluation=run)
            self.assertEqual(count,2);self.assertEqual(run.call_count,2);self.assertEqual(callback.call_count,2)
            for store in stores:store.publish.assert_not_called()
    def test_notebook_sources_are_self_contained_and_contain_no_credentials(self):
        from build_colab_v9_evaluator import build
        notebook=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(notebook)
        self.assertNotRegex(text,r'gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}')
        code=''.join(notebook['cells'][2]['source']);sources=ast.literal_eval(ast.parse(code).body[0].value)
        root=Path(__file__).parents[1]
        for name,content in sources.items():self.assertEqual((root/name).read_text(encoding='utf-8'),content)
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))
        with self.temporary() as folder:
            directory=Path(folder)
            for name,content in sources.items():(directory/name).write_text(content,encoding='utf-8')
            env=dict(os.environ,PYTHONPATH=os.pathsep.join(p for p in os.environ.get('PYTHONPATH','').split(os.pathsep) if 'api\\model' not in p))
            result=subprocess.run([sys.executable,'-c','import colab_v9_evaluator; print("isolated import passed")'],cwd=directory,env=env,capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_real_cpu_generation_runs_without_training(self):
        from nebula import Config
        torch.set_num_threads(1)
        with self.temporary() as folder:
            path=Path(folder)/'small.pt';save(Nebula(Config(width=32,heads=2,layers=1,context=512)),path,{'steps':321})
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            case={'category':'writing','messages':[{'role':'user','content':'Write a kind note.'}],'humanReviewRequired':True}
            report=companion.generated_checks(path,[case],'cpu')
            self.assertEqual(report['steps'],321);self.assertEqual(len(report['answers']),1);self.assertIsInstance(report['answers'][0]['reply'],str)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest)

if __name__=='__main__':unittest.main()
