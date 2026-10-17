import ast
from contextlib import redirect_stdout
import io,json,os
from pathlib import Path
import shutil,subprocess,sys,tempfile
import unittest
from unittest.mock import Mock,patch
import torch
from nebula import Config,Nebula,save,load,config_for_preset
from research_client import ResearchError
from dataflow import write_jsonl
from v7_teacher import clean_dialogue
from test_v7 import dialogue
import hashlib
from v8_grow import grow_model,TARGET
from v8_train import main as train
from v8_store import Store

class V8Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_exact_parameter_count_and_weight_tying(self):
        with torch.device('meta'):model=Nebula(TARGET)
        self.assertEqual(sum(p.numel() for p in model.parameters()),100219392)
        self.assertIs(model.token.weight,model.output.weight)
    def test_expansion_retains_logits_and_new_residual_layers_learn(self):
        torch.set_num_threads(1);torch.manual_seed(72)
        source=Nebula(Config(width=32,heads=2,layers=2,context=256))
        grown=grow_model(source,Config(width=96,heads=6,layers=3,context=256));x=torch.tensor([[4,9,16,25]])
        torch.testing.assert_close(source(x),grown(x),rtol=2e-4,atol=2e-5)
        grown.train();grown(x).square().mean().backward()
        self.assertGreater(float(grown.blocks[2].linear2.weight.grad.abs().sum()),0)
        self.assertIs(grown.output.weight,grown.token.weight)
    def test_activation_checkpointing_preserves_gradients(self):
        torch.set_num_threads(1);torch.manual_seed(42)
        first=Nebula(Config(width=32,heads=2,layers=2,context=64));second=Nebula(first.config);second.load_state_dict(first.state_dict());second._activation_checkpointing=True
        x=torch.tensor([[1,5,7,9]]);first(x).square().mean().backward();second(x).square().mean().backward()
        for key,param in first.named_parameters():torch.testing.assert_close(param.grad,dict(second.named_parameters())[key].grad)
    def test_large_checkpoint_shards_roundtrip_verify_checksums_and_atomic_failure(self):
        import v8_store
        with self.temporary() as folder:
            root=Path(folder);remote=root/'remote';remote.mkdir();blob=root/'weights.pt';blob.write_bytes(bytes(range(200)))
            store=object.__new__(Store);store.repo='private/example';store.token='unused';store.prefix='experiments/nebula-v8-100m/';store.revision='before';store.info=Mock()
            def commit(**kw):
                self.assertEqual(kw['parent_commit'],'before')
                for op in kw['operations']:
                    dest=remote/op.path_in_repo;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(op.path_or_fileobj,dest)
                return Mock(oid='after')
            store.api=Mock();store.api.create_commit.side_effect=commit
            with patch.object(v8_store,'PART_BYTES',64):state=store.publish({'round':1},{'working':(blob,'working.pt')},root)
            self.assertEqual(len(state['working']['parts']),4);self.assertEqual(store.revision,'after')
            with patch('huggingface_hub.hf_hub_download',side_effect=lambda repo,path,**kw:str(remote/path)):
                result=store.download(state['working'],root/'resumed.pt');self.assertEqual(result.read_bytes(),blob.read_bytes())
                bad={**state['working'],'sha256':'0'*64};old=root/'existing.pt';old.write_bytes(b'preserve me')
                with self.assertRaisesRegex(ResearchError,'V8_CHECKSUM_MISMATCH'):store.download(bad,old)
                self.assertEqual(old.read_bytes(),b'preserve me')
                part=remote/state['working']['parts'][0]['path'];part.write_bytes(b'corrupted')
                with self.assertRaisesRegex(ResearchError,'V4_CHECKSUM_MISMATCH'):store.download(state['working'],root/'fresh.pt')
    def test_failed_remote_commit_does_not_advance_revision(self):
        with self.temporary() as folder:
            root=Path(folder);file=root/'small';file.write_bytes(b'abc');store=object.__new__(Store)
            store.repo='private/test';store.prefix='experiments/test/';store.revision='old';store.info=Mock();store.api=Mock();store.api.create_commit.side_effect=RuntimeError('offline')
            with self.assertRaisesRegex(ResearchError,'V8_BACKUP_FAILED_OR_CONCURRENT_RUN'):store.publish({'round':1},{'best':(file,'best.pt')},root)
            self.assertEqual(store.revision,'old')
    def test_microbatch_accumulation_matches_full_batch_and_resumes(self):
        torch.set_num_threads(1)
        with self.temporary() as folder:
            root=Path(folder);data=root/'data.jsonl'
            rows=[{'reviewStatus':'approved','splitGroup':str(i),'source':{'kind':'seed'},'messages':[{'role':'user','content':f'Example {i}.'},{'role':'assistant','content':f'Here is example {i}.'}]} for i in range(50)]
            write_jsonl(data,rows);save(Nebula(Config(width=32,heads=2,layers=1,context=256)),root/'source.pt',{'steps':100})
            common=['--data',str(data),'--resume',str(root/'source.pt'),'--quality-anchor',str(root/'source.pt'),'--batch','4','--steps','3','--device','cpu']
            with redirect_stdout(io.StringIO()):
                train(common+['--output',str(root/'full.pt'),'--microbatch','4'])
                train(common+['--output',str(root/'micro.pt'),'--microbatch','1'])
                train(['--data',str(data),'--resume',str(root/'micro.pt'),'--quality-anchor',str(root/'source.pt'),'--output',str(root/'resume.pt'),'--batch','4','--steps','2','--device','cpu'])
            full,_=load(root/'full.pt');micro,info=load(root/'micro.pt')
            for key,value in full.state_dict().items():torch.testing.assert_close(value,micro.state_dict()[key],rtol=1e-4,atol=2e-6)
            self.assertEqual(info['steps'],103);self.assertEqual(load(root/'resume.pt')[1]['steps'],105);self.assertTrue(load(root/'resume.pt')[1]['optimizerStateRestored'])
    def test_two_cpu_ranks_match_equal_example_anchor_training(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder);data=root/'data.jsonl'
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':f'Say {i}.'},{'role':'assistant','content':f'Answer {i}.'}]} for i in range(100)]
            write_jsonl(data,rows)
            torch.manual_seed(42);save(Nebula(config_for_preset('smoke')),root/'start.pt',{'steps':0})
            script=Path(__file__).resolve().parents[1]/'v8_train.py'
            common=[sys.executable,str(script),'--data',str(data),'--resume',str(root/'start.pt'),
                    '--steps','3','--batch','4','--device','cpu','--quality-anchor',str(root/'start.pt'),'--microbatch','1']
            result=subprocess.run(common+['--output',str(root/'single.pt')],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-2000:])
            processes=[];streams=[]
            try:
                for rank in range(2):
                    env=dict(os.environ,RANK=str(rank),LOCAL_RANK=str(rank),WORLD_SIZE='2')
                    stream=(root/f'rank-{rank}.log').open('w');streams.append(stream)
                    process=subprocess.Popen(common+['--output',str(root/'multi.pt'),'--rendezvous',str(root/'rendezvous')],
                                             env=env,stdout=stream,stderr=subprocess.STDOUT)
                    processes.append(process)
                for process in processes:process.wait(timeout=60)
            finally:
                for process in processes:
                    if process.poll() is None:process.kill();process.wait()
                for stream in streams:stream.close()
            logs='\n'.join((root/f'rank-{rank}.log').read_text() for rank in range(2))
            self.assertTrue(all(p.returncode==0 for p in processes),logs[-4000:])
            one,_=load(root/'single.pt');two,info=load(root/'multi.pt')
            self.assertEqual(info['worldSize'],2);self.assertEqual(info['steps'],3)
            for key,value in one.state_dict().items():
                torch.testing.assert_close(value,two.state_dict()[key],rtol=1e-4,atol=2e-6)

    def test_initialize_uses_saved_v7_best_and_preserves_its_small_anchor(self):
        import v8_experiment as runner
        from contextlib import ExitStack
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();data=root/'data.jsonl';write_jsonl(data,[])
            source=root/'source.pt';save(Nebula(Config(width=32,heads=2,layers=1,context=256)),source,{'steps':35012})
            score={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.,'chatChecks':5,'chatCases':20}
            old={'round':1,'best':source,'sourceData':data,'data':data,'evaluationData':data,'checks':data,'bestReport':score,'teacherNextIndex':2014}
            previous=Mock();previous.state.return_value=old;previous.prefix='experiments/nebula-v7/';previous.revision='pinned'
            def download(ref,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ref,target);return target
            previous.download.side_effect=download
            def growth(src,dest):shutil.copyfile(src,dest);return {'parameters':100219392}
            def evaluate(*args):args[4].write_text('{}');return score
            store=Mock();store.repo='private/test';store.token='not-printed';store.publish.side_effect=lambda state,files,project:state
            with ExitStack() as stack:
                for name,value in [('PreviousStore',Mock(return_value=previous)),('restore_data',Mock()),('configure_rules',Mock()),('grow_checkpoint',growth),('launch',Mock(return_value={'peakGpuMemoryBytes':123})),('evaluate',evaluate)]:stack.enter_context(patch.object(runner,name,value))
                stack.enter_context(patch('torch.cuda.device_count',return_value=2))
                with redirect_stdout(io.StringIO()):state=runner.initialize(store,project)
                runner.launch.assert_called_once();self.assertTrue(runner.launch.call_args.kwargs['large_model']);self.assertEqual(runner.launch.call_args.kwargs['microbatch'],1)
            files=store.publish.call_args.args[1];self.assertEqual(load(files['qualityAnchor'][0])[1]['steps'],35012);self.assertEqual(load(source)[1]['steps'],35012)
            self.assertEqual(state['teacherNextIndex'],2014);previous.publish.assert_not_called();self.assertEqual(state['sourceRun'],'experiments/nebula-v7/')

    def test_teacher_and_historical_replay_both_update_the_model(self):
        torch.set_num_threads(1)
        with self.temporary() as folder:
            root=Path(folder);rows=[]
            for i in range(40):
                for kind,answer in [('v7-conversation',f'Here is a simple idea {i}.'),('memory',f'Your name is Test{i}.'),('identity','I am Nebula AI.'),('math',f'{i} + 1 = {i+1}.')]:
                    rows.append({'reviewStatus':'approved','splitGroup':f'{kind}-{i}','source':{'kind':'seed','curriculum':kind},'messages':[{'role':'user','content':f'Practice {kind} example {i}.'},{'role':'assistant','content':answer}]})
            write_jsonl(root/'data.jsonl',rows)
            teachers=[]
            for i,topic in enumerate(['painting','gardening','writing','baking','chess']):
                row=clean_dialogue(dialogue(topic),'v7-test-'+str(i));teachers.append(row)
            write_jsonl(root/'teachers.jsonl',teachers)
            review={'reviewStatus':'approved','source':{'kind':'teacher','trainingAllowed':True,'curriculum':'v6-reviewed','validation':'two-pass-review-v1'},'messages':[{'role':'user','content':'Suggest a quiet afternoon.'},{'role':'assistant','content':'Read a book and take a short walk.'}]}
            write_jsonl(root/'reviews.jsonl',[review]);model=Nebula(config_for_preset('smoke'));save(model,root/'anchor.pt',{'steps':17});original=hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest()
            common=['--data',str(root/'data.jsonl'),'--quality-anchor',str(root/'anchor.pt'),'--batch','2','--device','cpu','--conversation-mix','--teacher-data',str(root/'teachers.jsonl'),'--review-data',str(root/'reviews.jsonl')]
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'anchor.pt'),'--output',str(root/'end.pt'),'--steps','20','--lr','.000003'])
            trained,meta=load(root/'end.pt');self.assertEqual(meta['steps'],37);self.assertEqual(meta['conversationUpdates'],16);self.assertEqual(meta['mixedUpdates'],4);self.assertLessEqual(meta['reviewUpdates'],1);self.assertGreater(meta['teacherUpdates'],0);self.assertGreater(meta['pastBestReplayUpdates'],0)
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'end.pt'),'--output',str(root/'next.pt'),'--steps','5','--lr','.000001','--sampling-seed','777'])
            _,next_meta=load(root/'next.pt');self.assertEqual(next_meta['steps'],42);self.assertTrue(next_meta['optimizerStateRestored']);self.assertEqual(hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest(),original)
            self.assertTrue(any(not torch.equal(v,trained.state_dict()[k]) for k,v in model.state_dict().items()))
    def test_notebook_is_current_self_contained_and_has_no_credentials(self):
        from build_v8_notebook import build
        notebook=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(notebook)
        self.assertNotRegex(text,r'gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}');self.assertIn('100,219,392',text);self.assertIn('nebula-v8-100m',text)
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))

if __name__=='__main__':unittest.main()
