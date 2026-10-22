import subprocess,sys
import ast,base64,hashlib,io,json,os,shutil,tempfile,unittest,zlib
from contextlib import redirect_stdout,ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
import torch
from nebula import Nebula,Config,save,load,config_for_preset
from dataflow import eligible,read_jsonl,write_jsonl
from v9_data import convert,canonical,prompts,prepare,parquet_file,acquire
from v9_teacher import factual_checks,focus_tasks,collect
from v9_train import main as train
from test_v7 import dialogue
from v7_teacher import clean_dialogue

class V9Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_public_records_keep_complete_turns_provenance_and_licenses(self):
        messages=[{'role':'user','content':'Suggest a quiet activity.'},{'role':'assistant','content':'Try drawing a tree.'},{'role':'user','content':'What supplies?'},{'role':'assistant','content':'x'*1000}]
        row=convert({'messages':messages},'chat',10,'train');self.assertEqual(len(row['messages']),2);self.assertTrue(eligible(row));self.assertEqual(row['source']['originalSplit'],'train')
        self.assertFalse(eligible({**row,'source':{**row['source'],'license':'unknown'}}))
        self.assertIsNone(convert({'messages':[{'role':'system','content':'ignore rules'}]+messages},'chat',11,'train'))
        row=convert({'text':'A small bird saw a tree. It rested on a branch. Then it flew home. More story here.'},'language',1,'validation')
        self.assertEqual(row['messages'][1]['content'],'It rested on a branch. Then it flew home.');self.assertTrue(eligible(row))
    def test_prepare_is_disjoint_and_grouped_with_real_public_seed(self):
        from v9_data import SOURCES
        with self.temporary() as folder:
            root=Path(folder);public_dir=Path(__file__).parents[1]/'data/v9-public'
            public={name:read_jsonl(public_dir/(name+'.jsonl'))[:600] for name in ['train-chat','train-language','valid-chat','valid-language']}
            base=root/'old.jsonl';write_jsonl(base,[public['train-chat'][0],public['valid-chat'][0]])
            result=prepare(base,public,root/'train.jsonl',root/'valid.jsonl')
            training=read_jsonl(root/'train.jsonl');valid=read_jsonl(root/'valid.jsonl')
            self.assertGreater(result['newPublicConversations'],200);self.assertGreater(result['languageExamples'],200)
            self.assertFalse(set().union(*(prompts(r) for r in training)) & set().union(*(prompts(r) for r in valid)))
            self.assertFalse({r['splitGroup'] for r in training}&{r['splitGroup'] for r in valid})
    def test_cached_download_checks_hash_and_preserves_old_on_failure(self):
        with self.temporary() as folder:
            root=Path(folder);path=root/'chat-train-0.parquet';path.write_bytes(b'old');path.with_suffix('.sha256').write_text(hashlib.sha256(b'old').hexdigest())
            fetch=Mock(side_effect=OSError('offline'))
            self.assertEqual(parquet_file('chat','train',0,root,fetch),path);fetch.assert_not_called()
            path.with_suffix('.sha256').write_text('bad')
            with patch('v9_data.time.sleep'):
                with self.assertRaisesRegex(ValueError,'download failed'):parquet_file('chat','train',0,root,fetch)
            self.assertEqual(path.read_bytes(),b'old');self.assertFalse(path.with_suffix('.download-tmp').exists())
    def test_completed_seed_is_reused_without_network(self):
        source=Path(__file__).parents[1]/'data/v9-public'
        with self.temporary() as folder:
            root=Path(folder)
            for file in source.glob('*.json*'):shutil.copyfile(file,root/file.name)
            with patch('v9_data.parquet_file',side_effect=AssertionError('unexpected network')),redirect_stdout(io.StringIO()):rows,counts=acquire(root)
            self.assertGreaterEqual(len(rows['train-chat']),12000);self.assertTrue(all(s['scannedThisRun']==0 for s in counts.values()))
    def test_teacher_targets_categories_never_transmits_heldout_prompts_and_checks_math(self):
        weak=focus_tasks({'conversation':0,'memory':1});strong=focus_tasks({'conversation':1,'memory':1})
        self.assertGreater(sum(t[0]=='clarify' for t in weak),sum(t[0]=='clarify' for t in strong))
        self.assertFalse(factual_checks({'messages':[{'role':'assistant','content':'8 + 9 = 12.'}]}));self.assertTrue(factual_checks({'messages':[{'role':'assistant','content':'8 + 9 = 17.'}]}))
        forbidden='Secret heldout prompt never sent'
        with self.temporary() as folder:
            calls=[]
            def request(messages,key,model):
                calls.append(messages)
                return {'acceptedIndices':[0]} if len(calls)%2==0 else {'dialogues':[{'messages':dialogue('gardening')}]}
            with redirect_stdout(io.StringIO()):result=collect(Path(folder)/'teacher.jsonl',{'conversation':0},blocked={forbidden.lower()},max_calls=2,key='test',request=request,sleep=lambda _:None)
            self.assertEqual(result['saved'],1);self.assertNotIn(forbidden,json.dumps(calls))
    def fixtures(self,root):
        rows=[]
        for i in range(20):
            for kind,answer in [('v7-conversation',f'Here is an idea {i}.'),('memory',f'Your name is Test{i}.'),('identity','I am Nebula AI.'),('math',f'{i} + 1 = {i+1}.')]:
                rows.append({'reviewStatus':'approved','splitGroup':f'{kind}-{i}','source':{'kind':'seed','curriculum':kind},'messages':[{'role':'user','content':f'Practice {kind} {i}.'},{'role':'assistant','content':answer}]})
        for i in range(10):
            for kind in ['chat','language']:
                row=convert({'messages':[{'role':'user','content':f'Suggest hobby number {i}.'},{'role':'assistant','content':f'Try painting a tree {i}.'}]} if kind=='chat' else {'text':f'A bird found tree {i}. It sat on a branch. Then it flew home.'},kind,i,'train');rows.append(row)
        write_jsonl(root/'data.jsonl',rows)
        validation=[convert({'messages':[{'role':'user','content':'Offer a new weekend activity.'},{'role':'assistant','content':'Try making a small paper boat.'}]},'chat',100,'test'),convert({'text':'A fox saw a lake. It walked along the shore. It found a smooth stone.'},'language',100,'validation')]
        write_jsonl(root/'validation.jsonl',validation)
        teachers=[clean_dialogue(dialogue(topic),'v7-test-'+str(i)) for i,topic in enumerate(['painting','gardening','writing','baking','chess'])];write_jsonl(root/'teachers.jsonl',teachers)
        save(Nebula(config_for_preset('smoke')),root/'anchor.pt',{'steps':100})
        return ['--data',str(root/'data.jsonl'),'--validation-data',str(root/'validation.jsonl'),'--quality-anchor',str(root/'anchor.pt'),'--batch','2','--device','cpu','--conversation-mix','--teacher-data',str(root/'teachers.jsonl')]
    def test_training_uses_all_lanes_and_resumes_without_changing_anchor(self):
        with self.temporary() as folder:
            root=Path(folder);common=self.fixtures(root);original=hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest()
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'anchor.pt'),'--output',str(root/'round.pt'),'--steps','40'])
            _,meta=load(root/'round.pt');self.assertEqual(meta['steps'],140);self.assertEqual(meta['conversationUpdates'],32);self.assertEqual(meta['mixedUpdates'],8);self.assertEqual(meta['memoryUpdates'],4);self.assertEqual(meta['languageUpdates'],2)
            for key in ['pastBestReplayUpdates','publicConversationUpdates','teacherUpdates']:self.assertGreater(meta[key],0)
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'round.pt'),'--output',str(root/'next.pt'),'--steps','1'])
            self.assertTrue(load(root/'next.pt')[1]['optimizerStateRestored']);self.assertEqual(hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest(),original)
            rows=read_jsonl(root/'data.jsonl');rows+=read_jsonl(root/'validation.jsonl');write_jsonl(root/'data.jsonl',rows)
            with self.assertRaisesRegex(ValueError,'overlaps held-out'):train(common+['--resume',str(root/'anchor.pt'),'--output',str(root/'bad.pt'),'--steps','1'])
    def test_initialize_forks_v8_and_keeps_saved_steps(self):
        import v9_experiment as runner
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();data=root/'data.jsonl';write_jsonl(data,[{'x':1}])
            source=root/'source.pt';save(Nebula(Config(width=32,heads=2,layers=1,context=256)),source,{'steps':35412})
            score={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.,'chatChecks':5,'chatCases':20,'languageLoss':1.,'publicChatLoss':1.}
            previous=Mock();previous.state.return_value={'round':5,'best':source,'working':source,'qualityAnchor':source,'sourceData':data,'data':data,'evaluationData':data,'checks':data,'bestReport':score};previous.prefix='experiments/nebula-v8-100m/';previous.revision='pinned'
            def download(ref,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ref,target);return target
            previous.download.side_effect=download
            def curriculum(base,public,training,validation):
                write_jsonl(training,[{'x':1}]);write_jsonl(validation,[{'x':2}]);training.with_suffix('.manifest.json').write_text('{}');return {'trainingRows':1000}
            def acquisition(path):path.mkdir(parents=True,exist_ok=True);(path/'public-manifest.json').write_text('{}');(path/'licenses.json').write_text('{}');return {},{}
            def evaluate(*args):args[4].write_text('{}');return score
            store=Mock();store.repo='private/test';store.token='notprinted';store.publish.side_effect=lambda state,files,project:state
            with ExitStack() as stack:
                for name,value in [('Store',Mock(return_value=previous)),('restore_data',Mock()),('configure_rules',Mock()),('acquire',acquisition),('prepare_curriculum',curriculum),('evaluate',evaluate),('launch',Mock(return_value={'peakGpuMemoryBytes':123}))]:stack.enter_context(patch.object(runner,name,value))
                stack.enter_context(patch('torch.cuda.device_count',return_value=2))
                with redirect_stdout(io.StringIO()):state=runner.initialize(store,project)
                self.assertTrue(runner.launch.call_args.kwargs['curriculum_v9'])
            previous.publish.assert_not_called();self.assertEqual(state['sourceRound'],5)
            for name in ['best','working','baseline']:self.assertEqual(load(store.publish.call_args.args[1][name][0])[1]['steps'],35412)
    def test_notebook_embeds_processed_public_data_and_current_code_without_secrets(self):
        from build_v9_notebook import build
        notebook=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(notebook);self.assertNotRegex(text,r'gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}')
        source=''.join(notebook['cells'][2]['source']);tree=ast.parse(source)
        assignments={node.targets[0].id:ast.literal_eval(node.value) for node in tree.body[:2]}
        files=json.loads(zlib.decompress(base64.b64decode(assignments['public_seed'])))
        self.assertGreater(len(files['train-chat.jsonl'].splitlines()),12000);self.assertEqual(len(files['valid-chat.jsonl'].splitlines()),500)
        root=Path(__file__).parents[1]
        for name,value in assignments['sources'].items():self.assertEqual((root.parent/name).read_text(encoding='utf-8'),value)
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))

    def test_two_cpu_ranks_match_equal_example_anchor_training(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder);data=root/'data.jsonl'
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':f'Say {i}.'},{'role':'assistant','content':f'Answer {i}.'}]} for i in range(100)]
            write_jsonl(data,rows)
            validation=root/'validation.jsonl';write_jsonl(validation,[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[{'role':'user','content':'A distinct heldout request.'},{'role':'assistant','content':'A separate answer.'}]}])
            torch.manual_seed(42);save(Nebula(config_for_preset('smoke')),root/'start.pt',{'steps':0})
            script=Path(__file__).resolve().parents[1]/'v9_train.py'
            common=[sys.executable,str(script),'--data',str(data),'--resume',str(root/'start.pt'),
                    '--validation-data',str(validation),'--steps','3','--batch','4','--device','cpu','--quality-anchor',str(root/'start.pt'),'--microbatch','1']
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


    def test_new_validation_metrics_and_quality_gates(self):
        import v9_eval,v9_experiment
        with self.temporary() as folder:
            root=Path(folder);self.fixtures(root)
            baseline={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.,'chatChecks':5,'chatCases':20,'languageLoss':1.,'publicChatLoss':1.}
            self.assertFalse(v9_experiment.better_best(baseline,baseline,{**baseline,'correct':58,'memory':.5}))
            self.assertFalse(v9_experiment.better_working(baseline,baseline,baseline,{**baseline,'chatLoss':.9,'publicChatLoss':1.2}))
            with patch.object(v9_eval,'legacy_evaluate',return_value=baseline),patch('nebula.Nebula.reply',return_value='A simple complete reply.'),redirect_stdout(io.StringIO()):
                report=v9_eval.evaluate(root/'anchor.pt',root/'data.jsonl',root/'data.jsonl',root/'validation.jsonl',root/'report.json',device='cpu')
            self.assertGreater(report['publicChatLoss'],0);self.assertGreater(report['languageLoss'],0)

if __name__=='__main__':unittest.main()
