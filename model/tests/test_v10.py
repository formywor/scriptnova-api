import ast,hashlib,io,json,os,shutil,subprocess,sys,tempfile,unittest
from contextlib import redirect_stdout,ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
import torch
from nebula import Nebula,Config,load,save,config_for_preset
from dataflow import read_jsonl,write_jsonl
from research_client import ResearchError
from v10_data import owned,rejection,prepare
from v10_train import main as train
from v10_store import Store
import test_v9

class V10Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_owned_repairs_are_complete_and_never_frozen_questions(self):
        rows=owned();self.assertEqual(len(rows),40);self.assertTrue(all(rejection(r) is None for r in rows));self.assertGreater(sum(len(r['messages'])>2 for r in rows),30)
        row=json.loads(json.dumps(rows[0]));row['messages'][1]['content']='The same phrase the same phrase the same phrase.';self.assertEqual(rejection(row),'repeated_phrase')
        row=json.loads(json.dumps(rows[0]));row['messages'][1]['content']='8 + 9 = 12.';self.assertEqual(rejection(row),'incorrect_addition')
        row['messages'][1]['content']='x'*221+'.';self.assertEqual(rejection(row),'answer_length')
    def test_short_curriculum_preserves_fixed_validation_and_removes_overlaps(self):
        from v9_data import prompts
        with self.temporary() as folder:
            from v9_data import convert
            root=Path(folder);source=root/'source';source.mkdir()
            rows=[convert({'messages':[{'role':'user','content':f'Suggest a paper hobby for exercise {i}.'},{'role':'assistant','content':f'Draw a small tree for exercise {i}.'}]},'chat',i,'train') for i in range(250)]
            valid=[convert({'messages':[{'role':'user','content':'An unrelated validation request about a boat.'},{'role':'assistant','content':'Fold a sheet into a small paper boat.'}]},'chat',1000,'test')]
            write_jsonl(source/'train.jsonl',rows);write_jsonl(source/'validation.jsonl',valid)
            baseline=(source/'validation.jsonl').read_bytes();summary=prepare(source/'train.jsonl',source/'validation.jsonl',root/'train.jsonl')
            self.assertEqual(summary['validationSha256'],hashlib.sha256(baseline).hexdigest());self.assertGreater(summary['publicConversationRows'],200);self.assertGreater(summary['repairDialogues'],20)
            blocked=set().union(*(prompts(r) for r in valid))
            self.assertFalse(any(prompts(r)&blocked for r in read_jsonl(root/'train.jsonl')))
            self.assertEqual((source/'validation.jsonl').read_bytes(),baseline)
    def fixtures(self,root):
        common=test_v9.V9Tests.fixtures(self,root);write_jsonl(root/'data.jsonl',read_jsonl(root/'data.jsonl')+owned())
        save(Nebula(Config(width=32,heads=2,layers=1,context=768)),root/'anchor.pt',{'steps':35012})
        return common
    def test_training_keeps_80_20_uses_repairs_saves_early_candidates_and_resumes(self):
        with self.temporary() as folder:
            root=Path(folder);common=self.fixtures(root);original=hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest()
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'anchor.pt'),'--output',str(root/'round.pt'),'--steps','50','--save-every','25','--best-checkpoint','--lr','.0000015'])
            _,meta=load(root/'round.pt');self.assertEqual(meta['steps'],35062);self.assertEqual(meta['conversationUpdates'],40);self.assertEqual(meta['mixedUpdates'],10);self.assertEqual(meta['memoryUpdates'],5);self.assertGreater(meta['identityUpdates'],0)
            for key in ['repairUpdates','publicConversationUpdates','teacherUpdates','pastBestReplayUpdates']:self.assertGreater(meta[key],0)
            self.assertLessEqual(meta['repairUpdates'],max(1,(40*4+1)//2));self.assertEqual(load(root/'round.step-25.pt')[1]['steps'],35037);self.assertEqual(load(root/'round.step-50.pt')[1]['steps'],35062)
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'round.step-25.pt'),'--output',str(root/'next.pt'),'--steps','5','--lr','.0000015'])
            self.assertTrue(load(root/'next.pt')[1]['optimizerStateRestored']);self.assertEqual(load(root/'next.pt')[1]['steps'],35042)
            state=torch.load(root/'next.pt',weights_only=True)['trainingState'];self.assertEqual(state['totalUpdates'],30)
            self.assertEqual(hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest(),original)
    def test_teacher_rejection_reasons_are_safe_and_second_pass_is_required(self):
        from v10_teacher import collect
        from test_v7 import dialogue
        with self.temporary() as folder:
            bad=dialogue('gardening');bad[1]['content']='8 + 9 = 12.'
            request=Mock(side_effect=[{'dialogues':[{'messages':bad},{'messages':dialogue('painting')}]},{'acceptedIndices':[0]}])
            log=io.StringIO()
            with redirect_stdout(log):result=collect(Path(folder)/'teacher.jsonl',{'conversation':0},max_calls=2,key='test',request=request,sleep=lambda _:None)
            self.assertEqual(result['saved'],1);self.assertIn('incorrect_addition',log.getvalue());self.assertNotIn('8 + 9 = 12',log.getvalue());self.assertEqual(request.call_count,2)
    def test_gate_reasons_do_not_accept_lower_loss_with_lost_memory(self):
        from v10_experiment import preserves,rejection_reasons,better_best
        base={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.2,'chatChecks':5,'chatCases':20,'languageLoss':1.2,'publicChatLoss':1.6,'chatHealthy':.9}
        trial={**base,'loss':.58,'chatLoss':1.0,'memory':18/19,'correct':54}
        self.assertFalse(preserves(base,trial));self.assertEqual(set(rejection_reasons(base,base,base,trial)),{'memory','correct'})
        self.assertTrue(better_best(base,base,{**base,'chatChecks':6,'chatLoss':1.1}))
    def test_temporary_shard_download_verifies_and_preserves_existing_file(self):
        with self.temporary() as folder:
            root=Path(folder);remote=root/'remote';remote.mkdir();parts=[]
            for i,content in enumerate([b'hello',b' world']):
                path=remote/str(i);path.write_bytes(content);parts.append({'path':'experiments/test/'+str(i),'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()})
            store=object.__new__(Store);store.repo='private/test';store.token='unused';store.prefix='experiments/test/';store.revision='pinned'
            def fetch(repo,path,**kwargs):
                self.assertEqual(kwargs['revision'],'pinned');self.assertIn('local_dir',kwargs)
                target=Path(kwargs['local_dir'])/'part';shutil.copyfile(remote/Path(path).name,target);return str(target)
            ref={'bytes':11,'sha256':hashlib.sha256(b'hello world').hexdigest(),'parts':parts}
            with patch('huggingface_hub.hf_hub_download',side_effect=fetch):
                result=store.download(ref,root/'model.pt');self.assertEqual(result.read_bytes(),b'hello world')
                with self.assertRaisesRegex(ResearchError,'CHECKSUM'):store.download({**ref,'sha256':'0'*64},result)
                self.assertEqual(result.read_bytes(),b'hello world');self.assertFalse(list(root.glob('v10-download-*')))
    def test_initialize_anchors_to_protected_v9_best_and_preserves_inherited_steps(self):
        import v10_experiment as runner
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();data=root/'data.jsonl';write_jsonl(data,[{'a':1}]);source=root/'best.pt';save(Nebula(Config(width=32,heads=2,layers=1,context=256)),source,{'steps':35012})
            score={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.,'chatChecks':5,'chatCases':20,'languageLoss':1.,'publicChatLoss':1.,'chatHealthy':.9}
            previous=Mock();previous.state.return_value={'round':5,'best':source,'sourceData':data,'data':data,'validationData':data,'evaluationData':data,'checks':data,'licenseTexts':data,'teacherData':data,'bestReport':score};previous.prefix='experiments/nebula-v9-curriculum/';previous.revision='pinned'
            def download(ref,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ref,target);return target
            previous.download.side_effect=download
            def prepare(base,valid,path):write_jsonl(path,[{'a':1}]);path.with_suffix('.manifest.json').write_text('{}');return {'trainingRows':1000}
            def evaluate(*args):args[4].write_text('{}');return score
            store=Mock();store.repo='private/test';store.token='unused';store.publish.side_effect=lambda state,files,project:state
            with ExitStack() as stack:
                for name,value in [('Store',Mock(return_value=previous)),('restore_data',Mock()),('configure_rules',Mock()),('prepare_curriculum',prepare),('evaluate',evaluate),('launch',Mock(return_value={'peakGpuMemoryBytes':123}))]:stack.enter_context(patch.object(runner,name,value))
                stack.enter_context(patch('torch.cuda.device_count',return_value=2))
                with redirect_stdout(io.StringIO()):state=runner.initialize(store,project)
                self.assertTrue(runner.launch.call_args.kwargs['curriculum_v10'])
            files=store.publish.call_args.args[1]
            self.assertEqual(load(files['qualityAnchor'][0])[1]['steps'],35012);self.assertEqual(load(files['working'][0])[1]['steps'],35012);previous.publish.assert_not_called();self.assertEqual(state['sourceRound'],5)
    def test_notebook_is_current_self_contained_and_has_no_credentials(self):
        from build_v10_notebook import build
        notebook=json.loads(build().read_text(encoding='utf-8'));self.assertNotRegex(json.dumps(notebook),r'gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}')
        tree=ast.parse(''.join(notebook['cells'][2]['source']));sources=ast.literal_eval(tree.body[0].value);root=Path(__file__).parents[1].parent
        for name,source in sources.items():self.assertEqual((root/name).read_text(encoding='utf-8'),source)
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
            script=Path(__file__).resolve().parents[1]/'v10_train.py'
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



    def test_paused_run_stops_before_downloading_checkpoints(self):
        import v10_experiment as runner
        with self.temporary() as folder:
            store=Mock();store.state.return_value={'format':runner.VERSION,'round':3,'rejected':3}
            with patch.object(runner,'Store',return_value=store),patch('torch.cuda.is_available',return_value=True):
                with self.assertRaisesRegex(ResearchError,'PAUSED_INSPECT'):runner.main(['--project',folder,'--teacher-calls','0'])
            store.download.assert_not_called();store.publish.assert_not_called()
    def test_main_retains_early_improvement_when_later_candidate_regresses(self):
        import v10_experiment as runner
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();common=self.fixtures(root)
            checks=root/'checks.json';checks.write_text('{}')
            base={'loss':.6,'correct':57,'cases':76,'health':.99,'identity':.5,'memory':1.,'extraction':.93,'math':.7,'conversation':.3,'chatLoss':1.2,'chatChecks':5,'chatCases':20,'languageLoss':1.2,'publicChatLoss':1.6,'chatHealthy':.9}
            state={'format':runner.VERSION,'round':0,'rejected':0,'bestReport':base,'workingReport':base,'baselineReport':base,'sourceData':root/'anchor.pt','data':root/'data.jsonl','validationData':root/'validation.jsonl','evaluationData':root/'data.jsonl','checks':checks,'qualityAnchor':root/'anchor.pt','best':root/'anchor.pt','working':root/'anchor.pt','teacherData':root/'teachers.jsonl','profile':{'gpus':2}}
            store=Mock();store.state.return_value=state
            def download(source,target):
                target.parent.mkdir(parents=True,exist_ok=True)
                if source.resolve()!=target.resolve():shutil.copyfile(source,target)
                return target
            store.download.side_effect=download
            def publish(current,files,project):return {**current,**{key:value[0] for key,value in files.items()}}
            store.publish.side_effect=publish
            def launch(project,resume,output,steps,*args,**kwargs):
                model,_=load(resume)
                for number,path in [(25,output.with_name('round.step-25.pt')),(50,output.with_name('round.step-50.pt')),(100,output)]:save(model,path,{'steps':35012+number})
                shutil.copyfile(output,output.with_suffix('.best.pt'));output.with_suffix('.performance.json').write_text(json.dumps({'bestStep':100,'completedSteps':100}))
            def evaluate(path,legacy,checks,validation,output,**kwargs):
                score={**base,'chatChecks':6,'chatLoss':1.1} if 'step-25' in path.name else {**base,'memory':18/19,'correct':54,'chatLoss':1.0}
                output.write_text(json.dumps({'report':score,'metadata':load(path)[1]}));return score
            with ExitStack() as stack:
                for name,value in [('Store',Mock(return_value=store)),('restore_data',Mock()),('configure_rules',Mock()),('Client',Mock()),('refresh_reviews',Mock(return_value=0)),('launch',launch),('evaluate',evaluate)]:stack.enter_context(patch.object(runner,name,value))
                stack.enter_context(patch('torch.cuda.is_available',return_value=True));stack.enter_context(patch('torch.cuda.empty_cache'))
                with redirect_stdout(io.StringIO()):runner.main(['--project',str(project),'--rounds','1','--steps','100','--teacher-calls','0'])
            files=store.publish.call_args.args[1]
            self.assertEqual(load(files['best'][0])[1]['steps'],35037);self.assertEqual(load(files['working'][0])[1]['steps'],35037)
            self.assertEqual(store.publish.call_args.args[0]['bestReport']['chatChecks'],6)

    def test_short_followup_has_equal_turn_weight_and_gradient(self):
        from v10_train import turn_average
        values=torch.tensor([[1.,1.,1.,1.,0.,9.]],requires_grad=True);mask=torch.tensor([[True,True,True,True,False,True]])
        result=turn_average(values,mask);self.assertEqual(float(result.detach()),5.)
        result.sum().backward();torch.testing.assert_close(values.grad,torch.tensor([[.125,.125,.125,.125,0.,.5]]))

if __name__=='__main__':unittest.main()
