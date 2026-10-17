import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch
import torch
from torch.nn import functional as F
from dataflow import read_jsonl,write_jsonl
from nebula import Nebula,config_for_preset,save,load
from v7_train import global_batch,summed_loss,main as train
from v7_teacher import clean_dialogue,collect,http_json,TeacherError
from v7_data import short_complete
from v7_checks import CASES,touches_checks
from v7_experiment import better_best,better_working,initialize


def dialogue(topic='drawing'):
    return [{'role':'user','content':f'I want to practice {topic}.'},{'role':'assistant','content':'How much time do you have?'},{'role':'user','content':'I have fifteen minutes.'},{'role':'assistant','content':f'Try one small {topic} activity for fifteen minutes.'}]

def report(**kw):return {'loss':.6,'health':.99,'identity':.5,'math':.6,'memory':1.,'extraction':.93,'conversation':1/6,'correct':54,'cases':76,'chatLoss':2.,'chatChecks':5,'chatCases':20,**kw}

class V7Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_batches_mix_nonadjacent_examples_without_duplicate_neighbors(self):
        values=list(range(1000));batch=global_batch(values,16,50)
        self.assertEqual(batch,global_batch(values,16,50));self.assertEqual(len(set(batch)),16);self.assertGreater(max(batch)-min(batch),500)
    def test_short_and_long_examples_have_equal_weight_and_anchor_gets_no_gradients(self):
        class Toy(torch.nn.Module):
            def __init__(self):super().__init__();self.values=torch.nn.Parameter(torch.tensor([4.]+[0.]*261))
            def forward(self,x):return self.values.expand(*x.shape,262)
        model=Toy();anchor=Toy().requires_grad_(False)
        batch=[(torch.tensor([0]),torch.tensor([0])),(torch.tensor([1,1,1,1]),torch.tensor([1,1,1,1]))]
        value,n,tokens=summed_loss(model,batch,torch.device('cpu'),False,torch.float32,anchor,.2)
        expected=F.cross_entropy(model.values[None],torch.tensor([0]))+F.cross_entropy(model.values[None],torch.tensor([1]))
        torch.testing.assert_close(value,expected);self.assertEqual(n,2);self.assertEqual(tokens,5);value.backward();self.assertIsNone(anchor.values.grad)
    def test_teacher_rejects_malformed_data_and_frozen_questions(self):
        self.assertIsNotNone(clean_dialogue(dialogue(),'group'))
        unicode_example=dialogue();unicode_example[3]['content']='Try a low\u2011cost drawing exercise.'
        normalized=clean_dialogue(unicode_example,'unicode');self.assertIsNotNone(normalized);self.assertIn('low-cost',normalized['messages'][3]['content'])
        self.assertIsNone(clean_dialogue([*dialogue()[:2],'...'],'group'))
        frozen=dialogue();frozen[0]=CASES[0]['messages'][0];self.assertIsNone(clean_dialogue(frozen,'group'))
        bad=dialogue();bad[1]['content']='I am ChatGPT.';self.assertIsNone(clean_dialogue(bad,'group'))
        bad=dialogue();bad[1]['content']='A sentence that never finishes';self.assertIsNone(clean_dialogue(bad,'group'))
    def test_separate_key_is_required_and_only_second_pass_accepted_dialogues_are_saved(self):
        with self.temporary() as folder:
            path=Path(folder)/'teacher.jsonl';request=Mock()
            with patch.dict(os.environ,{'GROQ_API_KEY':'review-only'},clear=True):
                self.assertFalse(collect(path,request=request)['available']);request.assert_not_called()
            responses=[{'dialogues':[dialogue('painting'),dialogue('gardening'),dialogue('writing')]},{'acceptedIndices':[0,2]}]
            request.side_effect=responses
            result=collect(path,max_calls=2,key='private-teacher-key',request=request,sleep=lambda _:None)
            self.assertEqual(result['saved'],2);self.assertEqual(result['calls'],2);rows=read_jsonl(path);self.assertEqual(rows[0]['source']['validation'],'generated-dialogue-second-pass-v1');self.assertNotIn('private-teacher-key',path.read_text())
    def test_teacher_transport_uses_strict_schema_and_never_logs_http_details(self):
        class Response:
            status_code=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,n):yield json.dumps({'choices':[{'message':{'content':json.dumps({'dialogues':[]})}}]}).encode()
        send=Mock(return_value=Response());http_json([{'role':'system','content':'Create high-quality ORIGINAL dialogues.'},{'role':'user','content':'A task.'}],'private','openai/gpt-oss-20b',fetch=send)
        args=send.call_args;self.assertEqual(args.args[0],'https://api.groq.com/openai/v1/chat/completions');self.assertFalse(args.kwargs['allow_redirects']);self.assertTrue(args.kwargs['json']['response_format']['json_schema']['strict']);self.assertEqual(args.kwargs['headers']['Authorization'],'Bearer private')
        bad=Response();bad.status_code=429
        with self.assertRaisesRegex(TeacherError,'TEACHER_RATE_OR_QUOTA'):http_json([{'role':'system','content':'Create'}],'key','test',fetch=Mock(return_value=bad))
    def test_working_loss_improvement_can_continue_without_promoting_a_worse_best(self):
        base=report();candidate=report(chatLoss=1.98)
        self.assertTrue(better_working(base,base,base,candidate));self.assertFalse(better_best(base,base,candidate))
        self.assertTrue(better_best(base,base,report(chatLoss=1.98,chatChecks=6)))
        for value in [report(identity=0.,chatLoss=1.),report(memory=.5,chatLoss=1.),report(correct=44,chatLoss=1.)]:self.assertFalse(better_working(base,base,base,value));self.assertFalse(better_best(base,base,value))
    def test_real_quality_training_caps_small_pools_keeps_steps_and_restores_optimizer(self):
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
            trained,meta=load(root/'end.pt');self.assertEqual(meta['steps'],37);self.assertEqual(meta['conversationUpdates'],16);self.assertEqual(meta['mixedUpdates'],4);self.assertLessEqual(meta['reviewUpdates'],1);self.assertGreater(meta['teacherUpdates'],0)
            with redirect_stdout(io.StringIO()):train(common+['--resume',str(root/'end.pt'),'--output',str(root/'next.pt'),'--steps','5','--lr','.000001','--sampling-seed','777'])
            _,next_meta=load(root/'next.pt');self.assertEqual(next_meta['steps'],42);self.assertTrue(next_meta['optimizerStateRestored']);self.assertEqual(hashlib.sha256((root/'anchor.pt').read_bytes()).hexdigest(),original)
            self.assertTrue(any(not torch.equal(v,trained.state_dict()[k]) for k,v in model.state_dict().items()))
    def test_two_cpu_ranks_match_equal_example_anchor_training(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder);data=root/'data.jsonl'
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':f'Say {i}.'},{'role':'assistant','content':f'Answer {i}.'}]} for i in range(100)]
            write_jsonl(data,rows)
            torch.manual_seed(42);save(Nebula(config_for_preset('smoke')),root/'start.pt',{'steps':0})
            script=Path(__file__).resolve().parents[1]/'v7_train.py'
            common=[sys.executable,str(script),'--data',str(data),'--resume',str(root/'start.pt'),
                    '--steps','3','--batch','4','--device','cpu','--quality-anchor',str(root/'start.pt')]
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

    def test_round_without_teacher_key_backs_up_full_working_state_and_keeps_best(self):
        import shutil
        import v7_experiment as runner
        from contextlib import ExitStack
        from v7_data import VERSION
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();source=root/'original.pt'
            save(Nebula(config_for_preset('smoke')),source,{'steps':50})
            text=root/'data.jsonl';write_jsonl(text,[])
            state={'format':VERSION,'round':0,'rejected':0,'bestReport':report(),'workingReport':report(),'baselineReport':report(),'profile':{'gpus':1},'publicAutoUpdate':False}
            for key in ['sourceData','data','evaluationData','checks']:state[key]=text
            for key in ['baseline','best','working']:state[key]=source
            class Store:
                def state(self):return dict(state)
                def download(self,ref,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ref,target);return target
                def publish(self,value,files,project):
                    self.files=files;self.saved=value
                    result=dict(value)
                    for key,(local,remote) in files.items():
                        target=root/('backup-'+key+local.suffix);shutil.copyfile(local,target);result[key]=target
                    return result
            store=Store()
            def launch(project,resume,output,*args,**kwargs):
                model,meta=load(resume);save(model,output,{**meta,'steps':150},training_state={'optimizer':{'sentinel':torch.tensor(1)}});shutil.copyfile(output,output.with_suffix('.best.pt'))
            def evaluate(*args):
                args[4].write_text('{}');return report(chatLoss=1.98)
            temporary_directory=tempfile.TemporaryDirectory
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ,{},clear=True))
                for target,value in [('Store',Mock(return_value=store)),('Client',Mock()),('restore_data',Mock()),('configure_rules',Mock()),('refresh_reviews',Mock(return_value=0)),('launch',launch),('evaluate',evaluate)]:stack.enter_context(patch.object(runner,target,value))
                stack.enter_context(patch('torch.cuda.is_available',return_value=True));stack.enter_context(patch('torch.cuda.empty_cache'))
                stack.enter_context(patch.object(runner.tempfile,'TemporaryDirectory',side_effect=lambda **kw:temporary_directory(dir=root)))
                with redirect_stdout(io.StringIO()):runner.main(['--project',str(project),'--rounds','1','--steps','100'])
            self.assertNotIn('best',store.files);self.assertEqual(store.saved['bestReport']['chatChecks'],5)
            working=torch.load(root/'backup-working.pt',weights_only=True);self.assertIn('trainingState',working)
            self.assertEqual(working['metadata']['steps'],150);self.assertEqual(load(source)[1]['steps'],50)

    def test_notebook_is_self_contained_and_contains_no_keys(self):
        from build_v7_notebook import build
        value=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(value);self.assertNotRegex(text,r'gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}')
        self.assertIn('NEBULA_TEACHER_GROQ_KEY',text);self.assertIn('nebula-v7',text)
        for cell in value['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))

if __name__=='__main__':unittest.main()
