import ast,io,json,os,shutil,tempfile,unittest,subprocess,sys,re
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch,Mock
import torch
from nebula import Nebula,Config,save,load,encode,BOS
from dataflow import write_jsonl,read_jsonl,eligible
from v13_data import convert,acquire
from v14_data import practice,prepare,held,make_owned
from v14_train import pools,pick,main as train,language_sum
from v14_eval import evaluate,FIXED,blocked_prompts
from test_v13 import chat,passage

class V14Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def fixtures(self,root):
        trainrows=[];valid=[]
        for n,kind in enumerate(['stories','cosmopedia','fineweb']):
            for i in range(3):
                row,_=convert(passage(90000+n*100+i),kind,i,'pin')
                row['splitGroup']=f'{kind}-{i}'
                (valid if i==2 else trainrows).append(row)
        write_jsonl(root/'foundation.jsonl',trainrows);write_jsonl(root/'foundation-valid.jsonl',valid)
        rows=[];v=[]
        for pool in ['public','historical','context']:
            for i in range(3):
                row=make_owned([{'role':'user','content':f'Please describe a pleasant garden visit, exercise {pool} {i}.'},{'role':'assistant','content':'A garden has colorful flowers and quiet paths. Visitors walk slowly and enjoy the fresh air.'}],f'{pool}-{i}','friendly')
                row['source']['pool']=pool;(v if i==2 else rows).append(row)
        write_jsonl(root/'conversation.jsonl',rows);write_jsonl(root/'conversation-valid.jsonl',v)
        torch.manual_seed(14);save(Nebula(Config(width=16,heads=2,layers=1,context=256)),root/'start.pt',{'steps':100})
    def run_train(self,root,stage,output='trained.pt',resume='start.pt',steps=10,budget=10):
        args=['--stage',stage,'--data',str(root/(stage+'.jsonl')),'--validation-data',str(root/(stage+'-valid.jsonl')),'--resume',str(root/resume),'--output',str(root/output),'--steps',str(steps),'--stage-budget',str(budget),'--batch','2','--lr','0.0001','--warmup','2','--save-every','50','--device','cpu']
        with redirect_stdout(io.StringIO()):train(args)
        return torch.load(root/output,weights_only=True)
    def test_profile_variants_share_group_and_answers_are_checked(self):
        rows=practice(2000);groups={};skills=set()
        for row in rows:
            self.assertTrue(eligible(row));group=row['splitGroup'];first=row['messages'][0]['content']
            # Same profile fields independent of order map to one group.
            profile=tuple(re.search(pattern,first).group(1) for pattern in [r'named (\w+)',r'color is (\w+)',r'in the (\w+)',r'are (\d+) pencils'])
            self.assertEqual(groups.setdefault(('profile',profile),group),group)
            groups.setdefault(group,set()).add(held(group));skills.add(row['source']['skill'])
            skill=row['source']['skill'];answer=row['messages'][-1]['content']
            self.assertTrue(answer.strip());self.assertNotIn('Your name is',answer)
            if skill=='changed-quantity':self.assertGreaterEqual(int(answer),0)
        self.assertEqual(len(skills),6);self.assertTrue(all(len(v)==1 for k,v in groups.items() if isinstance(k,str)))
        self.assertTrue(any(held(r['splitGroup']) for r in rows));self.assertTrue(any(not held(r['splitGroup']) for r in rows))
        self.assertEqual(blocked_prompts() & {m['content'].casefold() for r in rows for m in r['messages'] if m['role']=='user'},set())
    def test_prepare_preserves_reserved_holdouts_raw_sources_and_dedup(self):
        with self.temporary() as d:
            root=Path(d);old=[];raw=[]
            for i in range(100):old.append(convert(chat(95000+i),'chat',i,'pin')[0])
            history=make_owned([{'role':'user','content':'Could you help plan a quiet afternoon at home?'},{'role':'assistant','content':'Read a book, prepare a simple snack, and take a short break outdoors.'}],'history','plan')
            history['source']['curriculum']='v7-conversation';old.append(history)
            hold=[convert(chat(97000+i),'chat',1000+i,'pin')[0] for i in range(20)]
            for n,kind in enumerate(['stories','cosmopedia','fineweb']):
                for i in range(100):
                    row=convert(passage(98000+n*100+i),kind,i,'pin')[0];raw.append(row)
            old.append(raw[0]);raw.append(raw[0])
            write_jsonl(root/'old.jsonl',old);write_jsonl(root/'fixed.jsonl',[]);write_jsonl(root/'hold.jsonl',hold)
            before=(root/'hold.jsonl').read_bytes()
            with redirect_stdout(io.StringIO()):summary=prepare(root/'old.jsonl',root/'fixed.jsonl',root/'hold.jsonl',raw,root/'data',100)
            self.assertEqual(before,(root/'hold.jsonl').read_bytes());self.assertEqual(len(summary['foundation']['sources']),3)
            self.assertEqual(summary['foundation']['excluded']['duplicate-text'],1)
            for stage in ['foundation','conversation']:
                a=read_jsonl(root/'data'/(stage+'.jsonl'));b=read_jsonl(root/'data'/(stage+'-valid.jsonl'))
                self.assertFalse({r['splitGroup'] for r in a}&{r['splitGroup'] for r in b})
            val=read_jsonl(root/'data/conversation-valid.jsonl');self.assertTrue(any(r['id']==hold[0]['id'] for r in val))
            self.assertEqual(set(summary['conversation']['poolRows']),{'public','context','historical'})
            self.assertEqual(summary['externalTeacherCalls'],0)
    def test_subset_acquisition_does_not_request_chat(self):
        with self.temporary() as d:
            calls=[]
            def stream(kind,spec):calls.append(kind);return 'pin',iter([passage(i) for i in range(2)])
            with redirect_stdout(io.StringIO()):result=acquire(d,{'stories':2,'cosmopedia':2,'fineweb':2},stream,kinds={'stories','cosmopedia','fineweb'})
            self.assertEqual(set(calls),{'stories','cosmopedia','fineweb'});self.assertEqual(len(result),3)
    def test_exact_update_mixes_and_complete_target_masks(self):
        with self.temporary() as d:
            root=Path(d);self.fixtures(root)
            for stage,expected in [('foundation',[4,3,3]),('conversation',[7,2,1])]:
                data=pools(read_jsonl(root/(stage+'.jsonl')),64,stage);counts={k:0 for k in data}
                for step in range(10):batch,key=pick(data,2,step,14,stage);counts[key]+=1
                self.assertEqual(sorted(counts.values()),sorted(expected))
            row=read_jsonl(root/'conversation.jsonl')[0];wrapped={**row,'source':{**row['source'],'curriculum':'v13-conversation'}}
            from v13_windows import examples
            tokens,masks=encode(wrapped['messages']);actual=[int(t) for _,y in examples([wrapped],64,False) for t in y if t!=-100]
            self.assertEqual(actual,[t for t,m in zip(tokens[1:],masks[1:]) if m])
    def test_cpu_phases_restore_optimizer_and_match_uninterrupted_run(self):
        with self.temporary() as d:
            root=Path(d);self.fixtures(root)
            full=self.run_train(root,'foundation',output='full.pt')
            self.run_train(root,'foundation',output='half.pt',steps=5)
            resumed=self.run_train(root,'foundation',output='resumed.pt',resume='half.pt',steps=5)
            self.assertTrue(resumed['metadata']['optimizerStateRestored']);self.assertEqual(resumed['metadata']['stageSteps'],10)
            self.assertEqual(sorted(resumed['metadata']['poolUpdates'].values()),[3,3,4])
            for name,value in full['state'].items():torch.testing.assert_close(value,resumed['state'][name],rtol=0,atol=0)
            chatmodel=self.run_train(root,'conversation',output='chat.pt',resume='resumed.pt')
            self.assertFalse(chatmodel['metadata']['optimizerStateRestored']);self.assertEqual(chatmodel['metadata']['steps'],120)
            self.assertEqual(sorted(chatmodel['metadata']['poolUpdates'].values()),[1,2,7]);self.assertFalse(chatmodel['metadata']['qualityApproved'])
            with self.assertRaisesRegex(ValueError,'configuration changed'):self.run_train(root,'foundation',resume='resumed.pt',steps=1,budget=11)
    def test_train_rejects_overlapping_groups(self):
        with self.temporary() as d:
            root=Path(d);self.fixtures(root);shutil.copyfile(root/'foundation.jsonl',root/'foundation-valid.jsonl')
            with self.assertRaisesRegex(ValueError,'overlap'):self.run_train(root,'foundation',steps=1)
    def test_no_external_review_and_actual_multi_turn_context(self):
        class FakeModel:
            config=Config(context=1024)
            def to(self,*a):return self
            def eval(self):return self
            def reply(self,messages,**kwargs):
                if 'Where is the folder?' in messages[-1]['content']:
                    self.assert_prior=messages[-2]['content'];return 'locker'
                return 'A coherent but unverified answer.'
        model=FakeModel()
        with self.temporary() as d,patch('v14_eval.load',return_value=(model,{})),patch('v14_eval.completion',return_value={'requiresSemanticReview':True}),patch('requests.post',side_effect=AssertionError('No teachers')),redirect_stdout(io.StringIO()):
            report=evaluate('fake',Path(d)/'report.json','conversation',device='cpu')
            self.assertGreater(report['pendingSemanticReview'],0);self.assertFalse(report['qualityApproved']);self.assertEqual(report['externalReviewCalls'],0)
            self.assertEqual(model.assert_prior,'A coherent but unverified answer.');self.assertEqual(report['generationCases'],18)
    def test_save_chunk_retains_final_even_when_loss_worsens(self):
        from v14_experiment import save_chunk
        with self.temporary() as d:
            root=Path(d);self.fixtures(root)
            payload=self.run_train(root,'foundation',steps=1)
            store=Mock();captured={}
            def publish(state,files,project):captured.update(files);return {**state,**{k:v[0] for k,v in files.items()}}
            store.publish.side_effect=publish
            state={'phase':'foundation','stageSteps':0,'chunk':0,'plan':{'foundationSteps':10},'foundationBestLoss':0.01,'control':'protected'}
            with redirect_stdout(io.StringIO()):result=save_chunk(store,state,root/'trained.pt',root)
            self.assertEqual(result['working'],root/'trained.pt');self.assertEqual(result['control'],'protected');self.assertNotIn('foundationLowestLoss',captured);self.assertFalse(result['publicAutoUpdate'])
            with self.assertRaisesRegex(Exception,'PROGRESS_INVALID'):save_chunk(store,result,root/'trained.pt',root)
    def test_raw_completion_uses_bos_without_chat_wrapper(self):
        from v14_eval import completion
        model=Nebula(Config(width=16,heads=2,layers=1,context=128));model.eval();seen=[]
        handle=model.register_forward_pre_hook(lambda mod,args:seen.append(args[0].clone()))
        result=completion(model,'The boat',maximum=5);handle.remove()
        self.assertEqual(seen[0].tolist(),[[BOS,*b'The boat']]);self.assertTrue(result['requiresSemanticReview'])
    def test_initializer_writes_only_new_run_and_copies_protected_weights(self):
        import v14_experiment as runner
        with self.temporary() as d:
            root=Path(d);self.fixtures(root);(root/'licenses.json').write_text('{}')
            old={'best':'best','data':'data','sourceData':'source','validationData':'validation','newPublicHoldout':'holdout','licenseTexts':'licenses','round':6}
            entries={'best':root/'start.pt','source':root/'start.pt','data':root/'conversation.jsonl','validation':root/'foundation-valid.jsonl','holdout':root/'conversation-valid.jsonl','licenses':root/'licenses.json'}
            stores={};writes=[]
            class FakeStore:
                def __init__(self,repo,token,run):self.repo=repo;self.token=token;self.prefix=run;self.revision='initial';stores[run]=self
                def state(self):return old if self.prefix=='nebula-v13-four-sources' else None
                def download(self,entry,destination):
                    destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(entries[entry],destination);return destination
                def publish(self,state,files,project):
                    writes.append(self.prefix);self.revision='after-preparation';return {**state,**{k:v[0] for k,v in files.items()}}
            main_store=FakeStore('owner/repo','unused',runner.RUN)
            def acquisition(folder,**kwargs):
                for kind in runner.TARGETS:write_jsonl(folder/(kind+'.jsonl'),[])
                kwargs['on_source']();return {}
            def prepared(base,fixed,held,raw,folder,**kwargs):
                folder.mkdir(parents=True,exist_ok=True)
                for name in ['foundation','foundation-valid','conversation','conversation-valid']:write_jsonl(folder/(name+'.jsonl'),read_jsonl(root/'foundation.jsonl'))
                return {'test':'summary'}
            project=root/'project';project.mkdir()
            with patch.object(runner,'Store',FakeStore),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'),patch.object(runner,'acquire',side_effect=acquisition),patch.object(runner,'prepare',side_effect=prepared),redirect_stdout(io.StringIO()):
                state=runner.initialize(main_store,project,runner.DEFAULT_PLAN)
            self.assertEqual(set(writes),{runner.RUN,runner.RUN+'-preparation'});self.assertFalse(state['publicAutoUpdate'])
            self.assertEqual((project/'preserved-v13-best.pt').read_bytes(),(root/'start.pt').read_bytes());self.assertEqual(state['phase'],'foundation')
    def test_two_cpu_ranks_match_single_rank_for_both_objectives(self):
        with self.temporary() as d:
            root=Path(d);self.fixtures(root);script=Path(__file__).resolve().parents[1]/'v14_train.py'
            for stage in ['foundation','conversation']:
                common=[sys.executable,str(script),'--stage',stage,'--data',str(root/(stage+'.jsonl')),'--validation-data',str(root/(stage+'-valid.jsonl')),'--resume',str(root/'start.pt'),'--steps','3','--stage-budget','10','--batch','4','--lr','0.0001','--warmup','2','--device','cpu']
                result=subprocess.run(common+['--output',str(root/'single.pt')],capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode,0,result.stderr[-2000:]);processes=[];streams=[]
                try:
                    for rank in range(2):
                        stream=(root/f'{stage}-{rank}.log').open('w');streams.append(stream)
                        env=dict(os.environ,RANK=str(rank),LOCAL_RANK=str(rank),WORLD_SIZE='2')
                        processes.append(subprocess.Popen(common+['--output',str(root/'multi.pt'),'--rendezvous',str(root/(stage+'-rendezvous'))],env=env,stdout=stream,stderr=subprocess.STDOUT))
                    for process in processes:process.wait(timeout=90)
                finally:
                    for process in processes:
                        if process.poll() is None:process.kill();process.wait()
                    for stream in streams:stream.close()
                logs='\n'.join((root/f'{stage}-{rank}.log').read_text() for rank in range(2));self.assertTrue(all(p.returncode==0 for p in processes),logs[-4000:])
                one,_=load(root/'single.pt');two,info=load(root/'multi.pt');self.assertEqual(info['worldSize'],2)
                for key,value in one.state_dict().items():torch.testing.assert_close(value,two.state_dict()[key],rtol=1e-4,atol=2e-6)
    def test_notebook_sources_are_current_and_runs_without_teacher_secret(self):
        from build_v14_notebook import build
        root=Path(__file__).parents[1];nb=json.loads(build().read_text(encoding='utf-8'))
        code=next(''.join(c['source']) for c in nb['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
        sources=ast.literal_eval(ast.parse(code).body[0].value)
        for name,source in sources.items():
            self.assertEqual(source,(root.parent/name).read_text(encoding='utf-8'))
            if name.endswith('.py'):ast.parse(source)
        setup=''.join(nb['cells'][1]['source']);self.assertNotIn('GROQ',setup);self.assertIn('NEBULA_HF_TOKEN',setup);self.assertIn('from v14_experiment import main',code)

if __name__=='__main__':unittest.main()
