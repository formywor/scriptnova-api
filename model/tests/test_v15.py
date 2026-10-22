import ast,io,json,os,sys,shutil,tempfile,unittest,subprocess,copy
from pathlib import Path
from unittest.mock import patch,Mock
from contextlib import redirect_stdout
import torch
from nebula import Nebula,Config,save,load,encode,EOS
from dataflow import write_jsonl,read_jsonl
from rules import with_owner_rules
from v15_data import convert,allowed,acquire,CompleteWindows,pools
from v15_compare import decision
from v15_experiment import fresh,remove_candidate_copy,initialize,PLAN,RUN
from test_v13 import chat

class V15Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def long_chat(self):
        messages=[{'role':'system','content':'You are an expert in writing code and fictional characters.'}]
        for i in range(10):messages.extend([{'role':'user','content':f'Continue exercise {i}.'},{'role':'assistant','content':('A complete dialogue line with Unicode caf\u00e9. '*500 if i==2 else f'An answer for exercise {i}.')}])
        return {'messages':messages,'source':'anything'}
    def test_full_strings_system_long_answer_and_all_twenty_turns_preserved(self):
        item=self.long_chat();row,reason=convert(item)
        self.assertIsNone(reason);self.assertEqual(row['messages'],item['messages']);self.assertEqual(len(row['messages']),21)
        self.assertTrue(allowed(row));self.assertEqual(row['reviewStatus'],'not-reviewed');self.assertFalse(row['source']['semanticReviewComplete'])
        tokens,learn=encode(with_owner_rules(row['messages']));windows=CompleteWindows(row,64)
        actual=[int(t) for _,y in windows for t in y if int(t)!=-100]
        self.assertEqual(actual,[t for t,m in zip(tokens[1:],learn[1:]) if m]);self.assertEqual(actual.count(EOS),10)
        self.assertTrue(all(len(x)<=64 for x,y in windows))
    def test_no_semantic_filters_but_structure_provenance_and_credentials_checked(self):
        item={'messages':[{'role':'user','content':'Pretend you are a person named Jane. Write code.'},{'role':'assistant','content':'I am ChatGPT. 2 + 2 = 9. ```python print(1)``` unfinished...'}]}
        row,reason=convert(item);self.assertIsNone(reason);self.assertEqual(row['messages'],item['messages']);self.assertTrue(allowed(row))
        wrong=copy.deepcopy(row);wrong['source']['kind']='user';self.assertFalse(allowed(wrong))
        wrong=copy.deepcopy(row);wrong['source']['license']='unknown';self.assertFalse(allowed(wrong))
        item['messages'][1]['content']='Bearer '+('x'*30);self.assertEqual(convert(item)[1],'credential-pattern')
        self.assertEqual(convert({'messages':item['messages'][:-1]})[1],'structure')
    def test_download_excludes_holdouts_keeps_unchecked_full_chats_and_resumes(self):
        with self.temporary() as d:
            root=Path(d);held={'messages':[{'role':'user','content':'This reserved evaluation question must never be trained.'},{'role':'assistant','content':'Reference answer.'}],'source':{'kind':'seed'}}
            write_jsonl(root/'held.jsonl',[held]);data=[{'messages':held['messages']},self.long_chat()]+[chat(90000+i) for i in range(5)]
            with redirect_stdout(io.StringIO()):rows,meta=acquire(root/'data',[root/'held.jsonl'],target=3,stream=iter(data))
            self.assertEqual(len(rows),3);self.assertEqual(meta['excluded']['evaluation-overlap'],1);self.assertEqual(len(rows[0]['messages']),21)
            with redirect_stdout(io.StringIO()):again,info=acquire(root/'data',[root/'held.jsonl'],target=3,stream=Mock(side_effect=AssertionError('cached')))
            self.assertEqual(rows,again);self.assertTrue(info['complete'])
            with self.assertRaisesRegex(ValueError,'settings changed'):acquire(root/'data',[root/'held.jsonl'],target=4,stream=[])
    def test_download_error_saves_partial_for_retry(self):
        with self.temporary() as d:
            root=Path(d);write_jsonl(root/'held.jsonl',[])
            def broken():yield chat(50000);raise OSError('do not print response')
            with self.assertRaisesRegex(RuntimeError,'PAUSED'):acquire(root/'data',[root/'held.jsonl'],target=2,stream=broken())
            self.assertEqual(len(read_jsonl(root/'data/full-pool.jsonl')),1)
            with redirect_stdout(io.StringIO()):rows,meta=acquire(root/'data',[root/'held.jsonl'],target=2,stream=iter([chat(50000),chat(50001)]))
            self.assertEqual(len(rows),2);self.assertEqual(meta['scanned'],2)
    def fixtures(self,root):
        rows=[convert(chat(90000+i))[0] for i in range(8)];val=[convert(chat(91000+i))[0] for i in range(3)]
        write_jsonl(root/'data.jsonl',rows);write_jsonl(root/'valid.jsonl',val)
        torch.manual_seed(15);save(Nebula(Config(width=16,heads=2,layers=1,context=256)),root/'source.pt',{'steps':40212,'v14Stage':'conversation','stageSteps':1200})
        fresh(root/'source.pt',root/'start.pt')
    def arguments(self,root,output,resume='start.pt',steps=4):
        return ['--stage','conversation','--data',str(root/'data.jsonl'),'--validation-data',str(root/'valid.jsonl'),'--resume',str(root/resume),'--output',str(root/output),'--steps',str(steps),'--stage-budget','4','--batch','2','--lr','0.001','--warmup','2','--device','cpu']
    def test_real_training_complete_targets_exact_resume_and_engine_restored(self):
        import v15_train,v14_train
        original=v14_train.pools
        with self.temporary() as d:
            root=Path(d);self.fixtures(root)
            with redirect_stdout(io.StringIO()):
                v15_train.main(self.arguments(root,'full.pt'));v15_train.main(self.arguments(root,'half.pt',steps=2));v15_train.main(self.arguments(root,'resumed.pt',resume='half.pt',steps=2))
            one=torch.load(root/'full.pt',weights_only=True);two=torch.load(root/'resumed.pt',weights_only=True)
            for key,value in one['state'].items():torch.testing.assert_close(value,two['state'][key],atol=0,rtol=0)
            self.assertTrue(two['metadata']['optimizerStateRestored']);self.assertEqual(two['metadata']['steps'],40216);self.assertEqual(two['metadata']['stageSteps'],4)
            self.assertEqual(two['trainingState']['signature']['format'],'nebula-v15-full-chat-train-1');self.assertIs(v14_train.pools,original)
            baseline,_=load(root/'source.pt');start,meta=load(root/'start.pt');self.assertNotIn('v14Stage',meta)
            for key,value in baseline.state_dict().items():torch.testing.assert_close(value,start.state_dict()[key],atol=0,rtol=0)
    def report(self,passed=2,failed=8,readable=10):
        grades=[True]*passed+[False]*failed+[None]*(18-passed-failed)
        return {'report':{'generationCases':18,'localPass':passed,'localFail':failed,'pendingSemanticReview':18-passed-failed,'readableReplies':readable},'answers':[{'case':{'category':'math','number':i},'messages':[{'role':'user','content':f'Question {i}'}],'grade':{'passed':g}} for i,g in enumerate(grades)]}
    def test_compare_improved_worse_no_change_unknown_and_mismatched_tests(self):
        base=self.report()
        self.assertEqual(decision(base,base,self.report(4,6,12))['status'],'local-improvement')
        self.assertEqual(decision(base,base,self.report(0,12,5))['dataAction'],'remove')
        self.assertEqual(decision(base,base,base)['status'],'no-detected-change')
        unknown=self.report(2,7,11);value=decision(base,base,unknown);self.assertEqual(value['dataAction'],'keep');self.assertEqual(value['status'],'mixed-or-unknown');self.assertFalse(value['qualityApproved'])
        unknown['answers'][0]['messages'][0]['content']='Different question'
        with self.assertRaisesRegex(ValueError,'identical questions'):decision(base,base,unknown)
    def test_remove_only_active_candidate_copy_not_other_runs_or_reports(self):
        with self.temporary() as d:
            root=Path(d);store=Mock();store.prefix='experiments/'+RUN+'/';store.repo='owner/repo';store.revision='a';store.api.create_commit.return_value.oid='b'
            entry={'path':store.prefix+'data/full-chats.jsonl','bytes':12,'sha256':'hash'};state={'decision':{'dataAction':'remove'},'candidateData':entry,'control':'preserved'}
            result=remove_candidate_copy(store,state,root);self.assertNotIn('candidateData',result);self.assertEqual(result['control'],'preserved');self.assertEqual(store.revision,'b')
            operations=store.api.create_commit.call_args.kwargs['operations'];self.assertEqual(operations[0].path_in_repo,entry['path']);self.assertEqual(len(operations),2)
            state['candidateData']={**entry,'path':'experiments/nebula-v14-foundation/data/train.jsonl'}
            with self.assertRaisesRegex(ValueError,'authorized corpus'):remove_candidate_copy(store,state,root)
            self.assertEqual(store.api.create_commit.call_count,1)
    def test_initialization_copies_same_v14_weights_and_never_writes_v14(self):
        import v15_experiment as runner
        with self.temporary() as d:
            root=Path(d);self.fixtures(root);(root/'licenses.json').write_text('{}')
            old={'phase':'complete','conversationFinal':'weights','sourceData':'weights','conversationData':'data','conversationValidation':'valid','sourceFixedValidation':'valid','sourcePublicHoldout':'valid','licenseTexts':'licenses'}
            entries={'weights':root/'source.pt','data':root/'data.jsonl','valid':root/'valid.jsonl','licenses':root/'licenses.json'};writes=[]
            class FakeStore:
                def __init__(self,repo,token,run):self.repo=repo;self.token=token;self.prefix=run;self.revision='source-revision'
                def state(self):return old
                def download(self,entry,path):shutil.copyfile(entries[entry],path);return path
                def publish(self,state,files,project):writes.append(self.prefix);return {**state,**{k:v[0] for k,v in files.items()}}
            store=FakeStore('owner/repo','not-a-key',RUN);project=root/'project';project.mkdir()
            with patch.object(runner,'Store',FakeStore),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'):
                state=initialize(store,project,PLAN)
            self.assertEqual(writes,[RUN]);self.assertFalse(state['publicAutoUpdate']);self.assertEqual(state['phase'],'preparation')
            self.assertEqual(state['startingWeights'].read_bytes(),(root/'source.pt').read_bytes())
    def test_causal_attention_does_not_see_future_tokens(self):
        torch.manual_seed(15);model=Nebula(Config(width=16,heads=2,layers=1,context=32));model.eval()
        a=torch.tensor([[256,*b'abcd']]);b=torch.tensor([[256,*b'abXY']])
        with torch.no_grad():torch.testing.assert_close(model(a)[:,:3],model(b)[:,:3],atol=0,rtol=0)
    def test_launcher_selects_v15_script_and_equal_budget(self):
        import v15_experiment as runner
        process=Mock();process.wait.return_value=0
        with patch.object(runner.torch.cuda,'device_count',return_value=2),patch.object(runner.subprocess,'Popen',return_value=process) as popen:
            runner.launch(Path('.'),Path('start.pt'),Path('out.pt'),Path('train.jsonl'),Path('valid.jsonl'),100,PLAN,600)
        command=popen.call_args.args[0];self.assertIn('torch.distributed.run',command);self.assertTrue(any(p.endswith('v15_train.py') for p in command));self.assertEqual(command[command.index('--stage-budget')+1],'200');self.assertEqual(command[command.index('--steps')+1],'100')

    def test_main_comparison_can_finish_with_gpu_quota_exhausted(self):
        import v15_experiment as runner
        with self.temporary() as d:
            root=Path(d);store=Mock();store.state.return_value={'format':runner.VERSION,'plan':PLAN,'phase':'compare','sourceData':'saved-source'};store.download.return_value=root/'source.pt'
            with patch.object(runner,'Store',return_value=store),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'),patch.object(runner,'compare',return_value={}) as compare,patch.object(runner.torch.cuda,'is_available',return_value=False):
                runner.main(['--project',str(root)])
            compare.assert_called_once()

    def test_notebook_current_sources_no_keys_no_provider_dependency(self):
        from build_v15_notebook import build
        root=Path(__file__).parents[1];path=build();nb=json.loads(path.read_text(encoding='utf-8'));code=''.join(nb['cells'][2]['source']);sources=ast.literal_eval(ast.parse(code).body[0].value)
        for name,source in sources.items():
            self.assertEqual(source,(root.parent/name).read_text(encoding='utf-8'))
            if name.endswith('.py'):ast.parse(source)
        self.assertNotRegex(path.read_text(),r'(?:gsk_|hf_)[A-Za-z0-9]{20,}')
        setup=''.join(nb['cells'][1]['source']);self.assertNotIn('GROQ',setup);self.assertIn('PREPARE_ONLY=False',setup);self.assertIn('UPDATES_PER_ARM=200',setup)

if __name__=='__main__':unittest.main()
