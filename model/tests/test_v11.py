import ast,hashlib,io,json,os,shutil,tempfile,unittest,subprocess,sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock,patch
import torch
from nebula import Config,Nebula,save,load
from research_client import ResearchError
from verified_grading import Reviewer,JudgeError,local_grade,protocol,validate_verdicts,valid_cached,http_review
import v11_experiment as runner

def vote(i,yes=True):return {'id':i,'relevant':yes,'coherent':yes,'correct':yes,'follows_request':yes,'reason':'Clear and relevant.' if yes else 'Incoherent or unrelated to the request.'}

def report(**changes):
    return {'gradingProtocol':protocol(),'reviewComplete':True,'pendingReview':0,'loss':.6,'correct':40,'cases':76,'health':.9,'identity':.5,'memory':1.,'extraction':.8,'math':.7,'conversation':.3,'chatLoss':1.2,'chatChecks':3,'chatCases':20,'languageLoss':1.2,'publicChatLoss':1.6,'chatHealthy':.8,'exactCopyCorrect':10,'contextNameCorrect':9,**changes}

class V11Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_arithmetic_checks_whole_equation_not_last_number(self):
        case={'category':'math','prompt':'What is 7 + 8?','number':15}
        for bad in ['7 + 8 = 14. The answer is 15.','7 + 8 = 14.','Words 15 and things.']:
            self.assertIsNot(local_grade(case,bad)['passed'],True)
        for good in ['15','15.','7 + 8 = 15.','The answer is 15.']:self.assertIs(local_grade(case,good)['passed'],True)
        for explanation in ['Fifteen.','15, the sum of 7 and 8.']:self.assertIsNone(local_grade(case,explanation)['passed'])
        self.assertTrue(local_grade(case,'15.0')['passed']);self.assertFalse(local_grade(case,'The answer is 14.')['passed'])

    def test_bad_arithmetic_reference_is_caught_before_grading(self):
        from v11_eval import task_cases
        with self.temporary() as folder:
            path=Path(folder)/'checks.json';path.write_text(json.dumps({'cases':[{'category':'math','prompt':'Add 7 and 8.','number':14}]}))
            with self.assertRaisesRegex(ValueError,'reference disagrees'):task_cases(path)
    def test_copy_is_exact_identity_roles_are_distinct(self):
        copy={'category':'memory','prompt':'Repeat this word exactly: Frindle','expected':'Frindle'}
        self.assertTrue(local_grade(copy,'Frindle')['passed'])
        for bad in ['frindle','Frindle.','Your name is Frindle.']:self.assertFalse(local_grade(copy,bad)['passed'])
        identity={'category':'identity','prompt':'Which assistant is this?','expected':'Nebula'}
        self.assertTrue(local_grade(identity,'I am Nebula AI.')['passed']);self.assertFalse(local_grade(identity,'Your name is Nebula.')['passed'])
        self.assertIsNone(local_grade(identity,'Nebula shapes a story with purple clouds.')['passed'])
        color={'category':'extraction','prompt':'The ribbon is teal. What color is it?','expected':'teal'}
        self.assertIsNone(local_grade(color,'It contains a teal.')['passed']);self.assertTrue(local_grade(color,'The ribbon is teal.')['passed'])
    def test_reported_false_positives_never_pass_from_keywords(self):
        cases=[{'prompt':'I need ideas but have not picked a subject yet.'},{'prompt':'I want a simple activity and have twelve minutes.'},{'prompt':'Explain why taking a short study break can help.'}]
        answers=['You can subject yet.','Your name is simple activity and have a simple activity to help you with the same and have a good day.','A short study break in the short study breaks and washing the study breaks. It can be a short to help you find a short to help.']
        with self.temporary() as folder:
            missing=Reviewer(Path(folder)/'cache.json',key='').grade(cases,answers)
            self.assertTrue(all(item['passed'] is not True for item in missing))
            request=Mock(side_effect=lambda items,*args:{item['id']:vote(item['id'],False) for item in items})
            checked=Reviewer(Path(folder)/'cache.json',key='test',request=request,sleep=lambda _:None).grade(cases,answers)
            self.assertTrue(all(item['passed'] is False for item in checked))
    def test_two_positive_reviews_required_short_thanks_can_pass_and_cache(self):
        with self.temporary() as folder:
            path=Path(folder)/'cache.json';case={'prompt':'Thank you for helping.'}
            request=Mock(side_effect=lambda items,*args:{item['id']:vote(item['id']) for item in items})
            one=Reviewer(path,key='test',request=request,max_calls=1,sleep=lambda _:None).grade([case],["You're welcome!"])
            self.assertIsNone(one[0]['passed'])
            request.reset_mock();two=Reviewer(path,key='test',request=request,sleep=lambda _:None).grade([case],["You're welcome!"])
            self.assertTrue(two[0]['passed']);self.assertEqual(request.call_count,2)
            request.reset_mock();cached=Reviewer(path,key='',request=request).grade([case],["You're welcome!"])
            self.assertTrue(cached[0]['passed']);request.assert_not_called()
    def test_negative_second_review_fails_and_outage_defers(self):
        with self.temporary() as folder:
            path=Path(folder)/'cache.json';cases=[{'prompt':'Suggest an activity.'}];answers=['Try drawing a tree.']
            request=Mock(side_effect=[{0:vote(0)},{0:vote(0,False)}])
            self.assertFalse(Reviewer(path,key='test',request=request,sleep=lambda _:None).grade(cases,answers)[0]['passed'])
            request=Mock(side_effect=JudgeError('JUDGE_RATE_LIMITED'))
            with redirect_stdout(io.StringIO()):result=Reviewer(Path(folder)/'other.json',key='test',request=request).grade(cases,answers)
            self.assertIsNone(result[0]['passed'])
    def test_invalid_bool_duplicate_or_poisoned_cache_cannot_approve(self):
        invalid=vote(0);invalid['correct']='false'
        for values in [[invalid],[vote(0),vote(0)],[vote(True)]]:
            with self.assertRaises(JudgeError):validate_verdicts(values,{0})
        self.assertFalse(valid_cached({'passed':True,'assessment':'ai-reviewed','reviews':[vote(0)]}))
        self.assertFalse(valid_cached({'passed':True,'assessment':'ai-reviewed','reviews':[vote(0),invalid]}))
        with self.temporary() as folder:
            request=Mock(return_value={0:invalid})
            with redirect_stdout(io.StringIO()):result=Reviewer(Path(folder)/'cache.json',key='test',request=request).grade([{'prompt':'Suggest a hobby.'}],['Try drawing a tree.'])
            self.assertIsNone(result[0]['passed'])
    def test_bad_exact_answers_never_sent_to_approving_judge(self):
        with self.temporary() as folder:
            request=Mock(return_value={0:vote(0)})
            result=Reviewer(Path(folder)/'cache.json',key='test',request=request).grade([{'prompt':'7 + 8?','number':15}],['7 + 8 = 14.'])
            self.assertFalse(result[0]['passed']);request.assert_not_called()
    def test_http_schema_failure_and_secret_are_not_logged(self):
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False);response.status_code=200
        response.iter_content.return_value=[json.dumps({'choices':[{'message':{'content':json.dumps({'verdicts':[{'id':0,'correct':'true'}]})}}]}).encode()]
        with self.assertRaisesRegex(JudgeError,'SCHEMA_INVALID'):http_review([{'id':0,'answer':'Hello.'}],'test-secret','openai/gpt-oss-20b',1,fetch=Mock(return_value=response))
    def test_mixed_protocol_pending_and_lost_memory_cannot_qualify(self):
        base=report()
        for candidate in [report(gradingProtocol='old'),report(reviewComplete=False),report(contextNameCorrect=8),report(memory=.9),report(chatChecks=2,chatLoss=1.0)]:
            self.assertFalse(runner.better_best(base,base,candidate));self.assertFalse(runner.better_working(base,base,base,candidate))
        self.assertTrue(runner.better_best(base,base,report(chatChecks=4)))
    def test_unknown_metrics_stay_pending_and_copy_separated(self):
        from v11_eval import summarize,metrics
        cases=[{'category':'memory','prompt':'Repeat this word exactly: Dapple','expected':'Dapple'},{'category':'memory','prompt':'Call me Tyra. Who am I?','expected':'Tyra'}]
        rows=summarize(cases,['Dapple','Tyra'],[local_grade(cases[0],'Dapple'),local_grade(cases[1],'Tyra')])
        chats=summarize([{'category':'open-chat','prompt':'Suggest a hobby.'}],['Tree subject.'],[{'passed':None,'assessment':'needs-review','reason':'Pending'}])
        value=metrics(rows,chats);self.assertFalse(value['reviewComplete']);self.assertEqual(value['pendingReview'],1);self.assertEqual(value['chatChecks'],0);self.assertEqual(value['exactCopyCases'],1);self.assertEqual(value['contextNameCases'],1)
    def test_pending_round_preserves_weights_and_retries_before_accepting(self):
        with self.temporary() as folder:
            root=Path(folder);model=Nebula(Config(width=16,heads=2,layers=1,context=128));path=root/'round.pt';save(model,path,{'steps':35212},training_state={'marker':123})
            state={'round':4,'rejected':1,'bestReport':report(),'workingReport':report(),'baselineReport':report()};store=Mock()
            store.publish.side_effect=lambda current,files,project:{**current,**{key:value[0] for key,value in files.items()}}
            def evaluate(path,legacy,checks,validation,output):
                result=report(reviewComplete=False,pendingReview=1);output.write_text(json.dumps({'report':result}));return result
            with patch.object(runner,'evaluate',side_effect=evaluate),redirect_stdout(io.StringIO()):pending,complete=runner.save_assessment(store,state,[('final',path)],root,None,None,None)
            self.assertFalse(complete);self.assertEqual(pending['round'],4);self.assertEqual(pending['rejected'],1);self.assertEqual(torch.load(pending['pendingCandidate0'],weights_only=True)['trainingState']['marker'],123)
            def approved(path,legacy,checks,validation,output):
                result=report(chatChecks=4);output.write_text(json.dumps({'report':result}));return result
            with patch.object(runner,'evaluate',side_effect=approved),redirect_stdout(io.StringIO()):saved,complete=runner.save_assessment(store,pending,[('final',path)],root,None,None,None,True)
            self.assertTrue(complete);self.assertEqual(saved['round'],5);self.assertEqual(saved['rejected'],0);self.assertIsNone(saved['pendingEvaluation']);self.assertNotIn('pendingCandidate0',saved);self.assertEqual(torch.load(saved['working'],weights_only=True)['trainingState']['marker'],123)
    def test_rejected_round_retains_accepted_optimizer(self):
        with self.temporary() as folder:
            root=Path(folder);path=root/'round.pt';save(Nebula(Config(width=16,heads=2,layers=1,context=64)),path,{'steps':100})
            state={'round':1,'rejected':0,'bestReport':report(),'workingReport':report(),'baselineReport':report(),'working':'accepted-full-checkpoint'}
            def evaluate(path,legacy,checks,validation,output):output.write_text('{}');return report(chatChecks=1,correct=30)
            with patch.object(runner,'evaluate',side_effect=evaluate),redirect_stdout(io.StringIO()):next_state,files=runner.assess_round(state,[('final',path)],root,None,None,None)
            self.assertEqual(next_state['working'],'accepted-full-checkpoint');self.assertNotIn('working',files);self.assertEqual(next_state['rejected'],1)
    def test_initialize_regrades_all_saved_sources_preserves_safe_working(self):
        with self.temporary() as folder:
            root=Path(folder);project=root/'project';project.mkdir();model=Nebula(Config(width=16,heads=2,layers=1,context=64));old={'round':4,'bestReport':{'correct':999}}
            for key in ['baseline','best','working','latest']:
                file=root/(key+'.pt');save(model,file,{'steps':35012+(100 if key=='working' else 200 if key=='latest' else 0)},training_state={'marker':7} if key=='working' else None);old[key]=file
            for key in ['sourceData','data','validationData','evaluationData','checks','qualityAnchor','licenseTexts']:
                file=root/(key+'.json');file.write_text('{}');old[key]=file
            previous=Mock();previous.state.return_value=old;previous.revision='pinned';previous.prefix='experiments/nebula-v10-dialogue/'
            def download(source,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);return target
            previous.download.side_effect=download;store=Mock(repo='private',token='fake');store.publish.side_effect=lambda state,files,project:{**state,**{key:value[0] for key,value in files.items()}}
            scored=[]
            def evaluate(path,legacy,checks,validation,output):
                key=path.stem.removeprefix('source-');scored.append(key);value=report(chatLoss=1.19) if key=='working' else report(correct=20,chatChecks=0) if key=='latest' else report();output.write_text(json.dumps({'report':value}));return value
            with patch.object(runner,'Store',return_value=previous),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'),patch.object(runner,'evaluate',side_effect=evaluate),patch('torch.cuda.device_count',return_value=2),redirect_stdout(io.StringIO()):state=runner.initialize(store,project)
            self.assertIn('working',scored);self.assertIn('latest',scored);self.assertEqual(state['selectedSourceWorking'],'working');self.assertEqual(torch.load(state['working'],weights_only=True)['trainingState']['marker'],7);self.assertEqual(state['baselineReport']['correct'],40);previous.publish.assert_not_called();self.assertFalse(state['publicAutoUpdate'])
    def test_version_and_pause_stop_before_download(self):
        with self.temporary() as folder:
            for state in [{'format':runner.VERSION,'gradingProtocol':'old','round':0},{'format':runner.VERSION,'gradingProtocol':protocol(),'round':3,'rejected':3}]:
                store=Mock();store.state.return_value=state
                with patch.object(runner,'Store',return_value=store),patch('torch.cuda.is_available',return_value=True):
                    with self.assertRaises(ResearchError):runner.main(['--project',folder])
                store.download.assert_not_called();store.publish.assert_not_called()
    def test_notebook_embeds_complete_sources_without_credentials(self):
        from build_v11_notebook import build
        notebook=json.loads(build().read_text(encoding='utf-8'));text=json.dumps(notebook)
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']))
        source_cell=next(''.join(cell['source']) for cell in notebook['cells'] if cell['cell_type']=='code' and ''.join(cell['source']).startswith('sources='))
        sources=ast.literal_eval(ast.parse(source_cell).body[0].value)
        for name,content in sources.items():
            if name.endswith('.py'):ast.parse(content)
        for name in ['model/verified_grading.py','model/v11_eval.py','model/v11_experiment.py','model/v10_train.py']:self.assertIn(name,sources)
        self.assertNotRegex(text,r'(?:gsk_|hf_)[A-Za-z0-9]{20,}')
        with self.temporary() as folder:
            root=Path(folder)
            for name,content in sources.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content,encoding='utf-8')
            # Import only embedded sources; the real model directory must not mask missing files.
            paths=[str(root/'model'),*[p for p in os.environ.get('PYTHONPATH','').split(os.pathsep) if p and 'nebula-public' not in p]]
            result=subprocess.run([sys.executable,'-c','import v11_experiment,v11_eval,verified_grading,v10_train;print("embedded imports passed")'],cwd=root,env={**os.environ,'PYTHONPATH':os.pathsep.join(paths)},capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-2000:]);self.assertIn('embedded imports passed',result.stdout)

    def test_cpu_evaluation_writes_full_answers_and_pending_grades(self):
        from dataflow import write_jsonl
        from v9_data import convert
        from v11_eval import evaluate
        with self.temporary() as folder:
            root=Path(folder);torch.set_num_threads(1)
            save(Nebula(Config(width=16,heads=2,layers=1,context=256)),root/'model.pt',{'steps':35212})
            legacy=[]
            for i in range(30):
                legacy.append({'reviewStatus':'approved','splitGroup':f'task-{i}','source':{'kind':'seed'},'messages':[{'role':'user','content':f'Tell me a fact about tree {i}.'},{'role':'assistant','content':f'Tree {i} grows leaves.'}]})
            write_jsonl(root/'legacy.jsonl',legacy)
            valid=[convert({'messages':[{'role':'user','content':'Suggest an activity.'},{'role':'assistant','content':'Try drawing a tree.'}]},'chat',100,'test'),convert({'text':'A fox saw a lake. It walked along the shore. It found a stone.'},'language',100,'validation')]
            write_jsonl(root/'validation.jsonl',valid);(root/'checks.json').write_text(json.dumps({'cases':[{'category':'memory','prompt':'Repeat this word exactly: Dapple','expected':'Dapple'},{'category':'conversation','prompt':'Explain a simple idea.'}]}))
            # Real CPU forward losses; deterministic generation isolates the grading integration.
            with patch.object(Nebula,'reply',return_value='You can subject yet.'),redirect_stdout(io.StringIO()):
                value=evaluate(root/'model.pt',root/'legacy.jsonl',root/'checks.json',root/'validation.jsonl',root/'report.json','cpu',Reviewer(root/'cache.json',key=''))
            contents=json.loads((root/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(contents['metadata']['steps'],35212);self.assertEqual(len(contents['answers']),20);self.assertEqual(len(contents['taskAnswers']),5)
            self.assertFalse(value['reviewComplete']);self.assertEqual(value['chatChecks'],0);self.assertGreater(value['pendingReview'],0);self.assertGreater(value['loss'],0);self.assertEqual(value['exactCopyCases'],1)

if __name__=='__main__':unittest.main()
