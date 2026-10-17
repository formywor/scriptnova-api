import json
from pathlib import Path
import tempfile
import threading
import unittest
import io
from contextlib import redirect_stdout
from urllib.error import HTTPError
from unittest.mock import patch
from conversations import curriculum, collect
from dataflow import eligible, read_jsonl
from nebula import encode
from rules import with_owner_rules
from train import examples
from teacher_http import TeacherRequestError

class Conversations(unittest.TestCase):
    def test_failed_groq_request_reports_provider_and_status(self):
        config={'name':'groq','url':'http://127.0.0.1:1234/chat','model':'test','trainingAllowed':True}
        def transport(_): raise HTTPError('http://127.0.0.1',403,'private provider body',{},None)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory, redirect_stdout(io.StringIO()) as output:
            report=collect([config],curriculum()[:1],Path(directory)/'pending.jsonl',limit=1,workers=1,transport=transport)
        self.assertEqual(report['saved'],0)
        lines=[json.loads(line) for line in output.getvalue().splitlines()]
        failure=next(line for line in lines if 'teacherDialogueFailed' in line)
        self.assertEqual(failure['provider'],'groq')
        self.assertEqual(failure['httpStatus'],403)
        self.assertNotIn('private provider body',output.getvalue())

    def test_failed_teacher_retries_later_while_other_finishes_jobs(self):
        configs=[{'name':name,'url':'http://127.0.0.1:1234/chat','model':name,'trainingAllowed':True} for name in ['gemini','groq']]
        events=[]; attempts={'gemini':0,'groq':0}; lock=threading.Lock(); elapsed=[0]
        def transport(request):
            name=json.loads(request.data)['model']
            with lock:
                attempts[name]+=1; events.append(name)
                first=attempts[name]==1
            if name=='gemini' and first: raise TeacherRequestError('quota',retry_after=3)
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        def sleep(delay): elapsed[0]+=delay
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'pending.jsonl'
            report=collect(configs,curriculum()[:4],path,limit=6,workers=2,transport=transport,retry_delay=3,clock=lambda:elapsed[0],sleep=sleep)
            self.assertEqual(len(read_jsonl(path)),4)
        self.assertEqual(report['failed'],1); self.assertEqual(report['saved'],4)
        retry=[i for i,name in enumerate(events) if name=='gemini'][1]
        self.assertEqual(events[:retry].count('groq'),2)
        self.assertGreaterEqual(elapsed[0],3)

    def test_slow_teacher_does_not_block_other_teacher_next_jobs(self):
        configs=[{'name':name,'url':'http://127.0.0.1:1234/chat','model':name,'trainingAllowed':True} for name in ['slow','fast']]
        ready=threading.Event(); fast=[]
        def transport(request):
            name=json.loads(request.data)['model']
            if name=='slow':
                if not ready.wait(timeout=3): raise TimeoutError('Fast teacher was blocked')
            else:
                fast.append(True)
                if len(fast)==3: ready.set()
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            report=collect(configs,curriculum()[:6],Path(directory)/'pending.jsonl',limit=6,workers=2,transport=transport)
        self.assertEqual(report['saved'],6); self.assertEqual(report['failed'],0)

    def test_retries_count_toward_budget_and_zero_quota_pauses_only_one_teacher(self):
        configs=[{'name':name,'url':'http://127.0.0.1:1234/chat','model':name,'trainingAllowed':True} for name in ['gemini','groq']]
        def transport(request):
            if json.loads(request.data)['model']=='gemini': raise TeacherRequestError('zero quota',retryable=False)
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            report=collect(configs,curriculum()[:8],Path(directory)/'pending.jsonl',limit=4,workers=2,transport=transport)
        self.assertEqual(report['attempts'],4); self.assertEqual(report['saved'],3); self.assertEqual(report['failed'],1)

    def test_gemini_groq_config_keeps_keys_with_correct_host(self):
        configs=json.loads((Path(__file__).resolve().parents[1]/'teachers.gemini-groq.json').read_text(encoding='utf-8'))
        sent=[]
        def transport(request):
            sent.append((request.full_url,request.get_header('Authorization'),json.loads(request.data)))
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory, patch.dict('os.environ',{'GEMINI_API_KEY':'test-gemini','GROQ_API_KEY':'test-groq','GEMINI_SECOND_API_KEY':'test-gemini-secondary'}):
            report=collect(configs,curriculum()[:3],Path(directory)/'pending.jsonl',limit=3,workers=3,transport=transport)
        self.assertEqual(report['saved'],3)
        self.assertCountEqual([authorization for _,authorization,_ in sent],['Bearer test-gemini','Bearer test-groq','Bearer test-gemini-secondary'])
        for url,authorization,payload in sent:
            if 'api.groq.com/' in url:
                self.assertEqual(authorization,'Bearer test-groq')
                self.assertEqual(payload['reasoning_effort'],'low')
            else:
                self.assertIn(authorization,['Bearer test-gemini','Bearer test-gemini-secondary'])
                self.assertNotIn('temperature',payload)

    def test_three_teachers_run_simultaneously(self):
        configs=[{'name':name,'url':'http://127.0.0.1:1234/chat','model':name,'trainingAllowed':True} for name in ['gemini','groq','gemini-secondary']]
        barrier=threading.Barrier(3)
        def transport(request):
            barrier.wait(timeout=3)
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'pending.jsonl'
            report=collect(configs,curriculum()[:3],path,limit=3,workers=3,transport=transport)
            self.assertEqual(report['saved'],3)
            self.assertCountEqual([r['source']['provider'] for r in read_jsonl(path)],['gemini','groq','gemini-secondary'])

    def test_dialogues_validate_and_learn_every_assistant_turn(self):
        row = curriculum()[0]
        self.assertTrue(eligible(row))
        expected = sum(len(m['content'].encode('utf-8'))+1 for m in row['messages'] if m['role']=='assistant')
        batch = examples([row],512,include_owner_rules=True)
        self.assertEqual(int((batch[0][1] != -100).sum()),expected)
        row['messages'][1]['role']='system'; self.assertFalse(eligible(row))

    def test_two_teachers_run_concurrently_and_resume_without_duplicates(self):
        configs = [{'name':name,'url':'http://127.0.0.1:1234/chat','model':name,'trainingAllowed':True} for name in ['one','two']]
        barrier = threading.Barrier(2)
        sent=[]; lock=threading.Lock()
        def transport(request):
            value=json.loads(request.data)
            with lock: sent.append(value['model'])
            barrier.wait(timeout=5)
            return {'choices':[{'message':{'content':json.dumps(['Hi!','Okay.','Got it.'])}}]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'pending.jsonl'
            prompts=curriculum()[:2]
            report=collect(configs,prompts,path,limit=2,workers=2,transport=transport)
            self.assertEqual(report['saved'],2); self.assertCountEqual(sent,['one','two'])
            rows=read_jsonl(path)
            self.assertEqual(len(rows),2)
            self.assertTrue(all(len(r['messages'])==6 and r['reviewStatus']=='pending' for r in rows))
            report=collect(configs,prompts,path,limit=2,workers=2,transport=lambda _:self.fail('Already collected'))
            self.assertEqual(report['attempts'],0)

    def test_private_user_chats_are_not_sent_to_teachers(self):
        config={'name':'one','url':'http://127.0.0.1:1234/chat','model':'one','trainingAllowed':True}
        with self.assertRaisesRegex(ValueError,'original seed'):
            collect([config],[{'source':{'kind':'user'},'messages':[]}],'unused.jsonl',transport=lambda _:self.fail('Private transmission'))

    def test_generated_curriculum_has_fitting_dialogues(self):
        rows=curriculum()
        self.assertGreater(len(rows),200)
        self.assertTrue(all(eligible(r) for r in rows))
        self.assertTrue(all(len(encode(with_owner_rules(r['messages']))[0])<=513 for r in rows))

if __name__=='__main__':unittest.main()
