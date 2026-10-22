import builtins
import contextlib
import copy
import io
import json
import re
import unittest
from unittest.mock import patch

import torch
from nebula import Nebula,Config
from v18_stream import serialize,deserialize,sha
from test_v18_foundation_control import MemoryHub,fixture
import v24_context as trainer
import v22_conversation_data as data


class ContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(2)

    def test_new_context_data_preserves_targets_and_heldout_inventory(self):
        from v24_context_data import context_lessons
        from v20_generalize_data import benchmarks,inventory,norm
        from nebula import encode,EOS
        seed=230221;cases=benchmarks(seed);rows,report=context_lessons(seed,cases,groups=80)
        self.assertGreater(len(rows),500)
        self.assertEqual(rows,context_lessons(seed,cases,groups=80)[0])
        forbidden={norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
        held=inventory(seed)
        for row in rows:
            self.assertLessEqual(len(encode(row['messages'])[0]),1025)
            roles=[m['role'] for m in row['messages']]
            self.assertEqual(roles[0],'system')
            self.assertEqual(roles[1:],['user','assistant']*((len(roles)-1)//2))
            words=set(re.findall(r'[A-Za-z0-9]+',' '.join(m['content'] for m in row['messages'])))
            for k in ['heldNames','heldColors','heldCodes','heldPlaces']:self.assertFalse(words&set(held[k]))
            self.assertFalse(any(norm(m['content']) in forbidden for m in row['messages'] if m['role']=='user'))
            _,target=data.window(row['messages'],1024)
            expected=[]
            for m in row['messages']:
                if m['role']=='assistant':expected+=list(m['content'].encode())+[EOS]
            self.assertEqual(target[target!=-100].tolist(),expected)
            if row['family']=='context/correction':
                messages=row['messages'][1:];facts=messages[0]['content'];correction=messages[2]['content']
                changed=re.search(r"([A-Za-z]+)'s",correction).group(1)
                for q,a in zip(messages[4::2],messages[5::2]):
                    name=re.search(r"of ([A-Za-z]+)'s",q['content']).group(1)
                    original=re.search(name+r' has a ([a-z]+)',facts).group(1)
                    if name==changed:self.assertNotEqual(a['content'],original)
                    else:self.assertEqual(a['content'],original)

    def test_reuses_pinned_public_snapshot_without_weights_or_source_writes(self):
        import v24_context_data as context
        import v23_public_chat as public
        source=MemoryHub();source.revision='pinned'
        rows=[public.convert({'messages':[{'role':'user','content':f'Question {i}?'},
            {'role':'assistant','content':f'Answer {i}.'}]},1024,set())[0] for i in range(300)]
        source.objects['public']=json.dumps(rows).encode()
        saved={'publicPreparation':{'complete':True},'publicRows':{'path':'public','sha256':'test-sha'}}
        output=MemoryHub();output.token='unit-test-only'
        with patch.object(context,'read_source',return_value=(source,saved)) as read,contextlib.redirect_stdout(io.StringIO()):
            state,result=context.prepare_public(output,{},trainer.DEFAULT,1024,set())
        self.assertEqual(result,rows);self.assertEqual(state['publicReference']['accepted'],300)
        self.assertEqual(read.call_args.args[1],trainer.DEFAULT['publicSourceRun'])
        self.assertEqual(read.call_args.args[2],trainer.DEFAULT['publicSourceRevision'])
        self.assertFalse(source.writes);self.assertNotIn('working',output.saved)

    def test_public_full_conversations_masking_filtering_and_split(self):
        import v23_public_chat as public
        from nebula import EOS
        messages=[{'role':'user','content':'What is ice?'},{'role':'assistant','content':'Frozen water.'},
                  {'role':'user','content':'And when does it melt?'},{'role':'assistant','content':'When it absorbs enough heat.'}]
        row,reason=public.convert({'messages':messages,'source':'sample'},1024,set())
        self.assertIsNone(reason);self.assertEqual(row['messages'],messages)
        x,y=data.window(row['messages'],1024)
        targets=y[y!=-100].tolist()
        self.assertEqual(targets,list(b'Frozen water.')+[EOS]+list(b'When it absorbs enough heat.')+[EOS])
        self.assertEqual(public.convert({'messages':messages},20,set())[1],'too_long_no_truncation')
        self.assertEqual(public.convert({'messages':messages},1024,{public.norm('What is ice?')})[1],'benchmark')
        for content in ['Email me at person@example.test','I am ChatGPT.','bad\ufffd text']:
            bad=[messages[0],{'role':'assistant','content':content}]
            self.assertIsNone(public.convert({'messages':bad},1024,set())[0])
        self.assertIsNone(public.convert({'messages':messages[:-1]},1024,set())[0])
        rows=[public.convert({'messages':[{'role':'user','content':f'Question {i}?'},{'role':'assistant','content':f'Answer {i}.'}]},512,set())[0] for i in range(100)]
        train,valid=public.partition(rows)
        self.assertFalse({r['id'] for r in train}&{r['id'] for r in valid})
        self.assertEqual(len(train)+len(valid),100)

    def test_preparation_restarts_from_saved_cursor_without_local_artifacts(self):
        import v23_public_chat as public
        class PublicHub(MemoryHub):
            def fetch(self,repo,path,revision,**kw):
                assert repo==public.DATASET and revision==public.REVISION and kw['dataset']
                return b'---\nlicense: apache-2.0\n---\nPublic source card'
        hub=PublicHub();config=dict(publicConversations=300,publicMaxScanned=600,seed=12)
        def reader(hub,cursor,seed):
            for i in range(cursor['row'],600):
                yield {'messages':[{'role':'user','content':f'Question {i}?'},{'role':'assistant','content':f'Answer {i}.'}]},dict(file=0,row=i+1),str(i)
        def interrupted(hub,cursor,seed):
            for i,item in enumerate(reader(hub,cursor,seed)):
                if i==250:raise KeyboardInterrupt()
                yield item
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):public.prepare_public(hub,{'updates':0},config,512,set(),reader=interrupted)
            self.assertEqual(hub.saved['publicPreparation']['accepted'],250)
            self.assertEqual(hub.saved['publicPreparation']['cursor']['row'],250)
            state,rows=public.prepare_public(hub,hub.saved,config,512,set(),reader=reader)
            self.assertTrue(state['publicPreparation']['complete']);self.assertEqual(len(rows),300)
            self.assertEqual(len({r['id'] for r in rows}),300)
            def must_not_read(*a):raise AssertionError('Completed preparation should use its HF snapshot')
            again,restored=public.prepare_public(hub,state,config,512,set(),reader=must_not_read)
            self.assertEqual(restored,rows)

    def test_context_sampling_and_bounded_defaults(self):
        rows=[{'family':f} for f in ['public','context/ownership','replay']]
        _,counts=trainer.tutor_batch(rows,list(range(3)),100,20000,42)
        self.assertTrue(9600<counts['context/ownership']<10400)
        self.assertTrue(5600<counts['replay']<6400)
        self.assertTrue(3600<counts['public']<4400)
        self.assertEqual(trainer.DEFAULT['updates'],2000)
        self.assertEqual(trainer.DEFAULT['sourceRun'],'nebula-v22-conversation')
        self.assertEqual(trainer.DEFAULT['evaluateEvery'],1000)

    def test_saved_v22_practice_is_replayed_and_benchmark_prompts_are_removed(self):
        source=MemoryHub()
        rows=[dict(family='dialogue',messages=[{'role':'user','content':'My original request'},{'role':'assistant','content':'Original answer'}],id='saved'),
              dict(family='direct',messages=[{'role':'user','content':'Held out question'},{'role':'assistant','content':'Not for training'}],id='excluded')]
        source.objects['practice']=b'\n'.join(json.dumps(r).encode() for r in rows)
        result=trainer.preservation_rows(source,{'practice':{'path':'practice'}},[],[{'messages':[{'role':'user','content':'Held out question'}]}])
        self.assertEqual([r['id'] for r in result],['saved'])

    def test_candidate_requires_context_not_just_lower_loss(self):
        state={'updates':1000,'working':{'path':'snapshot'}}
        baseline=dict(exactCorrect=35,byAxis={'entity-binding':{'correct':7}},heldoutPublic={'loss':1.},heldoutMixed={'loss':1.})
        good=copy.deepcopy(baseline);good['exactCorrect']=36
        selected=trainer.candidate_state(state,good,baseline)
        self.assertEqual(selected['bestCandidateUpdates'],1000)
        self.assertEqual(state,{'updates':1000,'working':{'path':'snapshot'}})
        bad=copy.deepcopy(good);bad['byAxis']['entity-binding']['correct']=6;bad['heldoutPublic']['loss']=.5
        self.assertEqual(trainer.candidate_state(state,bad,baseline),state)
        bad=copy.deepcopy(good);bad['heldoutMixed']['loss']=1.06
        self.assertEqual(trainer.candidate_state(state,bad,baseline),state)

    def test_independent_weight_and_raw_sources_resume_and_no_local_artifacts(self):
        corpus,corpus_state,_=fixture();source=MemoryHub();source.prefix='experiments/nebula-v22-conversation/'
        torch.manual_seed(20);model=Nebula(Config(width=8,heads=2,layers=1,context=512))
        stream=serialize(model,{});source.objects['working']=stream.getvalue();stream.close()
        source_state={'updates':4000,'uniqueTextBytes':corpus_state['uniqueTextBytes'],
            'working':{'path':'working','sha256':sha(source.objects['working'])},'corpusComplete':True}
        original=copy.deepcopy(source.objects);raw_original=copy.deepcopy(corpus.objects)
        config=copy.deepcopy(trainer.DEFAULT);config.update(updates=10,batch=2,microbatch=1,saveEvery=1,
                                                         warmup=2,maxSessionHours=.001,evaluateEvery=5)
        output=MemoryHub();output.prefix='experiments/nebula-v24-context/'
        source_calls=[]
        def read_source(repo,run,revision,token):
            source_calls.append((run,revision))
            return (source,source_state) if run=='nebula-v22-conversation' else (corpus,corpus_state)
        base=data.lessons(groups=10)
        small=(base[0]+[dict(family='context/test',messages=[{'role':'user','content':'A blue cup?'},{'role':'assistant','content':'blue'}],id='context')],base[1],base[2])
        import v23_public_chat as public
        public_rows=[public.convert({'messages':[{'role':'user','content':f'Question {i}?'},{'role':'assistant','content':f'Answer {i}.'}]},512,set())[0] for i in range(100)]
        def prepare(out,state,config,context,banned):return state,public_rows
        def evaluate(model,cases,pairs,label,updates,full=True):
            return dict(stage=label,additionalUpdates=updates,heldoutMixed={'loss':1.,'targets':10},heldoutTutor={'loss':2.},
                        exactCorrect=0,exactCases=len(cases),byAxis={},exactAnswers=[],qualityApproved=False)
        def execute(out,clock):
            old_open=builtins.open;old_io=io.open
            def guard(original):
                def call(file,mode='r',*a,**kw):
                    if any(c in mode for c in 'wax+'):raise AssertionError('No local artifact writes')
                    return original(file,mode,*a,**kw)
                return call
            with patch.object(trainer,'read_source',side_effect=read_source),patch.object(trainer,'TutorStore',return_value=out), \
                 patch.object(trainer,'lessons',return_value=small),patch.object(trainer,'context_lessons',return_value=([],{})),patch.object(trainer,'evaluate',side_effect=evaluate),patch.object(trainer,'prepare_public',side_effect=prepare), \
                 patch.object(builtins,'open',side_effect=guard(old_open)),patch.object(io,'open',side_effect=guard(old_io)), \
                 patch.dict('os.environ',{'NEBULA_HF_TOKEN':'unit-test-only'}),contextlib.redirect_stdout(io.StringIO()):
                return trainer.run_tutor(config=config,device='cpu',clock=clock)
        times=iter([0,0,10]);paused=execute(output,lambda:next(times));self.assertEqual(paused['updates'],1)
        report=execute(output,lambda:0)
        self.assertEqual(report['counters']['tutorUpdates'],8);self.assertEqual(report['counters']['rawUpdates'],2)
        straight=MemoryHub();straight.prefix=output.prefix;execute(straight,lambda:0)
        m1,_=deserialize(output.read_entry(output.saved['working']));m2,_=deserialize(straight.read_entry(straight.saved['working']))
        for name,value in m1.state_dict().items():self.assertTrue(torch.equal(value,m2.state_dict()[name]),name)
        self.assertIn((config['sourceRun'],config['sourceRevision']),source_calls)
        self.assertIn((config['rawCorpusRun'],config['rawCorpusRevision']),source_calls)
        self.assertFalse(source.writes);self.assertFalse(corpus.writes)
        self.assertEqual(original,source.objects);self.assertEqual(raw_original,corpus.objects)
        self.assertTrue(output.saved['complete']);self.assertFalse(report['qualityApproved'])

