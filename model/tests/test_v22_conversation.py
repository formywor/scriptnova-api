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
import v22_conversation as trainer
import v22_conversation_data as data


class ConversationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(2)

    def test_full_lessons_holdouts_labels_and_complete_windows(self):
        rows,cases,report=data.lessons()
        self.assertEqual(len(cases),96)
        banned={data.norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
        values=data.inventory(220221);held=set(values['heldNames']+values['heldColors']+values['heldPlaces']+values['heldCodes'])
        seen=set();ack=0;answer=0;ownership=0;dialogues=0
        for row in rows:
            self.assertNotIn(row['id'],seen);seen.add(row['id'])
            for m in row['messages']:
                if m['role']=='user':self.assertNotIn(data.norm(m['content']),banned)
            x,y=data.window(row['messages'],1024)
            self.assertGreater(int((y!=-100).sum()),0)
            self.assertLessEqual(len(x),1024)
            if row['family'].startswith('replay/'):continue
            tokens=set(re.findall(r'[A-Za-z0-9]+',' '.join(m['content'] for m in row['messages'])))
            self.assertFalse(tokens & held)
            if row['family']=='direct':
                msgs=row['messages'];q=msgs[-2]['content'];a=msgs[-1]['content']
                facts=msgs[1]['content']
                if a=='Thanks for telling me.':
                    ack+=1;self.assertNotIn('?',q)
                else:
                    answer+=1;self.assertNotEqual(a,'Understood.')
                    match=re.match(r'My name is (\w+)\. My scarf is (\w+)\. It is in the (\w+)\.',facts)
                    self.assertIsNotNone(match);self.assertIn(a,match.groups())
                    question=q[match.end():] if q.startswith(match[0]) else q
                    if 'name' in question.lower():self.assertEqual(a,match[1])
                    elif 'color' in question.lower():self.assertEqual(a,match[2])
                    else:self.assertEqual(a,match[3])
            elif row['family']=='ownership':
                ownership+=1;msgs=row['messages']
                mapping=dict(re.findall(r'(\w+) has a (\w+) scarf\.',msgs[1]['content']))
                self.assertEqual(len(mapping),2);self.assertEqual(len(set(mapping.values())),2)
                for i,m in enumerate(msgs):
                    if m['role']=='user':
                        question=m['content'].split('. ')[-1]
                        person=next(n for n in mapping if re.search(r'\b'+re.escape(n)+r'\b',question))
                        self.assertEqual(msgs[i+1]['content'],mapping[person])
            elif row['family']=='dialogue':
                dialogues+=1;self.assertEqual(len(row['messages']),7)
            elif row['family']=='arithmetic':
                nums=list(map(int,re.findall(r'\d+',row['messages'][1]['content'])))
                self.assertEqual(int(row['messages'][2]['content']),sum(nums));self.assertFalse(data.held_math(*nums))
        self.assertGreater(ack,1000);self.assertGreater(answer,ack*3)
        self.assertGreater(ownership,4000);self.assertGreater(dialogues,2000)
        self.assertFalse(report['naturalPublicConversationsAdded'])

    def test_budget_sources_and_evaluation_policy(self):
        import ast
        from pathlib import Path
        self.assertEqual(trainer.DEFAULT['sourceRun'],'nebula-v21-curriculum')
        self.assertEqual(trainer.DEFAULT['expectedSourceUpdates'],2400)
        self.assertEqual(trainer.DEFAULT['sourceRevision'],'47cba3a6b8af6554af78c986900c7936eac50062')
        self.assertEqual(trainer.DEFAULT['updates'],4000)
        self.assertNotIn('evaluateEvery',trainer.DEFAULT)
        tree=ast.parse(Path(trainer.__file__).read_text(encoding='utf-8'))
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='evaluate']
        self.assertEqual(len(calls),2)

    def test_independent_weight_and_raw_sources_resume_and_no_local_artifacts(self):
        corpus,corpus_state,_=fixture();source=MemoryHub();source.prefix='experiments/nebula-v21-curriculum/'
        torch.manual_seed(20);model=Nebula(Config(width=8,heads=2,layers=1,context=512))
        stream=serialize(model,{});source.objects['working']=stream.getvalue();stream.close()
        source_state={'updates':2400,'uniqueTextBytes':corpus_state['uniqueTextBytes'],
            'working':{'path':'working','sha256':sha(source.objects['working'])},'corpusComplete':True}
        original=copy.deepcopy(source.objects);raw_original=copy.deepcopy(corpus.objects)
        config=copy.deepcopy(trainer.DEFAULT);config.update(updates=10,batch=2,microbatch=1,saveEvery=1,
                                                         warmup=2,maxSessionHours=.001)
        output=MemoryHub();output.prefix='experiments/nebula-v22-conversation/'
        source_calls=[]
        def read_source(repo,run,revision,token):
            source_calls.append((run,revision))
            return (source,source_state) if run=='nebula-v21-curriculum' else (corpus,corpus_state)
        small=data.lessons(groups=30)
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
                 patch.object(trainer,'lessons',return_value=small),patch.object(trainer,'evaluate',side_effect=evaluate), \
                 patch.object(builtins,'open',side_effect=guard(old_open)),patch.object(io,'open',side_effect=guard(old_io)), \
                 patch.dict('os.environ',{'NEBULA_HF_TOKEN':'unit-test-only'}),contextlib.redirect_stdout(io.StringIO()):
                return trainer.run_tutor(config=config,device='cpu',clock=clock)
        times=iter([0,0,10]);paused=execute(output,lambda:next(times));self.assertEqual(paused['updates'],1)
        report=execute(output,lambda:0)
        self.assertEqual(report['counters']['tutorUpdates'],7);self.assertEqual(report['counters']['rawUpdates'],3)
        straight=MemoryHub();straight.prefix=output.prefix;execute(straight,lambda:0)
        m1,_=deserialize(output.read_entry(output.saved['working']));m2,_=deserialize(straight.read_entry(straight.saved['working']))
        for name,value in m1.state_dict().items():self.assertTrue(torch.equal(value,m2.state_dict()[name]),name)
        self.assertIn((config['sourceRun'],config['sourceRevision']),source_calls)
        self.assertIn((config['rawCorpusRun'],config['rawCorpusRevision']),source_calls)
        self.assertFalse(source.writes);self.assertFalse(corpus.writes)
        self.assertEqual(original,source.objects);self.assertEqual(raw_original,corpus.objects)
        self.assertTrue(output.saved['complete']);self.assertFalse(report['qualityApproved'])
