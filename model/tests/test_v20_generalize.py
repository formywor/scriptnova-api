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
import v20_generalize as trainer
import v20_generalize_data as data


class GeneralizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(2)

    def test_full_dataset_holdouts_paired_answers_and_complete_windows(self):
        rows,cases,report=data.lessons()
        self.assertGreater(len(rows),15000);self.assertEqual(len(cases),96)
        self.assertEqual(len({r['id'] for r in rows}),len(rows))
        banned={data.norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
        values=data.inventory(200221)
        self.assertFalse(set(values['names'])&set(values['heldNames']))
        self.assertFalse(set(values['codes'])&set(values['heldCodes']))
        text=' '.join(m['content'] for r in rows for m in r['messages'])
        for value in values['heldNames']+values['heldCodes']+values['heldColors']:
            self.assertIsNone(re.search(r'\b'+re.escape(value)+r'\b',text),value)
        paired=0
        for row in rows:
            self.assertFalse(any(data.norm(m['content']) in banned for m in row['messages'] if m['role']=='user'))
            x,y=data.window(row['messages'],1024)
            self.assertGreater(int((y!=-100).sum()),0)
            if row['family']=='binding' and len(row['messages'])>3:
                answers=[m['content'] for m in row['messages'] if m['role']=='assistant']
                self.assertEqual(len(answers),3);self.assertGreater(len(set(answers)),1);paired+=1
        self.assertGreater(paired,1500)

    def test_content_parser_respects_field_and_does_not_accept_keyword_stories(self):
        self.assertTrue(data.grade_content('Your name is Iris.','Iris','name')['verifiedContentCorrect'])
        self.assertFalse(data.grade_content('Your name is Iris.','Iris','name')['strictFormatCorrect'])
        self.assertIsNone(data.grade_content('Your scarf is Iris.','Iris','name')['verifiedContentCorrect'])
        self.assertIsNone(data.grade_content('A purple bird flew past.','purple','color')['verifiedContentCorrect'])
        self.assertFalse(data.grade_content('Your scarf is blue.','purple','color')['verifiedContentCorrect'])
        self.assertFalse(data.grade_content('Your scarf is purple or blue.','purple','color')['verifiedContentCorrect'])
        self.assertIsNone(data.grade_content('Iris\nThe person is Iris','Iris','name')['verifiedContentCorrect'])
        self.assertTrue(data.grade_content('PURPLE.','purple','color')['strictFormatCorrect'])
        self.assertTrue(data.grade_content('AbC9','AbC9','code')['strictFormatCorrect'])
        self.assertFalse(data.grade_content('abc9','AbC9','code')['verifiedContentCorrect'])
        self.assertFalse(data.grade_content('The code is abc9.','AbC9','code')['verifiedContentCorrect'])
        self.assertTrue(data.grade_content('The code is AbC9.','AbC9','code')['verifiedContentCorrect'])
        self.assertFalse(data.exact_grade(' AbC9','AbC9',True))
        self.assertFalse(data.exact_grade('AbC9.','AbC9',True))

    def test_curriculum_and_replay_are_deterministic(self):
        rows,_,_=data.lessons(groups=30);windows=[data.window(r['messages'],1024) for r in rows]
        first,early=trainer.tutor_batch(rows,windows,0,1000,42)
        again,counts=trainer.tutor_batch(rows,windows,0,1000,42)
        _,late=trainer.tutor_batch(rows,windows,700,1000,42)
        self.assertEqual(early,counts)
        self.assertTrue(all(torch.equal(a[0],b[0]) for a,b in zip(first,again)))
        self.assertGreater(early['copy'],late['copy'])
        replay=sum(n for family,n in early.items() if family.startswith('replay/'))
        self.assertTrue(150<replay<250)

    def test_updated_answer_labels_and_arithmetic_are_computed_from_context(self):
        rows,cases,_=data.lessons(groups=80)
        for r in rows:
            if r['family']=='updates':
                current=r['messages'][4]['content'].removeprefix('The current color is ').removesuffix('.')
                self.assertEqual(r['messages'][6]['content'],current)
            if r['family']=='arithmetic':
                nums=[int(v) for v in re.findall(r'\d+',r['messages'][1]['content'])]
                self.assertEqual(int(r['messages'][2]['content']),sum(nums))
                self.assertEqual(int(r['messages'][4]['content']),nums[0])
                self.assertEqual(int(r['messages'][6]['content']),nums[1])
                self.assertFalse(data.held_math(*nums))
        for c in cases:
            if c['axis']=='arithmetic-combinations':
                nums=[int(v) for v in re.findall(r'\d+',c['messages'][1]['content'])]
                self.assertEqual(int(c['expected']),sum(nums));self.assertTrue(data.held_math(*nums))

    def test_independent_weight_and_raw_sources_resume_and_no_local_artifacts(self):
        corpus,corpus_state,_=fixture();source=MemoryHub();source.prefix='experiments/nebula-v19-tutor/'
        torch.manual_seed(20);model=Nebula(Config(width=8,heads=2,layers=1,context=512))
        stream=serialize(model,{});source.objects['working']=stream.getvalue();stream.close()
        source_state={'updates':1200,'uniqueTextBytes':corpus_state['uniqueTextBytes'],
            'working':{'path':'working','sha256':sha(source.objects['working'])},'corpusComplete':True}
        original=copy.deepcopy(source.objects);raw_original=copy.deepcopy(corpus.objects)
        config=copy.deepcopy(trainer.DEFAULT);config.update(updates=10,batch=2,microbatch=1,saveEvery=1,evaluateEvery=5,
                                                         warmup=2,maxSessionHours=.001)
        output=MemoryHub();output.prefix='experiments/nebula-v20-generalize/'
        source_calls=[]
        def read_source(repo,run,revision,token):
            source_calls.append((run,revision))
            return (source,source_state) if run=='nebula-v19-tutor' else (corpus,corpus_state)
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


if __name__=='__main__':unittest.main()
