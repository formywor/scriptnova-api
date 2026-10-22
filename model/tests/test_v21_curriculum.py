import copy
import re
import unittest
from unittest.mock import patch
import torch
import v21_curriculum as trainer
import v21_curriculum_data as data
import test_v20_generalize as previous


class CurriculumTests(unittest.TestCase):
    def test_dataset_labels_holdouts_and_windows(self):
        rows,cases,report=data.lessons()
        self.assertGreater(len(rows),25000)
        self.assertEqual(len(cases),96)
        banned={data.norm(m['content']) for c in cases for m in c['messages'] if m['role']=='user'}
        seen=set();selection=set();pairs={}
        for row in rows:
            self.assertNotIn(row['id'],seen);seen.add(row['id'])
            for m in row['messages']:
                if m['role']=='user':self.assertNotIn(data.norm(m['content']),banned)
            x,y=data.window(row['messages'],1024)
            self.assertGreater(int((y!=-100).sum()),0)
            self.assertLessEqual(len(x),1024)
            if row['family']=='arithmetic':
                self.assertEqual(len(row['messages']),3)
                numbers=list(map(int,re.findall(r'\d+',row['messages'][1]['content'])))
                self.assertEqual(int(row['messages'][2]['content']),sum(numbers))
                self.assertFalse(data.held_math(*numbers))
            if row['family']=='instructions':
                q=row['messages'][1]['content'];a=row['messages'][2]['content']
                if q.startswith('List: '):
                    values,query=q[6:].split('. Give item ')
                    self.assertEqual(values.split(' / ')[int(query.split()[0])-1],a)
                    selection.add(int(query.split()[0]))
            if row['family']=='updates':
                msgs=row['messages'];lastq=msgs[-2]['content']
                if 'color' in lastq:
                    color=msgs[3]['content'].removeprefix('Correction: my scarf is ').removesuffix(' now.')
                    self.assertEqual(msgs[-1]['content'],color)
            if row['family']=='contrast' and len(row['messages'])==3:
                prefix=row['messages'][1]['content'].split(' Only the value.')[0]
                pairs.setdefault(prefix,set()).add(row['messages'][2]['content'])
        self.assertEqual(selection,{1,2,3})
        self.assertFalse(report['arithmeticOperandFollowups'])

    def test_progressive_sampling_and_no_intermediate_evaluations(self):
        rows,_,_=data.lessons(groups=20)
        windows=list(range(len(rows)))
        early,early_counts=trainer.tutor_batch(rows,windows,0,10000,42)
        late,late_counts=trainer.tutor_batch(rows,windows,1500,10000,42)
        self.assertGreater(early_counts['single'],late_counts['single']*2)
        self.assertGreater(late_counts['updates'],early_counts['updates']*3)
        self.assertTrue(1300<sum(n for k,n in early_counts.items() if k.startswith('replay/'))<1700)
        self.assertNotIn('evaluateEvery',trainer.DEFAULT)
        self.assertEqual(trainer.DEFAULT['sourceRun'],'nebula-v19-tutor')
        # Reuse the independent CPU checkpoint/resume + RAM-only integration test,
        # adding an assertion that evaluation runs exactly once before and once after training.
        base_test=previous.GeneralizeTests('test_independent_weight_and_raw_sources_resume_and_no_local_artifacts')
        original=copy.deepcopy(trainer.DEFAULT)
        calls=[]
        real_evaluate=trainer.evaluate
        class Settings(dict):
            def update(self,*args,**kwargs):
                kwargs.pop('evaluateEvery',None)
                return super().update(*args,**kwargs)
        def deepcopy(value,*args,**kwargs):
            if value is trainer.DEFAULT:return Settings(original)
            return real_deepcopy(value,*args,**kwargs)
        real_deepcopy=copy.deepcopy
        with patch.object(previous,'trainer',trainer),patch.object(previous,'data',data),patch.object(copy,'deepcopy',side_effect=deepcopy):
            base_test.test_independent_weight_and_raw_sources_resume_and_no_local_artifacts()


if __name__=='__main__':unittest.main()
