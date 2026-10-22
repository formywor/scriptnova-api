import builtins
import contextlib
import copy
import io
import json
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import torch
import torch.nn.functional as F
from nebula import Nebula,Config,encode
from v18_stream import serialize,deserialize,sha
from test_v18_foundation_control import MemoryHub,fixture
import v19_tutor as tutor
import v19_tutor_data as data


class TutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(2)

    def test_practice_determinism_separation_and_complete_windows(self):
        rows,cases,report=data.lessons()
        self.assertEqual((rows,cases,report),data.lessons())
        self.assertEqual(len(cases),64);self.assertEqual(len(report['familyExamples']),8)
        self.assertGreater(len(rows),1000)
        prompts={data.norm(m['content']) for r in rows for m in r['messages'] if m['role']=='user'}
        self.assertFalse(any(data.norm(m['content']) in prompts for c in cases for m in c['messages'] if m['role']=='user'))
        text=' '.join(m['content'] for r in rows for m in r['messages'])
        for word in data.NEW_NAMES+data.NEW_COLORS:self.assertIsNone(re.search(r'\b'+word+r'\b',text,re.I),word)
        for r in rows:
            x,y=data.window(r['messages'],1024)
            expected=sum(len(m['content'].encode('utf-8'))+1 for m in r['messages'] if m['role']=='assistant')
            self.assertEqual(int((y!=-100).sum()),expected)
        with self.assertRaisesRegex(ValueError,'exceeds context'):data.window(rows[0]['messages'],8)

    def test_mask_padding_and_microbatch_loss_reference(self):
        messages=data.pair('Say hello.','Hello!')
        messages.extend([{'role':'user','content':'What is your name?'},{'role':'assistant','content':'Nebula AI.'}])
        pairs=[data.window(messages,512),data.window(data.pair('Hi.','Hello.'),512)]
        x,y=data.collate(pairs);tokens,mask=encode(messages)
        self.assertEqual(y[0].tolist(),[v if learn else -100 for v,learn in zip(tokens[1:],mask[1:])])
        self.assertTrue((y[1,len(pairs[1][1]):]==-100).all())
        model=Nebula(Config(width=8,heads=2,layers=1,context=512));model.eval()
        logits=model(x);count=int((y!=-100).sum())
        loss=F.cross_entropy(logits.flatten(0,1),y.flatten(),reduction='sum')/count
        reference=sum(F.cross_entropy(model(a[None]).flatten(0,1),b,reduction='sum') for a,b in pairs)/count
        self.assertTrue(torch.allclose(loss,reference,atol=1e-5))

    def test_strict_grading_and_mojibake_filter(self):
        self.assertTrue(data.exact_grade(' Purple. ','purple'))
        self.assertFalse(data.exact_grade('Your scarf might be purple or blue.','purple'))
        self.assertFalse(data.exact_grade('There was a purple boat.','purple'))
        class Pool:
            calls=0
            def batch(self,step,n,seed):
                self.calls+=1;text='bad â€™ quote' if self.calls==1 else 'A clear sentence.'
                tokens=torch.tensor(list(text.encode('utf-8')))
                return [(tokens[:-1],tokens[1:]) for _ in range(n)]
        pairs,rejected=tutor.raw_clean(Pool(),0,2,1)
        self.assertEqual(len(pairs),2);self.assertEqual(rejected,2)

    def test_equal_family_sampling_reproducible(self):
        rows,_,_=data.lessons();windows=[data.window(r['messages'],1024) for r in rows]
        a,counts=tutor.tutor_batch(rows,windows,50,1000,42)
        b,again=tutor.tutor_batch(rows,windows,50,1000,42)
        self.assertEqual(counts,again);self.assertEqual(sum(counts.values()),1000)
        self.assertTrue(all(80<n<170 for n in counts.values()))
        self.assertTrue(all(torch.equal(x[0],y[0]) for x,y in zip(a,b)))

    def test_resume_mix_counters_source_preservation_and_no_disk_writes(self):
        source,source_state,_=fixture()
        torch.manual_seed(19);model=Nebula(Config(width=8,heads=2,layers=1,context=512))
        stream=serialize(model,{});source.objects['working']=stream.getvalue();stream.close()
        source_state['working']['sha256']=sha(source.objects['working'])
        original=copy.deepcopy(source.objects);output=MemoryHub();output.prefix='experiments/nebula-v19-tutor/'
        config=copy.deepcopy(tutor.DEFAULT);config.update(updates=10,batch=2,microbatch=1,saveEvery=1,evaluateEvery=5,
            warmup=2,maxSessionHours=.001)
        def fake_eval(model,cases,mixed_pairs,label,updates,full=True):
            return dict(stage=label,additionalUpdates=updates,heldoutMixed={'loss':1.,'targets':10},
                        heldoutTutor={'loss':2.},exactCorrect=0,exactCases=len(cases),byAxis={},exactAnswers=[],qualityApproved=False)
        def execute(out,clock):
            builtin_open=builtins.open;io_open=io.open
            def guard(original):
                def call(file,mode='r',*args,**kwargs):
                    if any(c in mode for c in 'wax+'):raise AssertionError('No filesystem artifact writes')
                    return original(file,mode,*args,**kwargs)
                return call
            with patch.object(tutor,'read_source',return_value=(source,source_state)), \
                 patch.object(tutor,'TutorStore',return_value=out),patch.object(tutor,'evaluate',side_effect=fake_eval), \
                 patch.object(builtins,'open',side_effect=guard(builtin_open)),patch.object(io,'open',side_effect=guard(io_open)), \
                 patch.dict('os.environ',{'NEBULA_HF_TOKEN':'unit-test-only'}),contextlib.redirect_stdout(io.StringIO()):
                return tutor.run_tutor(config=config,device='cpu',clock=clock)
        times=iter([0,0,10]);paused=execute(output,lambda:next(times))
        self.assertEqual(paused['updates'],1);self.assertFalse(paused['complete'])
        report=execute(output,lambda:0)
        self.assertEqual(report['counters']['tutorUpdates'],7);self.assertEqual(report['counters']['rawUpdates'],3)
        self.assertGreater(report['counters']['assistantTargets'],0);self.assertGreater(report['counters']['rawTargets'],0)
        uninterrupted=MemoryHub();uninterrupted.prefix=output.prefix;execute(uninterrupted,lambda:0)
        m1,_=deserialize(output.read_entry(output.saved['working']))
        m2,_=deserialize(uninterrupted.read_entry(uninterrupted.saved['working']))
        for name,value in m1.state_dict().items():self.assertTrue(torch.equal(value,m2.state_dict()[name]),name)
        self.assertEqual(source.objects,original);self.assertFalse(source.writes)
        self.assertTrue(output.saved['complete']);self.assertFalse(report['qualityApproved'])
        self.assertEqual(execute(output,lambda:0),json.loads(output.read_entry(output.saved['finalReport'])))


if __name__=='__main__':unittest.main()
