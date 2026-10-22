import contextlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import torch
from nebula import BOS,EOS
import v18_decode_probe as probe


class FakeModel(torch.nn.Module):
    def __init__(self,marker=None):
        super().__init__();self.weight=torch.nn.Parameter(torch.zeros(1));self.config=SimpleNamespace(context=1024)
        self.marker=marker
    def forward(self,tokens):
        logits=torch.full((1,tokens.shape[1],262),float('-inf'))
        if self.marker is not None:logits[:,:,self.marker]=10
        else:logits[:,:,97]=0;logits[:,:,98]=-.1
        return logits


class DecodeTests(unittest.TestCase):
    def test_sampling_reproducible_without_changing_global_rng_or_weights(self):
        model=FakeModel();before=torch.random.get_rng_state().clone()
        first=probe.generate(model,'A','raw',.7,.9,17,64)
        second=probe.generate(model,'A','raw',.7,.9,17,64)
        third=probe.generate(model,'A','raw',.7,.9,43,64)
        self.assertEqual(first,second);self.assertNotEqual(first['reply'],third['reply'])
        self.assertTrue(torch.equal(before,torch.random.get_rng_state()))
        self.assertEqual(model.weight.item(),0);self.assertIsNone(model.weight.grad)

    def test_greedy_and_top_p(self):
        self.assertEqual(probe.generate(FakeModel(),'A','raw',0,1,0,20)['reply'],'a'*20)
        self.assertEqual(probe.generate(FakeModel(),'A','raw',.7,.1,17,20)['reply'],'a'*20)

    def test_stopping_and_marker_mask(self):
        self.assertEqual(probe.generate(FakeModel(EOS),'A','raw',0,1,0)['stopReason'],'eos')
        self.assertEqual(probe.generate(FakeModel(BOS),'A','raw',0,1,0)['stopReason'],'special-marker')
        model=FakeModel();model.config.context=4
        out=probe.generate(model,'A','raw',0,1,0,100)
        self.assertEqual(out['generatedBytes'],2);self.assertEqual(out['stopReason'],'context-limit')
        # Chat may emit EOS but never a role/BOS marker.
        model=FakeModel(EOS)
        self.assertEqual(probe.generate(model,'A','chat',0,1,0)['generatedBytes'],0)

    def test_repetition_is_not_correctness_grade(self):
        self.assertGreater(probe.repetition('the pond of the pond of the pond')['repeatedTrigramFraction'],0)
        with contextlib.redirect_stdout(io.StringIO()):
            report=probe.compare(FakeModel(),max_bytes=4,raw=['A'],questions=['Hi'])
        self.assertEqual(len(report['answers']),10)
        self.assertFalse(report['qualityApproved']);self.assertFalse(report['trainingStarted'])
        self.assertTrue(all(x['relevanceGrade']=='pending-human-review' for x in report['answers']))

    def test_probe_never_initializes_writer_or_trains(self):
        api=SimpleNamespace(model_info=lambda *a,**k:SimpleNamespace(sha='pinned'))
        class Commit:
            def __init__(self,**kwargs):self.__dict__.update(kwargs)
        captured=[]
        def commit(**kwargs):captured.extend(kwargs['operations']);return SimpleNamespace(oid='report-commit')
        api.create_commit=commit
        import sys
        with patch.dict(sys.modules,{'huggingface_hub':SimpleNamespace(HfApi=lambda **k:api,CommitOperationAdd=Commit)}), \
             patch.dict('os.environ',{'NEBULA_HF_TOKEN':'fake-test-token'}), \
             patch.object(probe.Hub,'__init__',side_effect=AssertionError('Writer must not be initialized')), \
             patch.object(probe.Hub,'state',return_value={'updates':10102,'working':{'sha256':'hash'}}), \
             patch.object(probe.Hub,'read_entry',return_value=b'checkpoint'), \
             patch.object(probe,'deserialize',return_value=(SimpleNamespace(to=lambda d:SimpleNamespace(eval=lambda:None)),{})), \
             patch.object(probe,'compare',return_value={'answers':[],'summary':[]}), \
             patch.object(torch.cuda,'is_available',return_value=True), \
             patch.object(torch.cuda,'get_device_name',return_value='test'), \
             patch.object(torch.cuda,'empty_cache'), contextlib.redirect_stdout(io.StringIO()):
            # Simplify model movement while exercising pinned reads and unique report-only commit.
            probe.run_probe()
        self.assertEqual(len(captured),1)
        self.assertIn('/decode-reports/',captured[0].path_in_repo)
        self.assertIsInstance(captured[0].path_or_fileobj,bytes)
        self.assertNotIn('fake-test-token',captured[0].path_or_fileobj.decode())
        self.assertEqual(json.loads(captured[0].path_or_fileobj)['checkpointUpdates'],10102)


if __name__=='__main__':unittest.main()
