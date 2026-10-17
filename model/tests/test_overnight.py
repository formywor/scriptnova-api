import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import torch
from dataflow import eligible,write_jsonl
from nebula import encode,load
from overnight import curriculum,backup_data
from train import partition_rows,train

class OvernightTraining(unittest.TestCase):
    def test_data_backup_preserves_exact_bytes_and_excludes_unlisted_files(self):
        import hashlib,zlib
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); data=root/'model/data'; data.mkdir(parents=True)
            original=b'{"example":"saved data"}\r\n'
            (data/'v3-chat.jsonl').write_bytes(original)
            (root/'.env').write_text('PRIVATE_TEST_VALUE=do-not-copy')
            target=backup_data(root)
            saved=torch.load(target,map_location='cpu',weights_only=True)
            self.assertEqual(set(saved['files']),{'model/data/v3-chat.jsonl'})
            raw=zlib.decompress(saved['files']['model/data/v3-chat.jsonl'].numpy().tobytes())
            self.assertEqual(raw,original)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),saved['sha256']['model/data/v3-chat.jsonl'])

    def test_curriculum_is_unique_and_grouped_families_do_not_leak(self):
        rows=curriculum()
        self.assertGreater(len(rows),1000)
        self.assertEqual(len(rows),len({r['id'] for r in rows}))
        self.assertTrue(all(eligible(row) for row in rows))
        self.assertTrue(all(len(encode(row['messages'])[0])<800 for row in rows))
        training,validation=partition_rows(rows,42)
        groups=lambda data:{r['splitGroup'] for r in data if 'splitGroup' in r}
        self.assertFalse(groups(training)&groups(validation))
        self.assertGreater(len(validation),100)

    def args(self,root,output,steps,resume=None):
        data=root/'data.jsonl'
        if not data.exists():
            write_jsonl(data,[{'reviewStatus':'approved','source':{'kind':'seed'},
                              'messages':[{'role':'user','content':f'Say {i}.'},
                                          {'role':'assistant','content':f'Answer {i}.'}]}
                             for i in range(100)])
        return SimpleNamespace(data=data,output=root/output,resume=resume,steps=steps,
            batch=2,threads=1,seed=42,lr=.0001,preset='smoke',snapshot=None,
            continuous=False,save_every=2,patience=0,device='cpu',amp=False,
            objective='assistant',grouped_split=True,bucketed=True,max_validation=3,
            save_training_state=True,max_seconds=0)

    def test_optimizer_and_sampler_resume_match_uninterrupted_weights(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory)
            train(self.args(root,'whole.pt',4))
            train(self.args(root,'split.pt',2))
            path=root/'split.pt'
            train(self.args(root,'split.pt',2,path))
            whole,_=load(root/'whole.pt'); split,metadata=load(path)
            self.assertEqual(metadata['steps'],4)
            self.assertEqual(metadata['stageSteps'],4)
            saved=torch.load(path,map_location='cpu',weights_only=True)
            self.assertIn('optimizer',saved['trainingState'])
            for key,value in whole.state_dict().items():
                torch.testing.assert_close(value,split.state_dict()[key],rtol=0,atol=0)

    def test_time_limit_saves_a_resumable_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); args=self.args(root,'timed.pt',100)
            args.max_seconds=.000001
            result=train(args)
            self.assertEqual(result['reason'],'time_limit')
            _,metadata=load(args.output)
            self.assertEqual(metadata['stopReason'],'time_limit')
            self.assertTrue(metadata['trainingStateIncluded'])
            self.assertLess(metadata['steps'],100)

    def test_changed_batch_does_not_restore_incompatible_sampler(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); args=self.args(root,'prior.pt',2); train(args)
            args=self.args(root,'new.pt',1,args.output); args.batch=1
            with patch.object(torch.optim.AdamW,'load_state_dict',side_effect=AssertionError('Should not restore incompatible batches')):
                result=train(args)
            self.assertEqual(result['steps'],3)

if __name__=='__main__': unittest.main()
