import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zlib
import torch
from colab_transfer import FORMAT,verify,restore
from build_colab_resume import build

class ColabTransfer(unittest.TestCase):
    def payload(self):
        checkpoint=io.BytesIO()
        torch.save({'format':1,'config':{'width':32},'state':{'weight':torch.ones(1)},'metadata':{'steps':7}},checkpoint)
        raw={'model/checkpoints/test.pt':checkpoint.getvalue(),'model/data/public-approved.jsonl':b'{"messages": []}\n'}
        manifest={'format':FORMAT,'snapshotId':'test','resumeCheckpoint':'model/checkpoints/test.pt','resumeStage':'chat','preparedData':'model/data/public-approved.jsonl','checkpoints':{'model/checkpoints/test.pt':{'config':{'width':32},'steps':7}},'files':{name:{'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()} for name,value in raw.items()}}
        return {'format':FORMAT,'compression':'zlib','manifest':manifest,'files':{name:torch.frombuffer(bytearray(zlib.compress(value)),dtype=torch.uint8) for name,value in raw.items()}},raw

    def test_restore_checks_bytes_and_preserves_newer_checkpoint(self):
        payload,raw=self.payload()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder); transfer=root/'transfer.pt'; project=root/'project'
            torch.save(payload,transfer)
            _,preserved=restore(transfer,project)
            self.assertEqual(preserved,[])
            for name,value in raw.items(): self.assertEqual((project/name).read_bytes(),value)
            checkpoint=project/'model/checkpoints/test.pt'
            torch.save({'format':1,'config':{'width':32},'state':{'weight':torch.ones(1)},'metadata':{'steps':99}},checkpoint)
            _,preserved=restore(transfer,project)
            self.assertEqual(preserved,['model/checkpoints/test.pt'])
            self.assertEqual(torch.load(checkpoint,weights_only=True)['metadata']['steps'],99)

    def test_checksum_failure_prevents_restoration(self):
        payload,_=self.payload()
        payload['manifest']['files']['model/data/public-approved.jsonl']['sha256']='0'*64
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder); transfer=root/'transfer.pt'; torch.save(payload,transfer)
            with self.assertRaisesRegex(ValueError,'checksum'): restore(transfer,root/'project')
            self.assertFalse((root/'project').exists())

    def test_transfer_rejects_path_traversal(self):
        payload,_=self.payload()
        name='../outside'
        payload['files'][name]=torch.tensor([1],dtype=torch.uint8)
        payload['manifest']['files'][name]={'bytes':1,'sha256':'unused'}
        with self.assertRaisesRegex(ValueError,'Unsafe'): verify(payload)

    def test_data_change_is_not_silently_overwritten(self):
        payload,_=self.payload()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder); transfer=root/'transfer.pt'; project=root/'project'
            torch.save(payload,transfer); restore(transfer,project)
            data=project/'model/data/public-approved.jsonl'; data.write_text('changed',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'refusing to overwrite'): restore(transfer,project)
            self.assertEqual(data.read_text(encoding='utf-8'),'changed')

if __name__=='__main__':unittest.main()
