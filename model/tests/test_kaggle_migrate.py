import hashlib
from pathlib import Path
import tempfile
import unittest
import zlib
import torch
from kaggle_migrate import restore_data

class KaggleMigration(unittest.TestCase):
    def bundle(self,root,extra=None):
        entries={'model/data/v3-chat.jsonl':b'{"saved":"exact bytes"}\r\n',
                 'model/data/v3-language.jsonl':b'{}\n','nebula-rules.json':b'{}'}
        entries.update(extra or {})
        path=root/'Nebula_V3_Data.pt'
        torch.save({'format':'nebula-v3-data-1','compression':'zlib',
            'files':{name:torch.frombuffer(bytearray(zlib.compress(value)),dtype=torch.uint8) for name,value in entries.items()},
            'sha256':{name:hashlib.sha256(value).hexdigest() for name,value in entries.items()}},path)
        return path,entries

    def test_restore_keeps_exact_dataset_bytes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); path,entries=self.bundle(root); project=root/'restored'
            hashes=restore_data(path,project)
            for name,value in entries.items(): self.assertEqual((project/name).read_bytes(),value)
            restore_data(path,project)
            (project/'nebula-rules.json').write_text('changed')
            with self.assertRaisesRegex(ValueError,'differs'): restore_data(path,project)
            self.assertEqual((project/'nebula-rules.json').read_text(),'changed')

    def test_traversal_and_bad_checksum_write_nothing(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); path,_=self.bundle(root,{'../escape':b'bad'})
            with self.assertRaisesRegex(ValueError,'Unexpected'): restore_data(path,root/'output')
            self.assertFalse((root/'output').exists())
            path,_=self.bundle(root)
            data=torch.load(path,weights_only=True); data['sha256']['nebula-rules.json']='wrong'; torch.save(data,path)
            with self.assertRaisesRegex(ValueError,'checksum'): restore_data(path,root/'output')
            self.assertFalse((root/'output').exists())

if __name__=='__main__': unittest.main()
