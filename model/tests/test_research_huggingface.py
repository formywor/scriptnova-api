import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from research_client import Client,ResearchError

class HuggingFaceTransfers(unittest.TestCase):
    def setUp(self):
        self.client=Client('https://api.example.test/api/nebula/research','w'*40)
        self.ticket={'id':'12345678-1234-1234-1234-123456789abc','provider':'huggingface','repo':'owner/research',
                     'path':'checkpoints/12345678-1234-1234-1234-123456789abc.pt','revision':'b'*40,
                     'bytes':7,'sha256':hashlib.sha256(b'example').hexdigest()}
        self.hub=Mock();self.hub.model_info.return_value=SimpleNamespace(private=True)
        self.sdk=SimpleNamespace(HfApi=Mock(return_value=self.hub),hf_hub_download=Mock())
        self.environ=patch.dict(os.environ,{'NEBULA_HF_REPO':'owner/research','NEBULA_HF_TOKEN':'hf_fake_test_only'})
        self.environ.start();self.addCleanup(self.environ.stop)
    def test_upload_uses_hf_token_and_never_coordinator_token(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path=Path(folder)/'checkpoint.pt';path.write_bytes(b'example')
            with patch.dict('sys.modules',{'huggingface_hub':self.sdk}),patch.object(self.client,'call',side_effect=[self.ticket,{}]) as api:
                self.assertEqual(self.client.upload(path),self.ticket['id'])
            self.assertEqual(self.sdk.HfApi.call_args.kwargs['token'],'hf_fake_test_only')
            self.assertNotIn(self.client.token,str(self.hub.upload_file.call_args))
            self.assertEqual(api.call_args.args,('finish',{'id':self.ticket['id']}))
    def test_pinned_download_requires_the_expected_bytes_and_checksum(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            cached=Path(folder)/'cached.pt';cached.write_bytes(b'example')
            self.sdk.hf_hub_download.return_value=str(cached)
            with patch.dict('sys.modules',{'huggingface_hub':self.sdk}):
                result=self.client.download_huggingface(self.ticket,Path(folder)/'result.pt')
                self.assertEqual(result.read_bytes(),b'example')
                self.assertEqual(self.sdk.hf_hub_download.call_args.kwargs['revision'],'b'*40)
                cached.write_bytes(b'corrupt')
                with self.assertRaisesRegex(ResearchError,'CHECKPOINT_CHECKSUM_MISMATCH'):
                    self.client.download_huggingface(self.ticket,Path(folder)/'bad.pt')
    def test_public_repo_and_wrong_repo_fail_before_upload(self):
        with patch.dict('sys.modules',{'huggingface_hub':self.sdk}):
            self.hub.model_info.return_value=SimpleNamespace(private=False)
            with self.assertRaisesRegex(ResearchError,'HF_REPOSITORY_MUST_BE_PRIVATE'):self.client.huggingface(self.ticket)
            with self.assertRaisesRegex(ResearchError,'HF_CONFIGURATION_MISSING'):self.client.huggingface({**self.ticket,'repo':'someone/else'})
        self.hub.upload_file.assert_not_called()

if __name__=='__main__':unittest.main()
