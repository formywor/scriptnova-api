import hashlib,io,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
from checkpoint import authorized,download,validate_payload
class CheckpointTests(unittest.TestCase):
 def test_auth_fails_closed(self):
  self.assertFalse(authorized('',''));self.assertFalse(authorized('bad','a'*40));self.assertTrue(authorized('a'*40,'a'*40))
 def test_manifest_integrity(self):
  blob=b'known-checkpoint';digest=hashlib.sha256(blob).hexdigest();entry={'bytes':len(blob),'sha256':digest,'path':'experiments/nebula-vd2-test/object.bin'};manifest={'repo':'iiidevv/test','revision':'a'*40}
  with tempfile.TemporaryDirectory() as folder,patch('urllib.request.urlopen',return_value=io.BytesIO(blob)):
   path=download(entry,manifest,folder);self.assertEqual(path.read_bytes(),blob)
  with tempfile.TemporaryDirectory() as folder,patch('urllib.request.urlopen',return_value=io.BytesIO(b'wrong')):
   with self.assertRaises(ValueError):download(entry,manifest,folder)
   self.assertFalse(list(Path(folder).glob('*.partial')))
 def test_request_bounds(self):
  payload={'model':'nebula-v-d2','messages':[{'role':'system','content':'rules'},{'role':'user','content':'code'}],'maxNewTokens':512}
  self.assertEqual(validate_payload(payload)[1],128)
  with self.assertRaises(ValueError):validate_payload({**payload,'model':'another'})
if __name__=='__main__':unittest.main()
