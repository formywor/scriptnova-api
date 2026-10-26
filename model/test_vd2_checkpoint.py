"""No-network tests of the actual RAM checkpoint publisher and two-rank commit ordering."""
import copy,io,json,sys,types,unittest
from vd2_hub import Hub
class Add:
 def __init__(self,path_in_repo,path_or_fileobj):self.path=path_in_repo;self.data=path_or_fileobj
class API:
 def __init__(self):self.rev='0';self.tree={};self.snapshots={'0':{}};self.fail=False
 def create_commit(self,repo_id,parent_commit,operations,commit_message):
  if self.fail:raise RuntimeError('simulated upload/commit failure')
  if parent_commit!=self.rev:raise RuntimeError('concurrent writer')
  next=copy.deepcopy(self.tree)
  for op in operations:next[op.path]=op.data
  self.rev=str(int(self.rev)+1);self.tree=next;self.snapshots[self.rev]=copy.deepcopy(next)
  return types.SimpleNamespace(oid=self.rev)
def hub(api,prefix):
 h=object.__new__(Hub);h.api=api;h.repo='owner/private';h.prefix=prefix+'/';h.revision=api.rev;h.fetch=lambda repo,path,rev,max_bytes=160000000:api.snapshots[rev][path];return h
class Tests(unittest.TestCase):
 def setUp(self):self.old=sys.modules.get('huggingface_hub');sys.modules['huggingface_hub']=types.SimpleNamespace(CommitOperationAdd=Add)
 def tearDown(self):
  if self.old is None:sys.modules.pop('huggingface_hub',None)
  else:sys.modules['huggingface_hub']=self.old
 def test_rank1_save_does_not_replace_complete_main_checkpoint(self):
  api=API();main=hub(api,'main');old=main.publish({'updates':10},{'working':b'old model','optimizer0':b'old rank0','optimizer1':b'old rank1'})
  rank=hub(api,'rank1');r=rank.publish({'updates':20},{'optimizer1':b'new rank1'})
  self.assertEqual(json.loads(api.tree['main/state.json'])['updates'],10)
  api.fail=True;main.revision=rank.revision
  with self.assertRaises(RuntimeError):main.publish({**old,'updates':20,'optimizer1':r['optimizer1']},{'working':b'new weights','optimizer0':b'new rank0'})
  self.assertEqual(json.loads(api.tree['main/state.json'])['working'],old['working'])
  api.fail=False;new=main.publish({**old,'updates':20,'optimizer1':r['optimizer1']},{'working':b'new weights','optimizer0':b'new rank0'})
  self.assertEqual(main.read_entry('owner/private',main.revision,new['optimizer1']),b'new rank1')
 def test_checksums_and_parent_commit_fail_closed(self):
  api=API();one=hub(api,'one');two=hub(api,'two');state=one.publish({'updates':1},{'working':io.BytesIO(b'weights')})
  with self.assertRaises(RuntimeError):two.publish({'updates':2},{'working':b'wrong writer'})
  corrupted=copy.deepcopy(state['working']);corrupted['sha256']='a'*64
  with self.assertRaises(ValueError):one.read_entry('owner/private',one.revision,corrupted)
if __name__=='__main__':unittest.main()
