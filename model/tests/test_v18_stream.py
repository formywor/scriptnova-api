import ast
import builtins
import contextlib
import copy
import gzip
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import numpy as np
import requests
import torch
from nebula import Nebula,Config
import v18_stream as v18


class FakeAPI:
    def __init__(self):self.head='revision-0';self.objects={};self.commits=0;self.fail=False
    def model_info(self,repo):return SimpleNamespace(sha='source-revision',private=True)
    def create_commit(self,**kwargs):
        if self.fail:raise ValueError('Simulated upload rejection')
        if kwargs['parent_commit']!=self.head:raise ValueError('Conflicting writer')
        for op in kwargs['operations']:
            if not isinstance(op.path_or_fileobj,bytes):raise AssertionError('Uploads must use RAM bytes, not filesystem paths')
            self.objects[op.path_in_repo]=op.path_or_fileobj
        self.commits+=1;self.head='revision-'+str(self.commits)
        return SimpleNamespace(oid=self.head)


class Harness:
    def __init__(self):
        self.api=FakeAPI();self.source={};self.rows={}
        torch.manual_seed(421)
        model=Nebula(Config(width=32,heads=2,layers=1,context=64))
        stream=v18.serialize(model,{'privateUserChat':'PRIVATE_CHAT_DO_NOT_COPY'})
        blob=stream.getvalue();stream.close()
        prefix='experiments/nebula-v17-lab/'
        self.source[prefix+'weights.pt']=blob
        self.source[prefix+'state.json']=json.dumps({'current-foundationWeights':{'path':prefix+'weights.pt','bytes':len(blob),'sha256':v18.sha(blob)}}).encode()
        for key in v18.SOURCES:
            self.rows[key]=[{'text':f'Clear raw public document {key} {i}. '+('The child learned about boats and water. '*8),'url':f'https://example.test/{key}/{i}'} for i in range(1000)]
    def factory(self,repo,token,run):
        hub=object.__new__(v18.Hub);hub.repo=repo;hub.token=token;hub.prefix='experiments/'+run+'/'
        hub.revision=self.api.head;hub.api=self.api
        def fetch(repo,path,revision,*,dataset=False):
            if dataset:return b'Public upstream dataset attribution'
            values=self.api.objects if repo==hub.repo else self.source
            if path not in values:
                error=requests.HTTPError('Missing');error.response=SimpleNamespace(status_code=404);raise error
            return values[path]
        hub.fetch=fetch
        return hub
    def rows_fn(self,hub,key,cursor,seed):
        for i in range(cursor['row'],len(self.rows[key])):
            yield self.rows[key][i],{'file':0,'row':i+1},'data/train-000.parquet'
    def state(self):return json.loads(self.api.objects['experiments/nebula-v18-test/state.json'])
    def index(self,state):
        hub=self.factory('iiidevv/test-public','unused','nebula-v18-test');rows=[]
        for entry in state['corpus']['index']:
            rows.extend(json.loads(line) for line in gzip.decompress(hub.read_entry(entry)).splitlines())
        return rows


def config():
    value=copy.deepcopy(v18.DEFAULT)
    value.update(textBytes=30000,minDocumentBytes=32,maxDocumentBytes=1000,shardTextBytes=2500,
                 validationPercent=10,steps=4,warmup=2,cloudSaveEvery=2,evaluateEvery=2)
    return value


class StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load PyTorch's lazy modules before sys.modules snapshots are mocked.
        # Its C++ operator registrations cannot be unloaded by restoring sys.modules.
        torch.set_num_threads(1)
        model=Nebula(Config(width=32,heads=2,layers=1,context=64))
        optimizer=torch.optim.AdamW(model.parameters())
        model(torch.tensor([[1,2,3]])).sum().backward();optimizer.step()

    def setUp(self):
        torch.set_num_threads(1)
        self.hub_patch=patch.dict('sys.modules',{'huggingface_hub':SimpleNamespace(CommitOperationAdd=lambda **kw:SimpleNamespace(**kw))})
        self.hub_patch.start()
        self.env=patch.dict('os.environ',{'NEBULA_HF_TOKEN':'hf_testing_placeholder_not_real'});self.env.start()
    def tearDown(self):self.env.stop();self.hub_patch.stop()
    def run_action(self,harness,action='prepare',**kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return v18.run('iiidevv/test-public','nebula-v18-test',config(),action,1,
                hub_factory=harness.factory,rows_fn=harness.rows_fn,device='cpu',**kwargs)

    def test_prepare_packs_every_document_and_keeps_holdout_disjoint(self):
        h=Harness();state=self.run_action(h);rows=h.index(state)
        self.assertTrue(state['corpusComplete']);self.assertGreater(state['uniqueTextBytes'],27000)
        self.assertEqual(len({r['hash'] for r in rows}),len(rows))
        self.assertEqual(sum(r['utf8Bytes'] for r in rows),state['uniqueTextBytes'])
        hub=h.factory('iiidevv/test-public','unused','nebula-v18-test')
        for row in rows:
            split=row['split'];entry=state['corpus'][split][row['shard']]
            values=np.frombuffer(hub.read_entry(entry),dtype='<u2')[row['startToken']:row['endToken']]
            self.assertEqual((int(values[0]),int(values[-1])),(256,257))
            self.assertEqual(split,'validation' if int(row['hash'][:8],16)%100<10 else 'train')
            self.assertEqual(len(values)-2,row['utf8Bytes'])
        self.assertTrue(any(r['split']=='validation' for r in rows))

    def test_interrupt_then_resume_matches_complete_document_streams(self):
        expected=Harness();reference=self.run_action(expected)
        h=Harness();normal=h.rows_fn;interrupted=False
        def rows(*args):
            nonlocal interrupted
            for i,value in enumerate(normal(*args)):
                if not interrupted and i==12:interrupted=True;raise KeyboardInterrupt
                yield value
        h.rows_fn=rows;partial=self.run_action(h)
        self.assertFalse(partial['corpusComplete'])
        h.rows_fn=normal;resumed=self.run_action(h)
        self.assertEqual(resumed['sourceBytes'],reference['sourceBytes'])
        self.assertEqual({r['hash'] for r in h.index(resumed)},{r['hash'] for r in expected.index(reference)})

    def test_failed_commit_preserves_last_public_state(self):
        h=Harness();state=self.run_action(h);hub=h.factory('iiidevv/test-public','unused','nebula-v18-test')
        old=copy.deepcopy(h.api.objects);rev=hub.revision;h.api.fail=True
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):hub.publish({**state,'updates':999})
        self.assertEqual(h.api.objects,old);self.assertEqual(hub.revision,rev)

    def test_checksum_failure_is_rejected_before_training(self):
        h=Harness();state=self.run_action(h);entry=state['corpus']['train'][0]
        h.api.objects[entry['parts'][0]['path']]=b'tampered'
        hub=h.factory('iiidevv/test-public','unused','nebula-v18-test')
        with self.assertRaisesRegex(ValueError,'checksum'):hub.read_entry(entry)

    def test_no_dataset_checkpoint_or_report_filesystem_writes(self):
        h=Harness()
        # Warm up optimizer's lazy imports (package/code caches are outside the artifact assertion).
        optimizer=torch.optim.AdamW(Nebula(Config(width=32,heads=2,layers=1,context=64)).parameters());del optimizer
        original=builtins.open
        def guarded(path,mode='r',*args,**kwargs):
            if isinstance(path,(str,bytes,Path)) and any(c in str(mode) for c in 'wax+'):
                raise AssertionError('Filesystem write attempted: '+str(path))
            return original(path,mode,*args,**kwargs)
        original_save=torch.save
        def ram_save(payload,target,*args,**kwargs):
            self.assertIsInstance(target,io.BytesIO)
            return original_save(payload,target,*args,**kwargs)
        with patch('builtins.open',side_effect=guarded),patch('io.open',side_effect=guarded),patch('torch.save',side_effect=ram_save):
            self.run_action(h);trained=self.run_action(h,'train')
        self.assertEqual(trained['updates'],4)
        self.assertTrue(trained['trainingComplete'])
        joined=b''.join(h.api.objects.values())
        self.assertNotIn(b'PRIVATE_CHAT_DO_NOT_COPY',joined)
        self.assertNotIn(b'hf_testing_placeholder_not_real',joined)

    def test_full_optimizer_resume_matches_uninterrupted_training(self):
        first=Harness();self.run_action(first);reference=self.run_action(first,'train')
        h=Harness();self.run_action(h);original=v18.RemotePool.batch;paused=False
        def batch(pool,step,*args):
            nonlocal paused
            if pool.hold!=1 and step==2 and not paused:paused=True;raise KeyboardInterrupt
            return original(pool,step,*args)
        with patch.object(v18.RemotePool,'batch',batch):partial=self.run_action(h,'train')
        self.assertEqual(partial['updates'],2)
        resumed=self.run_action(h,'train');self.assertEqual(resumed['updates'],4)
        a,_=v18.deserialize(first.factory('iiidevv/test-public','unused','nebula-v18-test').read_entry(reference['working']))
        b,_=v18.deserialize(h.factory('iiidevv/test-public','unused','nebula-v18-test').read_entry(resumed['working']))
        for name,value in a.state_dict().items():torch.testing.assert_close(value,b.state_dict()[name],rtol=1e-5,atol=1e-6)

    def test_benchmark_does_not_replace_working_weights(self):
        h=Harness();self.run_action(h);state=self.run_action(h,'train');entry=copy.deepcopy(state['working'])
        result=self.run_action(h,'benchmark')
        self.assertEqual(result['working'],entry);self.assertEqual(result['updates'],4)

    def test_cuda_unavailable_never_silently_starts_cpu(self):
        h=Harness()
        with patch('torch.cuda.is_available',return_value=False),self.assertRaisesRegex(RuntimeError,'CUDA GPU'):
            v18.run(action='train',hub_factory=lambda *a: self.fail('Must reject before remote mutations'))

    def test_source_file_selection_uses_pinned_train_subset_only(self):
        api=SimpleNamespace(dataset_info=lambda *a,**kw:SimpleNamespace(card_data={'configs':[{'config_name':'sample-10BT','data_files':[{'split':'train','path':'sample/10BT/*.parquet'}]}]}),
            list_repo_files=lambda *a,**kw:['sample/10BT/0.parquet','sample/100BT/0.parquet','README.md'])
        self.assertEqual(v18.source_paths(SimpleNamespace(api=api),'fineweb'),['sample/10BT/0.parquet'])

    def test_remote_pool_uses_shifted_full_windows_and_bounded_cache(self):
        h=Harness();state=self.run_action(h);hub=h.factory('iiidevv/test-public','unused','nebula-v18-test')
        pool=v18.RemotePool(hub,state['corpus']['train'],64,1)
        for step in range(30):
            x,y=pool.batch(step,1,5)[0]
            self.assertEqual(len(x),64);torch.testing.assert_close(x[1:],y[:-1])
            self.assertLessEqual(len(pool.cache),2)

    def test_nonfinite_weights_cannot_replace_checkpoint(self):
        model=Nebula(Config(width=32,heads=2,layers=1,context=64))
        with torch.no_grad():next(model.parameters()).fill_(float('nan'))
        with self.assertRaisesRegex(ValueError,'Non-finite weights'):v18.serialize(model,{})

    def test_source_parquet_row_group_resume_uses_ram_blocks(self):
        opened=[]
        class FS:
            def __init__(self,**kwargs):pass
            def open(self,path,*args,**kwargs):opened.append(kwargs);return io.BytesIO(b'fake-parquet')
        class Parquet:
            schema=SimpleNamespace(names=['text']);num_row_groups=2
            metadata=SimpleNamespace(row_group=lambda i:SimpleNamespace(num_rows=3))
            def __init__(self,*a):pass
            def iter_batches(self,**kwargs):
                group=kwargs['row_groups'][0]
                yield SimpleNamespace(to_pylist=lambda:[{'text':str(i)} for i in range(group*3,group*3+3)])
        modules={'huggingface_hub':SimpleNamespace(HfFileSystem=FS),'pyarrow':SimpleNamespace(parquet=SimpleNamespace(ParquetFile=Parquet)),
                 'pyarrow.parquet':SimpleNamespace(ParquetFile=Parquet)}
        with patch.dict('sys.modules',modules),patch('v18_stream.source_paths',return_value=['train.parquet']):
            values=list(v18.source_rows(SimpleNamespace(token='unused'),'stories',{'file':0,'row':4},2))
        self.assertEqual([v[0]['text'] for v in values],['4','5'])
        self.assertEqual(values[-1][1],{'file':0,'row':6})
        self.assertEqual(opened[0]['cache_type'],'bytes')

    def test_builder_default_settings_and_metadata_uri(self):
        from build_v18_stream import build
        notebook=json.loads(build().read_text(encoding='utf-8'))
        code='\n'.join(''.join(c['source']) for c in notebook['cells'] if c['cell_type']=='code')
        ast.parse(code)
        self.assertIn("ACTION = 'prepare'",code);self.assertIn("constants.HF_HUB_DISABLE_XET=True",code)
        self.assertNotIn('hf_hub_download(',Path(v18.__file__).read_text().replace('no hf_hub_download,',''))
        self.assertIn('license_link: https://huggingface.co/iiidevv/test-public/',v18.readme('iiidevv/test-public'))


if __name__=='__main__':unittest.main()
