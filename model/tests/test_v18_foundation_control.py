import contextlib
import builtins
import copy
import gzip
import io
import json
from collections import OrderedDict
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import torch
from nebula import Nebula,Config,BOS,EOS
import v18_foundation_control as control
from v18_stream import serialize,deserialize,sha,RemotePool


class MemoryHub:
    def __init__(self):
        self.repo='iiidevv/nebula-raw-training';self.prefix='experiments/control/'
        self.revision='pinned';self.objects={};self.saved=None;self.writes=[]
    def read_entry(self,entry):return self.objects[entry['path']]
    def state(self):return copy.deepcopy(self.saved)
    def publish(self,state,blobs=None):
        result=copy.deepcopy(state)
        for key,(name,value) in (blobs or {}).items():
            if isinstance(value,str):raise AssertionError('Expected RAM bytes')
            value=bytes(value);path=self.prefix+sha(value)+'/'+name
            self.objects[path]=value;result[key]={'path':path,'bytes':len(value),'sha256':sha(value),
                                               'parts':[{'path':path,'bytes':len(value),'sha256':sha(value)}]}
            self.writes.append(path)
        self.saved=copy.deepcopy(result);return result


def fixture():
    torch.manual_seed(19021)
    model=Nebula(Config(width=16,heads=2,layers=1,context=64))
    optimizer=torch.optim.AdamW(model.parameters(),lr=.00003,weight_decay=.01)
    loss=model(torch.tensor([[256,72,105]] )).sum();loss.backward();optimizer.step();optimizer.zero_grad()
    stream=serialize(model,{}, {'optimizer':optimizer.state_dict(),'scaler':{},'updates':10102})
    hub=MemoryHub();hub.prefix='experiments/nebula-v18-raw-1gb/'
    hub.objects['working']=stream.getvalue();stream.close()
    state={'updates':10102,'corpusComplete':True,'working':{'path':'working','sha256':sha(hub.objects['working'])},
        'config':{'validationPercent':2,'shardHoldSteps':64,'seed':1802026,'batch':2,'microbatch':1,
                  'learningRate':.00003,'warmup':200,'steps':100000},
        'corpus':{'train':[],'validation':[],'index':[]},'sourceBytes':{},'uniqueTextBytes':0,'documents':0}
    records=[];buffers={'train':[],'validation':[]}
    for source in ['fineweb','cosmopedia','stories','textbooks']:
        counts={'train':0,'validation':0};i=0
        while min(counts.values())<5:
            text=f'The child {i} saw a boat by a quiet pond. The boat had a blue sail. Source {source}.'
            content=text.encode();identifier=sha(' '.join(text.casefold().split()).encode())
            split='validation' if int(identifier[:8],16)%100<2 else 'train';i+=1
            if counts[split]>=5:continue
            values=[BOS]+list(content)+[EOS];start=len(buffers[split]);buffers[split].extend(values)
            records.append(dict(hash=identifier,source=source,split=split,shard=0,startToken=start,
                                endToken=len(buffers[split]),utf8Bytes=len(content)))
            counts[split]+=1;state['sourceBytes'][source]=state['sourceBytes'].get(source,0)+len(content)
            state['documents']+=1;state['uniqueTextBytes']+=len(content)
    for split in buffers:
        value=np.array(buffers[split],dtype='<u2').tobytes();hub.objects[split]=value
        state['corpus'][split]=[{'path':split,'bytes':len(value),'sha256':sha(value)}]
    value=gzip.compress(b'\n'.join(json.dumps(r).encode() for r in records));hub.objects['index']=value
    state['corpus']['index']=[{'path':'index','bytes':len(value),'sha256':sha(value)}]
    return hub,state,records


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):torch.set_num_threads(2)

    def test_real_saved_batch_and_document_selection(self):
        hub,state,records=fixture()
        with contextlib.redirect_stdout(io.StringIO()):
            loaded,audit=control.load_index(hub,state)
            pools,actual=control.audit_payloads(hub,state,loaded,64)
        arrays,selection,prefixes=control.select_stories(pools,records,1000,1000)
        self.assertTrue(audit['indexCoverageComplete']);self.assertEqual(actual['payloadSamplesChecked'],32)
        self.assertTrue(actual['actualV18Batch']['targetShiftCorrect'])
        self.assertFalse(set(selection['train']['hashes'])&set(selection['validation']['hashes']))
        self.assertEqual(len(prefixes),2)
        for x,y in control.pairs_from_array(arrays['train'],64,8,42):self.assertTrue(torch.equal(x[1:],y[:-1]))

    def test_index_overlap_and_payload_corruption_rejected(self):
        hub,state,records=fixture();records[1]['hash']=records[0]['hash']
        hub.objects['index']=gzip.compress(b'\n'.join(json.dumps(r).encode() for r in records))
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(ValueError,'Duplicate'):
            control.load_index(hub,state)
        hub,state,records=fixture();pool=RemotePool(hub,state['corpus']['train'],64)
        row=next(r for r in records if r['split']=='train')
        value=bytearray(hub.objects['train']);value[row['startToken']*2]=1;hub.objects['train']=bytes(value)
        with self.assertRaisesRegex(ValueError,'boundary'):control.document(pool,row)

    def test_actual_causal_probe_rejects_future_leak(self):
        model=Nebula(Config(width=16,heads=2,layers=1,context=64))
        pair=control.pairs_from_array(np.arange(100,dtype=np.uint16),64,1,42)[0]
        self.assertTrue(control.audit_forward(model,pair)['manualNextTokenLossMatches'])
        class Leaky(torch.nn.Module):
            def __init__(self):super().__init__();self.parameter=torch.nn.Parameter(torch.ones(1))
            def forward(self,x):return x.float().sum().expand(1,x.shape[1],262)
        with self.assertRaisesRegex(ValueError,'Future-token'):control.audit_forward(Leaky(),pair)

    def test_control_checkpoint_resume_matches_continuous_training_and_preserves_source(self):
        source,source_state,_=fixture();original=copy.deepcopy(source.objects);output=MemoryHub()
        config=copy.deepcopy(control.DEFAULT);config.update(updates=2,saveEvery=1,trainUtf8Bytes=1000,
                                       validationUtf8Bytes=1000,maxSessionHours=.001)
        def probe(*a,**k):return {'answers':[],'summary':[],'qualityApproved':False,'trainingStarted':False}
        def execute(out,clock):
            builtin_open=builtins.open;io_open=io.open
            def guard(original):
                def call(file,mode='r',*args,**kwargs):
                    if any(c in mode for c in 'wax+'):raise AssertionError('No filesystem writes permitted for experiment artifacts')
                    return original(file,mode,*args,**kwargs)
                return call
            with patch.object(control,'read_source',return_value=(source,source_state)), \
                 patch.object(control,'Hub',return_value=out),patch.object(control,'compare',side_effect=probe), \
                 patch.object(builtins,'open',side_effect=guard(builtin_open)),patch.object(io,'open',side_effect=guard(io_open)), \
                 patch.dict('os.environ',{'NEBULA_HF_TOKEN':'unit-test-only'}),contextlib.redirect_stdout(io.StringIO()):
                return control.run_control(config=config,device='cpu',clock=clock)
        times=iter([0,0,10]);paused=execute(output,lambda:next(times))
        self.assertEqual(paused['updates'],1);self.assertFalse(paused['complete'])
        report=execute(output,lambda:0)
        self.assertEqual(report['additionalUpdates'],2);self.assertTrue(output.saved['complete'])
        uninterrupted=MemoryHub();execute(uninterrupted,lambda:0)
        m1,p1=deserialize(output.read_entry(output.saved['working']))
        m2,p2=deserialize(uninterrupted.read_entry(uninterrupted.saved['working']))
        for name,value in m1.state_dict().items():self.assertTrue(torch.equal(value,m2.state_dict()[name]),name)
        self.assertEqual(p1['trainingState']['updates'],p2['trainingState']['updates'])
        self.assertEqual(source.objects,original);self.assertFalse(source.writes)
        self.assertTrue(all('/control/' in p for p in output.writes))
        self.assertFalse(report['qualityApproved'])
        self.assertEqual(execute(output,lambda:0),json.loads(output.read_entry(output.saved['finalReport'])))


if __name__=='__main__':unittest.main()
