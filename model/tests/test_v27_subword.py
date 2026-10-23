import builtins
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch
import numpy as np
import torch
from v27_subword_model import Model,Config,SPECIAL,EOS,encode_chat,chat_window,checkpoint,restore
from v27_subword_data import train_tokenizer,prepare,raw_batch,public_windows
import v27_subword_train as trainer
from test_v18_foundation_control import MemoryHub,fixture

class SubwordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(2)
        cls.tokenizer=train_tokenizer(['A green tree grows by the blue river. A child reads a book.']*30,512)

    def test_tokenizer_roundtrip_special_ids_unicode_and_unseen_words(self):
        for i,s in enumerate(SPECIAL):self.assertEqual(self.tokenizer.token_to_id(s),i)
        for text in ['Hello, world!','Unseenword987',' café — 你好 🌍\n']:
            ids=self.tokenizer.encode(text).ids
            self.assertEqual(self.tokenizer.decode(ids),text)
            self.assertTrue(all(i>=6 for i in ids))

    def test_assistant_masking_real_eos_and_no_truncation(self):
        messages=[{'role':'system','content':'Be helpful.'},{'role':'user','content':'My bag is red.'},
            {'role':'assistant','content':'Understood.'},{'role':'user','content':'What color?'},
            {'role':'assistant','content':'red'}]
        x,y=chat_window(self.tokenizer,messages,256)
        expected=self.tokenizer.encode('Understood.').ids+[EOS]+self.tokenizer.encode('red').ids+[EOS]
        self.assertEqual(y[y!=-100].tolist(),expected)
        tokens,learn=encode_chat(self.tokenizer,messages)
        self.assertEqual(x.tolist(),tokens[:-1])
        with self.assertRaises(ValueError):chat_window(self.tokenizer,messages,4)
        with self.assertRaises(ValueError):encode_chat(self.tokenizer,[{'role':'user','content':SPECIAL[2]}])

    def test_causal_mask_padding_gradient_and_independent_loss(self):
        model=Model(Config(vocab=512,width=16,heads=2,layers=1,context=64));model.eval()
        a=torch.tensor([[1,16,25,47]]);b=a.clone();b[0,3]=99
        self.assertTrue(torch.allclose(model(a)[:,:3],model(b)[:,:3],atol=1e-6))
        padded=torch.cat([a,torch.zeros((1,3),dtype=torch.long)],1)
        self.assertTrue(torch.allclose(model(a),model(padded)[:,:4],atol=1e-6))
        pairs=[chat_window(self.tokenizer,[{'role':'user','content':'Hi'},{'role':'assistant','content':t}],64) for t in ['green','a blue river']]
        x,y=trainer.collate(pairs)
        loss=torch.nn.functional.cross_entropy(model(x).flatten(0,1),y.flatten(),reduction='sum')
        reference=sum(torch.nn.functional.cross_entropy(model(a[None]).flatten(0,1),b,reduction='sum') for a,b in pairs)
        self.assertAlmostEqual(float(loss.detach()),float(reference.detach()),places=4)
        loss.backward();self.assertTrue(all(torch.isfinite(p.grad).all() for p in model.parameters() if p.grad is not None))

    def test_prep_real_index_splits_balanced_sources_and_partial_resume(self):
        source,saved,_=fixture();original=copy.deepcopy(source.objects)
        source.fetch=lambda *a,**kw:b'Public source license/card'
        config=copy.deepcopy(trainer.DEFAULT);config.update(trainBytes=1000,validationBytes=1000,tokenizerBytes=500,vocab=512,context=64,
            sourceMix=dict(fineweb=25,cosmopedia=25,textbooks=25,stories=25))
        output=MemoryHub();state={}
        with contextlib.redirect_stdout(io.StringIO()):state,tok=prepare(output,state,source,saved,config)
        self.assertTrue(state['dataReady']);self.assertEqual(source.objects,original);self.assertFalse(source.writes)
        report=json.loads(output.read_entry(state['dataReport']))
        self.assertFalse(set(report['documentHashes']['train'])&set(report['documentHashes']['validation']))
        # Simulate interruption after tokenized train split was confirmed, before validation/card commit.
        partial={k:v for k,v in state.items() if k not in ['dataReady','validationTokens','dataReport'] and not k.startswith('sourceCard_')}
        with patch('v27_subword_data.train_tokenizer',side_effect=AssertionError('Must reuse persisted tokenizer')),contextlib.redirect_stdout(io.StringIO()):
            recovered,tok2=prepare(output,partial,source,saved,config)
        self.assertEqual(tok.to_str(),tok2.to_str());self.assertEqual(state['trainTokens'],recovered['trainTokens'])
        values=np.frombuffer(output.read_entry(state['trainTokens']),dtype='<u2')
        for x,y in raw_batch(values,1,4,64,42):self.assertTrue(torch.equal(x[1:],y[:-1]))

    def test_checkpoint_format_and_tokenizer_binding(self):
        model=Model(Config(vocab=512,width=16,heads=2,layers=1,context=64));stream=checkpoint(model,{'updates':4},'abc')
        blob=stream.getvalue();stream.close();loaded,state=restore(blob,'abc')
        self.assertEqual(state['updates'],4)
        for key,val in model.state_dict().items():self.assertTrue(torch.equal(val,loaded.state_dict()[key]))
        with self.assertRaises(ValueError):restore(blob,'different')
        old=io.BytesIO();torch.save({'format':1},old)
        with self.assertRaises(ValueError):restore(old.getvalue(),'abc')

    def test_cpu_resume_is_exact_and_stages_separate_no_disk_artifacts(self):
        tok=self.tokenizer;output=MemoryHub();cfg=copy.deepcopy(trainer.DEFAULT)
        cfg.update(vocab=512,width=16,heads=2,layers=1,context=64,foundationUpdates=10,conversationUpdates=10,batch=2,saveEvery=2,evaluateEvery=20,warmup=2)
        def prepare_mock(hub,state,*args):
            values=np.asarray(([1]+tok.encode('A green tree grows by a blue river.').ids+[2])*30,dtype='<u2').tobytes()
            state=hub.publish({**state,'dataReady':True},{'tokenizer':('tokenizer.json',tok.to_str().encode()),'trainTokens':('train.bin',values),'validationTokens':('validation.bin',values)})
            return state,tok
        source=MemoryHub();source.objects['public']=json.dumps([dict(id=f'{i:08x}',messages=[{'role':'user','content':'Hi'},{'role':'assistant','content':'Hello'}]) for i in range(500)]).encode()
        source_state={'publicRows':dict(path='public',sha256='mock-public-sha')}
        def evaluate(model,tokenizer,valid,stage,step,public_valid=None):return dict(stage=stage,updates=step,qualityApproved=False)
        def execute(out,stage='foundation',clock=lambda:0,hours=7.):
            old_open=builtins.open;old_io=io.open
            def guard(original):
                def call(file,mode='r',*a,**kw):
                    if any(c in mode for c in 'wax+'):raise AssertionError('No artifact disk writes')
                    return original(file,mode,*a,**kw)
                return call
            with patch.object(trainer,'Store',return_value=out),patch.object(trainer,'prepare',side_effect=prepare_mock),patch.object(trainer,'read_source',return_value=(source,source_state)),patch.object(trainer,'evaluate',side_effect=evaluate),patch.dict('os.environ',{'NEBULA_HF_TOKEN':'unit-test-only'}),patch.object(builtins,'open',side_effect=guard(old_open)),patch.object(io,'open',side_effect=guard(old_io)),contextlib.redirect_stdout(io.StringIO()):
                return trainer.run(config=cfg,stage=stage,device='cpu',clock=clock,hours=hours)
        with self.assertRaises(ValueError):execute(MemoryHub(),stage='conversation')
        times=iter([0,0,0,100]);paused=execute(output,clock=lambda:next(times),hours=.001)
        self.assertEqual(paused['steps']['foundation'],1)
        execute(output);straight=MemoryHub();execute(straight)
        a,_=restore(output.read_entry(output.saved['foundationWorking']),output.saved['tokenizer']['sha256'])
        b,_=restore(straight.read_entry(straight.saved['foundationWorking']),straight.saved['tokenizer']['sha256'])
        for key,val in a.state_dict().items():self.assertTrue(torch.equal(val,b.state_dict()[key]),key)
        foundation=copy.deepcopy(output.saved['foundationWorking'])
        execute(output,stage='conversation')
        self.assertEqual(output.saved['foundationWorking'],foundation)
        self.assertTrue(output.saved['foundationComplete']);self.assertTrue(output.saved['conversationComplete'])
        self.assertFalse(output.saved['qualityApproved']);self.assertFalse(source.writes)
        self.assertEqual(output.saved['steps'],dict(foundation=10,conversation=10))

    def test_notebook_embeds_current_dependencies_and_empty_outputs(self):
        import ast
        from pathlib import Path
        from build_v27_subword import build
        notebook=json.loads(build().read_text(encoding='utf-8'))
        tree=ast.parse(''.join(notebook['cells'][3]['source']))
        sources=ast.literal_eval(tree.body[0].value)
        root=Path(trainer.__file__).parent
        for name,value in sources.items():
            ast.parse(value);self.assertEqual(value,(root/name).read_text(encoding='utf-8'))
        for cell in notebook['cells']:
            if cell['cell_type']=='code':
                ast.parse(''.join(cell['source']));self.assertEqual(cell['outputs'],[])
        self.assertIn("RUN_STAGE='foundation'",''.join(notebook['cells'][2]['source']))
        self.assertIn('tokenizers==0.22.2',''.join(notebook['cells'][1]['source']))

    def test_default_budget_and_optimizer_groups(self):
        cfg=trainer.validate(copy.deepcopy(trainer.DEFAULT),'foundation')
        self.assertEqual(cfg['sourceMix']['stories'],5);self.assertEqual(cfg['vocab'],8192)
        self.assertEqual(cfg['foundationUpdates']*cfg['batch']*cfg['context'],81920000)
        model=Model(Config(vocab=512,width=16,heads=2,layers=1,context=64))
        opt=trainer.make_optimizer(model,.0003)
        self.assertEqual(opt.defaults['betas'],(.9,.95))
        for group in opt.param_groups:
            for p in group['params']:self.assertEqual(group['weight_decay'],.1 if p.ndim>=2 else 0.)

if __name__=='__main__':unittest.main()
