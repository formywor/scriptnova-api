import ast
import contextlib
import copy
import hashlib
import io
import json
import random
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
import torch
from nebula import Nebula,Config,BOS,EOS,save
from v17_raw_data import prepare,PackedPool,document,normalized_hash,SPECS
from v17_raw_lab import RAW_DEFAULT,validate,local_corpus_ready,main_raw


def fixtures():
    result={}
    for key in SPECS:
        result[key]=[{'text':(f'Public caf\u00e9 document {key} number {i}. '+('A clear sentence about learning. '*9)).ljust(320,'.'),
                      'url':f'https://example.test/{key}/{i}'} for i in range(500)]
        result[key].insert(0,{'text':'An identical public document across sources. '+('This is a full clear sentence. '*10)})
    return result


def configuration():
    value=copy.deepcopy(RAW_DEFAULT)
    value.update(textBytes=24000,validationPercent=20,minDocumentBytes=32,maxDocumentBytes=1000,
                 maxScannedPerSource=500,steps=4,batch=2,microbatch=1,localSaveEvery=1,cloudSaveEvery=2,evaluateEvery=2)
    return value


class RawTests(unittest.TestCase):
    def setUp(self):torch.set_num_threads(2)
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_document_checks_and_normalized_duplicates(self):
        self.assertEqual(normalized_hash('One  sentence.'),normalized_hash('one sentence.'))
        self.assertEqual(document({'blob_id':'metadata-only'},'cosmopedia')[1],'missing-text')
        self.assertEqual(document({'text':'Too short'},'fineweb')[1],'whole-document-size')
        self.assertEqual(document({'text':'hello '*100+'hf_'+'x'*30},'stories')[1],'credential-pattern')
        self.assertEqual(document({'text':'x'*1001},'stories',32,1000)[1],'whole-document-size')

    def test_packing_whole_documents_boundaries_dedup_and_validation(self):
        with self.temporary() as d:
            root=Path(d);streams=fixtures();state=prepare(root,configuration(),streams=streams)
            self.assertTrue(state['complete']);self.assertLessEqual(state['textBytes'],24000)
            db=sqlite3.connect(root/'documents.sqlite')
            rows=db.execute('SELECT hash,source,row_index,split,start_token,end_token,utf8_bytes FROM docs').fetchall();db.close()
            self.assertEqual(len(rows),len({r[0] for r in rows}))
            ids={split:{r[0] for r in rows if r[3]==split} for split in ['train','validation']}
            self.assertTrue(ids['validation']);self.assertFalse(ids['train'] & ids['validation'])
            arrays={split:np.fromfile(root/(split+'.bin'),dtype='<u2') for split in ids}
            for identifier,source,index,split,start,end,size in rows:
                values=arrays[split][start:end]
                self.assertEqual(values[0],BOS);self.assertEqual(values[-1],EOS)
                text=bytes(values[1:-1].astype(np.uint8)).decode('utf-8')
                self.assertEqual(text,streams[source][index]['text'].strip())
                self.assertEqual(len(text.encode()),size)
            self.assertGreater(sum(p['excluded'].get('normalized-duplicate',0) for p in state['sources'].values()),0)
            self.assertTrue(local_corpus_ready(root,configuration(),state['textBytes']))

    def test_interrupted_preparation_resumes_to_identical_binary_files(self):
        with self.temporary() as d:
            root=Path(d);full=root/'full';half=root/'half'
            expected=prepare(full,configuration(),streams=fixtures())
            def interrupt(path,state):
                if state['sources']['fineweb']['complete']:raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):prepare(half,configuration(),streams=fixtures(),on_save=interrupt)
            actual=prepare(half,configuration(),streams=fixtures())
            self.assertEqual(actual,expected)
            for name in ['train.bin','validation.bin']:self.assertEqual((full/name).read_bytes(),(half/name).read_bytes())

    def test_uncommitted_tails_manifest_recovery_and_corruption_rejection(self):
        with self.temporary() as d:
            root=Path(d);state=prepare(root,configuration(),streams=fixtures())
            with (root/'train.bin').open('ab') as stream:stream.write(b'uncommitted')
            (root/'manifest.json').write_text('{}')
            prepare(root,configuration(),streams={})
            self.assertEqual((root/'train.bin').stat().st_size,state['tokenCounts']['train']*2)
            self.assertEqual(json.loads((root/'manifest.json').read_text()),state)
            content=bytearray((root/'train.bin').read_bytes());content[5]^=1;(root/'train.bin').write_bytes(content)
            with self.assertRaisesRegex(ValueError,'CHECKSUM_MISMATCH'):prepare(root,configuration(),streams={})

    def test_signal_mid_batch_rolls_back_cursor_and_partial_records(self):
        with self.temporary() as d:
            root=Path(d);streams=fixtures()
            def interrupted_stream():
                for index,item in enumerate(streams['fineweb']):
                    if index==10:raise KeyboardInterrupt()
                    yield item
            broken={**streams,'fineweb':interrupted_stream()}
            with self.assertRaises(KeyboardInterrupt):prepare(root/'partial',configuration(),streams=broken)
            state=json.loads((root/'partial/manifest.json').read_text())
            self.assertEqual(state['sources']['fineweb']['scanned'],0)
            self.assertEqual((root/'partial/train.bin').stat().st_size,0)
            actual=prepare(root/'partial',configuration(),streams=fixtures())
            expected=prepare(root/'control',configuration(),streams=fixtures())
            self.assertEqual(actual,expected)
            self.assertEqual((root/'partial/train.bin').read_bytes(),(root/'control/train.bin').read_bytes())

    def test_full_context_mmap_samples_and_changed_preparation_rejected(self):
        with self.temporary() as d:
            root=Path(d);prepare(root,configuration(),streams=fixtures())
            pool=PackedPool(root/'train.bin',64,10)
            x,y=pool.sample(random.Random(17))
            self.assertEqual(x.dtype,torch.int64);self.assertEqual(len(x),64)
            self.assertTrue(torch.equal(x[1:],y[:-1]));self.assertLessEqual(int(y.max()),EOS)
            pool.close()
            changed=configuration();changed['seed']+=1
            with self.assertRaisesRegex(ValueError,'SETTINGS_CHANGED'):prepare(root,changed,streams={})

    def test_notebook_selects_raw_mode_without_changing_standard_config(self):
        from build_v17_colab import build
        from v17_lab import DEFAULT
        notebook=json.loads(build().read_text(encoding='utf-8'))
        cells=[''.join(c['source']) for c in notebook['cells'] if c['cell_type']=='code']
        values={};exec(cells[1].split('project=')[0],values)
        self.assertTrue(values['RAW_DATA_MODE']);self.assertEqual(values['RAW_CONFIG'],RAW_DEFAULT)
        self.assertEqual(values['CONFIG'],DEFAULT);self.assertIn('datasets>=3.6,<5',cells[0])
        sources=ast.literal_eval(ast.parse(cells[2]).body[0].value)
        self.assertIn('model/v17_raw_data.py',sources);self.assertIn('nebula-rules.json',sources)
        for cell in notebook['cells']:
            if cell['cell_type']=='code':ast.parse(''.join(cell['source']));self.assertEqual(cell['outputs'],[])

    def test_raw_controller_preparation_training_backups_and_completed_resume(self):
        with self.temporary() as d,contextlib.redirect_stdout(io.StringIO()):
            root=Path(d);project=root/'project';project.mkdir();remote=root/'remote';remote.mkdir();states={}
            (project/'nebula-rules.json').write_text(json.dumps({'instructions':['You are Nebula.']}))
            source=root/'source.pt';save(Nebula(Config(width=32,heads=2,layers=1,context=128)),source,{})
            original=hashlib.sha256(source.read_bytes()).hexdigest()
            states['nebula-v17-lab']={'current-foundationWeights':{'path':str(source),'sha256':original}}
            class LocalStore:
                def __init__(self,repo,token,run):self.repo=repo;self.token=token;self.run=run;self.revision='test'
                def state(self):return copy.deepcopy(states.get(self.run))
                def download(self,entry,path):
                    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
                    if Path(entry['path']).resolve()!=path.resolve():shutil.copyfile(entry['path'],path)
                    return path
                def publish(self,state,files,project):
                    self_state=copy.deepcopy(state)
                    for key,(path,name) in files.items():
                        target=remote/self.run/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
                        self_state[key]={'path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
                    states[self.run]=copy.deepcopy(self_state);return self_state
            actual_prepare=prepare
            def prepared(*args,**kwargs):return actual_prepare(*args,**kwargs,streams=fixtures())
            def licenses(folder):
                folder.mkdir(exist_ok=True)
                for key in SPECS:(folder/(key+'-README.md')).write_text('Fixture source card')
            report={'summary':{'validationLossNatsPerTarget':1.,'qualityApproved':False},'openAnswers':[]}
            with patch('v17_raw_lab.Store',LocalStore),patch('v17_raw_lab.prepare',prepared),patch('v17_raw_lab.cards',licenses),\
                 patch('v17_raw_lab.evaluate_raw',return_value=report),patch.dict('os.environ',
                 {'NEBULA_HF_REPO':'test/private','NEBULA_HF_TOKEN':'test','NEBULA_RULES_FILE':str(project/'nebula-rules.json')}):
                main_raw(project,'nebula-v17-raw-unit',configuration(),hours=1,device='cpu')
                self.assertEqual(states['nebula-v17-raw-unit']['phase'],'complete')
                self.assertEqual(states['nebula-v17-raw-unit']['progress']['updates'],4)
                self.assertIn('finalWeights',states['nebula-v17-raw-unit'])
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),original)
                with patch('v17_raw_lab.fit') as trainer:
                    main_raw(project,'nebula-v17-raw-unit',configuration(),hours=1,device='cpu');trainer.assert_not_called()
                changed=configuration();changed['steps']+=1
                with self.assertRaisesRegex(ValueError,'settings/code changed'):
                    main_raw(project,'nebula-v17-raw-unit',changed,hours=1,device='cpu')


if __name__=='__main__':unittest.main()
