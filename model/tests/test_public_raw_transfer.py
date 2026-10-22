import ast
import copy
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit
from unittest.mock import Mock,patch
from public_raw_transfer import build_release,publish_release,restore_entry,main,FORMAT
from v17_raw_data import prepare
from v17_raw_lab import RAW_DEFAULT
from test_v17_raw import fixtures


class PublicTransferTests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def corpus(self,root):
        config=copy.deepcopy(RAW_DEFAULT);config.update(textBytes=24000,maxScannedPerSource=500)
        folder=root/'raw';folder.mkdir()
        with contextlib.redirect_stdout(io.StringIO()):prepare(folder,config,streams=fixtures())
        return folder,config

    def test_allowlist_excludes_extra_files_tables_and_deleted_private_pages(self):
        with self.temporary() as folder:
            root=Path(folder);raw,config=self.corpus(root)
            (raw/'private-chat.json').write_text('private account conversation')
            db=sqlite3.connect(raw/'documents.sqlite')
            db.execute('CREATE TABLE private_reviews (text TEXT)')
            db.execute("INSERT INTO private_reviews VALUES ('PRIVATE_USER_CHAT_DO_NOT_PUBLISH')");db.commit();db.close()
            output=root/'release'
            manifest=build_release(raw,output,config)
            self.assertEqual({p.name for p in output.iterdir()},{'train.bin','validation.bin','documents.sqlite.bin','manifest.json'})
            self.assertNotIn(b'PRIVATE_USER_CHAT', (output/'documents.sqlite.bin').read_bytes())
            clean=sqlite3.connect(output/'documents.sqlite.bin')
            self.assertEqual({r[0] for r in clean.execute("SELECT name FROM sqlite_master WHERE type='table'")},{'docs','metadata'})
            self.assertGreater(clean.execute('SELECT COUNT(*) FROM docs').fetchone()[0],0);clean.close()
            self.assertTrue(manifest['complete'])

    def test_modified_text_is_rejected(self):
        with self.temporary() as folder:
            root=Path(folder);raw,config=self.corpus(root)
            with (raw/'train.bin').open('r+b') as stream:stream.seek(2);stream.write(b'Z\x00')
            with self.assertRaisesRegex(ValueError,'checksum'):build_release(raw,root/'release',config)

    def test_unindexed_tokens_or_unknown_sources_are_rejected(self):
        for mode in ['gap','source']:
            with self.temporary() as folder:
                root=Path(folder);raw,config=self.corpus(root)
                db=sqlite3.connect(raw/'documents.sqlite')
                db.execute("UPDATE docs SET start_token=start_token+1 WHERE split='train'" if mode=='gap' else "UPDATE docs SET source='user_reviews'")
                db.commit();db.close()
                with self.assertRaises(ValueError):build_release(raw,root/'release',config)

    def test_public_upload_is_allowlisted_sharded_and_anonymously_verified(self):
        with self.temporary() as folder:
            root=Path(folder);raw,config=self.corpus(root);remote={};calls=[]
            card=root/'upstream-card.md';card.write_text('Original upstream attribution')
            api=Mock();api.dataset_info.return_value=SimpleNamespace(private=False,sha='parent')
            def commit(**kwargs):
                self.assertEqual(kwargs['repo_type'],'dataset');self.assertEqual(kwargs['parent_commit'],'parent')
                for op in kwargs['operations']:remote[op.path_in_repo]=Path(op.path_or_fileobj).read_bytes()
                return SimpleNamespace(oid='verified-revision')
            api.create_commit.side_effect=commit
            def download(repo,name,**kwargs):
                calls.append(kwargs)
                if name=='README.md':return card
                target=root/'download'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(remote[name]);return target
            hub=SimpleNamespace(CommitOperationAdd=lambda **kw:SimpleNamespace(**kw))
            with patch.dict('sys.modules',{'huggingface_hub':hub}),patch('public_raw_transfer.PART_BYTES',16384),contextlib.redirect_stdout(io.StringIO()):
                state,revision=publish_release(api,'iiidevv/nebula-public-data',raw,config,download)
            self.assertEqual(revision,'verified-revision');self.assertFalse(state['containsModelWeights'])
            link=next(line.split(': ',1)[1] for line in remote['README.md'].decode().splitlines() if line.startswith('license_link:'))
            self.assertEqual(urlsplit(link).scheme,'https')
            self.assertEqual(urlsplit(link).netloc,'huggingface.co')
            self.assertIn('/datasets/iiidevv/nebula-public-data/blob/main/README.md',link)
            self.assertTrue(all(c['token'] is False for c in calls))
            self.assertTrue(all(not name.endswith('.pt') and 'review' not in name for name in remote))
            self.assertIn('parts',state['files']['train.bin'])
            with patch.dict('sys.modules',{'huggingface_hub':SimpleNamespace(hf_hub_download=download)}):
                restored=restore_entry('iiidevv/nebula-public-data','dataset',revision,state['files']['train.bin'],root/'restored.bin',False,'snapshots/'+state['release']+'/')
                self.assertEqual(restored.read_bytes(),(raw/'train.bin').read_bytes())

    def test_builder_has_no_gpu_or_old_global_variable_requirement(self):
        from build_public_transfer import build
        notebook=json.loads(build().read_text(encoding='utf-8'))
        self.assertNotIn('accelerator',notebook['metadata'])
        code='\n'.join(''.join(c['source']) for c in notebook['cells'] if c['cell_type']=='code')
        ast.parse(code)
        self.assertIn("userdata.get('NEBULA_HF_TOKEN')",code)
        self.assertNotIn('namespace[',code)

    def test_controller_restores_source_privacy_and_retains_newer_local_data(self):
        class Missing(Exception):pass
        with self.temporary() as folder:
            root=Path(folder);raw,config=self.corpus(root)
            project=root/'api';project.mkdir();shutil.copytree(raw,project/'raw-data')
            state=root/'state.json';state.write_text(json.dumps({'format':FORMAT,'config':config,'preparedTextBytes':0}))
            api=Mock();api.whoami.return_value={'name':'iiidevv'}
            api.model_info.side_effect=[SimpleNamespace(private=False,sha='before'),SimpleNamespace(private=True,sha='private-revision')]
            api.dataset_info.side_effect=Missing()
            hub=SimpleNamespace(HfApi=lambda **kw:api,hf_hub_download=lambda *a,**kw:state)
            errors=SimpleNamespace(EntryNotFoundError=Missing,RepositoryNotFoundError=Missing)
            with patch.dict('os.environ',{'NEBULA_HF_TOKEN':'hf_test_not_a_real_credential'}),patch.dict('sys.modules',{'huggingface_hub':hub,'huggingface_hub.errors':errors}),patch('public_raw_transfer.publish_release') as publish,contextlib.redirect_stdout(io.StringIO()):
                main(project)
            api.update_repo_settings.assert_called_once_with('iiidevv/nebula-research',repo_type='model',private=True)
            self.assertEqual(publish.call_count,1)
            api.delete_repo.assert_not_called()
            self.assertEqual((project/'raw-data'/'train.bin').read_bytes(),(raw/'train.bin').read_bytes())


if __name__=='__main__':unittest.main()
