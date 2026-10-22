import contextlib
import io
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from v8_store import Store,safe_server_detail
from research_client import ResearchError


class ServiceError(Exception):
    def __init__(self,status):
        super().__init__('SECRET_RESPONSE_MUST_NOT_APPEAR')
        self.response=Mock(status_code=status,headers={'Retry-After':'2'})


class BackupRetryTests(unittest.TestCase):
    def test_binary_snapshot_names_and_shards_preserve_contents(self):
        store=self.store([]);store.prefix='experiments/test/';store.info=Mock()
        captured={}
        def commit(**kwargs):
            for op in kwargs['operations']:
                captured[op.path_in_repo]=Path(op.path_or_fileobj).read_bytes()
            return Mock(oid='new-parent')
        store.api.create_commit.side_effect=commit
        fake_hub=SimpleNamespace(CommitOperationAdd=lambda **kw:SimpleNamespace(**kw))
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder);binary=root/'train.bin';binary.write_bytes(bytes(range(200)))
            index=root/'documents.sqlite';index.write_bytes(b'sqlite-example')
            with patch.dict('sys.modules',{'huggingface_hub':fake_hub}),patch('v8_store.PART_BYTES',64),contextlib.redirect_stdout(io.StringIO()):
                state=store.publish({}, {'rawTrain':(binary,'raw/train.bin'),'rawIndex':(index,'raw/documents.sqlite')},root)
        self.assertEqual(b''.join(captured[p['path']] for p in state['rawTrain']['parts']),bytes(range(200)))
        self.assertTrue(all(p['bytes']<=64 and p['path'].endswith('.bin') for p in state['rawTrain']['parts']))
        self.assertTrue(state['rawIndex']['path'].endswith('.sqlite.bin'))
        self.assertEqual(captured[state['rawIndex']['path']],b'sqlite-example')
        self.assertEqual(store.revision,'new-parent')

    def test_service_explanation_redacts_credentials_but_keeps_cause(self):
        error=ServiceError(400)
        error.server_message='File too large. hf_private123 https://example.test/private?token=abc Bearer privatevalue'
        detail=safe_server_detail(error)
        self.assertIn('File too large',detail)
        for sensitive in ['hf_private123','example.test','privatevalue']:
            self.assertNotIn(sensitive,detail)

    def store(self,failures):
        store=object.__new__(Store)
        store.repo='private/test';store.revision='protected-parent';store.api=Mock()
        store.api.create_commit.side_effect=failures
        return store

    def test_temporary_failure_recovers_without_changing_parent(self):
        store=self.store([ServiceError(429),ServiceError(503),Mock(oid='saved')])
        with patch('v8_store.time.sleep') as sleep,contextlib.redirect_stdout(io.StringIO()) as logs:
            self.assertEqual(store._commit_backup([]).oid,'saved')
        self.assertEqual(sleep.call_count,2)
        self.assertTrue(all(c.kwargs['parent_commit']=='protected-parent' for c in store.api.create_commit.call_args_list))
        self.assertNotIn('SECRET_RESPONSE',logs.getvalue())

    def test_conflicts_and_access_errors_never_retry_or_advance(self):
        for status in [409,412,401,403,400,413,422]:
            store=self.store([ServiceError(status)])
            with patch('v8_store.time.sleep') as sleep,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ResearchError):
                store._commit_backup([])
            sleep.assert_not_called()
            self.assertEqual(store.revision,'protected-parent')

    def test_timeout_retries_are_bounded_and_logs_are_sanitized(self):
        store=self.store([TimeoutError('secret URL') for _ in range(4)])
        with patch('v8_store.time.sleep') as sleep,contextlib.redirect_stdout(io.StringIO()) as logs,self.assertRaises(ResearchError):
            store._commit_backup([])
        self.assertEqual(store.api.create_commit.call_count,4)
        self.assertEqual(sleep.call_count,3)
        self.assertNotIn('secret URL',logs.getvalue())
        self.assertEqual(store.revision,'protected-parent')
