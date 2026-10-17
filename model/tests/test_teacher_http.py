import io
import json
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from teacher_http import request_json

def limited(message='', details=None):
    body = json.dumps({'error': {'message': message, 'details': details or []}}).encode()
    return HTTPError('https://example.test', 429, 'limited', {}, io.BytesIO(body))

class TeacherHTTP(unittest.TestCase):
    def test_zero_quota_fails_without_retry_or_raw_body(self):
        opener = Mock(); opener.open.side_effect = limited('secret_value limit: 0')
        sleep = Mock()
        with self.assertRaisesRegex(ValueError, 'zero quota') as caught: request_json(opener, None, sleep)
        self.assertNotIn('secret_value', str(caught.exception)); sleep.assert_not_called()

    def test_daily_quota_does_not_retry(self):
        opener = Mock(); opener.open.side_effect = limited(details=[{'@type': 'google.rpc.QuotaFailure', 'violations': [{'quotaId': 'RequestsPerDay'}]}])
        sleep = Mock()
        with self.assertRaisesRegex(ValueError, 'daily quota'): request_json(opener, None, sleep)
        sleep.assert_not_called()

    def test_transient_retries_are_bounded(self):
        opener = Mock(); opener.open.side_effect = [limited(), limited(), limited()]
        sleep = Mock()
        with self.assertRaisesRegex(ValueError, 'still blocks'): request_json(opener, None, sleep)
        self.assertEqual(opener.open.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [15, 30])

    def test_transient_retry_can_succeed(self):
        response = Mock(); response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"choices": []}'
        opener = Mock(); opener.open.side_effect = [limited(), response]
        self.assertEqual(request_json(opener, None, Mock()), {'choices': []})

if __name__ == '__main__': unittest.main()
