"""Bounded HTTP retries and credential-free quota diagnostics."""
import json
import math
import re
import time
from urllib.error import HTTPError

class TeacherRequestError(ValueError):
    def __init__(self, message, status=429, retry_after=60, retryable=True):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after
        self.retryable = retryable

def quota_info(error):
    result = {'zero': False, 'daily': False, 'retry': None}
    try:
        raw = error.read(200001)
        if len(raw) > 200000: return result
        value = json.loads(raw).get('error', {})
        message = str(value.get('message', ''))
        result['zero'] = bool(re.search(r'limit\s*:\s*0(?:\D|$)', message, re.I))
        for detail in value.get('details', []):
            if not isinstance(detail, dict): continue
            if str(detail.get('@type', '')).endswith('RetryInfo'):
                match = re.fullmatch(r'(\d+(?:\.\d+)?)s', str(detail.get('retryDelay', '')))
                if match: result['retry'] = math.ceil(float(match[1]))
            if str(detail.get('@type', '')).endswith('QuotaFailure'):
                for violation in detail.get('violations', []):
                    if not isinstance(violation, dict): continue
                    if str(violation.get('quotaValue', '')) == '0': result['zero'] = True
                    if 'perday' in str(violation.get('quotaId', '')).lower(): result['daily'] = True
        header = error.headers.get('Retry-After') if error.headers else None
        if header and header.isdigit(): result['retry'] = max(result['retry'] or 0, int(header))
    except (ValueError, TypeError, AttributeError, OSError): pass
    return result

def request_json(opener, request, sleep=time.sleep, provider='gemini', max_retries=2):
    label = 'Groq' if provider == 'groq' else 'Gemini secondary' if provider == 'gemini-secondary' else 'Gemini' if provider == 'gemini' else 'Teacher'
    quota_url = 'https://console.groq.com/settings/limits' if provider == 'groq' else 'https://aistudio.google.com/rate-limit' if provider in ['gemini','gemini-secondary'] else 'your provider quota dashboard'
    for attempt in range(max_retries + 1):
        try:
            with opener.open(request, timeout=60) as response:
                raw = response.read(200001)
                if len(raw) > 200000: raise ValueError('Teacher reply too large')
                return json.loads(raw)
        except HTTPError as error:
            if error.code != 429: raise
            info = quota_info(error)
            if info['zero']:
                raise TeacherRequestError(f'{label} HTTP 429: this model has a zero quota limit for your project. Check {quota_url} and select a model with available quota. Retrying cannot change a zero limit.', retryable=False) from None
            if info['daily']:
                raise TeacherRequestError(f'{label} HTTP 429: daily quota exhausted. Check {quota_url} for the reset. Completed examples remain saved.', retryable=False) from None
            delay = max(15 * (2 ** attempt), info['retry'] or 0)
            if attempt == max_retries or delay > 60:
                hint = f' Provider suggests waiting {info["retry"]} seconds.' if info['retry'] is not None else ''
                raise TeacherRequestError(f'{label} HTTP 429: rate or quota limit still blocks requests.' + hint + f' Check {quota_url}. Completed examples remain saved.', retry_after=max(60,info['retry'] or 0)) from None
            print(f'{label} rate limited. Waiting {delay} seconds before retry {attempt + 1}/2. Ctrl+C stops.', flush=True)
            sleep(delay)
