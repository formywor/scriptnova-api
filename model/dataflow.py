"""Reviewed datasets. These commands never call teachers with user chat content."""
import hashlib
import json
import re
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import os
import time
from teacher_http import request_json
from rules import owner_instructions

def read_jsonl(path):
    with Path(path).open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]

def write_jsonl(path, rows):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
    temporary.replace(path)

def redact(text):
    text = re.sub(r'\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b', '[email removed]', text)
    text = re.sub(r'\b(?:sk-|AIza|hf_|gsk_|AQ\.)[\w-]{15,}\b', '[credential removed]', text)
    text = re.sub(r'\bBearer\s+[\w.~/+=-]{12,}', '[credential removed]', text, flags=re.I)
    text = re.sub(r'(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)', '[number removed]', text)
    return text

def example_id(messages):
    return hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()

def eligible(row, snapshot=None):
    if row.get('reviewStatus') != 'approved': return False
    source = row.get('source', {})
    if source.get('kind') == 'user':
        if not snapshot: return False
        profile = snapshot.get('accounts', {}).get(source.get('accountKey'))
        owner = snapshot.get('training', {}).get(source.get('owner'))
        if not profile or profile.get('improve') is not True or not owner or owner.get('revoked'): return False
        if profile.get('trainingGeneration', 0) != source.get('generation'): return False
        original = owner.get('samples', {}).get(source.get('chatId'), {}).get(source.get('turnId'))
        if not original or original.get('consentVersion') != 1: return False
        # An export cannot be modified into different content while claiming old consent.
        messages = [{'role': m['role'], 'content': redact(m['content'])} for m in original.get('messages', [])]
        # Reviewers may correct the answer, but cannot replace the consented user prompt.
        if not messages or not row.get('messages') or row['messages'][0] != messages[0]: return False
    elif source.get('kind') == 'teacher':
        if source.get('trainingAllowed') is not True: return False
    elif source.get('kind') == 'public':
        allowed = (source.get('dataset') == 'HuggingFaceTB/everyday-conversations-llama3.1-2k' and source.get('subset') == 'default') or (source.get('dataset') == 'HuggingFaceTB/smoltalk' and source.get('subset') == 'smol-magpie-ultra')
        story = source.get('dataset') == 'roneneldan/TinyStories' and source.get('subset') == 'default' and source.get('license') == 'cdla-sharing-1.0'
        if not ((allowed and source.get('license') == 'apache-2.0') or story) or not source.get('recordId'): return False
    elif source.get('kind') != 'seed': return False
    messages = row.get('messages')
    # User exports remain a single consent-checked pair. Owned/teacher datasets may be dialogues.
    maximum = 2 if source.get('kind') == 'user' else 12
    return (isinstance(messages, list) and 2 <= len(messages) <= maximum and len(messages) % 2 == 0
            and all(isinstance(m, dict) and m.get('role') == ('user' if i % 2 == 0 else 'assistant')
                    and isinstance(m.get('content'), str) and 0 < len(m['content'].strip()) <= 16000
                    for i, m in enumerate(messages)))

def prepare(inputs, output, snapshot=None):
    rows, seen = [], set()
    for path in inputs:
        for row in read_jsonl(path):
            if not eligible(row, snapshot): continue
            identifier = example_id(row['messages'])
            if identifier in seen: continue
            seen.add(identifier); rows.append({**row, 'id': identifier})
    if not rows: raise ValueError('No approved, currently eligible training examples')
    write_jsonl(output, rows)
    return len(rows)

def generate_teacher(config, prompts, output, limit=10, transport=None):
    """Bounded calls to an OpenAI-compatible API. Original prompts only."""
    if not 1 <= limit <= 100: raise ValueError('Request limit must be 1 to 100')
    if config.get('trainingAllowed') is not True: raise ValueError('Choose a teacher whose output may be used for training')
    endpoint = config['url']; parsed = urlparse(endpoint)
    if parsed.username or parsed.password or parsed.query: raise ValueError('Credentials belong in an environment variable')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ['localhost', '127.0.0.1', '::1']): raise ValueError('HTTPS required for remote teacher')
    key = os.environ.get(config.get('keyEnv', 'NEBULA_TEACHER_KEY'), '')
    if not key and parsed.hostname not in ['localhost', '127.0.0.1', '::1']: raise ValueError('Teacher API key is missing')
    rows = read_jsonl(output) if Path(output).exists() else []
    completed = {r.get('promptId') for r in rows}
    calls = 0
    for prompt in prompts:
        # Prevent accidental transmission of exported user conversations to teachers.
        if prompt.get('source') != 'original' or not isinstance(prompt.get('prompt'), str): raise ValueError('Teacher prompts must be original curriculum prompts')
        text = prompt['prompt'].strip()
        if not text or len(text) > 4000: raise ValueError('Invalid curriculum prompt')
        identifier = hashlib.sha256((config.get('name', 'custom') + ':' + config['model'] + ':' + text).encode()).hexdigest()
        if identifier in completed: continue
        if calls >= limit: break
        payload = {'model': config['model'], 'messages': [{'role': 'system', 'content': 'Create a training example for Nebula using these owner instructions.\n' + owner_instructions() + '\n' + config.get('instructions', '')}, {'role': 'user', 'content': text}], 'max_tokens': min(int(config.get('maxTokens', 256)), 1024), 'temperature': 0.6}
        if config.get('temperature', 0.6) is None: payload.pop('temperature')
        if config.get('reasoningEffort') in ['low','medium','high']: payload['reasoning_effort'] = config['reasoningEffort']
        request = Request(endpoint, json.dumps(payload).encode(), {'Content-Type': 'application/json', 'User-Agent':'Nebula-Teacher/1.0', **({'Authorization': 'Bearer ' + key} if key else {})})
        if calls and not transport:
            delay = min(60, max(0, float(config.get('requestIntervalSeconds', 0))))
            if delay: time.sleep(delay)
        if transport: data = transport(request)
        else:
            # Never follow a redirect carrying a credential to another host.
            from urllib.request import build_opener, HTTPRedirectHandler
            class NoRedirect(HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs): return None
            data = request_json(build_opener(NoRedirect), request, provider=config.get('name','teacher'), max_retries=int(config.get('httpRetries',2)))
        answer = data['choices'][0]['message']['content']
        if not isinstance(answer, str) or not answer.strip() or len(answer) > 16000: raise ValueError('Invalid teacher answer')
        rows.append({'promptId': identifier, 'reviewStatus': 'pending', 'messages': [{'role': 'user', 'content': text}, {'role': 'assistant', 'content': redact(answer)}], 'source': {'kind': 'teacher', 'provider': config.get('name', 'custom'), 'model': config['model'], 'trainingAllowed': True}})
        calls += 1; completed.add(identifier); write_jsonl(output, rows)
    return calls
