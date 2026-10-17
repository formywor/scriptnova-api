"""Owner instructions shared by training and private inference."""
import json
import os
from pathlib import Path

def owner_instructions():
    configured = os.environ.get('NEBULA_RULES_FILE')
    path = Path(configured) if configured else Path(__file__).resolve().parent.parent / 'nebula-rules.json'
    value = json.loads(path.read_text(encoding='utf-8'))
    lines = value.get('instructions')
    if not isinstance(lines, list) or not lines or any(not isinstance(line, str) or not line.strip() for line in lines): raise ValueError('Invalid owner rules')
    extra = os.environ.get('NEBULA_OWNER_INSTRUCTIONS', '')
    text = '\n'.join(lines + ([extra] if extra else []))
    if len(text) > 16000: raise ValueError('Owner instructions too long')
    return text

def with_owner_rules(messages):
    text = owner_instructions()
    if messages and messages[0]['role'] == 'system' and (messages[0]['content'] == text or messages[0]['content'].startswith(text + '\n')): return messages
    return [{'role': 'system', 'content': text}, *messages]
