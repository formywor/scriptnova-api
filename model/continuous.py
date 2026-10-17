"""Generate a bounded Gemini dataset, then train locally until Ctrl+C."""
import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
# The workspace CPU runtime is outside the publishable API directory.
# Resolve relative to this file, independent of shell cwd/PYTHONPATH.
runtime = Path(__file__).resolve().parents[4] / 'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir():
    sys.path.insert(0, str(runtime))
from dataflow import generate_teacher, prepare, read_jsonl, write_jsonl
from train import train

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-teacher-output', action='store_true', help='Explicitly accept generated answers as unverified training examples')
    parser.add_argument('--max-teacher-calls', type=int, default=32)
    parser.add_argument('--model', default=os.environ.get('GEMINI_TEACHER_MODEL', 'gemini-3.8-flash'))
    args = parser.parse_args()
    if not args.accept_teacher_output:
        parser.error('Pass --accept-teacher-output to use generated answers without manual review')
    if not 1 <= args.max_teacher_calls <= 100:
        parser.error('Teacher call limit must be between 1 and 100')
    root = Path(__file__).resolve().parent
    output = root / 'data/gemini-pending.jsonl'
    config = {'name': 'gemini', 'url': 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', 'model': args.model, 'keyEnv': 'GEMINI_API_KEY', 'trainingAllowed': True, 'maxTokens': 256, 'requestIntervalSeconds': 15, 'instructions': 'Answer directly in plain English using at most 140 characters. No preamble or markdown. These are short examples for a tiny model.'}
    try:
        calls = generate_teacher(config, read_jsonl(root / 'curriculum.jsonl'), output, args.max_teacher_calls)
    except KeyboardInterrupt:
        print('Stopped teacher collection. Completed replies are saved; rerun to continue.')
        return
    except HTTPError as error:
        raise SystemExit(f'Gemini returned HTTP {error.code}. Check key, model access and quota. No response body or credential was printed.')
    except (URLError, TimeoutError):
        raise SystemExit('Gemini connection failed. Completed replies are saved; rerun to retry.')
    except ValueError as error:
        raise SystemExit(str(error))
    accepted = []
    for row in read_jsonl(output):
        if row.get('source', {}).get('model') != args.model: continue
        accepted.append({**row, 'reviewStatus': 'approved', 'approvalMethod': 'owner-opt-in-unverified'})
    if not accepted: raise SystemExit('No Gemini examples available; training did not start.')
    write_jsonl(root / 'data/gemini-accepted.jsonl', accepted)
    prepare([root / 'seed.jsonl', root / 'data/gemini-accepted.jsonl'], root / 'data/continuous.jsonl')
    checkpoint = root / 'checkpoints/nebula-continuous.pt'
    resume = checkpoint if checkpoint.exists() else root / 'checkpoints/nebula-practice.pt'
    print(json.dumps({'teacherCallsThisRun': calls, 'teacherExamples': len(accepted), 'mode': 'continuous local training', 'stop': 'Ctrl+C', 'unverifiedTeacherAnswers': True}), flush=True)
    train(SimpleNamespace(data=root / 'data/continuous.jsonl', output=checkpoint, snapshot=None, resume=resume if resume.exists() else None, preset='cpu', steps=500, batch=2, threads=2, seed=42, lr=.0005, continuous=True, save_every=100))

if __name__ == '__main__': main()
