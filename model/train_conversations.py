"""Collect dialogue examples with up to three teachers, then train owned weights."""
import argparse
import json
import os
from pathlib import Path
import random
import sys
from types import SimpleNamespace

root = Path(__file__).resolve().parent
runtime = root.parents[3] / 'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir(): sys.path.insert(0, str(runtime))
from conversations import curriculum, collect
from dataflow import prepare, read_jsonl, write_jsonl
from nebula import encode
from rules import with_owner_rules
from train import train

def configured_teachers(configs, environment):
    """Skip an optional teacher only when its key is absent; required keys remain required."""
    return [config for config in configs if not config.get('optional',False) or environment.get(config.get('keyEnv','NEBULA_TEACHER_KEY'),'').strip()]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect', action='store_true', help='Call teacher APIs before training')
    parser.add_argument('--collect-only', action='store_true', help='Collect examples and report provider errors without training')
    parser.add_argument('--teachers', help='Private JSON configuration array for one to three OpenAI-compatible teachers')
    parser.add_argument('--workers', type=int, choices=[1,2,3], default=3)
    parser.add_argument('--max-teacher-calls', type=int, default=32)
    parser.add_argument('--accept-teacher-output', action='store_true')
    parser.add_argument('--steps', type=int, default=500)
    parser.add_argument('--continuous', action='store_true')
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--batch', type=int, default=2)
    parser.add_argument('--patience', type=int, default=5, help='Stop after N validation checks without improvement; 0 disables')
    args = parser.parse_args()
    if args.collect_only: args.collect = True
    if args.collect and not args.collect_only and not args.accept_teacher_output:
        parser.error('--collect requires --accept-teacher-output for unverified generated answers')
    rows = [r for r in curriculum() if len(encode(with_owner_rules(r['messages']))[0]) <= 513]
    random.Random(73).shuffle(rows)
    folder = root/'data'; folder.mkdir(parents=True,exist_ok=True)
    write_jsonl(folder/'conversations-seed.jsonl', rows)
    pending = folder/'conversations-teacher-pending.jsonl'
    if args.collect:
        configs = json.loads((Path(args.teachers) if args.teachers else root/'teachers.gemini-groq.json').read_text(encoding='utf-8'))
        optional_missing=sum(1 for config in configs if config.get('optional',False) and not os.environ.get(config.get('keyEnv','NEBULA_TEACHER_KEY'),'').strip())
        configs=configured_teachers(configs,os.environ)
        if optional_missing: print(json.dumps({'optionalTeachersSkipped':optional_missing,'reason':'key_not_set'}),flush=True)
        if not configs: parser.error('No teachers have configured keys')
        for config in configs:
            override = os.environ.get('GEMINI_SECOND_TEACHER_MODEL' if config.get('name') == 'gemini-secondary' else 'GEMINI_TEACHER_MODEL' if config.get('name') == 'gemini' else 'GROQ_TEACHER_MODEL' if config.get('name') == 'groq' else '')
            if override: config['model'] = override
        for config in configs:
            if not os.environ.get(config.get('keyEnv','NEBULA_TEACHER_KEY')):
                key_name = config.get('keyEnv','NEBULA_TEACHER_KEY')
                parser.error('Missing teacher key: ' + (key_name if key_name in ['GEMINI_API_KEY','GROQ_API_KEY','GEMINI_SECOND_API_KEY'] else 'configured environment variable') + '. Set it in this PowerShell window before starting.')
        print(json.dumps({'teacherWorkers':args.workers,'configuredTeachers':len(configs),'maximumDialogueCalls':args.max_teacher_calls,'note':'Workers using the same project share its quota.'}),flush=True)
        try:
            report = collect(configs,rows,pending,args.max_teacher_calls,args.workers)
            print(json.dumps(report),flush=True)
        except KeyboardInterrupt:
            print('Stopped collection. Completed conversations are saved. Rerun to continue.'); return
        if args.collect_only:
            print('Collection check finished. No model training or deployment was started.'); return
        if report['attempts'] and not report['saved']:
            raise SystemExit('No new teacher conversations were saved. Training was not started. Fix the provider errors above, then rerun.')
    inputs = [root/'seed.jsonl', folder/'conversations-seed.jsonl']
    if args.accept_teacher_output and pending.exists():
        accepted = [{**r,'reviewStatus':'approved','approvalMethod':'owner-opt-in-unverified'} for r in read_jsonl(pending)]
        write_jsonl(folder/'conversations-teacher-accepted.jsonl',accepted)
        inputs.append(folder/'conversations-teacher-accepted.jsonl')
    data = folder/'conversations-approved.jsonl'
    count = prepare(inputs,data)
    checkpoint = root/'checkpoints/nebula-conversations.pt'
    # Start this new curriculum from the earlier weights, not the severely overfit run.
    best = checkpoint.with_suffix('.best.pt')
    resume = best if best.exists() else checkpoint if checkpoint.exists() else root/'checkpoints/nebula-practice.pt'
    print(json.dumps({'trainingConversationsAndPairs':count,'steps': 'until Ctrl+C' if args.continuous else args.steps,'resumeWeights':str(resume) if resume.exists() else None,'liveWebsiteChanged':False}),flush=True)
    train(SimpleNamespace(data=data, output=checkpoint, snapshot=None, resume=resume if resume.exists() else None,preset='cpu',steps=args.steps,batch=args.batch,threads=args.threads,seed=42,lr=.0003,continuous=args.continuous,save_every=100,patience=args.patience))

if __name__ == '__main__': main()
