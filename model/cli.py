"""Run `python model/cli.py --help`. Private data lives under ignored model/data/."""
import argparse
import json
from pathlib import Path
from dataflow import read_jsonl, write_jsonl, prepare, generate_teacher, example_id

def main():
    parser = argparse.ArgumentParser(description='Nebula dataset tools: teacher examples -> review -> prepare -> train. Never publish model/data/.')
    commands = parser.add_subparsers(dest='command', required=True)
    teacher = commands.add_parser('teach', help='Generate pending examples using configured APIs; calls may incur provider charges')
    teacher.add_argument('--config', required=True); teacher.add_argument('--prompts', required=True); teacher.add_argument('--output', required=True); teacher.add_argument('--limit', type=int, default=10)
    review = commands.add_parser('review', help='Review one example at a time; no blanket auto-approval')
    review.add_argument('--input', required=True); review.add_argument('--id'); review.add_argument('--decision', choices=['approved', 'rejected'])
    build = commands.add_parser('prepare', help='Combine approved examples; users require a fresh consent snapshot')
    build.add_argument('--inputs', nargs='+', required=True); build.add_argument('--output', required=True); build.add_argument('--snapshot')
    args = parser.parse_args()
    if args.command == 'teach':
        configs = json.loads(Path(args.config).read_text(encoding='utf-8'))
        # One shared request cap for the whole run, even when several teachers are configured.
        remaining = args.limit
        if not 1 <= remaining <= 100: raise ValueError('Limit must be between 1 and 100')
        for index, config in enumerate(configs):
            if remaining <= 0: break
            budget = max(1, (remaining + len(configs) - index - 1) // (len(configs) - index))
            remaining -= generate_teacher(config, read_jsonl(args.prompts), args.output, budget)
        print(json.dumps({'requests': args.limit - remaining, 'status': 'pending review'}))
    elif args.command == 'review':
        rows = read_jsonl(args.input)
        if args.decision and not args.id: raise ValueError('Select a specific example ID')
        found = False
        for row in rows:
            identifier = row.get('id') or example_id(row['messages']); row['id'] = identifier
            if args.id and identifier != args.id: continue
            found = True
            if args.decision: row['reviewStatus'] = args.decision
            print(json.dumps(row, ensure_ascii=False))
        if args.id and not found: raise ValueError('Example not found')
        if args.decision: write_jsonl(args.input, rows)
    else:
        snapshot = json.loads(Path(args.snapshot).read_text(encoding='utf-8')) if args.snapshot else None
        print(json.dumps({'approvedExamples': prepare(args.inputs, args.output, snapshot)}))

if __name__ == '__main__':
    try: main()
    except Exception:
        # Do not print URLs, headers, credentials, provider error bodies, or user examples.
        raise SystemExit('Dataset operation failed. Check configuration, approval status, and private input files.')
