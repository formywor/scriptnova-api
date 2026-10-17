"""Inspect a local checkpoint without teacher calls or deployment."""
import argparse
import json
import sys
from pathlib import Path

runtime = Path(__file__).resolve().parents[4] / 'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir(): sys.path.insert(0, str(runtime))
import torch
from nebula import load
from rules import with_owner_rules

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint', default=str(Path(__file__).resolve().parent/'checkpoints/nebula-continuous.pt'))
    args = parser.parse_args()
    torch.set_num_threads(2)
    model, metadata = load(args.checkpoint)
    print(json.dumps({'checkpoint': args.checkpoint, 'trainingSteps': metadata.get('steps'), 'validationLoss': metadata.get('validationLoss'), 'experimental': True}), flush=True)
    for prompt in ['hi', 'What is your name?', 'What is 2 + 2?', 'What is 7 + 8?', 'Explain gravity simply.', 'Can you help me write an email?', 'My name is Sam. What is my name?', 'Why is the sky blue?', 'Tell me a short story.', 'How do I boil an egg?']:
        torch.manual_seed(42)
        reply = model.reply(with_owner_rules([{'role': 'user', 'content': prompt}]), max_tokens=120, temperature=.7)
        print(json.dumps({'prompt': prompt, 'reply': reply}, ensure_ascii=True), flush=True)

if __name__ == '__main__': main()
