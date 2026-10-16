"""Export owned Nebula weights for the dependency-free Node inference runtime."""
import argparse
import base64
import json
from dataclasses import asdict
from pathlib import Path
import torch
from nebula import load, pack_prompt
from rules import with_owner_rules

def export(checkpoint, output, reference=None):
    torch.set_num_threads(1)
    model, metadata = load(checkpoint)
    weights = {}
    for name, tensor in model.state_dict().items():
        if name == 'output.weight': continue  # tied to token.weight
        weights[name] = {'shape': list(tensor.shape), 'data': base64.b64encode(tensor.detach().float().contiguous().numpy().astype('<f4').tobytes()).decode()}
    artifact = {'format': 1, 'config': asdict(model.config), 'weights': weights, 'metadata': {'experimental': True, 'parameters': sum(p.numel() for p in model.parameters()), 'trainingSteps': metadata.get('steps', 0)}}
    path = Path(output); path.parent.mkdir(parents=True, exist_ok=True); temporary = path.with_suffix('.tmp'); temporary.write_text(json.dumps(artifact, separators=(',', ':')), encoding='utf-8'); temporary.replace(path)
    if reference:
        messages = with_owner_rules([{'role': 'user', 'content': 'What is your name?'}]); tokens = pack_prompt(messages, model.config.context)
        with torch.no_grad(): logits = model(torch.tensor([tokens]))[0, -1].tolist()
        Path(reference).write_text(json.dumps({'messages': messages, 'tokens': tokens, 'logits': logits}), encoding='utf-8')
    print(json.dumps({'parameters': artifact['metadata']['parameters'], 'bytes': path.stat().st_size, 'experimental': True}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--checkpoint', required=True); parser.add_argument('--output', required=True); parser.add_argument('--reference'); args = parser.parse_args()
    export(args.checkpoint, args.output, args.reference)
