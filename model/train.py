import argparse
import hashlib
import json
import random
import time
import itertools
from pathlib import Path
import torch
from torch.nn import functional as F
from nebula import Config, Nebula, PAD, encode, load, save
from dataflow import read_jsonl, eligible
from rules import with_owner_rules

def examples(rows, context, include_owner_rules=False):
    result = []
    for row in rows:
        tokens, learn = encode(with_owner_rules(row['messages']) if include_owner_rules else row['messages'])
        if len(tokens) > context + 1: continue
        x = torch.tensor(tokens[:-1]); y = torch.tensor([v if mask else -100 for v, mask in zip(tokens[1:], learn[1:])])
        if (y != -100).any(): result.append((x, y))
    return result

def loss(model, batch):
    length = max(len(x) for x, _ in batch)
    x = torch.full((len(batch), length), PAD, dtype=torch.long); y = torch.full_like(x, -100)
    for i, (a, b) in enumerate(batch): x[i, :len(a)] = a; y[i, :len(b)] = b
    return F.cross_entropy(model(x).reshape(-1, 262), y.reshape(-1), ignore_index=-100)

def evaluate_loss(model, data, batch_size):
    total = tokens = 0
    for offset in range(0, len(data), batch_size):
        batch = data[offset:offset+batch_size]
        count = sum(int((y != -100).sum()) for _, y in batch)
        total += float(loss(model, batch)) * count; tokens += count
    return total / tokens if tokens else None

def train(args):
    if args.steps < 1 or args.batch < 1 or args.threads < 1: raise ValueError('Positive steps, batch and threads required')
    continuous = getattr(args, 'continuous', False)
    save_every = getattr(args, 'save_every', 100)
    patience = getattr(args, 'patience', 0)
    if patience < 0: raise ValueError('Patience must be zero or positive')
    if save_every < 1: raise ValueError('Save interval must be positive')
    torch.set_num_threads(args.threads); torch.manual_seed(args.seed); rng = random.Random(args.seed)
    rows = read_jsonl(args.data)
    snapshot = json.loads(Path(args.snapshot).read_text(encoding='utf-8')) if args.snapshot else None
    if any(row.get('source', {}).get('kind') == 'user' for row in rows):
        if continuous: raise ValueError('Continuous runs require seed/teacher data; user consent must be refreshed between bounded runs')
        if not snapshot or not 0 <= time.time() * 1000 - snapshot.get('createdAt', 0) < 300000:
            raise ValueError('User examples require a fresh consent check. Use scripts/model-data.mjs train.')
    # User records always require a fresh Firebase consent snapshot supplied by the wrapper.
    rows = [row for row in rows if eligible(row, snapshot)]
    model = load(args.resume)[0] if args.resume else Nebula(Config(width=64, heads=2, layers=1, context=256) if args.preset == 'smoke' else Config())
    data = examples(rows, model.config.context, include_owner_rules=True)
    if not data: raise ValueError('No approved examples fit the model context')
    rng.shuffle(data); split = max(1, int(len(data) * .9)); training, validation = data[:split], data[split:]
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=.01)
    with torch.no_grad(): initial = float(loss(model, training[:args.batch]))
    completed = 0
    data_hash = hashlib.sha256(Path(args.data).read_bytes()).hexdigest()
    best_path = Path(args.output).with_suffix('.best.pt')
    best_validation = float('inf')
    stale_checks = 0
    if best_path.exists():
        _, previous = load(best_path)
        if previous.get('dataSha256') == data_hash and previous.get('seed') == args.seed:
            previous_loss = previous.get('validationLoss')
            if isinstance(previous_loss, (int, float)): best_validation = previous_loss
    def checkpoint(stopped=False):
        nonlocal best_validation, stale_checks
        model.eval()
        with torch.no_grad():
            current = float(loss(model, training[:args.batch]))
            validation_loss = evaluate_loss(model, validation, args.batch)
        report = {'parameters': sum(p.numel() for p in model.parameters()), 'steps': completed, 'trainingExamples': len(training), 'validationExamples': len(validation), 'skippedExamples': len(rows) - len(data), 'initialLoss': initial, 'finalLoss': current, 'validationLoss': validation_loss, 'seed': args.seed, 'dataSha256': data_hash, 'experimental': True, 'qualityApproved': False, 'stopped': stopped}
        save(model, args.output, report)
        if validation_loss is not None and validation_loss < best_validation:
            best_validation = validation_loss
            stale_checks = 0
            save(model, best_path, report)
            print(json.dumps({'bestCheckpoint': str(best_path), 'validationLoss': best_validation}), flush=True)
        elif validation_loss is not None:
            stale_checks += 1
            if validation_loss > best_validation * 1.2:
                print('Validation loss is worsening: this run is overfitting. More varied data is needed; Ctrl+C saves and stops.', flush=True)
        print(json.dumps({'checkpoint': str(args.output), **report}), flush=True)
    # Save even before the first update, then periodically and on Ctrl+C.
    checkpoint()
    try:
        for step in itertools.count() if continuous else range(args.steps):
            model.train(); batch = [training[rng.randrange(len(training))] for _ in range(args.batch)]
            optimizer.zero_grad(set_to_none=True); value = loss(model, batch); value.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); optimizer.step()
            completed = step + 1
            if step == 0 or completed % 25 == 0: print(json.dumps({'step': completed, 'loss': round(float(value.detach()), 4)}), flush=True)
            if completed % save_every == 0:
                checkpoint()
                if patience and stale_checks >= patience:
                    print(json.dumps({'stopped':'validation_not_improving','steps':completed,'bestCheckpoint':str(best_path),'note':'Latest weights and best validation weights are saved. Live website unchanged.'}),flush=True)
                    return {'steps':completed,'stopped':True,'reason':'validation_not_improving'}
    except KeyboardInterrupt:
        checkpoint(stopped=True)
        print('Stopped. Latest weights saved; the live website was not changed.', flush=True)
        return {'steps': completed, 'stopped': True}
    checkpoint()
    model.eval()
    with torch.no_grad(): final = float(loss(model, training[:args.batch])); heldout = evaluate_loss(model, validation, args.batch)
    report = {'parameters': sum(p.numel() for p in model.parameters()), 'steps': completed, 'trainingExamples': len(training), 'validationExamples': len(validation), 'skippedExamples': len(rows) - len(data), 'initialLoss': initial, 'finalLoss': final, 'validationLoss': heldout, 'seed': args.seed, 'dataSha256': hashlib.sha256(Path(args.data).read_bytes()).hexdigest(), 'exampleIds': [r.get('id', '') for r in rows], 'experimental': True, 'qualityApproved': False}
    save(model, args.output, report); print(json.dumps(report), flush=True)
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train owned Nebula weights from scratch. CPU preset is experimental, not production quality.')
    parser.add_argument('--continuous', action='store_true'); parser.add_argument('--save-every', type=int, default=100)
    parser.add_argument('--patience', type=int, default=0, help='Stop after this many validation checks without improvement; 0 disables')
    parser.add_argument('--data', required=True); parser.add_argument('--output', required=True); parser.add_argument('--snapshot'); parser.add_argument('--resume'); parser.add_argument('--preset', choices=['cpu', 'smoke'], default='cpu'); parser.add_argument('--steps', type=int, default=500); parser.add_argument('--batch', type=int, default=4); parser.add_argument('--threads', type=int, default=2); parser.add_argument('--seed', type=int, default=42); parser.add_argument('--lr', type=float, default=.0005)
    train(parser.parse_args())
