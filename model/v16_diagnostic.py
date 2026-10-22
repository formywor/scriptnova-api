"""V16: test the existing byte-model pipeline before spending more GPU time."""
import hashlib
import json
import math
import random
import time
from collections import Counter
from pathlib import Path

import torch
from torch.nn import functional as F
from nebula import Nebula, Config, BOS, EOS, PAD, encode, load, save
from v13_windows import windows
from v10_train import summed_loss

FORMAT = 'nebula-v16-diagnostic-1'


def emit(**values):
    print(json.dumps(values), flush=True)


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def suite():
    """Original synthetic exercises. Held-out prompts and facts never enter training."""
    def pair(prompt, answer):
        return [{'role': 'user', 'content': prompt}, {'role': 'assistant', 'content': answer}]
    train = [pair('Say hello.', 'Hello!'), pair('What is your name?', 'Nebula'),
             pair('What are you?', 'An AI assistant.'), pair('Say thank you.', 'Thank you!'),
             pair('What is 2 + 2? Answer with only the number.', '4'),
             pair('What is 5 - 2? Answer with only the number.', '3'),
             pair('What is 3 + 4? Answer with only the number.', '7'),
             pair('What is 8 - 3? Answer with only the number.', '5')]
    names = ['Ada', 'Ben', 'Cleo', 'Dara', 'Eli', 'Faye', 'Gus', 'Hana']
    colors = ['red', 'blue', 'green', 'gold', 'pink', 'white', 'black', 'gray']
    for name, color in zip(names, colors):
        profile = f'Name: {name}. Color: {color}. '
        train.extend([pair(profile + 'Give only the name.', name), pair(profile + 'Give only the color.', color)])
    unseen = []
    for name, color in [('Iris', 'purple'), ('Juno', 'orange'), ('Kai', 'silver'), ('Lina', 'brown')]:
        # Reverse field order as well as changing facts.
        context = f'Color: {color}. Name: {name}. '
        unseen.extend([pair(context + 'Give only the name.', name), pair(context + 'Give only the color.', color)])
    unseen += [pair('What is 6 + 3? Answer with only the number.', '9'),
               pair('What is 9 - 2? Answer with only the number.', '7'),
               [{'role': 'user', 'content': 'My scarf is purple.'},
                {'role': 'assistant', 'content': 'Understood.'},
                {'role': 'user', 'content': 'What color is my scarf? Give only the color.'},
                {'role': 'assistant', 'content': 'purple'}],
               [{'role': 'user', 'content': 'My name is Iris.'},
                {'role': 'assistant', 'content': 'Hello, Iris.'},
                {'role': 'user', 'content': 'What is my name? Give only the name.'},
                {'role': 'assistant', 'content': 'Iris'}]]
    opens = [[{'role': 'user', 'content': text}] for text in [
        'Hello! What can you help me with?', 'Why does ice melt?',
        'Write a thank-you note to a neighbor.', 'Which should I choose?']]
    assert not {json.dumps(x[:-1], sort_keys=True) for x in train} & {json.dumps(x[:-1], sort_keys=True) for x in unseen}
    return train, unseen, opens


def training_windows(rows, context):
    result = []
    for messages in rows:
        tokens, learn = encode(messages)
        result.extend(windows(tokens, learn, context))
    return result


def audit():
    """Executable invariants of the same architecture, window maker and SFT loss."""
    torch.manual_seed(16016)
    model = Nebula(Config(width=32, heads=2, layers=1, context=64)).eval()
    checked = []
    def require(condition, label):
        if not condition:
            raise AssertionError('V16_PIPELINE_CHECK_FAILED: ' + label)
        checked.append(label)
    messages = [{'role': 'system', 'content': 'Test rules.'},
                {'role': 'user', 'content': 'Question?'},
                {'role': 'assistant', 'content': 'A long caf\u00e9 answer. ' * 9},
                {'role': 'user', 'content': 'Next?'},
                {'role': 'assistant', 'content': 'Done.'}]
    tokens, learn = encode(messages)
    batches = list(windows(tokens, learn, 64))
    actual = [int(v) for _, y in batches for v in y if v != -100]
    require(actual == [v for v, flag in zip(tokens, learn) if flag], 'every_assistant_byte_and_true_eos_once')
    require(actual.count(EOS) == 2, 'no_fake_eos_at_window_edges')
    require(len(actual) == sum(learn), 'user_and_system_targets_masked')
    for x, y in batches:
        require(len(x) == len(y) and len(x) <= 64, 'window_shapes')
        start = next(i for i in range(len(tokens)) if tokens[i:i + len(x)] == x.tolist())
        require(all(int(v) == -100 or int(v) == tokens[start + i + 1] for i, v in enumerate(y)), 'one_token_target_shift')
    a = torch.tensor([[BOS, 65, 66, 67, 68]])
    b = a.clone(); b[0, 3:] = torch.tensor([90, 91])
    with torch.no_grad():
        require(torch.allclose(model(a)[:, :3], model(b)[:, :3], atol=1e-5), 'future_tokens_cannot_change_past_logits')
        padded = F.pad(a, (0, 4), value=PAD)
        require(torch.allclose(model(a), model(padded)[:, :a.shape[1]], atol=1e-5), 'right_padding_does_not_change_valid_prefix')
        small = training_windows(suite()[0][:2], 64)
        measured, n, count = summed_loss(model, small, torch.device('cpu'), False, torch.float32)
        reference = []
        for x, y in small:
            losses = F.cross_entropy(model(x[None]).reshape(-1, 262), y, ignore_index=-100, reduction='none')
            # These are single assistant-turn windows, so mean target loss is the reference.
            reference.append(losses[y != -100].mean())
        require(torch.allclose(measured / n, torch.stack(reference).mean(), atol=1e-5), 'batched_assistant_loss_matches_independent_reference')
        require(count == sum(int((y != -100).sum()) for _, y in small), 'supervised_token_counter')
    model.train()
    loss, n, _ = summed_loss(model, small, torch.device('cpu'), False, torch.float32)
    (loss / n).backward()
    require(all(p.grad is None or torch.isfinite(p.grad).all() for p in model.parameters()), 'finite_gradients')
    return {'format': FORMAT, 'checks': sorted(set(checked)), 'passed': True,
            'scope': 'Synthetic invariants; passing does not certify the entire historical pipeline.'}


@torch.inference_mode()
def assess(model, rows, opens=()):
    answers = []
    for index, messages in enumerate(rows):
        expected = messages[-1]['content']
        reply = model.reply(messages[:-1], max_tokens=64, temperature=0)
        answers.append({'messages': messages[:-1], 'expected': expected, 'reply': reply,
                        'exactMatch': reply.strip().casefold() == expected.strip().casefold()})
        if (index + 1) % 12 == 0:
            emit(v16EvaluationProgress=index + 1, total=len(rows))
    free = [{'messages': m, 'reply': model.reply(m, max_tokens=120, temperature=0),
             'grade': 'pending-human-review'} for m in opens]
    return {'exactCorrect': sum(a['exactMatch'] for a in answers), 'cases': len(answers),
            'answers': answers, 'openAnswers': free, 'humanVerified': False, 'qualityApproved': False}


def fit(model, rows, output, *, steps=1000, batch=4, lr=.001, seed=16016,
        device='cpu', checkpoint_every=100, checkpoint_callback=None,
        resume=None, max_seconds=3600, stop_score=.9, source_sha='fresh', stop_file=None):
    """Use production SFT loss; deterministic sampling and complete Adam/scaler resume."""
    output = Path(output); device = torch.device(device); model.to(device)
    amp = device.type == 'cuda'
    dtype = torch.float16  # T4-compatible; full precision master weights and scaled gradients.
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=.01)
    scaler = torch.amp.GradScaler('cuda', enabled=amp, init_scale=1024)
    data = training_windows(rows, model.config.context)
    if not data: raise ValueError('No assistant targets')
    signature = {'format': FORMAT, 'config': vars(model.config), 'steps': steps, 'batch': batch,
                 'lr': lr, 'seed': seed, 'precision': 'fp16-amp' if amp else 'fp32',
                 'data': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
                 'sourceSha256': source_sha,
                 'engineSha256': hashlib.sha256(b''.join(Path(__file__).with_name(n).read_bytes()
                    for n in ['v16_diagnostic.py', 'nebula.py', 'v13_windows.py', 'v10_train.py'])).hexdigest()}
    count = inputs = targets = 0; learned = False; last_metadata = None
    if resume:
        stored = torch.load(resume, map_location='cpu', weights_only=True)
        state = stored['trainingState']
        if state['signature'] != signature: raise ValueError('V16_RESUME_CONFIGURATION_CHANGED')
        model.load_state_dict(stored['state']); optimizer.load_state_dict(state['optimizer'])
        scaler.load_state_dict(state['scaler'])
        count = state['updates']; inputs = state['inputPositions']; targets = state['supervisedTokens']
        learned = state.get('memorizationPassed', False)
        last_metadata = stored['metadata']
        emit(v16OptimizerRestored=True, updates=count)
    started = time.monotonic(); failed = 0; report = None
    def checkpoint(reason):
        nonlocal report, learned, last_metadata
        if last_metadata is not None and last_metadata['updates'] == count:
            return last_metadata
        report = assess(model, rows)
        learned = report['exactCorrect'] / report['cases'] >= stop_score
        meta = {'format': FORMAT, 'updates': count, 'inputPositions': inputs,
                'supervisedTokens': targets, 'tokenUnit': 'byte tokens plus structural tokens; repeated exposure included',
                'memorizationPassed': learned, 'memorizationReport': report, 'reason': reason,
                'parameters': sum(p.numel() for p in model.parameters()),
                'experimental': True, 'qualityApproved': False, 'publicWebsiteUpdated': False}
        save(model, output, meta, training_state={'signature': signature, 'optimizer': optimizer.state_dict(),
             'scaler': scaler.state_dict(), 'updates': count, 'inputPositions': inputs,
             'supervisedTokens': targets, 'memorizationPassed': learned})
        emit(v16Checkpoint=str(output), updates=count, exactMemorized=report['exactCorrect'],
             total=report['cases'], inputPositions=inputs, supervisedTokens=targets, reason=reason)
        if checkpoint_callback: checkpoint_callback(output, meta)
        last_metadata = meta
        return meta
    try:
        while count < steps and not learned:
            if stop_file and Path(stop_file).exists(): break
            if time.monotonic() - started >= max_seconds: break
            rng = random.Random(seed + count)
            selected = [rng.choice(data) for _ in range(batch)]
            optimizer.zero_grad(set_to_none=True); model.train()
            # Warm up once per experiment; don't restart warmup at each cloud resume.
            rate = lr * min(1., (count + 1) / 25)
            for group in optimizer.param_groups: group['lr'] = rate
            loss, n, supervised = summed_loss(model, selected, device, amp, dtype)
            objective = loss / n
            if not torch.isfinite(objective): raise ValueError('V16_NONFINITE_LOSS')
            scaler.scale(objective).backward(); scaler.unscale_(optimizer)
            norm = torch.nn.utils.clip_grad_norm_(model.parameters(), 1.)
            if not torch.isfinite(norm):
                failed += 1
                if not amp or failed > 8: raise ValueError('V16_NONFINITE_GRADIENTS')
                scaler.update(new_scale=scaler.get_scale() / 2); continue
            failed = 0; scaler.step(optimizer); scaler.update(); count += 1
            inputs += sum(len(x) for x, _ in selected); targets += supervised
            if count % 25 == 0:
                emit(v16Update=count, budget=steps, loss=round(float(objective.detach()), 4),
                     supervisedTokens=targets, learningRate=rate)
            if count % checkpoint_every == 0: checkpoint('periodic')
    except KeyboardInterrupt:
        checkpoint('interrupted'); raise
    return checkpoint('memorization-threshold' if learned else 'budget-or-time-limit')
