"""Private, isolated Colab diagnostics. No teacher calls, user data or deployment."""
import gc
import hashlib
import json
import os
import time
from pathlib import Path
import torch
from nebula import Nebula, Config, load
from v10_store import Store
from v16_diagnostic import FORMAT, suite, audit, assess, fit, atomic_json, emit

RUN = 'nebula-v16-diagnostics'
DEFAULT_PLAN = {'tinySteps': 1000, 'currentSteps': 500, 'batch': 4,
                'tinyLr': .001, 'currentLr': .0001, 'seed': 16016,
                'checkpointEvery': 100, 'memorizationThreshold': .9}


def main(project, hours=2, plan=None):
    if not 0 < hours <= 8: raise ValueError('Choose a session between zero and eight hours')
    if not torch.cuda.is_available():
        raise RuntimeError('Select Runtime > Change runtime type > T4 GPU, then Run all. No training started.')
    project = Path(project); project.mkdir(parents=True, exist_ok=True)
    torch.set_num_threads(2)
    deadline = time.monotonic() + hours * 3600
    plan = dict(DEFAULT_PLAN if plan is None else plan)
    store = Store(os.environ.get('NEBULA_HF_REPO', 'iiidevv/nebula-research'),
                  os.environ['NEBULA_HF_TOKEN'], RUN)
    state = store.state()
    if state and (state.get('format') != FORMAT or state.get('plan') != plan):
        raise ValueError('V16 settings changed: preserve this experiment and use a new run name.')
    # Compile/audit before acquiring a large model or starting training.
    checks = audit(); atomic_json(project / 'pipeline-audit.json', checks)
    emit(v16PipelineAudit=checks)
    train, heldout, opens = suite()
    atomic_json(project / 'synthetic-exercises.json', {'training': train, 'heldout': heldout, 'open': opens})
    if state is None:
        state = store.publish({'format': FORMAT, 'plan': plan, 'phase': 'tiny',
                 'publicAutoUpdate': False, 'qualityApproved': False, 'sourceRun': 'nebula-v15-full-chats'},
                 {'audit': (project / 'pipeline-audit.json', 'reports/pipeline-audit.json'),
                  'exercises': (project / 'synthetic-exercises.json', 'data/synthetic-exercises.json')}, project)
    if state['phase'] in ['complete', 'tiny-needs-investigation']:
        report = store.download(state['summary'], project / 'summary.json')
        print(report.read_text(encoding='utf-8'), flush=True)
        emit(v16AlreadyFinished=True, instructions='Inspect the summary and answer reports. Run all does not extend the budget.')
        return

    def backup(phase):
        def callback(path, metadata):
            nonlocal state
            manifest = {k: v for k, v in metadata.items() if k != 'memorizationReport'}
            atomic_json(project / (phase + '-training.json'), metadata)
            state = store.publish({**state, phase + 'Progress': manifest},
                    {phase + 'Working': (path, phase + '-working.pt'),
                     phase + 'Report': (project / (phase + '-training.json'), 'reports/' + phase + '-training.json')}, project)
            emit(v16CloudBackupConfirmed=True, phase=phase, updates=metadata['updates'], publicWebsiteUpdated=False)
        return callback

    for phase in ['tiny', 'current']:
        if state['phase'] != phase: continue
        if (project / 'STOP').exists() or time.monotonic() >= deadline:
            emit(v16Paused=True, phase=phase, instructions='Remove STOP if present and Run all to resume.'); return
        resume = store.download(state[phase + 'Working'], project / (phase + '-working.pt')) if state.get(phase + 'Working') else None
        if phase == 'tiny':
            torch.manual_seed(plan['seed'])
            model = Nebula(Config(width=128, heads=4, layers=2, context=256))
            source_sha = 'random-initialization-seed-' + str(plan['seed'])
        else:
            if not state.get('protectedSource'):
                previous = Store(store.repo, store.token, 'nebula-v15-full-chats')
                old = previous.state()
                if not old or not old.get('fullWeights'):
                    raise RuntimeError('V16 needs the completed V15 fullWeights snapshot. Older checkpoints remain untouched.')
                source = previous.download(old['fullWeights'], project / 'protected-v15-source.pt')
                state = store.publish({**state, 'sourceRevision': previous.revision,
                      'sourceSha256': old['fullWeights']['sha256'], 'sourceKey': 'fullWeights'},
                      {'protectedSource': (source, 'protected-v15-source.pt')}, project)
            else:
                source = store.download(state['protectedSource'], project / 'protected-v15-source.pt')
            model, _ = load(resume or source)
            source_sha = state['sourceSha256']
        model.to('cuda')
        emit(v16Phase=phase, parameters=sum(p.numel() for p in model.parameters()),
             context=model.config.context, GPU=torch.cuda.get_device_name(0),
             trainingExamples=len(train), heldoutExamples=len(heldout), precision='fp16-amp',
             publicWebsiteUpdated=False)
        if not state.get(phase + 'Baseline'):
            baseline = {'memorization': assess(model, train), 'generalization': assess(model, heldout, opens)}
            atomic_json(project / (phase + '-baseline.json'), baseline)
            state = store.publish(state, {phase + 'Baseline': (project / (phase + '-baseline.json'), 'reports/' + phase + '-baseline.json')}, project)
        try:
            metadata = fit(model, train, project / (phase + '-working.pt'),
                steps=plan[phase + 'Steps'], batch=plan['batch'], lr=plan[phase + 'Lr'],
                seed=plan['seed'], device='cuda', checkpoint_every=plan['checkpointEvery'],
                checkpoint_callback=backup(phase), resume=resume,
                max_seconds=max(1, deadline - time.monotonic()), stop_score=plan['memorizationThreshold'],
                source_sha=source_sha, stop_file=project / 'STOP')
        except KeyboardInterrupt:
            emit(v16Paused=True, instructions='Last completed checkpoint was backed up if CloudBackupConfirmed appeared. Run all resumes.'); return
        final = {'memorization': metadata['memorizationReport'], 'generalization': assess(model, heldout, opens),
                 'important': 'Memorization is a pipeline diagnostic, not proof of intelligence. Held-out and open answers never train the model.'}
        atomic_json(project / (phase + '-final.json'), final)
        state = store.publish(state, {phase + 'Final': (project / (phase + '-final.json'), 'reports/' + phase + '-final.json')}, project)
        del model; gc.collect(); torch.cuda.empty_cache()
        if not metadata['memorizationPassed'] and metadata['updates'] < plan[phase + 'Steps']:
            emit(v16Paused=True, phase=phase, resumeAvailable=True); return
        if phase == 'tiny' and not metadata['memorizationPassed']:
            state['phase'] = 'tiny-needs-investigation'
        elif phase == 'tiny':
            state = store.publish({**state, 'phase': 'current'}, {}, project); continue
        else:
            state['phase'] = 'complete'
        summary = {'format': FORMAT, 'phase': state['phase'], 'pipelineAuditPassed': True,
                   'tinyMemorizationPassed': state.get('tinyProgress', {}).get('memorizationPassed', False),
                   'currentMemorizationPassed': state.get('currentProgress', {}).get('memorizationPassed', False),
                   'interpretation': 'If tiny fails, investigate optimization/pipeline before scaling data. If tiny passes but current fails, investigate the old checkpoint and adaptation. If memorization passes but held-out answers fail, generalization remains unresolved.',
                   'publicWebsiteUpdated': False, 'qualityApproved': False,
                   'nextStep': 'Inspect baseline/final answer reports before selecting another training experiment.'}
        atomic_json(project / 'summary.json', summary)
        state = store.publish(state, {'summary': (project / 'summary.json', 'reports/summary.json')}, project)
        emit(v16Finished=summary, checkpointBackupConfirmed=True)
        return
