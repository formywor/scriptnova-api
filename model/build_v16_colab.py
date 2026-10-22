"""Build a self-contained Colab learning-diagnostic notebook from current source."""
import ast
import json
from pathlib import Path


def build():
    root = Path(__file__).resolve().parent
    old = json.loads((root / 'Nebula_Colab_V15_Full_Chats.ipynb').read_text(encoding='utf-8'))
    old_run = next(''.join(c['source']) for c in old['cells'] if c['cell_type'] == 'code' and ''.join(c['source']).startswith('sources='))
    names = ast.literal_eval(ast.parse(old_run).body[0].value).keys()
    sources = {name: (root.parent / name).read_text(encoding='utf-8') for name in names}
    for name in ['v16_diagnostic.py', 'v16_experiment.py']:
        sources['model/' + name] = (root / name).read_text(encoding='utf-8')
    intro = '''# Nebula V16 — prove the learning pipeline

Select **Runtime > Change runtime type > T4 GPU**. Add your existing **NEBULA_HF_TOKEN** in Colab Secrets (key icon) and enable notebook access. Stop other training workers, then **Run all**. No Gemini/Groq keys, Drive mount or local-data upload is needed. No website/API upload is needed to run this notebook.

This is a bounded diagnostic, not another promise that a larger dataset will fix Nebula. It uses 24 original synthetic training exercises and 12 separate exact-answer tests (including multi-turn context), plus 4 open questions for human inspection. Test answers never enter training. Exact-match grading is intentionally strict; open answers remain ungraded. Memorizing examples does not establish generalization or public readiness.

1. Audit the existing causal Transformer, rolling assistant-only windows, next-token alignment, EOS boundaries, causal/padding behavior, finite gradients and production SFT loss against a reference calculation.
2. Start a small fresh model on the exercises, up to 1,000 updates. If it cannot achieve 90% exact memorization, stop before spending time on the old 100M model.
3. If it passes, copy V15's completed **fullWeights** snapshot into this new private experiment and test it on the same exercises, up to 500 updates. It is a diagnostic adaptation with a fresh optimizer, not a public release. Older weights, tokenizer, reports and data are preserved. The synthetic curriculum isolates the core chat serialization without adding owner-rule text; it does not measure production rule-following.

The tiny model deliberately uses a higher learning rate to test learning capacity. The old 100M copy uses 0.0001. These are diagnostic settings, not a recommendation for future full-corpus training. FP16 mixed precision uses FP32 model weights, gradient scaling and clipping on the T4. Input-position and supervised-token counts include repeated exposure and special tokens, exclude validation, and begin at zero for V16; they are not historical lifetime counts.

Local resumable model/Adam/scaler checkpoints and private Hugging Face backups are written every 100 updates and at a graceful stop. Large 100M checkpoints include Adam state and may take minutes to upload; transfer is not learning. Wait for **v16CloudBackupConfirmed** before closing the runtime. Colab termination can still lose work since the last confirmed backup. No free unlimited GPU access is implied. Session budget defaults to two hours, plus an in-progress evaluation/upload. Run all resumes the same budget; it does not train forever. Do not refresh while trying to interrupt.

Backups are under `experiments/nebula-v16-diagnostics/` in your existing private repository. The final reports separate training-example memorization from unseen-question performance. Inspect the actual replies. Nothing is promoted to the public site, regardless of scores.
'''
    setup = '''import os, sys, subprocess
from pathlib import Path
from google.colab import userdata
subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', 'huggingface_hub>=0.34,<2', 'requests>=2.32,<3'], check=True)
try:
    token = userdata.get('NEBULA_HF_TOKEN')
except Exception:
    raise RuntimeError('Add NEBULA_HF_TOKEN in Colab Secrets and enable notebook access.') from None
if not token or not token.strip():
    raise RuntimeError('NEBULA_HF_TOKEN is empty.')
os.environ['NEBULA_HF_TOKEN'] = token
os.environ['HF_TOKEN'] = token
os.environ['NEBULA_HF_REPO'] = 'iiidevv/nebula-research'
project = Path('/content/nebula-v16-diagnostics/api')
project.mkdir(parents=True, exist_ok=True)
HOURS = 2
'''
    run = 'sources=' + repr(sources) + '''
for name, content in sources.items():
    target = project / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')
sys.path.insert(0, str(project / 'model'))
for name in sources:
    if name.endswith('.py'):
        sys.modules.pop(Path(name).stem, None)
from v16_experiment import main
main(project, hours=HOURS)
'''
    ending = '''## Pause, resume and read results

Use Colab's stop button for a graceful interruption. If the process has time to handle it, it saves and uploads the current completed update. Wait for backup confirmation. For an orderly stop from another cell, create `/content/nebula-v16-diagnostics/api/STOP`; remove that file before resuming.

Run all reconnects to the confirmed private snapshot with the same optimizer/scaler state and counters. If you change settings or code, resume rejects incompatible configurations rather than silently reusing state. A finished run prints its summary without extending training. Backup failures stop the run; do not start a second worker.

Inspect `reports/pipeline-audit.json`, `reports/tiny-final.json`, `reports/current-baseline.json`, `reports/current-final.json`, and `reports/summary.json` in the private V16 experiment. Current-model reports appear only if the tiny control passed and that phase ran. A successful pipeline audit alone does not certify the entire historical pipeline. Improvements on 24 memorized exercises are not proof that Nebula can chat.
'''
    cells = []
    for i, (kind, source) in enumerate([('markdown', intro), ('code', setup), ('code', run), ('markdown', ending)]):
        cell = {'id': f'v16-{i:02d}', 'cell_type': kind, 'metadata': {}, 'source': source.splitlines(True)}
        if kind == 'code':
            ast.parse(source); cell.update(execution_count=None, outputs=[])
        cells.append(cell)
    for name, source in sources.items():
        if name.endswith('.py'): ast.parse(source)
    value = {'nbformat': 4, 'nbformat_minor': 5, 'metadata': {'accelerator': 'GPU',
             'colab': {'name': 'Nebula_Colab_V16_Diagnostics.ipynb'},
             'kernelspec': {'display_name': 'Python 3', 'language': 'python', 'name': 'python3'}}, 'cells': cells}
    target = root / 'Nebula_Colab_V16_Diagnostics.ipynb'
    target.write_text(json.dumps(value, indent=1), encoding='utf-8')
    return target


if __name__ == '__main__': print(build())
