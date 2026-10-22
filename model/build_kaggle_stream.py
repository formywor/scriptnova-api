"""Build the Kaggle entry point around the unchanged V18 RAM-only engine."""
import ast
import json
from pathlib import Path

from build_v18_stream import build as build_portable


def build():
    notebook = json.loads(build_portable().read_text(encoding='utf-8'))
    notebook['cells'][0]['source'] = '''# Nebula — Kaggle raw-data training

1. Import this notebook into Kaggle. Turn **Internet on**.
2. Under **Add-ons → Secrets**, add and enable `NEBULA_HF_TOKEN` with your Hugging Face write token.
3. Enable a supported NVIDIA GPU and select **Run all**. The notebook checks CUDA before starting automatic preparation/training.

Default ACTION is `prepare_and_train`: acquire up to **1 GB of unique raw UTF-8 text**, then train the existing ~100M Nebula model.
Mix: 50% FineWeb-Edu, 25% Cosmopedia v2, 15% TinyStories, 10% Cosmopedia synthetic textbook-style text.
No teacher API calls are required. Data uses whole-document validation splits, exact deduplication and basic filters;
it is not fully fact-checked. More text is an experiment, not a promise of conversational ability.

**Saves:** https://huggingface.co/iiidevv/nebula-raw-training (PUBLIC).
Datasets, model/optimizer checkpoints and reports stay in RAM and upload directly to Hugging Face.
Only notebook/code/packages use local disk. No local data/checkpoint fallback, Google Drive, ZIP or token file.
Use a token that can create/write this repository and read the source `iiidevv/nebula-research`.
Original model files remain preserved; source is V17 `current-foundationWeights`, before narrow context drills.
No website deployment or automatic public-model update is enabled.

**Resume:** import this same notebook and Run all with identical RUN_NAME and CONFIG.
The last confirmed remote data cursor, model, optimizer and scaler are restored. Do not run duplicate workers.
Changing data size, learning rate or training budget requires a new RUN_NAME.
The default session is **5 hours total**, including preparation, with some possible overrun for uploads/evaluation.
If preparation uses the session budget, run again to continue; training begins once preparation completes.
Set ACTION to `prepare` to prepare with the accelerator off and preserve GPU quota; switch back afterward.
`benchmark` and `evaluate` are also available. This runner uses **one GPU** even if Kaggle allocates two T4s.

Training saves every 500 updates and on a graceful interrupt. Wait for `v18PublicBackupConfirmed` before closing.
An abrupt runtime shutdown loses RAM progress since the last confirmed backup. Public history retains old snapshots.
16 GB or more system RAM is recommended. GPU quotas still apply; preparation/network waits can consume allocated GPU time.
'''.splitlines(True)
    setup = ''.join(notebook['cells'][1]['source'])
    start = setup.index("token=os.environ.get")
    setup = setup[:start] + '''token=os.environ.get('NEBULA_HF_TOKEN') or os.environ.get('HF_TOKEN')
if not token:
    try:
        from kaggle_secrets import UserSecretsClient
        token=UserSecretsClient().get_secret('NEBULA_HF_TOKEN')
    except Exception:
        raise RuntimeError('Add and enable Kaggle secret NEBULA_HF_TOKEN, then Run all again.') from None
if not token or not token.strip():
    raise RuntimeError('Kaggle secret NEBULA_HF_TOKEN is empty.')
os.environ['NEBULA_HF_TOKEN']=token.strip()
del token
'''
    setup = setup.replace('import os, sys, subprocess, getpass', 'import os, sys, subprocess')
    notebook['cells'][1]['source'] = setup.splitlines(True)
    config = ''.join(notebook['cells'][2]['source'])
    config = config.replace("ACTION = 'prepare'", "ACTION = 'prepare_and_train'").replace('SESSION_HOURS = 2', 'SESSION_HOURS = 5')
    notebook['cells'][2]['source'] = config.splitlines(True)
    execute = ''.join(notebook['cells'][3]['source'])
    execute = execute.replace("    result=run(OUTPUT_REPO,RUN_NAME,CONFIG,ACTION,SESSION_HOURS)", '''    import time, torch
    if ACTION == 'prepare_and_train':
        if not torch.cuda.is_available():
            raise RuntimeError('Enable a Kaggle NVIDIA GPU, or use ACTION=prepare with the accelerator off.')
        print({'GPU':torch.cuda.get_device_name(0),'availableGPUs':torch.cuda.device_count(),
               'trainingGPUs':1,'publicWebsiteUpdated':False},flush=True)
        session_start=time.monotonic()
        result=run(OUTPUT_REPO,RUN_NAME,CONFIG,'prepare',SESSION_HOURS)
        remaining=SESSION_HOURS-(time.monotonic()-session_start)/3600
        if result.get('corpusComplete') and remaining > 0.01:
            result=run(OUTPUT_REPO,RUN_NAME,CONFIG,'train',remaining)
        else:
            print({'sessionFinished':True,'preparationComplete':result.get('corpusComplete',False),
                   'nextAction':'Run all again with the same settings to continue.'},flush=True)
    else:
        result=run(OUTPUT_REPO,RUN_NAME,CONFIG,ACTION,SESSION_HOURS)''')
    notebook['cells'][3]['source'] = execute.splitlines(True)
    for cell in notebook['cells']:
        if cell['cell_type'] == 'code':
            ast.parse(''.join(cell['source']))
            assert cell['outputs'] == [] and cell['execution_count'] is None
    # Kaggle GPU/Internet choices remain explicit settings in the imported notebook UI.
    path=Path(__file__).parent/'Nebula_Kaggle_Raw_Training.ipynb'
    path.write_text(json.dumps(notebook,indent=1),encoding='utf-8')
    return path


if __name__ == '__main__':
    print(build())
