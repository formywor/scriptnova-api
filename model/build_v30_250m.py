"""Build a bounded cleaned-foundation experiment while preserving prior runs."""
import ast
import json
from pathlib import Path
from v30_250m_train import DEFAULT

INTRO="# Nebula V30 - 250M depth expansion (248,067,072 parameters)\n\nEnable Kaggle **Internet**, **GPU** and secret **NEBULA_HF_TOKEN**, then **Run all**.\nOne GPU is used, with microbatch 1, activation checkpointing and FP16 AMP on T4.\nThe full-sized model has not been GPU-tested here; runtime checks remain enabled.\n\n## Your V29 stop and saved work\n\nV29 successfully prepared **95,934,244 training tokens** and **2,010,886 validation\ntokens**. It accepted 103,256 train documents and 2,116 validation documents.\nIt stopped before optimizer updates when FP32 train/eval logits differed by 0.0471.\nCausal masking and prefix checks passed. This does not prove the cause of its\npoor generations or distinguish a kernel numerical difference from a deeper bug.\nThe old v18 backup log's zero fields were irrelevant defaults, not lost data.\n\nV30 reuses that completed cleaned corpus at immutable revision\n**6eec7e5076a6e1c29d8055395179c397287094f8**, run **nebula-v29-clean-foundation**.\nNo downloading/recleaning the original corpus. Its tokenizer and configuration\nare checked before copying the prepared token objects into the new run's namespace.\nAll old runs remain untouched. Public Hugging Face may deduplicate identical\nobject content; upload progress still does not confirm the manifest commit.\n\n## Bigger, while retaining existing learning\n\nStart with V28's confirmed final weights (30,000 foundation updates), immutable\nrevision **9cfc225eae2fefe1fee5e01d77690487172d6dce**. Keep the exact tokenizer,\n8,192 vocabulary, 768 width, 12 heads and 1,024-token context. Expand 13 to **34 layers**,\nfor exactly **248,067,072 trainable parameters**, rounded to 250M.\n\nEvery old layer, embedding, output and normalization weight is retained. Added\nlayers start with zero attention/feedforward residual outputs, so they initially\nact as identity functions; their residual output weights then learn by gradients.\nThis preserves the parent's mathematical initial function, not bitwise equality\nacross GPU kernels. No pretrained substitution, averaging, random restart of the\nold weights, or claim that new capacity already knows anything. The extra layers\ncan improve or hurt learning; they need training, and training will be slower.\n\n## One attention implementation and a real audit\n\nUse explicit causal scaled-dot-product attention for both training and evaluation,\nwith no separate eval-only TransformerEncoder/MHA fast path. Keep parameter names\ncompatible for weight transfer. Do not simply loosen the failed V29 threshold.\nBefore any optimizer updates, check train/eval agreement, future masking, prefix\nconsistency and finite logits on the actual device. The training comparison uses\ngradient-enabled execution. If it fails, retry with the explicit math attention backend at unchanged tolerances;\nretain both reports. If that also fails, save the report and stop. A successful\nmath fallback is retained on resume and can be slower. Small CPU\nsoftware checks do not establish that this passes on your GPU.\n\n## Training plan\n\nBudget **10,000 updates**, up to **81.92M additional supervised token positions**,\nacross resumable sessions. Fresh AdamW for the expansion, betas 0.9/0.95, matrix\nweight decay 0.1 and vector decay 0, gradient clipping 1.0. Learning rate **3e-5**,\n100-update warmup then held constant for this bounded continuation. Own resumes\nrestore optimizer, scaler and RNG. The parent optimizer is intentionally discarded.\nGradient checkpointing saves activation memory at the cost of extra computation.\n\nBaseline/every 1,000 updates/final checks use the same cleaned validation set,\nper-source losses and both greedy and sampled continuations. No penalties hide\nrepetition. These are development probes, not independent quality certification.\nCompare the new baseline and later reports; old uncleaned validation losses use a\ndifferent set. Lower loss alone is not proof of meaningful conversation.\n\nFoundation only by default. Conversation SFT remains a separate manual stage after\ncompletion and inspection. No teacher calls or user chats. No automatic promotion\nor website update. This version does not implement automatic self-correction;\nunchecked model guesses must not become trusted training labels.\n\n## Time, backups and storage\n\nDefault **SESSION_HOURS=6.5**, with **10 minutes reserved** for saving. Set it below\nyour remaining quota. Quota cannot be detected automatically. Each resumed session\ngets a new elapsed-time budget; preparation/downloads count toward it.\nSave every **100 updates or five minutes**, plus graceful stop/time pause. A full\nAdamW checkpoint is roughly **3 GB**, so uploads may take a while. The RAM-only\nstore supports these larger multipart checkpoints and verifies the manifest.\nWait for **v30CheckpointConfirmed** before closing. Sudden shutdowns or network\nstalls can still lose progress after the latest confirmed backup. Failed saves\nstop updates. Do not run two workers writing the same output run.\n\nKeep RUN_NAME, CONFIG and code unchanged to resume. Change output run for changed\nsettings. All training artifacts stay in **RAM -> PUBLIC Hugging Face**\n**iiidevv/nebula-raw-training**, **experiments/nebula-v30-250m/**. No local corpus,\nmodel/report fallback, Drive or ZIP. Code/packages/notebooks can use disk.\nPREPARE_ONLY=True can copy the prepared corpus on CPU before enabling GPU and\nsetting it back to False. Training starts only when this notebook is executed.\n"

def build():
    root=Path(__file__).parent
    old=json.loads((root/'Nebula_Kaggle_V28_Longrun.ipynb').read_text(encoding='utf-8'))
    sources=ast.literal_eval(ast.parse(''.join(old['cells'][3]['source'])).body[0].value)
    for name in ['v28_longrun.py','v28_foundation_data.py']:sources.pop(name)
    for name in ['v30_250m_train.py','v30_expanded_model.py','v30_store.py','v30_device_audit.py','v29_clean_data.py','v29_clean_text.py']:
        sources[name]=(root/name).read_text(encoding='utf-8')
    setup=''.join(old['cells'][1]['source']).replace('nebula-v28-tokenizer-packages','nebula-v30-isolated-packages')
    setup=setup.replace("'tokenizers==0.22.2'", "'tokenizers==0.22.2','ftfy==6.3.1','wcwidth==0.2.13'")
    config="RUN_NAME='nebula-v30-250m'\nRUN_STAGE='foundation'\nSESSION_HOURS=6.5\nRESERVE_MINUTES=10.0\nPREPARE_ONLY=False\nCONFIG="+repr(DEFAULT)+'\n'
    execute='sources='+repr(sources)+'''
import importlib
code_root=Path.cwd()/'nebula-v30-250m-code'
code_root.mkdir(exist_ok=True)
for name,source in sources.items():(code_root/name).write_text(source,encoding='utf-8')
sys.path.insert(0,str(code_root))
for name in sources:sys.modules.pop(Path(name).stem,None)
importlib.invalidate_caches()
from v30_250m_train import run
report=run(RUN_NAME,CONFIG,stage=RUN_STAGE,hours=SESSION_HOURS,
           reserve_minutes=RESERVE_MINUTES,prepare_only=PREPARE_ONLY)
if report.get('rawCompletions'):
    for item in report['rawCompletions']:
        print('MODE:',item.get('mode'),'PREFIX:',item['prefix'])
        print('CONTINUATION:',item['continuation'])
elif PREPARE_ONLY:
    print('Data preparation saved. Enable GPU and set PREPARE_ONLY=False to train.')
else:
    print('Paused and saved. Run all with unchanged configuration and session time below remaining quota.')
'''
    cells=[]
    for i,(kind,source) in enumerate([('markdown',INTRO),('code',setup),('code',config),('code',execute)]):
        cell=dict(id='v30-'+str(i),cell_type=kind,metadata={},source=source.splitlines(True))
        if kind=='code':ast.parse(source);cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    for value in sources.values():ast.parse(value)
    path=root/'Nebula_Kaggle_V30_250M.ipynb'
    path.write_text(json.dumps(dict(nbformat=4,nbformat_minor=5,metadata=old['metadata'],cells=cells),indent=1),encoding='utf-8')
    return path

if __name__=='__main__':print(build())
