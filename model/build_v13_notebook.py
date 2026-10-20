"""Self-contained source bundle; public corpora stream on Kaggle, not this API."""
import ast,copy,json
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    base=json.loads((root/'Nebula_Kaggle_V11_Verified.ipynb').read_text(encoding='utf-8'))
    code=next(''.join(c['source']) for c in base['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    names=ast.literal_eval(ast.parse(code).body[0].value).keys()
    sources={name:(root.parent/name).read_text(encoding='utf-8') for name in names}
    for name in ['v12_data.py','v13_data.py','v13_windows.py','v13_review.py','v13_experiment.py']:
        sources['model/'+name]=(root/name).read_text(encoding='utf-8')
    nb=copy.deepcopy(base)
    nb['cells'][0]['source']='''# Nebula V13 - four public corpora, no Groq required

Stop the older trainer before starting this notebook. Import into a **private Kaggle notebook**, enable **Internet** and **T4 x2**, enable the same secrets, and Run all. This preserves your owned 100M model; it does not substitute pretrained weights. No API/website upload is required.

The first phase streams pinned public TRAIN splits from all four requested sources. The default candidate targets are **12,000 Smol-SmolTalk conversations, 1,000 Cosmopedia v2 passages, 1,000 FineWeb-Edu sample-10BT passages, and 1,000 TinyStories stories**. These are acquisition targets, not promises that every record will pass. It does not download entire trillion-token corpora. Each source has a bounded scan, an atomic local progress file, a source revision, checksums and attribution. A failed source stops initialization with a preparation backup; it never silently substitutes a different source.

Complete source conversations (up to six user/assistant turns) and answers up to **12,000 UTF-8 bytes** are retained. Overlong whole records, malformed/incomplete answers, identity conflicts, roleplay, code blocks, contact/credential patterns, exact arithmetic errors, excessive repetition and known evaluation prompts are excluded. Known rewriting instructions are retained; unsupported source system instructions are rejected. Formatting and punctuation normalization are recorded. This is filtering, not a claim of factual accuracy.

Prefer natural multi-turn conversations, not another rewrite-heavy batch. **Groq is off by default and no teacher/judge key is required.** All eligible structurally filtered new conversations can enter training. Saved two-pass approvals are retained, known rejected conversations are excluded, and other examples are explicitly labeled **not individually fact-checked**. No automatic AI verification is claimed for those examples. Completed public-data downloads are reused from the same private preparation backup. Text passages receive structural/educational-source filtering. `humanVerified` stays false. This makes the run independent of provider quota, with a corresponding reduction in semantic quality checking.

Full answers are trained through overlapping windows. **Every assistant target byte is learned once per source example**, including later portions of long answers; user/system tokens are masked. Overlap supplies context only. No end-of-answer token is invented at window boundaries. Educational text uses raw next-byte language modeling, not fabricated questions/answers. **The model's 1,024-byte context is unchanged**: this does not give it unlimited memory or let it attend to an entire long conversation at once.

The 80% conversation / 20% mixed update mix remains. Mixed practice covers memory, identity, arithmetic and language, with the three new text sources rotating equally by language update. Existing best replay, fresh consent-checked reviews and previously saved teacher examples remain. No new Groq teacher calls are made by default. Training starts from the verified saved V12 best, or V11 best if V12 is absent. A changed dataset/anchor starts a fresh optimizer; compatible V13 resumes restore it. All prior runs stay intact.

New original records are split into training/held-out groups before windows. Whole-record hashes/source IDs exclude existing records; normalized opening prompts exclude existing chat starts, and all old fixed-validation prompts remain blocked. Different conversations may share ordinary follow-ups. New chats sharing an opening prompt stay in the same partition. Old fixed validation stays byte-for-byte unchanged. New public holdouts are saved separately and produce per-source loss diagnostics. The strict synthetic/chat checks still control verified-best selection; extra public losses are diagnostics, not proof of conversation quality. Cached semantic decisions can be reused; unknown replies remain pending. Without a provider, finite held-out losses, readability, exact-copy and name checks can allow a **provisional research checkpoint** to continue training. This does not certify conversational correctness or replace the verified best. Full working optimizer state and reports are backed up. Three rounds that fail these local safeguards pause the run. Website updates remain off; provisional checkpoints require semantic/manual review before release. Logs retain some `v11`/`v10` names because the verified runner is reused.

Preparation/review progress saves privately to `experiments/nebula-v13-four-sources-preparation`; accepted training state saves to `experiments/nebula-v13-four-sources`. Wait for `checkpointBackupConfirmed: true` or `v13PreparationBackupConfirmed: true` before ending a session. Local work since the latest backup can be lost if Kaggle disconnects.

Public website updates remain **off**. More data is an experiment, not a guarantee of smarter replies.
'''.splitlines(True)
    setup=''.join(nb['cells'][1]['source']).replace('nebula-v11-verified','nebula-v13-four-sources')
    setup=setup.replace("'requests>=2.32,<3'","'requests>=2.32,<3','datasets>=3.6,<5','pyarrow>=18,<24'")
    setup=setup.replace('STEPS_PER_ROUND=100','STEPS_PER_ROUND=200').replace('TEACHER_MAX_CALLS=96','TEACHER_MAX_CALLS=0')
    setup='\n'.join(line for line in setup.splitlines() if not line.startswith("if not (os.environ['NEBULA_JUDGE_GROQ_KEY']"))+'\n'
    setup+="\nprint({'v13MergeEngine':'single-pass-heldout-matcher-1'})\nos.environ['NEBULA_V13_USE_GROQ']='false'\nos.environ['HF_TOKEN']=os.environ['NEBULA_HF_TOKEN']\n"
    nb['cells'][1]['source']=setup.splitlines(True)
    nb['cells'][2]['source']=('sources='+repr(sources)+'''
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v13_experiment import main
from research_client import ResearchError
try:
    main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
except ResearchError as error:
    print({'v13Stopped':error.code,'publicWebsiteUpdated':False})
    if 'PENDING' in error.code:print('Wait for the source or review service to recover, then Run all. Private preparation backups retain completed data/reviews; older model runs remain intact.')
    else:raise
''').splitlines(True)
    nb['cells'][3]['source']='''## Stop and resume

Create `/kaggle/working/nebula-v13-four-sources/api/STOP_AFTER_ROUND` for a graceful stop. Wait for a confirmed backup. Remove the file before resuming. Run all with the same secrets/run name resumes saved V13 state or preparation. Do not run two copies of this trainer simultaneously. No model is automatically published.
'''.splitlines(True)
    for i,cell in enumerate(nb['cells']):
        cell['id']=f'v13-{i:02d}'
        if cell['cell_type']=='code':ast.parse(''.join(cell['source']));cell.update(execution_count=None,outputs=[])
    for name,source in sources.items():
        if name.endswith('.py'):ast.parse(source)
    target=root/'Nebula_Kaggle_V13_No_Groq.ipynb';target.write_text(json.dumps(nb,indent=1),encoding='utf-8');(root/'Nebula_Kaggle_V13_Four_Sources.ipynb').write_bytes(target.read_bytes());return target

if __name__=='__main__':print(build())
