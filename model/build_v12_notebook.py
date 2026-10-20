"""Package complete public examples with the verified Kaggle research runner."""
import ast,base64,copy,hashlib,json,zlib
from pathlib import Path

def build():
    root=Path(__file__).resolve().parent
    base=json.loads((root/'Nebula_Kaggle_V11_Verified.ipynb').read_text(encoding='utf-8'))
    old_source=next(''.join(c['source']) for c in base['cells'] if c['cell_type']=='code' and ''.join(c['source']).startswith('sources='))
    names=ast.literal_eval(ast.parse(old_source).body[0].value).keys()
    sources={name:(root.parent/name).read_text(encoding='utf-8') for name in names}
    sources.update({'model/'+name:(root/name).read_text(encoding='utf-8') for name in ['v12_data.py','v12_review.py','v12_experiment.py']})
    folder=root/'data/v12-public';seed_names=['conversations.jsonl','manifest.json','licenses.json']
    if (folder/'screening-cache.json').is_file():seed_names.append('screening-cache.json')
    files={name:(folder/name).read_text(encoding='utf-8') for name in seed_names}
    manifest=json.loads(files['manifest.json'])
    if hashlib.sha256(files['conversations.jsonl'].encode()).hexdigest()!=manifest['sha256']:raise ValueError('Public seed checksum mismatch')
    raw=json.dumps(files,sort_keys=True).encode();encoded=base64.b64encode(zlib.compress(raw,9)).decode();checksum=hashlib.sha256(raw).hexdigest()
    nb=copy.deepcopy(base)
    nb['cells'][0]['source']=('''# Nebula V12 — complete public conversation expansion

V11 has paused and confirmed its backup. Import this notebook into a private Kaggle notebook, enable Internet and T4 x2, enable the **same secrets**, and Run all. No API/website upload, new secret, Colab session or manual dataset upload is needed. Stop any older trainer before starting this one.

This notebook includes **'''+str(manifest['accepted'])+''' complete, screened public examples** from HuggingFaceTB/smol-smoltalk. Only the public training split was used. Of 230,000 records scanned, 820 passed structural filtering, 304 survived local overlap checks, and 265 passed both Groq review calls. Additional assistant inspection excluded 62 cases for altered meaning, unsupported claims, missed instructions or unsuitable language. The final bounded batch contains 193 editing tasks and 7 multi-turn conversations. Most short everyday conversations were already present or overlapped validation, so this batch primarily expands editing practice. These are AI checks, not human verification, and errors may remain.

Coding, complex formatting tasks, roleplay/human biographies, unsupported system instructions, malformed text, repetitive or incomplete answers, known frozen questions and answers exceeding the current limits were excluded. Conversations and answers were not shortened. The known rewriting instruction is moved intact into the user request; other system instructions are rejected.

On initialization, V12 rechecks overlaps with the actual V11 training records and fixed validation, including original source-record IDs, normalized user prompts and full conversation hashes. **Completed review decisions are included and reused**, so these examples do not need to be screened again. Any uncached examples would require both review passes with the separate training Groq key. Only approved examples enter training. Screening is bounded to 96 requests per initialization, with cached progress and up to three one-minute retries for service failures. At least 200 genuinely new reviewed conversations must survive or initialization stops. The actual added count is logged as `newCompleteConversations`. Dataset provenance, component labels, hashes, selection exclusions and the Apache 2.0 license text are retained.

V12 starts from the **verified saved V11 best**, preserving its owned 100M weights and inherited training step count. V11 and all previous runs remain intact. New training data and the anchor require a **fresh initial optimizer**; compatible V12 optimizer state resumes after that. The fixed validation data and strict evaluation remain. Data writes only to `experiments/nebula-v12-public`.

The 80% conversation / 20% mixed training mix stays, with memory, identity and arithmetic rehearsal, historical examples, checked Groq teacher practice and fresh consent-checked reviews. The verified V11 runner still handles semantic evaluation, early candidates, pending-review backups and a pause after three fully reviewed rejected rounds. Logs therefore retain the `v11Evaluation` and `v11RoundSaved` event names. Missing reviews never count as passes, and lower loss alone cannot replace the best model.

Public website updates stay **off**. More examples may help, but improvement is not guaranteed. Inspect actual replies and named metrics before publishing. Wait for `checkpointBackupConfirmed: true`; local intermediate work can be lost when Kaggle stops.
''').splitlines(True)
    setup=''.join(nb['cells'][1]['source']).replace('nebula-v11-verified','nebula-v12-public').replace('re-grade saved V10 checkpoints','merge public examples and verify V11 best')
    setup+="\nif not os.environ.get('NEBULA_TEACHER_GROQ_KEY'):raise RuntimeError('Enable the separate NEBULA_TEACHER_GROQ_KEY secret for public-example screening.')\n"
    nb['cells'][1]['source']=setup.splitlines(True)
    code='sources='+repr(sources)+'\npublic_seed='+repr(encoded)+'\npublic_seed_sha256='+repr(checksum)+'''
import base64,hashlib,json,zlib
for name,content in sources.items():
    target=project/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
decoder=zlib.decompressobj();payload=decoder.decompress(base64.b64decode(public_seed),32*1024*1024)
if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data or hashlib.sha256(payload).hexdigest()!=public_seed_sha256:raise RuntimeError('Public seed checksum or size failure')
public_files=json.loads(payload)
if not {'conversations.jsonl','manifest.json','licenses.json'}<=set(public_files) or set(public_files)-{'conversations.jsonl','manifest.json','licenses.json','screening-cache.json'}:raise RuntimeError('Unexpected public seed paths')
for name,content in public_files.items():
    target=project/'model/data/v12-public'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content,encoding='utf-8')
sys.path.insert(0,str(project/'model'))
for name in sources:
    if name.endswith('.py'):sys.modules.pop(Path(name).stem,None)
from v12_experiment import main
from research_client import ResearchError
try:
    main(['--project',str(project),'--run',RUN_NAME,'--hours',str(HOURS),'--rounds',str(MAX_ROUNDS),'--steps',str(STEPS_PER_ROUND),'--teacher-calls',str(TEACHER_MAX_CALLS)])
except ResearchError as error:
    print({'v12Stopped':error.code,'publicWebsiteUpdated':False})
    if 'REVIEW_PENDING' in error.code:print('Review could not finish. Wait for provider recovery, then Run all in the same runtime to reuse completed reviews. Saved model checkpoints remain intact.')
    else:raise
'''
    ast.parse(code);nb['cells'][2]['source']=code.splitlines(True)
    nb['cells'][3]['source']='''## Stop and resume

For a graceful stop create `/kaggle/working/nebula-v12-public/api/STOP_AFTER_ROUND` and wait for a confirmed backup. Remove that file before resuming. Run all with the same run name resumes accepted V12 progress or retries a pending review first. Three rejected rounds deliberately pause this run. No model is automatically published to users.
'''.splitlines(True)
    for i,cell in enumerate(nb['cells']):
        cell['id']=f'v12-{i:02d}'
        if cell['cell_type']=='code':ast.parse(''.join(cell['source']));cell.update(execution_count=None,outputs=[])
    target=root/'Nebula_Kaggle_V12_Public.ipynb';target.write_text(json.dumps(nb,indent=1),encoding='utf-8');return target

if __name__=='__main__':print(build())
