"""Pinned, licensed Python sources -> private D2 corpus. Never execute source code."""
import ast,copy,gzip,hashlib,io,json,tarfile,tokenize
from pathlib import PurePosixPath
from vd2_data import Corpus,sha,SPECIAL
from vd2_lab import DEFAULT,engine_hash

def fetch_archive(source,max_bytes=80_000_000):
    import requests
    repo=source['repo'];revision=source['revision']
    import re
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or not re.fullmatch(r'[a-f0-9]{40}',revision):raise ValueError('Pin an exact GitHub source commit')
    data=bytearray()
    with requests.get(f'https://codeload.github.com/{repo}/tar.gz/{revision}',stream=True,timeout=(30,180)) as response:
        response.raise_for_status()
        for chunk in response.iter_content(1024*1024):
            data.extend(chunk)
            if len(data)>max_bytes:raise ValueError('Source archive exceeds RAM budget')
    return bytes(data)

def collect(sources,config=DEFAULT,fetcher=fetch_archive):
    corpus=Corpus(config['maxCorpusBytes']);provenance=[];skipped={}
    for spec in sources:
        if not spec.get('approved') or not spec.get('licenseText') or spec.get('origin')!='public-licensed':raise ValueError('Explicitly reviewed public source and full license required')
        archive=fetcher(spec);archive_hash=sha(archive)
        if spec.get('archiveSha256') and archive_hash!=spec['archiveSha256']:raise ValueError('Pinned source archive checksum changed')
        count=0
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
            members=tar.getmembers();roots={m.name.split('/')[0] for m in members}
            if len(roots)!=1:raise ValueError('Unexpected archive root')
            root=next(iter(roots))+'/'
            notice=tar.extractfile(root+spec['licensePath']).read().decode('utf-8')
            if notice!=spec['licenseText']:raise ValueError('License text differs from reviewed commit')
            for member in members:
                name=member.name[len(root):];path=PurePosixPath(name)
                if not member.isfile() or '..' in path.parts or not name.endswith('.py') or not name.startswith(spec.get('prefix','')):continue
                if any(p.lower() in ['vendor','vendored','_vendor','third_party','third-party','node_modules','data','datafiles'] for p in path.parts):continue
                if not 60<=member.size<=150000:continue
                try:
                    raw=tar.extractfile(member).read();encoding,_=tokenize.detect_encoding(io.BytesIO(raw).readline);text=raw.decode(encoding)
                    ast.parse(text,filename=name) # Syntax check only. No imports or execution.
                except (SyntaxError,UnicodeError,LookupError,ValueError,RecursionError):skipped['syntax-or-encoding']=skipped.get('syntax-or-encoding',0)+1;continue
                # Whole directory groups stay together; content dedup also moves overlaps to validation.
                group='/'.join(path.parts[:2]) if spec['repo']!='python/cpython' else '/'.join(path.parts[:3])
                split='validation' if int(sha((spec['repo']+'/'+group).encode())[:8],16)%20==0 else 'train'
                source=dict(repo='github:'+spec['repo'],revision=spec['revision'],key=name,license=spec['license'],origin='public-licensed',approved=True,split=split)
                corpus.add(text,source);count+=1
        provenance.append({**spec,'archiveSha256':archive_hash,'syntaxCheckedPythonFiles':count})
        print(json.dumps({'vd2PublicSource':spec['repo'],'filesChecked':count,**corpus.summary()}),flush=True)
        del archive
    return corpus,provenance,skipped

def prepare_public(repo,token,sources,config=DEFAULT):
    from tokenizers import Tokenizer,models,pre_tokenizers,decoders,trainers
    from vd2_hub import Hub
    hub=Hub(repo,token);existing=hub.state()
    signature=sha(json.dumps(dict(config=config,sources=sources,engine=engine_hash(),publicPipeline=sha(open(__file__,'rb').read())),sort_keys=True).encode())
    if existing:
        if existing.get('signature')!=signature:raise ValueError('Changed public corpus/config: choose a new private destination')
        if existing.get('dataReady'):return existing
    corpus,provenance,skipped=collect(sources,config)
    summary=corpus.summary()
    if summary['counts'].get('train/code',0)<config['minCodeDocuments']:raise ValueError('Not enough unique syntax-checked coding documents')
    if summary['counts'].get('validation/code',0)<50:raise ValueError('Insufficient independent coding validation')
    tokenizer=Tokenizer(models.BPE(unk_token=None));tokenizer.pre_tokenizer=pre_tokenizers.ByteLevel(add_prefix_space=False);tokenizer.decoder=decoders.ByteLevel()
    tokenizer.train_from_iterator((r['text'] for r in corpus.records.values() if r['split']=='train'),trainers.BpeTrainer(vocab_size=config['model']['vocab'],special_tokens=SPECIAL,initial_alphabet=pre_tokenizers.ByteLevel.alphabet()))
    if tokenizer.get_vocab_size()!=config['model']['vocab']:raise ValueError('Target vocabulary not reached')
    state=dict(format='nebula-vd2-code-1',signature=signature,engine=engine_hash(),config=config,dataReady=True,updates=0,qualityApproved=False,websiteUpdated=False,summary=summary,sources=provenance,skipped=skipped,
               corpusScope='Python code foundation pilot; no instruction tuning or user chats; directory/content holdouts. Syntax checking does not establish correctness.')
    notices=json.dumps(dict(sources=provenance,changes='Filtered Python files, normalized newlines, deduplicated and split for a private foundation-training corpus. No source executed.'),ensure_ascii=False).encode()
    return hub.publish(state,{'corpus':gzip.compress(corpus.payload()),'tokenizer':tokenizer.to_str().encode(),'sourceNotices':gzip.compress(notices)})
