"""Explicit, allowlisted publication of public-source raw corpus data; never weights."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import numpy as np
from v17_raw_data import FORMAT,SPECS,CREDENTIAL,normalized_hash,prepare,file_sha256
from v17_raw_lab import validate,local_corpus_ready
from v17_data import digest

PUBLIC_FORMAT='nebula-public-raw-corpus-1'
PART_BYTES=64*1024*1024
MAX_BYTES=2*1024*1024*1024
RUN='nebula-v17-raw-prose'


def read_json(path):return json.loads(Path(path).read_text(encoding='utf-8'))


def safe_config(config):
    return validate(copy.deepcopy(config))


def restore_entry(repo,repo_type,revision,entry,target,token,prefix):
    from huggingface_hub import hf_hub_download
    size=entry.get('bytes',0)
    if type(size) is not int or not 0<size<=MAX_BYTES:raise ValueError('Invalid snapshot size')
    target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() and target.stat().st_size==size and file_sha256(target)==entry['sha256']:return target
    with tempfile.TemporaryDirectory(dir=target.parent) as temp:
        output=Path(temp)/'assembled'
        with output.open('wb') as stream:
            parts=entry.get('parts',[entry])
            if not isinstance(parts,list) or not 1<=len(parts)<=32 or sum(p.get('bytes',0) for p in parts)!=size:
                raise ValueError('Invalid snapshot parts')
            for part in parts:
                name=part.get('path','')
                if not name.startswith(prefix) or '..' in name.split('/') or '\\' in name:
                    raise ValueError('Invalid snapshot path')
                fetched=Path(hf_hub_download(repo,name,repo_type=repo_type,revision=revision,token=token,local_dir=Path(temp)/'download'))
                if fetched.stat().st_size!=part['bytes'] or file_sha256(fetched)!=part['sha256']:
                    raise ValueError('Snapshot checksum mismatch')
                with fetched.open('rb') as source:shutil.copyfileobj(source,stream)
        if output.stat().st_size!=size or file_sha256(output)!=entry['sha256']:raise ValueError('Assembled checksum mismatch')
        output.replace(target)
    return target


def build_release(folder,output,config):
    """Rebuild a minimal index and prove all committed bytes are indexed public documents."""
    folder=Path(folder);output=Path(output);output.mkdir(parents=True,exist_ok=True)
    config=safe_config(config)
    source=sqlite3.connect(f'file:{(folder/"documents.sqlite").as_posix()}?mode=ro',uri=True)
    target=None
    try:
        state=json.loads(source.execute("SELECT value FROM metadata WHERE key='state'").fetchone()[0])
        if state['format']!=FORMAT or state['sourceSpecs']!=SPECS or state['dtype']!='<u2' or state['specialTokens']!={'BOS':256,'EOS':257}:
            raise ValueError('Unexpected public corpus format or provenance')
        if state['signature']!=digest({'format':FORMAT,'config':config,'sources':SPECS}):raise ValueError('Corpus settings mismatch')
        if read_json(folder/'manifest.json')!=state:raise ValueError('Local manifest is inconsistent; resume preparation first')
        # Export only known metadata fields; no arbitrary tables, SQLite free pages or files.
        allowed=['format','signature','sources','tokenCounts','textBytes','complete','dtype','specialTokens','sourceSpecs',
                 'screening','validationScope','binarySha256']
        clean={k:state[k] for k in allowed if k in state}
        if CREDENTIAL.search(json.dumps(clean)):raise ValueError('Credential pattern in corpus metadata')
        target=sqlite3.connect(output/'documents.sqlite.bin')
        target.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        target.execute('CREATE TABLE docs (hash TEXT PRIMARY KEY,source TEXT,row_index INTEGER,split TEXT,start_token INTEGER,end_token INTEGER,utf8_bytes INTEGER,provenance TEXT)')
        totals={key:{'bytes':0,'documents':0} for key in SPECS};all_bytes=0;all_docs=0
        for split in ['train','validation']:
            count=state['tokenCounts'][split]
            if type(count) is not int or not 0<=count<=512_000_000:raise ValueError('Invalid committed length')
            path=folder/(split+'.bin')
            if path.stat().st_size<count*2:raise ValueError('Packed data is incomplete')
            cursor=0
            with path.open('rb') as stream,(output/(split+'.bin')).open('wb') as out:
                for row in source.execute('SELECT hash,source,row_index,split,start_token,end_token,utf8_bytes,provenance FROM docs WHERE split=? ORDER BY start_token',(split,)):
                    identifier,kind,index,_,start,end,n,provenance=row
                    if kind not in SPECS or type(index) is not int or index<0 or start!=cursor or end>count or end-start!=n+2 or n>config['maxDocumentBytes']:
                        raise ValueError('Unindexed bytes or unexpected source document')
                    blob=stream.read((end-start)*2);tokens=np.frombuffer(blob,dtype='<u2')
                    if len(tokens)!=end-start or tokens[0]!=256 or tokens[-1]!=257 or np.any(tokens[1:-1]>255):raise ValueError('Unexpected packed tokens')
                    text=tokens[1:-1].astype(np.uint8).tobytes().decode('utf-8')
                    if normalized_hash(text)!=identifier or CREDENTIAL.search(text):raise ValueError('Document checksum or credential screening failed')
                    values=json.loads(provenance)
                    if not isinstance(values,dict):raise ValueError('Invalid provenance')
                    values={k:v for k,v in values.items() if k in ['id','url','file_path','audience','format']}
                    if any(not isinstance(v,str) or len(v)>1000 for v in values.values()) or CREDENTIAL.search(json.dumps(values)):
                        raise ValueError('Invalid public provenance')
                    target.execute('INSERT INTO docs VALUES (?,?,?,?,?,?,?,?)',(*row[:7],json.dumps(values)))
                    out.write(blob);cursor=end;all_bytes+=n;all_docs+=1;totals[kind]['bytes']+=n;totals[kind]['documents']+=1
                if cursor!=count:raise ValueError('Unindexed packed data cannot be published')
        if all_docs!=source.execute('SELECT COUNT(*) FROM docs').fetchone()[0] or all_bytes!=state['textBytes']:
            raise ValueError('Document totals mismatch')
        for key,values in totals.items():
            if values['bytes']!=state['sources'][key]['utf8Bytes'] or values['documents']!=state['sources'][key]['accepted']:
                raise ValueError('Source attribution totals mismatch')
        clean['binarySha256']={s:file_sha256(output/(s+'.bin')) for s in ['train','validation']}
        # Hashes are only part of a completed preparation manifest, as expected by prepare().
        if not clean['complete']:clean.pop('binarySha256',None)
        target.execute("INSERT INTO metadata VALUES ('state',?)",(json.dumps(clean),));target.commit();target.close();target=None
        (output/'manifest.json').write_text(json.dumps(clean,indent=2),encoding='utf-8')
        return clean
    finally:
        source.close()
        if target is not None:target.close()


def publish_release(api,repo,folder,config,download,run=RUN):
    """Create a new public dataset only after a local allowlist audit; verify anonymous access."""
    from huggingface_hub import CommitOperationAdd
    with tempfile.TemporaryDirectory(dir=Path(folder).parent,prefix='public-release-') as temp:
        output=Path(temp);manifest=build_release(folder,output,config)
        release=digest({'config':config,'manifest':manifest})
        prefix='snapshots/'+release+'/'
        operations=[];files={}
        for name in ['train.bin','validation.bin','documents.sqlite.bin','manifest.json']:
            path=output/name
            if path.stat().st_size==0:continue
            size=path.stat().st_size;parts=[]
            if size>PART_BYTES:
                with path.open('rb') as source:
                    for i in range((size+PART_BYTES-1)//PART_BYTES):
                        part=output/(name+f'.part{i:03d}.bin');part.write_bytes(source.read(PART_BYTES))
                        remote=prefix+part.name
                        parts.append({'path':remote,'bytes':part.stat().st_size,'sha256':file_sha256(part)})
                        operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=str(part)))
                entry={'bytes':size,'sha256':file_sha256(path),'parts':parts}
            else:
                remote=prefix+name;entry={'path':remote,'bytes':size,'sha256':file_sha256(path)}
                operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=str(path)))
            files[name]=entry
        for key,spec in SPECS.items():
            card=Path(download(spec['dataset'],'README.md',repo_type='dataset',revision=spec['revision'],token=False))
            card_path=output/(key+'-README.md');card_path.write_bytes(card.read_bytes())
            operations.append(CommitOperationAdd(path_in_repo='attribution/'+card_path.name,path_or_fileobj=str(card_path)))
        overview={'format':PUBLIC_FORMAT,'run':run,'config':config,'release':release,'preparedTextBytes':manifest['textBytes'],
                  'complete':manifest['complete'],'files':files,'sourceSpecs':SPECS,'containsModelWeights':False,'containsUserChatExports':False}
        pointer=output/'public-state.json';pointer.write_text(json.dumps(overview,indent=2),encoding='utf-8')
        operations.append(CommitOperationAdd(path_in_repo='public-state.json',path_or_fileobj=str(pointer)))
        readme=output/'README.md'
        source_lines='\n'.join(f"- [{s['dataset']}](https://huggingface.co/datasets/{s['dataset']}/tree/{s['revision']}), subset `{s['subset']}`, license `{s['license']}`." for s in SPECS.values())
        readme.write_text('''---
license: other
license_name: per-source-licenses
license_link: https://huggingface.co/datasets/'''+repo+'''/blob/main/README.md#licenses-and-attribution
language:
- en
tags:
- nebula
- pretraining
---
# Nebula public raw corpus

This dataset contains a bounded sample of public-source UTF-8 documents packed as
little-endian uint16 byte token IDs. BOS=256 and EOS=257; IDs 0-255 encode bytes.
The index preserves whole-document boundaries, source attribution and train/validation assignment.
No Nebula model checkpoint, private account-chat export, review feed, token or API configuration is uploaded.
This is a research corpus, not a conversational model or a claim of verified factual quality.
Original public web documents may themselves contain personal information; the filters are not a full PII audit.

## Licenses and attribution

Each component retains its upstream license and terms; this collection does not relicense them.
Read the pinned upstream cards retained under `attribution/` and original source pages.
FineWeb-Edu also retains the original source URLs and Common Crawl attribution in the index.
ODC-By terms: https://opendatacommons.org/licenses/by/1-0/
TinyStories CDLA terms: https://cdla.dev/sharing-1-0/

'''+source_lines+'''

## Snapshot format

`public-state.json` points to a content-addressed snapshot. Each file or part has a SHA256 and byte count.
Concatenate `.partNNN.bin` files in manifest order to restore a sharded file.
`manifest.json` reports whether the requested corpus preparation is complete; partial snapshots can resume.
`documents.sqlite.bin` is a fresh SQLite database containing only the validated corpus index and preparation metadata.
No previous repository history is imported. No source files are deleted by this transfer.
''',encoding='utf-8')
        operations.append(CommitOperationAdd(path_in_repo='README.md',path_or_fileobj=str(readme)))
        api.create_repo(repo,repo_type='dataset',private=False,exist_ok=True)
        info=api.dataset_info(repo)
        if info.private is not False:raise ValueError('Destination must be the separate public DATASET repository')
        # Compare-and-swap protects a second worker from being overwritten.
        result=api.create_commit(repo_id=repo,repo_type='dataset',parent_commit=info.sha,operations=operations,
                                 commit_message='Save validated public-source raw corpus')
        # Verify every published data part through public, unauthenticated downloads.
        for name,entry in files.items():
            for part in entry.get('parts',[entry]):
                fetched=Path(download(repo,part['path'],repo_type='dataset',revision=result.oid,token=False))
                if fetched.stat().st_size!=part['bytes'] or file_sha256(fetched)!=part['sha256']:
                    raise ValueError('Public remote verification failed; retain local files')
        saved=Path(download(repo,'public-state.json',repo_type='dataset',revision=result.oid,token=False))
        if read_json(saved)!=overview:raise ValueError('Public manifest verification failed')
        print(json.dumps({'publicCorpusBackupConfirmed':True,'repository':repo,'revision':result.oid,
                          'preparedTextBytes':manifest['textBytes'],'preparationComplete':manifest['complete'],
                          'modelWeightsUploaded':False,'sourceFilesDeleted':False}),flush=True)
        return overview,result.oid


def main(project,source_repo='iiidevv/nebula-research',public_repo='iiidevv/nebula-public-data',hours=1):
    from huggingface_hub import HfApi,hf_hub_download
    from huggingface_hub.errors import EntryNotFoundError,RepositoryNotFoundError
    token=os.environ.get('NEBULA_HF_TOKEN')
    if not token:raise RuntimeError('Enable NEBULA_HF_TOKEN in Colab Secrets first')
    if source_repo==public_repo or not re.fullmatch(r'[\w-]+/[\w.-]+',public_repo):raise ValueError('Choose a separate public dataset repository')
    api=HfApi(token=token)
    if public_repo.split('/')[0]!=api.whoami()['name']:raise ValueError('Destination must belong to the signed-in account')
    info=api.model_info(source_repo)
    if info.private is not True:
        api.update_repo_settings(source_repo,repo_type='model',private=True)
        info=api.model_info(source_repo)
        if info.private is not True:raise RuntimeError('Could not restore the original repository to private')
    print(json.dumps({'originalRepositoryPrivate':True,'trainingEnabled':False}),flush=True)
    prefix='experiments/'+RUN+'/'
    state=read_json(hf_hub_download(source_repo,prefix+'state.json',revision=info.sha,token=token))
    if state.get('format')!=FORMAT:raise ValueError('Expected raw-data experiment state')
    config=safe_config(state['config']);project=Path(project);project.mkdir(parents=True,exist_ok=True)
    folder=project/'raw-data';folder.mkdir(exist_ok=True)
    public=None;public_revision=None
    try:
        public_info=api.dataset_info(public_repo)
        if public_info.private is not False:raise ValueError('Existing destination is not public')
        public=read_json(hf_hub_download(public_repo,'public-state.json',repo_type='dataset',revision=public_info.sha,token=False))
        if public.get('format')!=PUBLIC_FORMAT or public.get('config')!=config:raise ValueError('Existing public destination has different settings')
        public_revision=public_info.sha
    except (RepositoryNotFoundError,EntryNotFoundError):pass
    minimum=max(state.get('preparedTextBytes',0),public.get('preparedTextBytes',0) if public else 0)
    if not local_corpus_ready(folder,config,minimum):
        if public and public['preparedTextBytes']>=state.get('preparedTextBytes',0):
            for name,local in [('train.bin','train.bin'),('validation.bin','validation.bin'),('documents.sqlite.bin','documents.sqlite'),('manifest.json','manifest.json')]:
                if name in public['files']:restore_entry(public_repo,'dataset',public_revision,public['files'][name],folder/local,False,'snapshots/'+public['release']+'/')
        else:
            for key,name in [('rawTrain','train.bin'),('rawValidation','validation.bin'),('rawIndex','documents.sqlite'),('rawManifest','manifest.json')]:
                if key in state:restore_entry(source_repo,'model',info.sha,state[key],folder/name,token,prefix)
    # Publish before acquiring more data, so the currently surviving corpus is protected first.
    if not local_corpus_ready(folder,config,minimum):raise ValueError('A consistent raw corpus snapshot was not found')
    current=read_json(folder/'manifest.json')
    last=current['textBytes']
    publish_release(api,public_repo,folder,config,hf_hub_download)
    def backup(path,manifest):
        nonlocal last
        if manifest['textBytes']-last>=8_000_000 or manifest['complete']:
            publish_release(api,public_repo,path,config,hf_hub_download);last=manifest['textBytes']
    if not current['complete']:
        try:
            prepare(folder,config,on_save=backup,max_seconds=hours*3600,stop_file=project/'STOP')
        except BaseException:
            print('Preparation stopped. Local data is retained; only publicCorpusBackupConfirmed marks verified online progress.',flush=True)
            raise
        current=read_json(folder/'manifest.json')
        if current['textBytes']!=last:publish_release(api,public_repo,folder,config,hf_hub_download)
    print('Public corpus transfer finished. No model training, checkpoint publication, source deletion or private-history migration was performed.',flush=True)
