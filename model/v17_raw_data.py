"""Stream whole public documents into resumable little-endian uint16 byte-token files."""
import hashlib
import itertools
import json
import os
import re
import sqlite3
import time
import unicodedata
from pathlib import Path
import numpy as np
import torch
from nebula import BOS, EOS
from v13_data import SOURCES
from v16_diagnostic import atomic_json, emit
from v17_data import digest

FORMAT = 'nebula-v17-packed-raw-1'
SPECS = {key: {k:SOURCES[key][k] for k in ['dataset','subset','revision','license']}
         for key in ['fineweb','cosmopedia','stories']}
BLOCKED = ['A child found a small boat beside the pond.', 'Ice melts when it takes in heat.',
           'The rain stopped, and the neighbors opened their windows.',
           'Hello! What can you help me with?', 'Write a thank-you note to a neighbor.']
CREDENTIAL = re.compile(r'\b(?:gsk_|hf_|sk-|AIza|AQ\.)[\w-]{18,}|\bBearer\s+[\w.~/+=-]{18,}')


def file_sha256(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def normalized_hash(text):
    value=' '.join(unicodedata.normalize('NFKC',text).casefold().split())
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def document(item, source, minimum=200, maximum=1000000):
    text=item.get('text')
    if not isinstance(text,str):return None,'missing-text'
    text=text.replace('\r\n','\n').replace('\r','\n').strip()
    try:content=text.encode('utf-8')
    except UnicodeError:return None,'malformed-unicode'
    if not minimum<=len(content)<=maximum:return None,'whole-document-size'
    if '\ufffd' in text or any(ord(c)<32 and c not in '\n\t' for c in text):return None,'malformed-controls'
    if CREDENTIAL.search(text):return None,'credential-pattern'
    lower=text.casefold()
    if any(p.casefold() in lower for p in BLOCKED):return None,'fixed-probe-overlap'
    if source=='fineweb' and item.get('language','en')!='en':return None,'non-english'
    return (text,content,normalized_hash(text)),None


def prepare(folder, config, *, streams=None, on_save=None, max_seconds=3600, stop_file=None):
    """SQLite is authoritative: committed binary lengths/cursors recover partial writes."""
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    signature=digest({'format':FORMAT,'config':config,'sources':SPECS})
    db=sqlite3.connect(folder/'documents.sqlite')
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS docs (hash TEXT PRIMARY KEY, source TEXT, row_index INTEGER, split TEXT, start_token INTEGER, end_token INTEGER, utf8_bytes INTEGER, provenance TEXT)')
    existing=db.execute("SELECT value FROM metadata WHERE key='state'").fetchone()
    state=json.loads(existing[0]) if existing else {'format':FORMAT,'signature':signature,
        'sources':{k:{'scanned':0,'accepted':0,'utf8Bytes':0,'excluded':{},'complete':False} for k in SPECS},
        'tokenCounts':{'train':0,'validation':0},'textBytes':0,'complete':False,
        'dtype':'<u2','specialTokens':{'BOS':BOS,'EOS':EOS},'sourceSpecs':SPECS,
        'screening':'Whole-document size/Unicode checks, normalized exact deduplication, credential-pattern exclusion and fixed-probe exclusion. Not fuzzy-deduplicated or fact-checked.',
        'validationScope':'Whole normalized documents are assigned to only one split in this run. This does not establish lifetime novelty for the starting checkpoint.'}
    if state['signature']!=signature:db.close();raise ValueError('RAW_PREPARATION_SETTINGS_CHANGED_USE_NEW_RUN')
    handles={}
    try:
        for split in ['train','validation']:
            path=folder/(split+'.bin');expected=state['tokenCounts'][split]*2
            if not path.exists():path.touch()
            handle=path.open('r+b')
            if path.stat().st_size<expected:handle.close();raise ValueError('Committed packed data is missing; restore a confirmed snapshot')
            # Remove only uncommitted tail bytes left by abrupt interruption.
            handle.truncate(expected);handle.seek(expected);handles[split]=handle
        started=time.monotonic()
        def persist():
            for handle in handles.values():handle.flush();os.fsync(handle.fileno())
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('state', ?)",(json.dumps(state),));db.commit()
            atomic_json(folder/'manifest.json',state)
            if on_save:on_save(folder,state)
        atomic_json(folder/'manifest.json',state)
        if not existing:persist()
        if state['complete']:
            for split,expected in state.get('binarySha256',{}).items():
                if file_sha256(folder/(split+'.bin'))!=expected:raise ValueError('RAW_PACKED_CORPUS_CHECKSUM_MISMATCH')
            return state
        for key,spec in SPECS.items():
            progress=state['sources'][key]
            if progress['complete']:continue
            goal=int(config['textBytes']*config['weights'][key]/100)
            if goal==0:progress['complete']=True;persist();continue
            emit(rawSourceConnecting=key,targetUtf8Bytes=goal,pinnedRevision=spec['revision'])
            if streams is None:
                from datasets import load_dataset
                source=load_dataset(spec['dataset'],spec['subset'],split='train',revision=spec['revision'],streaming=True)
                source=source.shuffle(seed=config['seed'],buffer_size=256)
            else:source=streams[key]
            cursor=progress['scanned']
            for index,item in enumerate(itertools.islice(source,cursor,None),cursor):
                if time.monotonic()-started>=max_seconds or stop_file and Path(stop_file).exists():persist();return state
                progress['scanned']=index+1
                converted,reason=document(item,key,config['minDocumentBytes'],config['maxDocumentBytes'])
                if converted:
                    text,content,identifier=converted
                    if db.execute('SELECT 1 FROM docs WHERE hash=?',(identifier,)).fetchone():reason='normalized-duplicate'
                    elif len(content)>goal-progress['utf8Bytes']:reason='source-byte-cap-no-truncation'
                    else:
                        split='validation' if int(identifier[:8],16)%100<config['validationPercent'] else 'train'
                        tokens=np.empty(len(content)+2,dtype='<u2');tokens[0]=BOS;tokens[-1]=EOS
                        tokens[1:-1]=np.frombuffer(content,dtype=np.uint8)
                        start=state['tokenCounts'][split];handles[split].write(tokens.tobytes())
                        provenance={k:str(item[k])[:1000] for k in ['id','url','file_path','audience','format'] if k in item}
                        db.execute('INSERT INTO docs VALUES (?,?,?,?,?,?,?,?)',
                            (identifier,key,index,split,start,start+len(tokens),len(content),json.dumps(provenance)))
                        state['tokenCounts'][split]+=len(tokens);state['textBytes']+=len(content)
                        progress['utf8Bytes']+=len(content);progress['accepted']+=1
                if reason:progress['excluded'][reason]=progress['excluded'].get(reason,0)+1
                if progress['scanned']%250==0:
                    persist();emit(rawPreparedBytes=state['textBytes'],source=key,scanned=progress['scanned'],documents=progress['accepted'])
                # End within one minimum-sized document of the requested source cap.
                if progress['utf8Bytes']>=goal*.995 or goal-progress['utf8Bytes']<config['minDocumentBytes'] or progress['scanned']>=config['maxScannedPerSource']:break
            if progress['utf8Bytes']<goal*.90:
                persist();raise RuntimeError('RAW_SOURCE_INCOMPLETE_'+key.upper()+'_RESUME_OR_INSPECT_MANIFEST')
            progress['complete']=True;persist()
        for handle in handles.values():handle.flush();os.fsync(handle.fileno())
        state['binarySha256']={split:file_sha256(folder/(split+'.bin')) for split in ['train','validation']}
        state['complete']=True;persist();return state
    except BaseException:
        # A signal can arrive between a binary write, SQL insert and Python counter update.
        # Roll back the uncommitted batch, rather than committing a possibly half-updated record.
        db.rollback()
        committed=db.execute("SELECT value FROM metadata WHERE key='state'").fetchone()
        if committed:
            state=json.loads(committed[0])
            for split,handle in handles.items():
                expected=state['tokenCounts'][split]*2
                if os.fstat(handle.fileno()).st_size>=expected:handle.truncate(expected)
                handle.flush();os.fsync(handle.fileno())
            atomic_json(folder/'manifest.json',state)
        raise
    finally:
        for handle in handles.values():handle.close()
        db.close()


class PackedPool:
    """Full-context continuous spans; uint16 on disk, int64 only for sampled batches."""
    def __init__(self, path, context, documents):
        self.path=Path(path);self.context=context;self.rows=range(documents)
        if self.path.stat().st_size%2:raise ValueError('Invalid packed byte length')
        self.data=np.memmap(self.path,dtype='<u2',mode='r')
        if len(self.data)<context+1:raise ValueError('Not enough packed tokens for context')
    def sample(self,rng):
        start=rng.randrange(len(self.data)-self.context)
        values=torch.from_numpy(np.array(self.data[start:start+self.context+1],dtype=np.int64))
        return values[:-1],values[1:]
    def validation(self,maximum=24):
        import random
        rng=random.Random(1702026)
        return [self.sample(rng) for _ in range(maximum)]
    def close(self):self.data._mmap.close()
