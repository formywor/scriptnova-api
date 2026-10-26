"""V-D2 data admission, provenance, deduplication and holdout isolation. No torch dependency."""
import hashlib,json,re,io,gzip,struct,unicodedata
SECRET=re.compile(r'\b(?:hf_|gsk_|sk-|AIza)[A-Za-z0-9_-]{18,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._-]{20,}')
SPECIAL=['<|n27_pad|>','<|n27_bos|>','<|n27_eos|>','<|n27_system|>','<|n27_user|>','<|n27_assistant|>','<|fim_prefix|>','<|fim_suffix|>','<|fim_middle|>']
def sha(b):return hashlib.sha256(b).hexdigest()

def source_split(source):
    # Historical manifests use camelCase names, including publicHoldout.
    names=' '.join([str(source.get('key','')),str(source.get('state','')),str(source.get('entry',{}).get('path',''))]+[str(p.get('path','')) for p in source.get('entry',{}).get('parts',[])]).lower()
    return 'validation' if source.get('split')=='validation' or any(x in names for x in ['validation','heldout','held-out','held_out','holdout','hold-out','hold_out']) else 'train'
def parameter_count(vocab=8192,width=1536,layers=35,context=2048):return vocab*width+context*width+layers*(12*width*width+13*width)+2*width

def pointers(value,trail=()):
    if isinstance(value,dict):
        if type(value.get('bytes')) is int and isinstance(value.get('sha256'),str) and ('path' in value or 'parts' in value):yield trail,value
        else:
            for k,v in value.items():yield from pointers(v,trail+(str(k),))
    elif isinstance(value,list):
        for i,v in enumerate(value):yield from pointers(v,trail+(str(i),))

def candidates(repo,revision,state_path,state):
    out=[]
    for keys,entry in pointers(state):
        name='/'.join(keys);path=entry.get('path') or entry.get('parts',[{}])[0].get('path','');s=(name+' '+path).lower()
        if any(x in s for x in ['eval','probe','checks','judge','rules','report','card-','license','index','sourcecard','baseline']):continue
        kind='jsonl' if '.jsonl' in path else 'bpe-u16' if name in ['trainTokens','validationTokens'] else 'bytes-u16' if name.startswith('corpus/train/') or name.startswith('corpus/validation/') else None
        if not kind:continue
        source=dict(repo=repo,revision=revision,state=state_path,key=name,entry=entry,format=kind,tokenizer=state.get('tokenizer') if kind=='bpe-u16' else None,approved=False,license='',origin='historical-unreviewed')
        source['split']=source_split(source);out.append(source)
    return out

def texts(blob,kind,tokenizer=None):
    if kind=='jsonl':
        for line in blob.decode('utf-8',errors='strict').splitlines():
            if not line.strip():continue
            r=json.loads(line)
            if not isinstance(r,dict):continue
            if (isinstance(r.get('source'),dict) and r['source'].get('kind')=='user') or r.get('origin') in ['user-chat','review-feed']:continue
            if isinstance(r.get('text'),str):yield r['text']
            elif isinstance(r.get('code'),str):yield r['code']
            elif isinstance(r.get('messages'),list):
                # Preserve whole approved conversations as code documentation, not a new chat objective.
                messages=r['messages']
                if all(isinstance(m,dict) and m.get('role') in ['system','user','assistant'] and isinstance(m.get('content'),str) for m in messages):
                    yield '\n\n'.join(m['content'] for m in messages)
    elif kind in ['bytes-u16','bpe-u16']:
        if len(blob)%2:raise ValueError('Unaligned uint16 corpus')
        chunk=[]
        for (token,) in struct.iter_unpack('<H',blob):
            boundary=token>=256 if kind=='bytes-u16' else token<6
            if boundary:
                if chunk:yield bytes(chunk).decode('utf-8',errors='strict') if kind=='bytes-u16' else tokenizer.decode(chunk,skip_special_tokens=True)
                chunk=[]
            else:chunk.append(token)
        if chunk:yield bytes(chunk).decode('utf-8',errors='strict') if kind=='bytes-u16' else tokenizer.decode(chunk,skip_special_tokens=True)
    else:raise ValueError('Unsupported encoding: '+kind)

def clean(text):
    text=unicodedata.normalize('NFC',text.replace('\r\n','\n')).strip()
    if not 60<=len(text)<=150000 or SECRET.search(text) or '\ufffd' in text or any(x in text for x in SPECIAL):return None
    if any(ord(c)<32 and c not in '\n\t\r' for c in text):return None
    return text

def category(text):
    if re.search(r'(?m)^\s*(?:def |class |import |from \w+ import |function |export |const |let |public |package |#include|SELECT |CREATE TABLE)|```(?:python|py|javascript|js|typescript|ts|sql|rust|go|java|cpp|html)',text):return 'code'
    if re.search(r'\b(?:unit test|regression test|SQL injection|authorization|authentication|parameterized|compiler|algorithm|data structure|HTTP|database|API|function|programming)\b',text,re.I):return 'docs'
    return 'general'

class Corpus:
    def __init__(self,max_bytes=256_000_000):self.records={};self.bytes=0;self.max_bytes=max_bytes;self.rejected={}
    def add(self,text,source):
        text=clean(text)
        if text is None:self.rejected['invalid-or-secret']=self.rejected.get('invalid-or-secret',0)+1;return
        if not source.get('approved') or not source.get('license') or source.get('origin') in ['user-chat','review-feed','historical-unreviewed']:raise ValueError('Explicit provenance and license review required')
        fingerprint=sha(re.sub(r'\s+',' ',text).encode());split='validation' if source_split(source)=='validation' or int(fingerprint[:8],16)%50==0 else 'train'
        if fingerprint in self.records:
            if split=='validation':self.records[fingerprint]['split']='validation'
            return
        size=len(text.encode())
        if self.bytes+size>self.max_bytes:raise ValueError('RAM corpus budget reached; reduce source selection or increase deliberate budget')
        self.records[fingerprint]=dict(id=fingerprint,text=text,split=split,category=category(text),source={k:source[k] for k in ['repo','revision','key','license','origin']});self.bytes+=size
    def summary(self):
        counts={}
        for r in self.records.values():k=r['split']+'/'+r['category'];counts[k]=counts.get(k,0)+1
        return dict(documents=len(self.records),uniqueUtf8Bytes=self.bytes,counts=counts,rejected=self.rejected)
    def payload(self):return '\n'.join(json.dumps(r,ensure_ascii=False) for r in self.records.values()).encode()
