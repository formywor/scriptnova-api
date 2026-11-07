import hashlib,hmac,json,re,urllib.request
from pathlib import Path


def authorized(provided,expected):
    return isinstance(expected,str) and len(expected)>=32 and isinstance(provided,str) and hmac.compare_digest(provided,expected)


def download(entry,manifest,directory):
    size=entry.get('bytes');digest=entry.get('sha256','')
    if type(size)is not int or not 0<size<=5_000_000_000 or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid artifact manifest')
    target=Path(directory)/digest;target.parent.mkdir(parents=True,exist_ok=True)
    def hashed(path):
        out=hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda:source.read(1024*1024),b''):out.update(chunk)
        return out.hexdigest()
    if target.exists() and target.stat().st_size==size and hashed(target)==digest:return target
    pending=target.with_suffix('.partial');total=0;combined=hashlib.sha256()
    try:
        with pending.open('wb') as output:
            parts=entry.get('parts',[entry])
            for index,part in enumerate(parts):
                path=part.get('path','');expected=part.get('bytes')
                if not path.startswith('experiments/nebula-vd2-') or '..' in path.split('/') or type(expected)is not int or not 0<expected<=size:raise ValueError('Invalid artifact part')
                url='https://huggingface.co/'+manifest['repo']+'/resolve/'+manifest['revision']+'/'+path
                seen=0;checksum=hashlib.sha256()
                with urllib.request.urlopen(url,timeout=180) as response:
                    while True:
                        chunk=response.read(1024*1024)
                        if not chunk:break
                        seen+=len(chunk);total+=len(chunk)
                        if seen>expected or total>size:raise ValueError('Artifact size mismatch')
                        checksum.update(chunk);combined.update(chunk);output.write(chunk)
                if seen!=expected or checksum.hexdigest()!=part['sha256']:raise ValueError('Artifact checksum mismatch')
                print('D2_LITE_PART_VERIFIED',index+1,len(parts),total,flush=True)
        if total!=size or combined.hexdigest()!=digest:raise ValueError('Combined artifact mismatch')
        pending.replace(target);return target
    except BaseException:
        pending.unlink(missing_ok=True);raise


def validate_payload(value):
    if not isinstance(value,dict) or value.get('model')!='nebula-v-d2':raise ValueError('Invalid model')
    messages=value.get('messages');limit=value.get('maxNewTokens')
    if not isinstance(messages,list) or len(messages)!=2 or [m.get('role') for m in messages]!=['system','user']:raise ValueError('Invalid messages')
    if any(not isinstance(m.get('content'),str) for m in messages) or sum(len(m['content']) for m in messages)>6000:raise ValueError('Invalid content')
    if type(limit)is not int or not 1<=limit<=2048:raise ValueError('Invalid output limit')
    return messages,min(limit,128)
