"""Private, atomic HF artifacts: RAM buffers -> immutable parts -> manifest. No local model/data cache."""
import copy,hashlib,json,re,io
from urllib.parse import quote

def sha(b):return hashlib.sha256(b).hexdigest()
class Hub:
    def __init__(self,repo,token,run='nebula-vd2-1b-code'):
        import requests
        from huggingface_hub import HfApi
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'nebula-vd2-[\w-]{1,50}',run):raise ValueError('Invalid output namespace')
        self.repo=repo;self.token=token;self.api=HfApi(token=token);self.session=requests.Session();self.prefix='experiments/'+run+'/'
        if self.api.whoami()['name']!=repo.split('/')[0]:raise ValueError('Output must belong to the token owner')
        self.api.create_repo(repo,repo_type='model',private=True,exist_ok=True)
        info=self.api.model_info(repo)
        if not info.private:raise ValueError('Owner-only weights require a PRIVATE output repository; source repositories remain unchanged')
        self.revision=info.sha
    def fetch(self,repo,path,revision,max_bytes=160000000):
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or '..' in path.split('/') or path.startswith('/'):raise ValueError('Invalid source path')
        url=f'https://huggingface.co/{repo}/resolve/{quote(revision,safe="")}/{quote(path,safe="/")}'
        with self.session.get(url,headers={'Authorization':'Bearer '+self.token},timeout=(30,180),stream=True) as r:
            r.raise_for_status();out=bytearray()
            for chunk in r.iter_content(1024*1024):
                out.extend(chunk)
                if len(out)>max_bytes:raise ValueError('Object exceeds declared RAM limit')
            return bytes(out)
    def read_entry(self,repo,revision,entry):
        if not 0<entry['bytes']<=20_000_000_000:raise ValueError('Invalid object size')
        out=io.BytesIO()
        for p in entry.get('parts',[entry]):
            data=self.fetch(repo,p['path'],revision,max_bytes=p['bytes'])
            if len(data)!=p['bytes'] or sha(data)!=p['sha256']:raise ValueError('Source checksum mismatch')
            out.write(data)
        data=out.getvalue()
        if len(data)!=entry['bytes'] or sha(data)!=entry['sha256']:raise ValueError('Combined checksum mismatch')
        return data
    def state(self):
        import requests
        try:return json.loads(self.fetch(self.repo,self.prefix+'state.json',self.revision,2_000_000))
        except requests.HTTPError as e:
            if e.response.status_code==404:return None
            raise
    def publish(self,state,artifacts):
        from huggingface_hub import CommitOperationAdd
        next=copy.deepcopy(state);ops=[]
        for key,value in artifacts.items():
            view=value.getbuffer() if isinstance(value,io.BytesIO) else memoryview(value)
            digest=hashlib.sha256(view).hexdigest();parts=[]
            for i,start in enumerate(range(0,len(view),64*1024*1024)):
                b=bytes(view[start:start+64*1024*1024]);path=self.prefix+'objects/'+digest+f'/part-{i:04d}.bin'
                parts.append(dict(path=path,bytes=len(b),sha256=sha(b)));ops.append(CommitOperationAdd(path_in_repo=path,path_or_fileobj=b))
            next[key]=dict(bytes=len(view),sha256=digest,parts=parts)
        ops.append(CommitOperationAdd(path_in_repo=self.prefix+'state.json',path_or_fileobj=json.dumps(next,indent=2).encode()))
        commit=self.api.create_commit(repo_id=self.repo,parent_commit=self.revision,operations=ops,commit_message='V-D2 owner-only data/checkpoint backup')
        self.revision=commit.oid
        if json.loads(self.fetch(self.repo,self.prefix+'state.json',self.revision,2_000_000))!=next:raise ValueError('Backup verification failed')
        print(json.dumps(dict(vd2BackupConfirmed=True,revision=self.revision,updates=next.get('updates',0),private=True,websiteUpdated=False)),flush=True)
        return next
