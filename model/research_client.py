"""Private worker protocol. Tokens never go to object-storage URLs or logs."""
import base64
import hashlib
import os
from pathlib import Path
from urllib.parse import urlparse
import requests

class ResearchError(RuntimeError):
    def __init__(self,code,status=0):super().__init__(str(code));self.code=code;self.status=status

def digests(path):
    sha=hashlib.sha256();md5=hashlib.md5(usedforsecurity=False)
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):sha.update(chunk);md5.update(chunk)
    return sha.hexdigest(),base64.b64encode(md5.digest()).decode()

def storage_url(url):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or not (
            parsed.hostname=='storage.googleapis.com' or (parsed.hostname or '').endswith('.storage.googleapis.com')):
        raise ResearchError('UNEXPECTED_STORAGE_HOST')
    return url

class Client:
    def __init__(self,api=None,token=None):
        self.api=(api or os.environ.get('NEBULA_RESEARCH_API','')).rstrip('/')
        self.token=token or os.environ.get('NEBULA_WORKER_TOKEN','')
        parsed=urlparse(self.api)
        if parsed.scheme!='https' or parsed.username or parsed.password or parsed.query or parsed.fragment or len(self.token)<32:
            raise ResearchError('WORKER_CONFIGURATION_MISSING')
    def call(self,action,body=None):
        try:
            response=requests.request('GET' if body is None else 'POST',self.api+'/'+action,
                headers={'Authorization':'Bearer '+self.token},json=body,timeout=45,allow_redirects=False)
            value=response.json()
        except Exception:raise ResearchError('COORDINATOR_UNREACHABLE') from None
        if response.status_code!=200:raise ResearchError(value.get('code','COORDINATOR_FAILED'),response.status_code)
        return value
    def download(self,identifier,destination):
        ticket=self.call('download',{'id':identifier});url=storage_url(ticket['url'])
        path=Path(destination);path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists() and path.stat().st_size==ticket['bytes'] and digests(path)[0]==ticket['sha256']:return path
        temporary=path.with_suffix(path.suffix+'.download-tmp');sha=hashlib.sha256();count=0
        try:
            with requests.get(url,stream=True,timeout=90,allow_redirects=False) as response:
                if response.status_code!=200:raise ResearchError('CHECKPOINT_DOWNLOAD_FAILED')
                with temporary.open('wb') as stream:
                    for chunk in response.iter_content(1024*1024):
                        count+=len(chunk)
                        if count>ticket['bytes'] or count>100*1024*1024:raise ResearchError('CHECKPOINT_SIZE_MISMATCH')
                        sha.update(chunk);stream.write(chunk)
            if count!=ticket['bytes'] or sha.hexdigest()!=ticket['sha256']:raise ResearchError('CHECKPOINT_CHECKSUM_MISMATCH')
            temporary.replace(path);return path
        except ResearchError:raise
        except Exception:raise ResearchError('CHECKPOINT_DOWNLOAD_FAILED') from None
    def upload(self,path,kind='checkpoint',parent=None,lease=None):
        path=Path(path);sha,md5=digests(path)
        ticket=self.call('upload',{'kind':kind,'bytes':path.stat().st_size,'sha256':sha,'md5':md5,
                                   'parent':parent,'lease':lease})
        try:
            with path.open('rb') as stream:
                response=requests.put(storage_url(ticket['url']),data=stream,headers=ticket['headers'],timeout=180,allow_redirects=False)
                # A timeout or retry may occur after an upload succeeded. The
                # coordinator checks the immutable object before accepting it.
                if response.status_code not in [200,201,412]:raise ResearchError('CHECKPOINT_UPLOAD_FAILED')
        except Exception:
            try:self.call('finish',{'id':ticket['id']})
            except Exception:raise ResearchError('CHECKPOINT_UPLOAD_FAILED') from None
        else:self.call('finish',{'id':ticket['id']})
        return ticket['id']
