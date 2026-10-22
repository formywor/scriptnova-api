"""Atomic private manifests for large, sharded training checkpoints."""
import json
from pathlib import Path
import shutil
import tempfile
import time
import os
import re
from v4_store import Store as SmallStore
from research_client import ResearchError,digests

PART_BYTES=64*1024*1024
MAX_BYTES=2*1024*1024*1024

def safe_server_detail(error):
    """Expose the service's explanation, with credentials and URLs removed."""
    detail=getattr(error,'server_message',None)
    if not isinstance(detail,str) or not detail.strip():
        try:
            body=error.response.json()
            detail=body.get('error') or body.get('message') if isinstance(body,dict) else None
        except Exception:detail=None
    if not isinstance(detail,str):return 'No structured server explanation was provided.'
    for key,value in os.environ.items():
        if re.search(r'TOKEN|SECRET|PASSWORD|API_KEY',key,re.I) and len(value)>=6:
            detail=detail.replace(value,'[redacted]')
    detail=re.sub(r'https?://\S+','[URL removed]',detail)
    detail=re.sub(r'(?i)\b(?:hf_|gsk_|AIza)[A-Za-z0-9_.-]+','[redacted]',detail)
    detail=re.sub(r'(?i)(?:bearer\s+|(?:token|api[_-]?key|password|secret)\s*[:=]\s*)[^\s,;]+','[redacted]',detail)
    return ' '.join(detail.split())[:700]

class Store(SmallStore):
    def _commit_backup(self, operations):
        """Retry temporary failures with the SAME parent; never overwrite another writer."""
        for attempt in range(4):
            try:
                return self.api.create_commit(repo_id=self.repo,operations=operations,
                    commit_message='Save Nebula 100M experiment',parent_commit=self.revision)
            except Exception as error:
                response=getattr(error,'response',None)
                status=getattr(response,'status_code',None)
                # Do not expose exception text, response bodies, URLs, headers or credentials.
                status=status if type(status) is int else None
                network=any(kind.__name__ in {'Timeout','TimeoutError','ConnectTimeout','ReadTimeout',
                    'ConnectionError','ConnectError','ReadError','RemoteProtocolError'} for kind in type(error).__mro__)
                retryable=status in {408,429,500,502,503,504} or network
                reason=('CONCURRENT_OR_AMBIGUOUS_COMMIT' if status in {409,412} else
                        'ACCESS_DENIED' if status in {401,403} else
                        'REQUEST_REJECTED' if status in {400,413,422} else
                        'TEMPORARY_SERVICE_FAILURE' if retryable else 'UNCLASSIFIED_FAILURE')
                retry=retryable and attempt<3
                wait=5*(2**attempt)
                if status==429:
                    try:wait=max(wait,min(60,max(0,float(response.headers.get('Retry-After',0)))))
                    except (AttributeError,TypeError,ValueError):pass
                print(json.dumps({'backupFailed':True,'reason':reason,'httpStatus':status,
                    'attempt':attempt+1,'retrying':retry,'retryInSeconds':wait if retry else 0,
                    'serverDetail':safe_server_detail(error),
                    'localFilesPreserved':True}),flush=True)
                if not retry:
                    raise ResearchError('V8_BACKUP_FAILED_OR_CONCURRENT_RUN:'+reason) from None
                time.sleep(wait)

    def download(self,file,destination):
        if 'parts' not in file:return super().download(file,destination)
        if not 0<file.get('bytes',0)<=MAX_BYTES or not isinstance(file.get('parts'),list) or not 1<=len(file['parts'])<=32 or sum(p.get('bytes',0) for p in file['parts'])!=file['bytes']:
            raise ResearchError('V8_INVALID_SHARDED_CHECKPOINT')
        destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.is_file() and destination.stat().st_size==file['bytes'] and digests(destination)[0]==file['sha256']:return destination
        temporary=destination.with_suffix(destination.suffix+'.download-tmp')
        try:
            with tempfile.TemporaryDirectory(dir=destination.parent,prefix='v8-parts-') as folder:
                with temporary.open('wb') as output:
                    for i,part in enumerate(file['parts']):
                        local=super().download(part,Path(folder)/str(i))
                        with local.open('rb') as source:shutil.copyfileobj(source,output,1024*1024)
            if temporary.stat().st_size!=file['bytes'] or digests(temporary)[0]!=file['sha256']:raise ResearchError('V8_CHECKSUM_MISMATCH')
            temporary.replace(destination)
        except BaseException:
            temporary.unlink(missing_ok=True);raise
        return destination

    def publish(self,state,files,project,manifest_name='state.json'):
        from huggingface_hub import CommitOperationAdd
        if manifest_name!='state.json':raise ResearchError('V8_INVALID_MANIFEST')
        self.info();value=json.loads(json.dumps(state));operations=[]
        with tempfile.TemporaryDirectory(dir=project,prefix='v8-upload-') as folder:
            for key,(path,name) in files.items():
                path=Path(path);size=path.stat().st_size
                if '..' in name.split('/') or name.startswith('/') or '\\' in name or not 0<size<=MAX_BYTES:raise ResearchError('V8_INVALID_FILE_REFERENCE')
                # Use a recognized binary extension for SQLite snapshots and shards.
                # Local file names and existing manifests remain valid.
                if name.endswith('.sqlite'):name+='.bin'
                if size<=PART_BYTES:
                    remote=self.prefix+name
                    value[key]={'path':remote,'bytes':size,'sha256':digests(path)[0]}
                    operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=str(path)));continue
                parts=[]
                with path.open('rb') as source:
                    index=0
                    while chunk:=source.read(PART_BYTES):
                        local=Path(folder)/(key+'-'+str(index));local.write_bytes(chunk)
                        remote=self.prefix+name+f'.part{index:03d}.bin'
                        parts.append({'path':remote,'bytes':len(chunk),'sha256':digests(local)[0]})
                        operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=str(local)));index+=1
                value[key]={'bytes':size,'sha256':digests(path)[0],'parts':parts}
            manifest=Path(folder)/'state.json';manifest.write_text(json.dumps(value,indent=2),encoding='utf-8')
            operations.append(CommitOperationAdd(path_in_repo=self.prefix+manifest_name,path_or_fileobj=str(manifest)))
            result=self._commit_backup(operations)
        self.revision=result.oid
        print(json.dumps({'v8BackupSaved':True,'round':value.get('round',0),'publicWebsiteUpdated':False}),flush=True)
        return value
