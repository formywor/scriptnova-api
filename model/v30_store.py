"""Large RAM-only checkpoint objects; immutable, checksum-verified HF commits."""
import copy,json,time
from v18_stream import Hub as BaseHub,sha,emit
from v8_store import safe_server_detail

class Hub(BaseHub):

    def read_entry(self,entry,repo=None,revision=None,prefix=None):
            repo=repo or self.repo;revision=revision or self.revision;prefix=prefix or self.prefix
            if type(entry.get('bytes')) is not int or not 0<entry['bytes']<=8_589_934_592:raise ValueError('Invalid object size')
            parts=entry.get('parts',[entry])
            if not 1<=len(parts)<=128 or sum(p['bytes'] for p in parts)!=entry['bytes']:raise ValueError('Invalid object parts')
            data=bytearray()
            for part in parts:
                if not part['path'].startswith(prefix):raise ValueError('Unexpected object namespace')
                value=self.fetch(repo,part['path'],revision)
                if len(value)!=part['bytes'] or sha(value)!=part['sha256']:raise ValueError('Object part checksum mismatch')
                data.extend(value)
            if sha(data)!=entry['sha256']:raise ValueError('Object checksum mismatch')
            return data

    def publish(self,state,blobs=None,root_readme=None):
            from huggingface_hub import CommitOperationAdd
            result=copy.deepcopy(state);operations=[];blobs=blobs or {}
            for key,(name,blob) in blobs.items():
                if '..' in name.split('/') or name.startswith('/') or '\\' in name:raise ValueError('Invalid output name')
                size=len(blob)
                if not 0<size<=8_589_934_592:raise ValueError('Invalid output object size')
                identifier=sha(blob);parts=[]
                for offset in range(0,size,64*1024*1024):
                    chunk=bytes(memoryview(blob)[offset:offset+64*1024*1024])
                    remote=self.prefix+'objects/'+identifier+'/'+name+f'.part{len(parts):03d}.bin'
                    parts.append({'path':remote,'bytes':len(chunk),'sha256':sha(chunk)})
                    operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=chunk))
                result[key]={'bytes':size,'sha256':identifier,'parts':parts}
            # Raw object pointers added by the caller are resolved before this small atomic manifest.
            for split in ['train','validation','index']:
                key='_new_'+split
                if key in result:
                    result['corpus'][split].append(result.pop(key))
            operations.append(CommitOperationAdd(path_in_repo=self.prefix+'state.json',path_or_fileobj=json.dumps(result,indent=2).encode()))
            if root_readme:operations.append(CommitOperationAdd(path_in_repo='README.md',path_or_fileobj=root_readme.encode()))
            for attempt in range(4):
                try:
                    saved=self.api.create_commit(repo_id=self.repo,parent_commit=self.revision,operations=operations,commit_message='Save Nebula RAM-only raw experiment')
                    break
                except Exception as error:
                    response=getattr(error,'response',None);status=getattr(response,'status_code',None)
                    retry=status in [408,429,500,502,503,504] and attempt<3
                    emit(v18BackupFailed=True,httpStatus=status,serverDetail=safe_server_detail(error),retrying=retry)
                    if not retry:raise
                    time.sleep(min(60,5*2**attempt))
            self.revision=saved.oid
            if json.loads(self.fetch(self.repo,self.prefix+'state.json',self.revision))!=result:raise ValueError('Remote manifest verification failed')
            emit(v30PublicBackupConfirmed=True,revision=self.revision,steps=result.get('steps',{}),dataReady=result.get('dataReady',False),publicWebsiteUpdated=False)
            return result
