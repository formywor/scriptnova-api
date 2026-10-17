"""Private experiment snapshots, committed atomically with a resume manifest."""
import hashlib
import json
from pathlib import Path
import re
import shutil
from research_client import ResearchError,digests

class Store:
    def __init__(self,repo,token,run):
        if not re.fullmatch(r'[\w-]+/[\w.-]+',repo) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',run) or not token.startswith('hf_'):
            raise ResearchError('V4_STORAGE_CONFIGURATION_MISSING')
        from huggingface_hub import HfApi
        self.repo=repo;self.token=token;self.prefix='experiments/'+run+'/'
        self.api=HfApi(endpoint='https://huggingface.co',token=token)
        self.revision=self.info().sha
    def info(self):
        try:value=self.api.model_info(self.repo)
        except Exception:raise ResearchError('V4_STORAGE_ACCESS_FAILED') from None
        if value.private is not True:raise ResearchError('HF_REPOSITORY_MUST_BE_PRIVATE')
        return value
    def state(self,manifest_name='state.json'):
        if manifest_name not in ['state.json','prepared.json']:raise ResearchError('V4_INVALID_FILE_REFERENCE')
        from huggingface_hub import hf_hub_download
        from huggingface_hub.errors import EntryNotFoundError
        try:
            path=hf_hub_download(self.repo,self.prefix+manifest_name,revision=self.revision,token=self.token)
            return json.loads(Path(path).read_text(encoding='utf-8'))
        except EntryNotFoundError:return None
        except Exception:raise ResearchError('V4_RESUME_MANIFEST_UNREADABLE') from None
    def download(self,file,destination):
        from huggingface_hub import hf_hub_download
        if not file['path'].startswith(self.prefix) or '..' in file['path'].split('/') or not 0<file['bytes']<=256*1024*1024:
            raise ResearchError('V4_INVALID_FILE_REFERENCE')
        destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists() and destination.stat().st_size==file['bytes'] and digests(destination)[0]==file['sha256']:return destination
        try:cached=Path(hf_hub_download(self.repo,file['path'],revision=self.revision,token=self.token))
        except Exception:raise ResearchError('V4_SNAPSHOT_DOWNLOAD_FAILED') from None
        if cached.stat().st_size!=file['bytes'] or digests(cached)[0]!=file['sha256']:raise ResearchError('V4_CHECKSUM_MISMATCH')
        temporary=destination.with_suffix(destination.suffix+'.download-tmp');shutil.copyfile(cached,temporary);temporary.replace(destination)
        return destination
    def publish(self,state,files,project,manifest_name='state.json'):
        if manifest_name not in ['state.json','prepared.json']:raise ResearchError('V4_INVALID_FILE_REFERENCE')
        from huggingface_hub import CommitOperationAdd
        self.info();operations=[];state=json.loads(json.dumps(state))
        for key,(path,name) in files.items():
            path=Path(path)
            if '..' in name.split('/') or name.startswith('/') or '\\' in name:raise ResearchError('V4_INVALID_FILE_REFERENCE')
            if not 0<path.stat().st_size<=256*1024*1024:raise ResearchError('V4_SNAPSHOT_TOO_LARGE')
            remote=self.prefix+name
            state[key]={'path':remote,'bytes':path.stat().st_size,'sha256':digests(path)[0]}
            operations.append(CommitOperationAdd(path_in_repo=remote,path_or_fileobj=str(path)))
        manifest=Path(project)/('v4-'+manifest_name);manifest.write_text(json.dumps(state,indent=2),encoding='utf-8')
        operations.append(CommitOperationAdd(path_in_repo=self.prefix+manifest_name,path_or_fileobj=str(manifest)))
        try:
            result=self.api.create_commit(repo_id=self.repo,operations=operations,
                commit_message='Save bounded Nebula V4 experiment',parent_commit=self.revision)
        except Exception:raise ResearchError('V4_BACKUP_FAILED_OR_CONCURRENT_RUN') from None
        self.revision=result.oid
        print(json.dumps({'v4BackupSaved':True,'round':state.get('round',0),'publicWebsiteUpdated':False}),flush=True)
        return state
