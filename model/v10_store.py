"""V10 snapshots: verified temporary downloads avoid an ever-growing local weight cache."""
import json,shutil,tempfile
from pathlib import Path
from v8_store import Store as LargeStore,MAX_BYTES
from research_client import ResearchError,digests

class Store(LargeStore):
    def download(self,file,destination):
        destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
        size=file.get('bytes',0)
        if not isinstance(size,int) or not 0<size<=MAX_BYTES:raise ResearchError('V10_INVALID_SNAPSHOT_SIZE')
        if destination.is_file() and destination.stat().st_size==size and digests(destination)[0]==file.get('sha256'):return destination
        temporary=destination.with_suffix(destination.suffix+'.download-tmp')
        try:
            with tempfile.TemporaryDirectory(dir=destination.parent,prefix='v10-download-') as folder:
                if 'parts' in file:
                    parts=file['parts']
                    if not isinstance(parts,list) or not 1<=len(parts)<=32 or sum(part.get('bytes',0) for part in parts)!=size:raise ResearchError('V10_INVALID_SHARDS')
                    with temporary.open('wb') as target:
                        for index,part in enumerate(parts):
                            local=self.download(part,Path(folder)/('part-'+str(index)))
                            with local.open('rb') as source:shutil.copyfileobj(source,target,1024*1024)
                            local.unlink()
                else:
                    from huggingface_hub import hf_hub_download
                    path=file.get('path','')
                    if not path.startswith(self.prefix) or '..' in path.split('/') or '\\' in path or size>256*1024*1024:raise ResearchError('V10_INVALID_SNAPSHOT_PATH')
                    try:cached=Path(hf_hub_download(self.repo,path,revision=self.revision,token=self.token,local_dir=folder))
                    except Exception:raise ResearchError('V10_DOWNLOAD_UNAVAILABLE') from None
                    if cached.stat().st_size!=size or digests(cached)[0]!=file.get('sha256'):raise ResearchError('V10_CHECKSUM_MISMATCH')
                    shutil.copyfile(cached,temporary)
            if temporary.stat().st_size!=size or digests(temporary)[0]!=file.get('sha256'):raise ResearchError('V10_CHECKSUM_MISMATCH')
            temporary.replace(destination);return destination
        except BaseException:
            temporary.unlink(missing_ok=True);raise
