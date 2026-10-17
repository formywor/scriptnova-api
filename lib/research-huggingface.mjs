import {createHash} from 'node:crypto';

const fail=code=>{throw Object.assign(new Error(code),{code,status:503});};
export function huggingFaceStorage(env=process.env,fetcher=fetch){
  const repo=env.NEBULA_HF_REPO,token=env.NEBULA_HF_TOKEN;
  if(!/^[\w-]+\/[\w.-]+$/.test(repo||'')||!token?.startsWith('hf_'))fail('HF_CONFIGURATION_MISSING');
  const api=`https://huggingface.co/api/models/${repo}`;
  const path=file=>`checkpoints/${file.id}.pt`;
  async function request(url,options={},hop=0){
    let response;
    try{response=await fetcher(url,{...options,headers:{...options.headers,Authorization:`Bearer ${token}`},redirect:'manual',signal:AbortSignal.timeout(30000)});}
    catch{fail('HF_STORAGE_UNREACHABLE');}
    if([301,302,303,307,308].includes(response.status)){
      const target=new URL(response.headers.get('location')||'',url);
      if(hop>=3||target.origin!=='https://huggingface.co'||target.username||target.password||options.method&&options.method!=='GET')fail('HF_REDIRECT_REFUSED');
      return request(target.href,options,hop+1);
    }
    if(!response.ok)fail(response.status===401||response.status===403?'HF_ACCESS_DENIED':'HF_STORAGE_FAILED');
    return response;
  }
  async function privateRevision(){
    const info=await (await request(api)).json();
    if(info.private!==true)fail('HF_REPOSITORY_MUST_BE_PRIVATE');
    if(!/^[a-f0-9]{40}$/.test(info.sha||''))fail('HF_REVISION_INVALID');
    return info.sha;
  }
  return {
    async upload(file){await privateRevision();return {provider:'huggingface',repo,path:path(file)};},
    async verify(file){
      const revision=await privateRevision();
      const entries=await (await request(`${api}/paths-info/${revision}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:[path(file)]})})).json();
      const entry=entries.find(x=>x.path===path(file));
      if(!entry||entry.size!==file.bytes)return false;
      if(entry.lfs)return entry.lfs.oid===file.sha256&&entry.lfs.size===file.bytes;
      // Small files may be regular Git blobs; hash the bytes instead of trusting a Git SHA-1.
      const response=await request(`https://huggingface.co/${repo}/resolve/${revision}/${path(file)}`);
      const hash=createHash('sha256');let bytes=0;
      for await(const chunk of response.body){bytes+=chunk.length;if(bytes>file.bytes)return false;hash.update(chunk);}
      return bytes===file.bytes&&hash.digest('hex')===file.sha256;
    },
    async download(file){return {provider:'huggingface',repo,path:path(file),revision:await privateRevision()};},
    async remove(file){
      const revision=await privateRevision();
      const entries=await (await request(`${api}/paths-info/${revision}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:[path(file)]})})).json();
      if(!entries.some(x=>x.path===path(file)))return;
      const records=[{key:'header',value:{summary:'Prune inactive Nebula research checkpoint'}},{key:'deletedFile',value:{path:path(file)}}];
      await request(`${api}/commit/main`,{method:'POST',headers:{'Content-Type':'application/x-ndjson'},body:records.map(x=>JSON.stringify(x)).join('\n')+'\n'});
    },
  };
}
