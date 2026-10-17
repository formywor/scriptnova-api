import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {huggingFaceStorage} from '../lib/research-huggingface.mjs';
const env={NEBULA_HF_REPO:'owner/research',NEBULA_HF_TOKEN:'hf_test_only'};
const revision='b'.repeat(40),file={id:'12345678-1234-1234-1234-123456789abc',bytes:7,sha256:createHash('sha256').update('example').digest('hex')};
const json=value=>new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
test('HF tickets contain scoped paths and pinned downloads without credentials',async()=>{
  const service=huggingFaceStorage(env,async(url,options)=>{
    assert.equal(url,'https://huggingface.co/api/models/owner/research');
    assert.equal(options.headers.Authorization,'Bearer hf_test_only');
    return json({private:true,sha:revision});
  });
  const upload=await service.upload(file),download=await service.download(file);
  assert.deepEqual(upload,{provider:'huggingface',repo:env.NEBULA_HF_REPO,path:`checkpoints/${file.id}.pt`});
  assert.equal(download.revision,revision);assert.ok(!JSON.stringify(download).includes(env.NEBULA_HF_TOKEN));
});
test('HF refuses public repositories and sanitizes authentication errors',async()=>{
  await assert.rejects(()=>huggingFaceStorage(env,async()=>json({private:false,sha:revision})).upload(file),e=>e.code==='HF_REPOSITORY_MUST_BE_PRIVATE');
  await assert.rejects(()=>huggingFaceStorage(env,async()=>new Response('secret upstream text',{status:403})).upload(file),e=>e.code==='HF_ACCESS_DENIED'&&!e.message.includes('upstream'));
});
test('HF verifies LFS size and SHA-256 rather than trusting upload completion',async()=>{
  const service=huggingFaceStorage(env,async url=>url.endsWith(revision)?json([{path:`checkpoints/${file.id}.pt`,size:7,lfs:{size:7,oid:file.sha256}}]):json({private:true,sha:revision}));
  assert.equal(await service.verify(file),true);
  assert.equal(await service.verify({...file,sha256:'a'.repeat(64)}),false);
  assert.equal(await service.verify({...file,bytes:8}),false);
});
test('HF hashes regular Git blobs and never forwards auth across a redirect origin',async()=>{
  const fetcher=async url=>url.endsWith('/research')?json({private:true,sha:revision}):url.includes('/paths-info/')?json([{path:`checkpoints/${file.id}.pt`,size:7}]):new Response('example');
  assert.equal(await huggingFaceStorage(env,fetcher).verify(file),true);
  let calls=0;
  await assert.rejects(()=>huggingFaceStorage(env,async()=>{calls++;return new Response(null,{status:302,headers:{location:'https://evil.example/file'}});}).upload(file),e=>e.code==='HF_REDIRECT_REFUSED');
  assert.equal(calls,1);
});
test('HF cleanup tolerates a file already removed before an interrupted acknowledgement',async()=>{
  const calls=[];const service=huggingFaceStorage(env,async(url,options)=>{calls.push(options.method||'GET');return url.includes('paths-info')?json([]):json({private:true,sha:revision});});
  await service.remove(file);assert.deepEqual(calls,['GET','POST']);
});
