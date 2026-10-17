import {test} from 'node:test';
import assert from 'node:assert/strict';
import {acceptable,BENCHMARK,changeResearch,createResearchHandler} from '../lib/research.mjs';
import {createResearchStorage} from '../lib/research-storage.mjs';
import {memoryDatabase} from './helpers/database.mjs';

const time=1700000000000;
const descriptor={kind:'checkpoint',bytes:100,sha256:'a'.repeat(64),md5:Buffer.alloc(16).toString('base64')};
const score=(patch={})=>({benchmark:BENCHMARK,loss:1,identity:.5,math:.5,memory:.5,extraction:.5,health:1,...patch});
function seeded(){
  let state;
  for(const [id,kind] of [['data','dataset'],['base','checkpoint']]){
    state=changeResearch(state,'trainer','upload',{...descriptor,kind},time,id);
    state=changeResearch(state,'trainer','finish',{id},time);
  }
  return changeResearch(state,'trainer','seed',{dataset:'data',checkpoint:'base',dataSha256:'b'.repeat(64)},time);
}
function submitted(){
  let state=changeResearch(seeded(),'trainer','claim',{},time,'trainer-lease');
  state=changeResearch(state,'trainer','upload',{...descriptor,parent:'base',lease:'trainer-lease'},time,'trained');
  state=changeResearch(state,'trainer','finish',{id:'trained'},time);
  return changeResearch(state,'trainer','submit',{id:'trained',lease:'trainer-lease'},time);
}
test('only one trainer lease exists and stale worker cannot submit',()=>{
  let state=seeded();state=changeResearch(state,'trainer','claim',{},time,'one');
  assert.throws(()=>changeResearch(state,'trainer','claim',{},time,'two'),e=>e.code==='WORKER_BUSY');
  const renewed=changeResearch(state,'trainer','claim',{},time+11*60000,'two');
  assert.throws(()=>changeResearch(renewed,'trainer','heartbeat',{lease:'one'},time+11*60000),e=>e.code==='LEASE_LOST');
  assert.throws(()=>changeResearch(renewed,'evaluator','heartbeat',{lease:'two'},time+11*60000),e=>e.code==='LEASE_LOST');
});
test('evaluator selects verified experiment using compare-and-swap parent checks',()=>{
  let state=changeResearch(submitted(),'evaluator','claim',{},time,'evaluation');
  assert.throws(()=>changeResearch(state,'evaluator','upload',{...descriptor,parent:'base',lease:'evaluation'},time,'wrong'),e=>e.code==='STALE_PARENT');
  state=changeResearch(state,'evaluator','upload',{...descriptor,parent:'trained',lease:'evaluation'},time,'experiment');
  state=changeResearch(state,'evaluator','finish',{id:'experiment'},time);
  const body={lease:'evaluation',candidate:'trained',baseline:score(),trained:score({identity:.75}),experiment:{id:'experiment',report:score({identity:.75,memory:.75})}};
  state=changeResearch(state,'evaluator','decide',body,time);
  assert.equal(state.head,'experiment');assert.equal(state.candidate,null);assert.equal(state.revision,2);
  assert.throws(()=>changeResearch(state,'evaluator','decide',body,time),e=>e.code==='LEASE_LOST');
});
test('regressions and non-finite metrics cannot promote a model',()=>{
  assert.equal(acceptable(score(),score({loss:.5,memory:0})),false);
  assert.equal(acceptable(score(),score({loss:.9,health:.5})),false);
  assert.equal(acceptable(score(),score({loss:.99})),true);
  assert.throws(()=>acceptable(score(),score({loss:NaN})),e=>e.code==='INVALID_REPORT');
  let state=changeResearch(submitted(),'evaluator','claim',{},time,'eval');
  state=changeResearch(state,'evaluator','decide',{lease:'eval',candidate:'trained',baseline:score(),trained:score({memory:0})},time);
  assert.equal(state.head,'base');assert.equal(state.rejectedRounds,1);
});
test('uploads are bounded and cannot overwrite another role or seed a running campaign',()=>{
  assert.throws(()=>changeResearch(null,'evaluator','upload',descriptor,time),e=>e.code==='FORBIDDEN');
  assert.throws(()=>changeResearch(null,'trainer','upload',{...descriptor,bytes:200*1024*1024},time),e=>e.code==='INVALID_UPLOAD');
  assert.throws(()=>changeResearch(seeded(),'trainer','seed',{},time),e=>e.code==='ALREADY_INITIALIZED');
});
test('private worker API rejects browser and wrong-role credentials and stays disabled by default',async()=>{
  let state=seeded();const env={NEBULA_RESEARCH_ENABLED:'true',NEBULA_TRAINER_TOKEN:'t'.repeat(40),NEBULA_EVALUATOR_TOKEN:'e'.repeat(40)};
  const services=async()=>({read:async()=>state,update:async fn=>state=fn(state),verify:async()=>true,
    upload:async()=>({url:'https://storage.googleapis.com/private'}),download:async()=> 'https://storage.googleapis.com/private',remove:async()=>{}});
  const handler=createResearchHandler({services,env,now:()=>time});
  const request=(action,body,token=env.NEBULA_TRAINER_TOKEN,origin)=>new Request('https://api.test/api/nebula/research/'+action,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{}),...(origin?{origin}:{})},...(body?{body:JSON.stringify(body)}:{})});
  assert.equal((await handler(request('state',null,'wrong'))).status,401);
  assert.equal((await handler(request('state',null,env.NEBULA_TRAINER_TOKEN,'https://scriptnovaa.com'))).status,403);
  assert.equal((await handler(request('state'))).status,200);
  assert.equal((await handler(request('claim',{},env.NEBULA_EVALUATOR_TOKEN))).status,409);
  const disabled=createResearchHandler({services,env:{}});
  assert.equal((await disabled(request('state'))).status,503);
});
test('cold database transactions recover the real research state before checking a lease',async()=>{
  const {db}=memoryDatabase({coldTransactions:true});
  await db.ref('nebulaResearch/v1/main').set(seeded());
  const service=createResearchStorage(db,{});
  const state=await service.update(old=>changeResearch(old,'trainer','claim',{},time,'cold-lease'));
  assert.equal(state.head,'base');assert.equal(state.lease.id,'cold-lease');
  await assert.rejects(()=>service.update(old=>changeResearch(old,'evaluator','heartbeat',{lease:'cold-lease'},time)),e=>e.code==='LEASE_LOST');
  assert.equal((await service.read()).head,'base');
});
test('signed uploads bind size, digest and create-only generation, and metadata must match',async()=>{
  const {db}=memoryDatabase();let signing;
  const file={...descriptor,id:'object',expiresAt:time+1000};
  const bucket={file:path=>{
    assert.equal(path,'nebula-research/v1/object.pt');
    return {getSignedUrl:async options=>{signing=options;return ['https://storage.googleapis.com/private'];},
      getMetadata:async()=>[{size:'100',md5Hash:descriptor.md5,metadata:{sha256:descriptor.sha256}}]};
  }};
  const service=createResearchStorage(db,bucket);const ticket=await service.upload(file);
  assert.equal(signing.contentMd5,descriptor.md5);assert.equal(signing.extensionHeaders['content-length'],'100');
  assert.equal(signing.extensionHeaders['x-goog-if-generation-match'],'0');
  assert.equal(ticket.headers['content-md5'],descriptor.md5);assert.equal(await service.verify(file),true);
  assert.equal(await service.verify({...file,bytes:99}),false);
});
