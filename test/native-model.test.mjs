import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync,mkdtempSync,writeFileSync,unlinkSync,rmdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {NativeNebula,packPrompt,loadReleaseArtifact} from '../lib/native-model.mjs';
import {createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const asset=new URL('../model-assets/nebula-pilot.json',import.meta.url);
test('embedded model keeps system rules and latest UTF-8 question or rejects context overflow',()=>{
 const prompt=packPrompt([{role:'system',content:'OWNER'},{role:'user',content:'old'.repeat(80)},{role:'user',content:'Hi ☃'}],48);assert.equal(prompt[0],256);assert.equal(prompt[1],258);assert.equal(prompt.at(-1),260);assert.match(Buffer.from(prompt.filter(v=>v<256)).toString(),/Hi ☃/);assert.throws(()=>packPrompt([{role:'system',content:'x'.repeat(100)},{role:'user',content:'Hi'}],48));
});
test('malformed model artifacts fail before inference',()=>{assert.throws(()=>new NativeNebula({format:0}));assert.throws(()=>new NativeNebula({format:1,config:{width:64,heads:3,layers:1,context:256}}));});

test('a corrupt release shard fails closed before JSON decoding or inference',()=>{
 const directory=mkdtempSync(join(tmpdir(),'nebula-release-')),manifest=join(directory,'release.json'),part=join(directory,'nebula-test-01.part');
 try{
  writeFileSync(part,'bad');writeFileSync(manifest,JSON.stringify({asset:'nebula-test.json',shards:['nebula-test-01.part'],bytes:3,sha256:'0'.repeat(64)}));
  assert.throws(()=>loadReleaseArtifact(pathToFileURL(directory+'/')),error=>error.code==='MODEL_RELEASE_CHECKSUM_MISMATCH');
 }finally{unlinkSync(part);unlinkSync(manifest);rmdirSync(directory);}
});

test('experimental release pins the strongest V4 weights and supports ten layers',()=>{
 const {release,artifact}=loadReleaseArtifact();
 assert.ok(release.shards.length>1);
 const model=new NativeNebula(artifact);assert.equal(model.config.layers,10);assert.equal(model.metadata.parameters,8227328);
 const reference=JSON.parse(readFileSync(new URL('./fixtures/v4-native-reference.json',import.meta.url)));
 const actual=model.logits(reference.tokens);
 assert.ok(Math.max(...actual.map((v,i)=>Math.abs(v-reference.logits[i])))<.001);
 assert.equal(release.experimental,true);assert.equal(release.automaticPromotion,false);
 assert.throws(()=>model.reply([{role:'user',content:'Hi'}],{maxMilliseconds:-1}),error=>error.code==='MODEL_INFERENCE_TIMEOUT');
 assert.throws(()=>model.reply([{role:'user',content:'x'.repeat(1100)}]),error=>error.code==='MODEL_CONTEXT_LIMIT');
});

test('missing manifest and missing parts produce distinct sanitized deployment reasons',()=>{
 const directory=mkdtempSync(join(tmpdir(),'nebula-missing-release-')),manifest=join(directory,'release.json');
 try{
  assert.throws(()=>loadReleaseArtifact(pathToFileURL(directory+'/')),error=>error.code==='MODEL_RELEASE_MISSING');
  writeFileSync(manifest,JSON.stringify({asset:'nebula-test.json',shards:['nebula-test-01.part'],bytes:3,sha256:'0'.repeat(64)}));
  assert.throws(()=>loadReleaseArtifact(pathToFileURL(directory+'/')),error=>error.code==='MODEL_SHARD_MISSING');
 }finally{if(existsSync(manifest))unlinkSync(manifest);rmdirSync(directory);}
});
test('native Transformer agrees with independent PyTorch reference logits',{skip:!existsSync(asset)},()=>{
 const model=new NativeNebula(JSON.parse(readFileSync(asset,'utf8'))),reference=JSON.parse(readFileSync(new URL('./fixtures/native-reference.json',import.meta.url),'utf8'));assert.deepEqual(packPrompt(reference.messages,model.config.context),reference.tokens);const actual=model.logits(reference.tokens);assert.ok(Math.max(...actual.map((v,i)=>Math.abs(v-reference.logits[i])))<.0001);assert.ok(model.reply(reference.messages,{temperature:0}).length>0);
});
test('public chat requires Ultra configuration even when embedded artifacts exist',async()=>{
 const{db}=memoryDatabase();const app=createApp({getStore:async()=>createStore(db),config:{origins:[],rateSecret:'s'.repeat(40),modelMode:'embedded',training:false},log:()=>{}});
 const r=await app(new Request('https://api.test/api/nebula/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:[{role:'user',content:'Hi'}]})}));
 assert.equal(r.status,503);assert.equal((await r.json()).code,'ULTRA_NOT_CONFIGURED');
});
