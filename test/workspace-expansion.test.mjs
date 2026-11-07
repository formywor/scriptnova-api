import {createApp} from '../lib/app.mjs';import {accountKey} from '../lib/accounts.mjs';
import {test} from 'node:test';import assert from 'node:assert/strict';
import {inspectWorkspaceData} from '../lib/workspace-data.mjs';
import {createStore} from '../lib/firebase.mjs';import {memoryDatabase} from './helpers/database.mjs';
test('archive bulk operations preserve active, concurrently restored and other-account chats',async()=>{
 const {db}=memoryDatabase(),s=createStore(db),time=1000;
 for(const [key,id,archived] of [['owner','archived',true],['owner','active',false],['owner','raced',true],['other','archived',true]])await s.putChat(key,id,{revision:0,title:id,archived,messages:[{id:'turn',role:'user',content:'hello'}]},time);
 const archived=await s.getChat('owner','archived'),raced=await s.getChat('owner','raced'),active=await s.getChat('owner','active');
 await s.patchChat('owner','raced',{revision:raced.revision,archived:false},time+1);
 const result=await s.bulkArchived('owner','delete',[{id:'archived',revision:archived.revision},{id:'active',revision:active.revision},{id:'raced',revision:raced.revision}],time+2);
 assert.deepEqual(result.changed,['archived']);assert.equal((await s.getChat('owner','raced')).archived,false);assert.ok(await s.getChat('owner','active'));assert.ok(await s.getChat('other','archived'));
});
test('saved-data inspection handles quoted multiline CSV, missing cells and invalid JSON without execution',()=>{
 const csv=inspectWorkspaceData({path:'sample.csv',content:'name,score\n"A, B",12\n"Two\nlines",18\nC,\n'});assert.equal(csv.rows,3);assert.equal(csv.columnSummary[1].mean,15);assert.equal(csv.columnSummary[1].missing,1);
 assert.equal(inspectWorkspaceData({path:'data.json',content:'{not valid}'}).valid,false);assert.equal(inspectWorkspaceData({path:'data.json',content:'[{"a":1},null]'}).items,2);assert.throws(()=>inspectWorkspaceData(null));assert.equal(inspectWorkspaceData({path:'notes.txt',content:'hello world'}).words,2);
});

test('archive batch API validates scope and restores only the confirmed archived revision',async()=>{
 const {db}=memoryDatabase(),store=createStore(db),key=accountKey('owner');await store.putChat(key,'saved',{revision:0,title:'Saved',archived:true,messages:[{id:'one',role:'user',content:'hello'}]},1000);const chat=await store.getChat(key,'saved');
 const app=createApp({getStore:async()=>store,verifyToken:async()=>({uid:'owner',email_verified:true}),now:()=>2000,config:{origins:[],publicTiers:false,rateSecret:'x'.repeat(40)}});
 const call=body=>app(new Request('https://api.test/api/nebula/chats',{method:'PATCH',headers:{Authorization:'Bearer test.jwt.token','Content-Type':'application/json'},body:JSON.stringify(body)}));
 const ok=await call({archiveBatch:{action:'restore',items:[{id:'saved',revision:chat.revision}]}});assert.equal(ok.status,200);assert.deepEqual((await ok.json()).changed,['saved']);assert.equal((await store.getChat(key,'saved')).archived,false);
 const invalid=await call({archiveBatch:{action:'delete',items:[{id:'saved',revision:-1}]}});assert.equal(invalid.status,400);assert.ok(await store.getChat(key,'saved'));
});
