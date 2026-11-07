import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {createApp} from '../lib/app.mjs';
import {accountKey,accountOwner} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const time=1700000000000,key=accountKey('alice');
const chat=(archived=false)=>({title:'Test',revision:0,archived,messages:[{id:'turn',role:'user',content:'Test'}]});
test('cold bulk operations change archived records, protect active/stale records, and tolerate missing IDs',async()=>{
 const {db}=memoryDatabase({coldTransactions:true}),s=createStore(db);
 for(const id of ['restore','delete','stale'])await s.putChat(key,id,chat(true),time);
 await s.putChat(key,'active',chat(),time);
 const r=await s.bulkArchived(key,'restore',[{id:'restore',revision:1},{id:'active',revision:1},{id:'stale',revision:0},{id:'missing',revision:1}],time+1);
 assert.deepEqual(r,{changed:['restore'],skipped:['active','stale','missing']});
 assert.equal((await s.getChat(key,'restore')).archived,false);
 assert.deepEqual((await s.bulkArchived(key,'delete',[{id:'delete',revision:1}],time+2)).changed,['delete']);
 await assert.rejects(()=>s.getChat(key,'delete'),e=>e.code==='NOT_FOUND');
 assert.equal((await s.getChat(key,'stale')).archived,true);
 await s.clearChats(key,time+3);assert.equal((await s.listChats(key)).length,0);
 await assert.rejects(()=>s.putChat(key,'delete',chat(),time+4),e=>e.code==='CHAT_CONFLICT');
});
test('content erasure is isolated, revokes every training generation and preserves quota counters',async()=>{
 const {db,records}=memoryDatabase({coldTransactions:true}),s=createStore(db);
 await s.preferences(key,{displayName:'Private',trainingGeneration:2},time);
 await s.putChat(key,'archived',chat(true),time);await s.putChat(key,'active',chat(),time);
 const paths=['nebulaMemory/v1/','nebulaDesk/v1/','nebulaGallery/v1/','nebulaEnvironment/v1/','nebulaCloud/v1/','nebulaCloudConnections/v1/','nebulaCloudOAuth/v1/'];
 for(const path of paths){await db.ref(path+key).set({private:'content'});await db.ref(path+'bob').set({keep:true});}
 await db.ref('nebulaPublicPlans/v1/'+key).set({short:{used:10}});
 await db.ref('nebulaPc/v1/accounts/'+key).set({device:{id:'device'}});await db.ref('nebulaPc/v1/devices/device').set({id:'device',ownerKey:key,jobs:{secret:'text'}});
 await db.ref('nebulaDeveloperApi/v1/accounts/'+key+'/keys').set({api:{id:'api',owner:key,status:'active'}});await db.ref('nebulaDeveloperApi/v1/keys/api').set({secretHash:'hash',owner:key});
 await s.eraseAccountData(key,'alice',time+1);
 for(const path of paths){assert.equal(records.has(path+key),false);assert.equal(records.get(path+'bob').keep,true);}
 assert.equal(records.has('nebulaPc/v1/devices/device'),false);assert.equal(records.has('nebulaDeveloperApi/v1/keys/api'),false);
 for(let i=0;i<=2;i++)assert.deepEqual(records.get('nebulaTraining/v1/'+accountOwner('alice',i)),{revoked:true});
 assert.equal((await s.listChats(key)).length,0);assert.equal((await s.account(key,time)).improve,false);assert.equal((await s.account(key,time)).displayName,undefined);
 assert.equal(records.get('nebulaPublicPlans/v1/'+key).short.used,10);
});
test('destructive routes require recent server-verified identity; deletion targets only authenticated UID',async()=>{
 const {db}=memoryDatabase(),s=createStore(db);let age=301;const deleted=[];
 const app=createApp({getStore:async()=>s,verifyToken:async()=>({uid:'alice',auth_time:time/1000-age}),deleteUser:async uid=>deleted.push(uid),now:()=>time,config:{origins:[],rateSecret:'x'.repeat(40)},log:()=>{}});
 const request=(path,token=true)=>app(new Request('https://api.scriptnovaa.com/api/nebula'+path,{method:'DELETE',headers:token?{Authorization:'Bearer alice.valid.token'}:{}}));
 assert.equal((await request('/account',false)).status,401);
 assert.equal((await request('/account')).status,401);assert.equal(deleted.length,0);
 age=0;assert.equal((await request('/account/data')).status,200);assert.equal(deleted.length,0);
 assert.equal((await request('/account?uid=bob')).status,200);assert.deepEqual(deleted,['alice']);
});

