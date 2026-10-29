import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createStore} from '../lib/firebase.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {createDeskHandler} from '../lib/desk.mjs';
import {memoryDatabase} from './helpers/database.mjs';
const card={kind:'assumption',title:'Needs checking',text:'My own notes',done:false,checked:false,archived:false,revision:0};
function fixture(cold=false){const memory=memoryDatabase({coldTransactions:cold}),store=createStore(memory.db),handler=createDeskHandler({getStore:async()=>store,verifyToken:async token=>({uid:token==='bob.valid.token'?'bob':'alice'})});const ask=async(path='',method='GET',body,token='alice.valid.token')=>{const r=await handler(new Request('https://api.test/api/nebula/desk'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})}));return {status:r.status,body:await r.json()};};return{store,memory,ask};}
async function source(store){const k=accountKey('alice');await store.putChat(k,'original',{title:'Original',revision:0,messages:[{id:'q',role:'user',content:'Private question',contextPrivate:true}]},1);await store.appendReply(k,'original','q','Answer with <script>untrusted text</script>',2,{modelId:'nebula-ultra'});return store.getChat(k,'original');}
test('Workboard is account-private and source excerpts are server-owned',async()=>{
 const f=fixture(),chat=await source(f.store);assert.equal((await f.ask('', 'GET',null,null)).status,401);const a=await f.ask('/pin','PUT',{...card,source:{chatId:'original',messageId:chat.messages[1].id}});assert.equal(a.status,200);assert.match(a.body.card.source.quote,/Answer with/);
 assert.equal((await f.ask('','GET',null,'bob.valid.token')).body.cards.length,0);assert.equal((await f.ask('/fake','PUT',{...card,source:{chatId:'original',messageId:chat.messages[1].id}},'bob.valid.token')).status,404);
 assert.equal((await f.ask('/pin','PUT',{...card,revision:1,source:{chatId:'original',messageId:'fake'}})).status,400);const b=await f.ask('/pin','PUT',{...card,revision:1,text:'Changed notes'});assert.equal(b.body.card.source.quote,a.body.card.source.quote);assert.ok(!JSON.stringify([...f.memory.records]).includes('nebulaTraining'));
});
test('cold-cache edits, stale revisions, archive/restore and deletion stay isolated',async()=>{
 const f=fixture(true);let a=await f.ask('/note','PUT',card);assert.equal(a.status,200);a=await f.ask('/note','PUT',{...card,revision:1,archived:true});assert.equal(a.status,200);assert.equal(a.body.card.archived,true);
 assert.equal((await f.ask('/note','PUT',{...card,revision:1})).status,409);assert.equal((await f.ask('/note','DELETE',{revision:2},'bob.valid.token')).status,200);assert.equal((await f.ask()).body.cards.length,1);
 assert.equal((await f.ask('/note','DELETE',{revision:2})).status,200);assert.equal((await f.ask()).body.cards.length,0);
});
test('branches copy only the owned stored prefix and can continue without rewriting inherited replies',async()=>{
 const f=fixture(true),chat=await source(f.store),last=chat.messages[1].id;const b=await f.ask('/fork','POST',{chatId:'original',through:last,id:'alternative',title:'Another approach'});assert.equal(b.status,201);assert.equal(b.body.chat.messages.length,2);assert.ok(b.body.chat.messages.every(m=>m.trainingEligible===false&&!m.reviewEligible));assert.equal(b.body.chat.messages[0].contextPrivate,true);
 const retry=await f.ask('/fork','POST',{chatId:'original',through:last,id:'alternative',title:'Another approach'});assert.equal(retry.body.chat.revision,1);assert.equal((await f.store.listChats(accountKey('alice'))).length,2);
 const extended=await f.store.putChat(accountKey('alice'),'alternative',{...b.body.chat,messages:[...b.body.chat.messages,{id:'next',role:'user',content:'Try the other approach.',contextPrivate:true}]},3);assert.equal(extended.branchedFrom.chatId,'original');assert.equal((await f.store.getChat(accountKey('alice'),'original')).messages.length,2);
 assert.equal((await f.ask('/fork','POST',{chatId:'original',through:last,id:'stolen',title:'No'},'bob.valid.token')).status,404);
});
test('invalid cards, forged source fields and wrong-origin requests are rejected',async()=>{
 const f=fixture();for(const b of [{...card,kind:'system'},{...card,text:'x'.repeat(2001)},{...card,quote:'forged'},{...card,source:{chatId:'original',messageId:'q',quote:'fake'}}])assert.equal((await f.ask('/bad','PUT',b)).status,400);
});
test('retrying a card creation is idempotent and invalid origins cannot read account cards',async()=>{
 const f=fixture(true);await f.ask('/repeat','PUT',card);const r=await f.ask('/repeat','PUT',card);assert.equal(r.status,200);assert.equal(r.body.card.revision,1);assert.equal((await f.ask()).body.cards.length,1);
 const h=createDeskHandler({getStore:async()=>f.store,verifyToken:async()=>({uid:'alice'})});const denied=await h(new Request('https://api.test/api/nebula/desk',{headers:{Origin:'https://untrusted.example',Authorization:'Bearer alice.valid.token'}}));assert.equal(denied.status,403);
});
