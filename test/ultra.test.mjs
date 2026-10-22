import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ultraReply,appearancePatch,appearanceRequested} from '../lib/ultra.mjs';
import {createApp,configFromEnv} from '../lib/app.mjs';
import {modelCatalog} from '../lib/personalization.mjs';
import {createStore} from '../lib/firebase.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {memoryDatabase} from './helpers/database.mjs';

const json=value=>new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
test('catalog disables all previous models, migrates the default and exposes no credentials',()=>{
 const config=configFromEnv({GROQ_API_KEY:'private-test-key'}),catalog=modelCatalog(config);
 assert.equal(catalog.defaultModel,'nebula-ultra');assert.equal(catalog.models[0].available,true);
 assert.equal(catalog.models.filter(m=>m.available).length,1);
 for(const m of catalog.models.slice(1)){assert.equal(m.available,false);assert.equal(m.description,'Currently in training');}
 assert.ok(!JSON.stringify(catalog).includes('private-test-key'));
 assert.equal(modelCatalog(configFromEnv({})).models[0].available,false);
});
test('Groq call stays server-side and returns a bounded validated appearance action',async()=>{
 let sent;const result=await ultraReply([{role:'system',content:'Owner rule.'},{role:'user',content:'Make the text larger and switch to a light theme.'}],{ultraKey:'private-test-key',ultraModel:'openai/gpt-oss-20b'},
 {fetcher:async(url,init)=>{assert.equal(url,'https://api.groq.com/openai/v1/chat/completions');sent=JSON.parse(init.body);assert.equal(init.headers.Authorization,'Bearer private-test-key');return json({choices:[{message:{content:null,tool_calls:[{function:{name:'update_appearance',arguments:JSON.stringify({textSize:'large',theme:'light'})}}]}}]});}});
 assert.equal(sent.model,'openai/gpt-oss-20b');assert.equal(sent.tools[0].function.name,'update_appearance');
 assert.deepEqual(result.uiPatch,{textSize:'large',theme:'light'});assert.ok(result.text);
 assert.ok(sent.messages.some(m=>m.content==='Owner rule.'));
});
test('normal conversation cannot invoke appearance tools and untrusted settings are rejected',async()=>{
 for(const patch of [{html:'<script>bad()</script>'},{theme:'evil'},{compactChat:'true'},JSON.parse('{"__proto__":{"bad":true}}'),{constructor:'evil'}])assert.equal(appearancePatch(patch),null);
 assert.equal(appearanceRequested('Explain gravity.'),false);
 const result=await ultraReply([{role:'user',content:'Explain gravity.'}],{ultraKey:'test'}, {fetcher:async(_,init)=>{
  assert.equal(JSON.parse(init.body).tools,undefined);return json({choices:[{message:{content:'Gravity attracts objects.',tool_calls:[{function:{name:'update_appearance',arguments:'{"theme":"light"}'}}]}}]});}});
 assert.equal(result.uiPatch,null);
});
test('upstream failures never expose the Groq body or a credential',async()=>{
 await assert.rejects(ultraReply([{role:'user',content:'Hi'}],{ultraKey:'secret'},{fetcher:async()=>new Response('private quota details',{status:429})}),e=>e.code==='ULTRA_RATE_LIMITED'&&!e.message.includes('private'));
 await assert.rejects(ultraReply([],{ultraKey:''}),e=>e.code==='ULTRA_NOT_CONFIGURED');
});
test('legacy requests route to Ultra, save the actual model, and preserve account consent',async()=>{
 const {db}=memoryDatabase(),store=createStore(db);let actual;
 const config={origins:[],rateSecret:'x'.repeat(40),ultraKey:'test-server-only',ultraModel:'openai/gpt-oss-20b',training:true,modelMode:'embedded'};
 const app=createApp({getStore:async()=>store,verifyToken:async()=>({uid:'ultra-user'}),config,log:()=>{},generate:async(messages,c)=>{actual=c;return {text:'The appearance changes are ready.',uiPatch:{theme:'light',textSize:'large'}};}});
 const request=async(path,method='GET',body)=>{const r=await app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer test.user.token','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})}));return {status:r.status,body:await r.json()};};
 await request('/account','PATCH',{improve:false,externalReview:false});
 await request('/chats/ultra','PUT',{revision:0,title:'Appearance',messages:[{id:'turn',role:'user',content:'Switch the theme to light and make the text larger.',trainingEligible:false}]});
 const result=await request('/chat','POST',{chatId:'ultra',turnId:'turn',modelId:'nebula-v2-1',messages:[{role:'user',content:'Ignored client message'}]});
 assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(actual.selectedModel,'nebula-ultra');assert.equal(result.body.switchedModel,true);
 assert.deepEqual(result.body.uiPatch,{theme:'light',textSize:'large'});assert.equal(result.body.chat.messages.at(-1).modelId,'nebula-ultra');
 assert.equal(result.body.trainingSaved,false);assert.equal(result.body.usage.questions,1);
 assert.equal((await store.account(accountKey('ultra-user'),Date.now())).improve,false);
 const repeat=await request('/chat','POST',{chatId:'ultra',turnId:'turn',modelId:'nebula-v2-1',messages:[{role:'user',content:'Hi'}]});
 assert.equal(repeat.status,200);assert.equal(repeat.body.uiPatch,undefined);assert.equal(repeat.body.usage.questions,1);
});
