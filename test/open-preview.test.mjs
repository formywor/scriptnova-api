import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openReply,openResetAt} from '../lib/assistants.mjs';
import {configFromEnv,createApp} from '../lib/app.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';

const env={NEBULA_OPEN_ACCOUNT_ID:'a'.repeat(32),NEBULA_OPEN_API_TOKEN:'test-token'};
const config={...configFromEnv(env),rateSecret:'r'.repeat(40),training:false};
const question=[{role:'user',content:'Calculate 32 times 7 using the calculator.'}];

test('Nebula Open sends a tool round trip only to the Cloudflare endpoint',async()=>{
 const bodies=[],phases=[];let charged=0;
 const reply=await openReply(question,{...config,onProgress:phase=>phases.push(phase),consumeOpenCall:async()=>charged++},{
  cloud:{calculate:async expression=>{assert.equal(expression,'32*7');return {value:224};}},
  fetcher:async(url,init)=>{
   assert.equal(url,'https://api.cloudflare.com/client/v4/accounts/'+env.NEBULA_OPEN_ACCOUNT_ID+'/ai/v1/chat/completions');
   assert.equal(init.headers.Authorization,'Bearer test-token');
   const body=JSON.parse(init.body);
   assert.equal(body.model,'@cf/openai/gpt-oss-20b');
   assert.equal(typeof body.max_tokens,'number');
   assert.equal(body.max_completion_tokens,undefined);
   assert.ok(body.messages.every(message=>typeof message.content==='string'));
   assert.ok(body.tools.some(tool=>tool.function.name==='calculate'));
   bodies.push(body);
   const message=bodies.length===1?{content:null,tool_calls:[{id:'call_1',type:'function',function:{name:'calculate',arguments:'{"expression":"32*7"}'}}]}:{content:'32 × 7 = 224',reasoning:'private'};
   return Response.json({choices:[{message}]});
  }
 });
 assert.equal(charged,2);
 assert.equal(bodies[1].messages.at(-1).tool_call_id,'call_1');
 assert.match(bodies[1].messages.at(-1).content,/224/);
 assert.equal(reply.text,'32 × 7 = 224');
 assert.deepEqual(reply.activity,[{tool:'calculate',status:'completed'}]);
 assert.ok(phases.length>0);
});

test('Nebula Open requires a verified invite and stops at the UTC daily cap',async()=>{
 const {db}=memoryDatabase(),store=createStore(db);
 let identity=null;
 const now=Date.UTC(2026,10,6,23,59);
 const app=createApp({getStore:async()=>store,verifyToken:async()=>identity,now:()=>now,config,log:()=>{},
  generate:async(messages,c)=>{await c.consumeOpenCall();return '224';}
 });
 const request=async(path,method='GET',body)=>{
  const headers={'Content-Type':'application/json'};
  if(identity)headers.Authorization='Bearer test.user.token';
  const res=await app(new Request('https://api.test/api/nebula'+path,{method,headers,body:body&&JSON.stringify(body)}));
  return [res.status,await res.json()];
 };
 const chat={chatId:'open-chat',turnId:'open-turn',modelId:'nebula-open',messages:question};
 assert.ok((await request('/models'))[1].models.some(model=>model.id==='nebula-open'&&model.invitationRequired));
 assert.equal((await request('/chat','POST',chat))[1].code,'OPEN_INVITE_REQUIRED');
 identity={uid:'open-test',email:'invite@example.com',email_verified:true};
 assert.equal((await request('/chat','POST',chat))[1].code,'OPEN_INVITE_REQUIRED');
 await store.developerSetGrant(identity.email,{tier:'invite',status:'active',reason:'Preview test',by:'owner',at:now});
 assert.deepEqual((await request('/usage'))[1].previewModels,['nebula-open']);
 assert.equal((await request('/chats/open-chat','PUT',{revision:0,title:'Open',messages:[{id:'open-turn',...question[0],trainingEligible:false}]}))[0],200);
 const {accountKey}=await import('../lib/accounts.mjs'),key=accountKey(identity.uid);
 for(let count=0;count<24;count++)assert.equal(await store.consumeOpenCall(key,now),true);
 const [status,body]=await request('/chat','POST',chat);
 assert.equal(status,429);
 assert.equal(body.code,'OPEN_DAILY_LIMIT');
 assert.equal(body.resetAt,Date.UTC(2026,10,7));
 assert.equal(await store.consumeOpenCall(key,openResetAt(now)),true);
});

test('Nebula Open recovers bare PC tool JSON without displaying it as a reply',async()=>{
 const actions=[];
 let round=0;
 const payload=(action,args)=>JSON.stringify({action,arguments:JSON.stringify(args)});
 const reply=await openReply([{role:'user',content:'Write a message to friend@example.com on Gmail using browser control.'}],config,{
  cloud:{pc:{run:async(action,args,options)=>{
   actions.push({action,args:JSON.parse(args),options});
   return action==='navigate'?{status:'completed',result:{tabId:9,readyState:'complete'}}:{status:'awaiting-approval',jobId:'a'.repeat(32)};
  }}},
  fetcher:async(_url,init)=>{
   const body=JSON.parse(init.body);
   if(round===1){
    const tool=body.messages.at(-1),assistant=body.messages.at(-2);
    assert.equal(assistant.content,'');
    assert.equal(tool.tool_call_id,assistant.tool_calls[0].id);
    assert.equal(assistant.tool_calls[0].function.name,'pc_browser');
   }
   const content=round++===0?payload('navigate',{url:'[https://mail.google.com/](https://mail.google.com/)',newTab:true}):payload('click',{snapshotId:'test',elementId:'e1'});
   return Response.json({choices:[{message:{content,tool_calls:[]}}]});
  }
 });
 assert.deepEqual(actions[0],{action:'navigate',args:{url:'https://mail.google.com/',newTab:true},options:{mailIntent:'draft',preferExistingTab:true}});
 assert.equal(actions[1].action,'click');
 assert.match(reply.text,/waiting for your approval/);
 assert.equal(reply.activity.at(-1).jobStatus,'awaiting-approval');
});

test('JSON requested as an example stays text in PC mode',async()=>{
 const content=JSON.stringify({action:'navigate',arguments:JSON.stringify({url:'https://example.com/'})});
 const reply=await openReply([{role:'user',content:'Show me a JSON example of how to open a tab.'}],config,{
  cloud:{pc:{run:async()=>assert.fail('An example must never execute')}},
  fetcher:async()=>Response.json({choices:[{message:{content}}]})
 });
 assert.equal(reply.text,content);
});
