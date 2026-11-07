import {test} from 'node:test';import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createPcStore,pcCommand,pcUrl,pcTools,createPcHandler,pcView} from '../lib/pc.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {createApp} from '../lib/app.mjs';
import {accountKey} from '../lib/accounts.mjs';
import {ultraReply} from '../lib/ultra.mjs';

async function fixture(options={}){const memory=memoryDatabase(options),store=createStore(memory.db),time=1000000,pair=await store.pcStart('Laptop',time),key=accountKey('owner');await store.pcPair(pair.code,key,time);await store.pcPoll(pair.deviceId,time);return {store,memory,pair,key,time};}
const snapshot=()=>({snapshotId:randomUUID(),tabId:7,url:'https://owned.test/mail',elements:[{id:'e1',label:'Send email',role:'button'},{id:'e2',label:'Message',role:'textarea'}]});
async function inspect(f){const id='a'.repeat(32);await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),id,f.time);const {job}=await f.store.pcPoll(f.pair.deviceId,f.time);const result=snapshot();await f.store.pcResult(f.pair.deviceId,job.id,job.lease,result,null,f.time);return result;}

test('pairing tokens are hashed, codes are single-use/account-bound and sessions expire after one hour',async()=>{const f=await fixture(),d=await f.store.pcDevice(f.pair.deviceId);assert.equal(d.expiresAt,f.time+3600000);assert.ok(!JSON.stringify([...f.memory.records]).includes(f.pair.token));assert.ok(!JSON.stringify(pcView(d,f.time)).includes(d.tokenHash));await assert.rejects(f.store.pcPair(f.pair.code,accountKey('intruder'),f.time),e=>e.code==='PC_PAIR_EXPIRED');const old=await f.store.pcStart('Old',0);await assert.rejects(f.store.pcPair(old.code,f.key,700000),e=>e.code==='PC_PAIR_EXPIRED');});
test('same-account concurrent pairing cannot orphan the successful device or duplicate its session',async()=>{const {db}=memoryDatabase(),s=createPcStore(db),p=await s.pcStart('Laptop',1000000);const results=await Promise.allSettled([s.pcPair(p.code,'owner',1000000),s.pcPair(p.code,'owner',1000000)]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal((await s.pcList('owner')).length,1);});
test('PC command protocol rejects arbitrary code, private addresses, credentials, secrets and invalid targets',()=>{for(const u of ['http://owned.test/','https://localhost/','https://127.0.0.1/','https://[::1]/','https://api.scriptnovaa.com/','https://user:pass@owned.test/','https://owned.test/?token=secret'])assert.throws(()=>pcUrl(u));for(const action of ['eval','shell','readFile','upload'])assert.throws(()=>pcCommand(action,{}));assert.throws(()=>pcCommand('type',{snapshotId:randomUUID(),elementId:'e1',text:'gsk_'+'a'.repeat(40)}));assert.throws(()=>pcCommand('click',{snapshotId:randomUUID(),elementId:'e1',selector:'body'}));assert.equal(pcCommand('inspect',{}).requiresApproval,false);assert.equal(pcCommand('click',{snapshotId:randomUUID(),elementId:'e1'}).requiresApproval,true);});
test('writes need a real fresh observation and owner approval, bound to exact tab, element and page',async()=>{const f=await fixture();const id='b'.repeat(32);await assert.rejects(f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('click',{snapshotId:randomUUID(),elementId:'e1'}),id,f.time));const observed=await inspect(f);await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('click',{snapshotId:observed.snapshotId,elementId:'e1'}),id,f.time);assert.equal((await f.store.pcPoll(f.pair.deviceId,f.time)).job,null);const d=await f.store.pcDevice(f.pair.deviceId);assert.equal(d.jobs[id].status,'awaiting-approval');assert.equal(d.jobs[id].target.label,'Send email');assert.equal(d.jobs[id].args.tabId,7);await assert.rejects(f.store.pcDecision(f.pair.deviceId,'other',id,true,f.time));await f.store.pcDecision(f.pair.deviceId,f.key,id,true,f.time);const claim=await f.store.pcPoll(f.pair.deviceId,f.time);assert.equal(claim.job.id,id);assert.equal(claim.job.approvedAt,f.time);assert.equal((await f.store.pcPoll(f.pair.deviceId,f.time)).job,null);await assert.rejects(f.store.pcResult(f.pair.deviceId,id,randomUUID(),{},null,f.time));await f.store.pcResult(f.pair.deviceId,id,claim.job.lease,{clicked:true},null,f.time);assert.equal((await f.store.pcDevice(f.pair.deviceId)).jobs[id].status,'completed');});
test('Stop cancels future actions, expired leases become interrupted and writes are never automatically replayed',async()=>{const f=await fixture();await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),'c'.repeat(32),f.time);const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;assert.equal((await f.store.pcPoll(f.pair.deviceId,f.time+46000)).job,null);assert.equal((await f.store.pcDevice(f.pair.deviceId)).jobs[j.id].status,'interrupted');await f.store.pcRevoke(f.pair.deviceId,f.key,f.time+46001);await assert.rejects(f.store.pcPoll(f.pair.deviceId,f.time+46002));await assert.rejects(f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),'d'.repeat(32),f.time+46002));});
test('read actions are deduplicated across chat retries and tool results redact credential values',async()=>{const f=await fixture(),tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time,turnTag:'turn',wait:async()=>{const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;if(j)await f.store.pcResult(f.pair.deviceId,j.id,j.lease,{text:'gsk_'+'a'.repeat(40),cookies:'private-cookie'},null,f.time);}});const a=await tools.run('inspect','{}'),b=await tools.run('inspect','{}');assert.equal(a.jobId,b.jobId);assert.equal(a.status,'completed');assert.equal((await f.store.pcDevice(f.pair.deviceId)).issued,1);const v=await f.store.pcDevice(f.pair.deviceId);assert.ok(!JSON.stringify(v).includes('gsk_'));assert.ok(!JSON.stringify(v).includes('private-cookie'));});
test('cold transaction initialization does not delete paired sessions or skip read claims',async()=>{const f=await fixture({coldTransactions:true});await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),'e'.repeat(32),f.time);const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;assert.ok(j);assert.equal((await f.store.pcDevice(f.pair.deviceId)).ownerKey,f.key);});
test('PC API enforces verified account pairing, extension-scoped token routes, lease validation and redaction',async()=>{let time=1000000;const store=createStore(memoryDatabase().db),verifyToken=async token=>{if(token==='owner.jwt.token')return{uid:'owner',email_verified:true};if(token==='unverified.jwt.token')return{uid:'unverified',email_verified:false};throw Object.assign(Error(),{code:'auth/invalid-id-token'});};const handler=createPcHandler({getStore:async()=>store,verifyToken,config:{origins:['https://scriptnovaa.com']},now:()=>time});
 const req=async(path,{body,token,origin,method=body===undefined?'GET':'POST'}={})=>{const r=await handler(new Request('https://api.test/api/nebula/pc'+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{}),...(origin?{Origin:origin}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})}));return{status:r.status,data:await r.json()};};
 const start=await req('/pair/start',{body:{name:'My PC'},origin:'chrome-extension://'+'a'.repeat(32)});assert.equal(start.status,201);const p=start.data;assert.equal((await req('/pair/approve',{body:{code:p.code,consent:true},token:'unverified.jwt.token'})).status,403);assert.equal((await req('/pair/approve',{body:{code:p.code,consent:false},token:'owner.jwt.token'})).status,400);assert.equal((await req('/pair/approve',{body:{code:p.code,consent:true},token:'owner.jwt.token',origin:'chrome-extension://'+'a'.repeat(32)})).status,403);
 assert.equal((await req('/pair/approve',{body:{code:p.code,consent:true},token:'owner.jwt.token'})).status,200);
 assert.equal((await req('/'+p.deviceId+'/policy',{body:{approvalMode:'full',consent:false},token:'owner.jwt.token'})).status,400);assert.equal((await req('/'+p.deviceId+'/policy',{body:{approvalMode:'full',consent:true},token:'owner.jwt.token',origin:'chrome-extension://'+'a'.repeat(32)})).status,403);assert.equal((await req('/'+p.deviceId+'/policy',{body:{approvalMode:'full',consent:true},token:'owner.jwt.token'})).data.device.approvalMode,'full');await req('/'+p.deviceId+'/policy',{body:{approvalMode:'ask',consent:true},token:'owner.jwt.token'});
assert.equal((await req('',{token:p.token})).status,401);assert.equal((await req('/agent/'+p.deviceId+'/poll',{body:{},token:'wrong.token.value'})).status,401);await req('/agent/'+p.deviceId+'/poll',{body:{},token:p.token});const tag='f'.repeat(32);await store.pcQueue(p.deviceId,accountKey('owner'),pcCommand('inspect',{}),tag,time);const claim=await req('/agent/'+p.deviceId+'/poll',{body:{},token:p.token});assert.equal(claim.data.job.id,tag);
 const result=await req('/agent/'+p.deviceId+'/result',{token:p.token,body:{jobId:tag,lease:claim.data.job.lease,result:{text:'gsk_'+'a'.repeat(40),cookies:'cookie-value',headers:{Authorization:'secret'}},error:null}});assert.equal(result.status,200);const view=await req('',{token:'owner.jwt.token'});assert.ok(!JSON.stringify(view.data).includes('cookie-value'));assert.ok(!JSON.stringify(view.data).includes('gsk_'));assert.ok(!JSON.stringify(view.data).includes(p.token));time+=3600001;assert.equal((await req('/agent/'+p.deviceId+'/poll',{body:{},token:p.token})).status,410);
});
test('PC mode and Cloud mode are exclusive; PC context stays out of training and cross-chat memory',async()=>{const f=await fixture();let generated=false;const app=createApp({getStore:async()=>f.store,verifyToken:async()=>({uid:'owner',email_verified:true,email:'owner@example.com'}),now:()=>f.time,config:{origins:[],publicTiers:false,rateSecret:'x'.repeat(40),ultraKey:'fixture',training:true},generate:async(_m,c)=>{generated=true;assert.ok(c.cloudTools.pc);assert.equal(c.cloudTools.read,undefined);assert.equal(c.cloudTools.runCode,undefined);assert.equal(c.contextUsed.memoryEnabled,false);return {text:'Ready to inspect your approved browser.'};}});const req=(path,body,method='POST')=>app(new Request('https://api.test/api/nebula'+path,{method,headers:{Authorization:'Bearer owner.jwt.token','Content-Type':'application/json'},body:JSON.stringify(body)}));
 await req('/chats/pc-test',{revision:0,title:'PC task',messages:[{id:'turn',role:'user',content:'Inspect my tab.',trainingEligible:true}]},'PUT');const base={chatId:'pc-test',turnId:'turn',modelId:'nebula-ultra',messages:[{role:'user',content:'Inspect my tab.'}],toolMode:'pc',pcDeviceId:f.pair.deviceId,training:{enabled:true,token:'a'.repeat(64),chatId:'pc-test',turnId:'turn',consentVersion:1}};assert.equal((await req('/chat',{...base,cloudMode:true})).status,400);assert.equal(generated,false);const r=await req('/chat',base),d=await r.json();assert.equal(r.status,200,JSON.stringify(d));assert.equal(d.trainingSaved,false);assert.equal(d.chat.messages.at(-1).contextPrivate,true);
});
test('Ultra stops tool execution as soon as a browser action needs approval',async()=>{let calls=0;const r=await ultraReply([{role:'user',content:'Prepare an email draft.'}],{ultraKey:'fixture',pcContext:{device:'My PC'}},{cloud:{pc:{run:async()=>({jobId:'a'.repeat(32),status:'awaiting-approval'})}},fetcher:async(_u,init)=>{calls++;const b=JSON.parse(init.body);assert.equal(b.parallel_tool_calls,false);assert.ok(b.tools.every(t=>t.function.name.startsWith('pc_')));return Response.json({choices:[{message:{tool_calls:[{id:'action',function:{name:'pc_browser',arguments:JSON.stringify({action:'type',arguments:JSON.stringify({snapshotId:randomUUID(),elementId:'e2',text:'Draft'})})}}]}}]});}});assert.equal(calls,1);assert.equal(r.activity[0].status,'pending');assert.match(r.text,/waiting for your approval/);});
import {PC_CONNECTION_MS} from '../lib/pc.mjs';
test('30-day connections require updated extension plus explicit 30-day approval; legacy approvals stay one hour',async()=>{const s=createStore(memoryDatabase().db),time=1000000,key=accountKey('owner');const legacy=await s.pcStart('Legacy',time);await assert.rejects(s.pcPair(legacy.code,key,time,30),e=>e.code==='PC_EXTENSION_UPDATE_REQUIRED');const modern=await s.pcStart('Modern',time,2),paired=await s.pcPair(modern.code,key,time,30);assert.equal(paired.expiresAt,time+PC_CONNECTION_MS);const cachedPage=await s.pcStart('Cached old consent',time,2),short=await s.pcPair(cachedPage.code,key,time);assert.equal(short.expiresAt,time+3600000);assert.equal((await s.pcDevice(paired.id)).expiresAt,paired.expiresAt);await assert.rejects(s.pcPoll(paired.id,time+PC_CONNECTION_MS+1));});
test('stopping a connection frees its pairing slot immediately, including long-lived connections',async()=>{const s=createStore(memoryDatabase().db),time=1000000,key=accountKey('owner');for(let n=0;n<5;n++){const p=await s.pcStart('Connection '+n,time,2),d=await s.pcPair(p.code,key,time,30);await s.pcRevoke(d.id,key,time);}const final=await s.pcStart('Final',time,2);assert.ok((await s.pcPair(final.code,key,time,30)).ownerKey);});
test('command limits reset each hour instead of blocking a 30-day connection after 120 lifetime actions',async()=>{const {db}=memoryDatabase(),s=createPcStore(db),time=1000000,p=await s.pcStart('Modern',time,2),d=await s.pcPair(p.code,'owner',time,30);await s.pcPoll(d.id,time);await db.ref('nebulaPc/v1/devices/'+d.id).transaction(old=>({...old,issued:120,issueWindow:Math.floor(time/3600000)}));await assert.rejects(s.pcQueue(d.id,'owner',pcCommand('inspect',{}),'1'.repeat(32),time));const next=3600001;await s.pcPoll(d.id,next);await s.pcQueue(d.id,'owner',pcCommand('inspect',{}),'2'.repeat(32),next);assert.equal((await s.pcDevice(d.id)).issued,1);});
test('explicit PC page-reading requests start a real browser tool instead of stopping at an approval proposal',async()=>{let calls=0;const r=await ultraReply([{role:'user',content:'Inspect the approved example.com tab and report its heading.'}],{ultraKey:'fixture',pcContext:{device:'My PC'}},{cloud:{pc:{run:async()=>({status:'completed',result:{snapshotId:randomUUID(),title:'Example Domain',text:'Documentation example.'}})}},fetcher:async(_u,init)=>{const b=JSON.parse(init.body);if(calls++===0){assert.equal(b.tool_choice.function.name,'pc_browser');return Response.json({choices:[{message:{tool_calls:[{id:'read',function:{name:'pc_browser',arguments:'{"action":"inspect","arguments":"{}"}'}}]}}]});}assert.equal(b.tool_choice,'auto');return Response.json({choices:[{message:{content:'The heading is Example Domain.'}}]});}});assert.equal(r.activity[0].status,'completed');assert.match(r.text,/Example Domain/);});

test('approval modes remain owner-controlled and automatic actions still bind to real observations',async()=>{const f=await fixture({coldTransactions:true}),observed=await inspect(f);await assert.rejects(f.store.pcPolicy(f.pair.deviceId,'other','full',f.time));await f.store.pcPolicy(f.pair.deviceId,f.key,'auto',f.time);let d=await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('type',{snapshotId:observed.snapshotId,elementId:'e2',text:'Hello'}),'3'.repeat(32),f.time);assert.equal(d.jobs['3'.repeat(32)].status,'queued');assert.equal(d.jobs['3'.repeat(32)].approvalSource,'auto');d=await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('click',{snapshotId:observed.snapshotId,elementId:'e1'}),'4'.repeat(32),f.time);assert.equal(d.jobs['4'.repeat(32)].status,'awaiting-approval');await f.store.pcPolicy(f.pair.deviceId,f.key,'ask',f.time);d=await f.store.pcDevice(f.pair.deviceId);assert.equal(d.jobs['3'.repeat(32)].status,'awaiting-approval');assert.equal(d.jobs['3'.repeat(32)].approvedAt,null);await f.store.pcPolicy(f.pair.deviceId,f.key,'full',f.time);const tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time,wait:async()=>{const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;if(j)await f.store.pcResult(f.pair.deviceId,j.id,j.lease,{sent:true},null,f.time);}});const result=await tools.run('click',JSON.stringify({snapshotId:observed.snapshotId,elementId:'e1'}));assert.equal(result.status,'completed');assert.equal(result.result.sent,true);});
import {pcApprovalRequired} from '../lib/pc.mjs';
test('Full Browser Access never automatically approves payment, security or destructive controls',()=>{for(const label of ['Delete account','Pay now','Change password','Allow permission','Erase all'])for(const mode of ['auto','full'])assert.equal(pcApprovalRequired({action:'click',args:{}},{label,url:'https://example.com/'},mode),true);assert.equal(pcApprovalRequired({action:'click',args:{}},{label:'Send',url:'https://mail.google.com/'},'full'),false);assert.equal(pcApprovalRequired({action:'click',args:{}},{label:'Send',url:'https://mail.google.com/'},'auto'),true);assert.equal(pcApprovalRequired({action:'inspect',args:{}},null,'ask'),false);});
test('pending read jobs never ask for approval, and Continue checks the existing job first',async()=>{let called=0;const r=await ultraReply([{role:'user',content:'Continue my PC task. First check pc_action_result for jobId '+ 'a'.repeat(32)+'. Do not repeat the previous action.'}],{ultraKey:'fixture'},{cloud:{pc:{result:async id=>{assert.equal(id,'a'.repeat(32));return {jobId:id,status:'running'};}}},fetcher:async(_u,init)=>{called++;const body=JSON.parse(init.body);assert.equal(body.tool_choice.function.name,'pc_action_result');return Response.json({choices:[{message:{tool_calls:[{id:'pending',function:{name:'pc_action_result',arguments:JSON.stringify({jobId:'a'.repeat(32)})}}]}}]});}});assert.equal(called,1);assert.match(r.text,/No approval is needed/);assert.equal(r.activity[0].jobId,'a'.repeat(32));});
test('new page tools are validated and require the current extension protocol',async()=>{const f=await fixture(),tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time});await assert.rejects(tools.run('page_status','{}'),e=>e.code==='PC_EXTENSION_UPDATE_REQUIRED');assert.equal(pcCommand('wait_for_page',{timeoutMs:1000,text:'Inbox'}).requiresApproval,false);assert.throws(()=>pcCommand('wait_for_page',{timeoutMs:60000}));assert.throws(()=>pcCommand('select_option',{snapshotId:randomUUID(),elementId:'e1',value:7}));assert.throws(()=>pcCommand('set_checked',{snapshotId:randomUUID(),elementId:'e1',checked:'yes'}));});
test('stopped pairing records cannot hide a new active computer from the account list',async()=>{const f=await fixture();await f.store.pcRevoke(f.pair.deviceId,f.key,f.time);for(let n=0;n<4;n++){const p=await f.store.pcStart('Old '+n,f.time,3);await f.store.pcPair(p.code,f.key,f.time,30);await f.store.pcRevoke(p.deviceId,f.key,f.time);}const p=await f.store.pcStart('Active',f.time,3);await f.store.pcPair(p.code,f.key,f.time,30);assert.equal((await f.store.pcList(f.key))[0].id,p.deviceId);});

test('extension capability upgrade preserves connection expiry and the explicit approval mode',async()=>{const f=await fixture();await f.store.pcPolicy(f.pair.deviceId,f.key,'auto',f.time);const before=await f.store.pcDevice(f.pair.deviceId);const after=await f.store.pcUpgrade(f.pair.deviceId,f.time);assert.equal(after.protocolVersion,3);assert.equal(after.expiresAt,before.expiresAt);assert.equal(after.approvalMode,'auto');assert.equal(after.ownerKey,before.ownerKey);assert.equal(after.tokenHash,before.tokenHash);});
import {pcJobView} from '../lib/pc.mjs';
import {pcEmailTask} from '../lib/ultra.mjs';
test('expired jobs stop looking busy even when the extension never polls again',async()=>{const f=await fixture();await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),'7'.repeat(32),f.time);await f.store.pcPoll(f.pair.deviceId,f.time);const tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time+46000,wait:async()=>assert.fail('expired job must not wait')});const result=await tools.result('7'.repeat(32));assert.equal(result.status,'interrupted');assert.equal(result.error,'PC_ACTION_INTERRUPTED');assert.equal(pcView(await f.store.pcDevice(f.pair.deviceId),f.time+46000).jobs[0].status,'interrupted');assert.equal(pcJobView({status:'awaiting-approval',expiresAt:1},2).status,'interrupted');});
test('status checks wait briefly for the existing action instead of requiring another user turn',async()=>{const f=await fixture();await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),'8'.repeat(32),f.time);const claim=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;let waits=0;const tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time,wait:async()=>{waits++;await f.store.pcResult(f.pair.deviceId,claim.id,claim.lease,{title:'Ready'},null,f.time);}});const result=await tools.result(claim.id);assert.equal(result.status,'completed');assert.equal(waits,1);assert.equal((await f.store.pcDevice(f.pair.deviceId)).issued,1);});
test('Gmail PC tasks continue from a real tab lookup rather than returning a stale capability refusal',async()=>{let round=0;const steps=[];const r=await ultraReply([{role:'user',content:'Send a Gmail to friend@example.com and tell them I said hi'}],{ultraKey:'fixture',pcContext:{device:'Browser'}},{cloud:{pc:{run:async action=>{steps.push(action);return action==='tabs'?{status:'completed',result:{tabs:[{tabId:7,url:'https://mail.google.com/'}]}}:action==='inspect'?{status:'completed',result:{snapshotId:randomUUID(),elements:[{id:'e1',label:'Compose',role:'button'}]}}:{status:'awaiting-approval',jobId:'9'.repeat(32)};}}},fetcher:async(_u,init)=>{const b=JSON.parse(init.body);const n=round++;if(n===1)return Response.json({choices:[{message:{content:"I’m sorry, but I don’t have access to your Gmail account or the ability to send an email."}}]});const action=n===0?'tabs':n===2?'inspect':'click';if(n===2)assert.equal(b.tool_choice.function.name,'pc_browser');return Response.json({choices:[{message:{tool_calls:[{id:'step'+n,function:{name:'pc_browser',arguments:JSON.stringify({action,arguments:'{}'})}}]}}]});}});assert.deepEqual(steps,['tabs','inspect','click']);assert.match(r.text,/Review the action card/);assert.equal(r.activity.at(-1).jobStatus,'awaiting-approval');});
test('email followups preserve the goal but never revive it after a different user request',()=>{const m=content=>({role:'user',content});assert.equal(pcEmailTask([m('Send a Gmail to friend@example.com'),m('Sure do so'),m('Use pc skill')]),true);assert.equal(pcEmailTask([m('Send a Gmail to friend@example.com'),m('Find today’s weather'),m('Continue')]),false);assert.equal(pcEmailTask([m('Do not send any email')]),false);});

test('Gmail draft intent survives status followups and Full Browser Access does not override draft-only scope',async()=>{
 const m=content=>({role:'user',content});
 assert.equal(pcEmailTask([m('Write a message to friend@example.com saying hello on Gmail'),m('use the pc'),m('my settings are on full access no need to ask for approval'),m('gmail is open')]),true);
 const f=await fixture(),device=f.pair.deviceId;
 await f.store.pcPolicy(device,f.key,'full',f.time);
 const snapshotId=randomUUID(),readId='e'.repeat(32);
 await f.store.pcQueue(device,f.key,pcCommand('inspect',{}),readId,f.time);
 const read=(await f.store.pcPoll(device,f.time)).job;
 await f.store.pcResult(device,readId,read.lease,{snapshotId,tabId:7,url:'https://mail.google.com/mail/u/0/',elements:[{id:'e1',label:'Send',role:'button'},{id:'e2',label:'Compose',role:'button'}]},null,f.time);
 let claim;
 const tools=pcTools(f.store,f.key,device,{modelId:'nebula-open',turnTag:'chat:turn',now:()=>f.time,wait:async()=>{
  claim=(await f.store.pcPoll(device,f.time)).job;
  await f.store.pcResult(device,claim.id,claim.lease,{target:'Compose'},null,f.time);
 }});
 await assert.rejects(tools.run('click',JSON.stringify({snapshotId,elementId:'e1'}),{mailIntent:'draft'}),e=>e.code==='PC_EMAIL_DRAFT_ONLY');
 const first=await tools.run('click',JSON.stringify({snapshotId,elementId:'e2'}),{mailIntent:'draft'});
 assert.equal(first.status,'completed');
 assert.equal(claim.approvalSource,'full');
 assert.equal(claim.modelId,'nebula-open');
 const secondSnapshot=randomUUID(),secondRead='d'.repeat(32);
 await f.store.pcQueue(device,f.key,pcCommand('inspect',{}),secondRead,f.time);
 const secondClaim=(await f.store.pcPoll(device,f.time)).job;
 await f.store.pcResult(device,secondRead,secondClaim.lease,{snapshotId:secondSnapshot,tabId:7,url:'https://mail.google.com/mail/u/0/',elements:[{id:'e4',label:'Compose',role:'button'}]},null,f.time);
 const repeat=await tools.run('click',JSON.stringify({snapshotId:secondSnapshot,elementId:'e4'}),{mailIntent:'draft'});
 assert.equal(repeat.deduplicated,true);
 assert.equal(repeat.jobId,first.jobId);
 assert.equal((await f.store.pcPoll(device,f.time)).job,null);
});

test('inspection reuses a snapshot until the page changes, then gives a fresh target',async()=>{
 const f=await fixture();
 await f.store.pcPolicy(f.pair.deviceId,f.key,'full',f.time);
 let inspections=0,lastWrite;
 const tools=pcTools(f.store,f.key,f.pair.deviceId,{turnTag:'chat:fresh',now:()=>f.time,wait:async()=>{
  const {job}=await f.store.pcPoll(f.pair.deviceId,f.time);
  if(job.action==='inspect')inspections++;
  else lastWrite=job;
  await f.store.pcResult(f.pair.deviceId,job.id,job.lease,job.action==='inspect'?snapshot():{ok:true},null,f.time);
 }});
 const first=await tools.run('inspect',{});
 assert.equal((await tools.run('inspect','{}')).jobId,first.jobId);
 await tools.run('click',{elementId:'e2'});
 assert.equal(lastWrite.args.snapshotId,first.result.snapshotId);
 await assert.rejects(tools.run('click',{elementId:'e2'}),e=>e.code==='INVALID_PC_ACTION');
 const next=await tools.run('inspect',{});
 assert.equal(inspections,2);
 assert.notEqual(next.result.snapshotId,first.result.snapshotId);
});

test('an explicit blank-tab request ignores the earlier Gmail goal and makes no model call',async()=>{
 const answer=await ultraReply([{role:'user',content:'Write a Gmail message to a@example.com'},{role:'assistant',content:'Ready.'},{role:'user',content:'open 4 new tabs'}],{ultraKey:'test'},{fetcher:async()=>assert.fail('Blank tabs do not need the model'),cloud:{pc:{run:async(action,raw)=>{
  assert.equal(action,'open_tabs');assert.deepEqual(JSON.parse(raw),{count:4});
  return {status:'completed',result:{opened:4}};
 }}}});
 assert.match(answer.text,/Opened 4 blank tabs/);
});

test('PC tasks repair a rejected control and can continue beyond six tool calls',async()=>{
 let modelRound=0,dispatched=0;
 const actions=['navigate','inspect','click','inspect','click','inspect','type','inspect'];
 const reply=await ultraReply([{role:'user',content:'Navigate and fill in the requested test page.'}],{ultraKey:'test'},{
  cloud:{pc:{run:async action=>{
   dispatched++;
   if(dispatched===3)throw Object.assign(Error('Invalid target'),{code:'INVALID_PC_ACTION'});
   return {status:'completed',result:{target:action,title:'Test page'}};
  }}},
  fetcher:async(_url,init)=>{
   const body=JSON.parse(init.body);
   if(modelRound===3)assert.match(body.messages.at(-1).content,/was not dispatched/);
   const action=actions[modelRound++];
   return Response.json({choices:[{message:action?{tool_calls:[{id:'call-'+modelRound,function:{name:'pc_browser',arguments:JSON.stringify({action,arguments:'{}'})}}]}:{content:'Finished the test page.'}}]});
  }
 });
 assert.equal(dispatched,8);
 assert.match(reply.text,/Finished/);
});

test('send-it authorizes the existing email task and recovers a stale refusal',async()=>{
 const messages=[{role:'user',content:'Draft a Gmail to friend@example.com saying Hi how are you. Do not send.'},{role:'assistant',content:'The draft is ready.'},{role:'user',content:'send it'}];
 assert.equal(pcEmailTask(messages),true);assert.equal(pcEmailTask([{role:'user',content:'send it'}]),false);
 assert.equal(pcEmailTask([...messages.slice(0,2),{role:'user',content:'Find the weather'},{role:'user',content:'send it'}]),false);
 let round=0;const actions=[];
 const reply=await ultraReply(messages,{ultraKey:'fixture',pcContext:{approvalMode:'full',lastTaskTab:{tabId:7,url:'https://mail.google.com/'}}},{cloud:{pc:{run:async(action,args,options)=>{actions.push({action,options});return action==='inspect'?{status:'completed',result:{snapshotId:randomUUID(),tabId:7,elements:[{id:'e1',label:'Send',role:'button'}]}}:{status:'awaiting-approval',jobId:'b'.repeat(32)};}}},fetcher:async(_u,init)=>{
  const b=JSON.parse(init.body);const n=round++;if(n===1)return Response.json({choices:[{message:{content:'I cannot send the email for you.'}}]});
  assert.equal(b.tool_choice.function.name,'pc_browser');return Response.json({choices:[{message:{tool_calls:[{id:'s'+n,function:{name:'pc_browser',arguments:JSON.stringify({action:n===0?'inspect':'click',arguments:{tabId:7}})}}]}}]});
 }});
 assert.deepEqual(actions.map(x=>x.action),['inspect','click']);assert.equal(actions[1].options.mailIntent,'send');assert.equal(actions[1].options.continueDraft,true);assert.match(reply.text,/approval/);
});
test('email continuation inspects the last same-chat Gmail tab instead of opening another',async()=>{
 const f=await fixture();const id='c'.repeat(32);
 await f.store.pcQueue(f.pair.deviceId,f.key,{...pcCommand('inspect',{tabId:7}),chatId:'chat',turnId:'previous'},id,f.time);
 const read=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;
 await f.store.pcResult(f.pair.deviceId,id,read.lease,{tabId:7,url:'https://mail.google.com/mail/u/0/',snapshotId:randomUUID(),elements:[]},null,f.time);
 const executed=[];const make=chat=>pcTools(f.store,f.key,f.pair.deviceId,{turnTag:chat+':next',now:()=>f.time,wait:async()=>{const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;executed.push(j);await f.store.pcResult(f.pair.deviceId,j.id,j.lease,{tabId:7,url:'https://mail.google.com/'},null,f.time);}});
 await make('chat').run('navigate',{url:'https://mail.google.com/',newTab:true},{mailIntent:'send',preferExistingTab:true});
 assert.equal(executed[0].action,'inspect');assert.equal(executed[0].args.tabId,7);
 await make('other-chat').run('navigate',{url:'https://mail.google.com/',newTab:true},{mailIntent:'send',preferExistingTab:true});assert.equal(executed[1].action,'navigate');
 await make('explicit-new').run('navigate',{url:'https://mail.google.com/',newTab:true},{mailIntent:'send',preferExistingTab:false});assert.equal(executed[2].action,'navigate');
});

test('sending an existing draft cannot click Compose again',async()=>{
 const f=await fixture();const snap=await inspect(f);const tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time});
 // This is a fresh observation with a real Gmail Compose control.
 const id='d'.repeat(32);await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('inspect',{}),id,f.time);const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;
 const page={...snapshot(),url:'https://mail.google.com/',elements:[{id:'e1',label:'Compose',role:'button'}]};await f.store.pcResult(f.pair.deviceId,id,j.lease,page,null,f.time);
 await assert.rejects(tools.run('click',{elementId:'e1',snapshotId:page.snapshotId},{mailIntent:'send',continueDraft:true}),e=>e.code==='INVALID_PC_ACTION'&&e.repair.includes('existing draft'));
});

test('cursor task remains active between actions and old turns cannot finish a newer task',async()=>{
 const f=await fixture();const device=f.pair.deviceId;
 await f.store.pcQueue(device,f.key,{...pcCommand('inspect',{}),chatId:'chat',turnId:'one'},'1'.repeat(32),f.time);
 let response=await f.store.pcPoll(device,f.time);assert.equal(response.task.status,'active');
 const j=response.job;await f.store.pcResult(device,j.id,j.lease,{ok:true},null,f.time);
 assert.equal((await f.store.pcPoll(device,f.time)).task.status,'active');
 await f.store.pcTaskFinish(device,f.key,'chat:one','waiting',f.time);assert.equal((await f.store.pcPoll(device,f.time)).task.status,'waiting');
 await f.store.pcQueue(device,f.key,{...pcCommand('inspect',{}),chatId:'chat',turnId:'two'},'2'.repeat(32),f.time);
 await f.store.pcTaskFinish(device,f.key,'chat:one','finished',f.time);assert.equal((await f.store.pcPoll(device,f.time)).task.status,'active');
 await f.store.pcTaskFinish(device,f.key,'chat:two','finished',f.time);assert.equal((await f.store.pcPoll(device,f.time)).task.status,'finished');
});
test('PC reply completion reports finished, waiting and canceled task states',async()=>{
 const states=[];const c={ultraKey:'fixture',cloudTools:{pc:{finish:async s=>states.push(s)}}};
 await ultraReply([{role:'user',content:'Hello'}],c,{fetcher:async()=>Response.json({choices:[{message:{content:'Hello'}}]})});assert.equal(states.pop(),'finished');
 await assert.rejects(ultraReply([{role:'user',content:'Hello'}],c,{fetcher:async()=>{throw Error('interrupted');}}));assert.equal(states.pop(),'canceled');
});

test('an unrecorded Gmail draft continuation explains the chat mismatch without browser or model calls',async()=>{
 let calls=0;const result=await ultraReply([{role:'user',content:'Continue the unsent Gmail draft on the Compose window you opened. Fill the body. Do not send.'}],{ultraKey:'fixture',pcContext:{draftRecorded:false}},{cloud:{pc:{run:async()=>{calls++;throw Error('Must not browse');}}},fetcher:async()=>{calls++;throw Error('Must not infer');}});
 assert.equal(calls,0);assert.match(result.text,/different chat/);assert.match(result.text,/new draft/);assert.deepEqual(result.activity,[]);
});
test('a recorded draft continuation still uses the paired browser',async()=>{
 let calls=0;const result=await ultraReply([{role:'user',content:'Continue the unsent Gmail draft on the Compose window you opened.'}],{ultraKey:'fixture',pcContext:{draftRecorded:true}},{cloud:{pc:{run:async()=>{calls++;return {status:'awaiting-approval',jobId:'a'.repeat(32)};}}},fetcher:async()=>Response.json({choices:[{message:{tool_calls:[{id:'pc',function:{name:'pc_browser',arguments:JSON.stringify({action:'inspect',arguments:{}})}}]}}]})});assert.equal(calls,1);assert.equal(result.activity.at(-1).status,'pending');
});

test('computer selection follows the account across clients and rejects another account',async()=>{
 const f=await fixture();
 const client=uid=>createPcHandler({getStore:async()=>f.store,verifyToken:async()=>({uid,email_verified:true}),now:()=>f.time,config:{origins:[]}});
 const request=(handler,path,body)=>handler(new Request('https://api.test/api/nebula/pc'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer owner.jwt.token','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})}));
 assert.equal((await request(client('owner'),'/selection',{deviceId:f.pair.deviceId})).status,200);
 const data=await (await request(client('owner'),'')).json();assert.equal(data.selectedDeviceId,f.pair.deviceId);assert.equal(data.devices[0].id,f.pair.deviceId);assert.ok(!JSON.stringify(data).includes(f.pair.token));
 const stranger=await (await request(client('stranger'),'')).json();assert.equal(stranger.selectedDeviceId,'');assert.equal(stranger.devices.length,0);
 assert.equal((await request(client('stranger'),'/selection',{deviceId:f.pair.deviceId})).status,404);
 await f.store.pcRevoke(f.pair.deviceId,f.key,f.time);assert.equal((await (await request(client('owner'),'')).json()).selectedDeviceId,'');
});

test('tab closure requires a real recent tab observation and follows the approval mode',async()=>{
 const f=await fixture();await f.store.pcUpgrade(f.pair.deviceId,f.time,5);const id='7'.repeat(32);
 await f.store.pcQueue(f.pair.deviceId,f.key,pcCommand('tabs',{}),id,f.time);const j=(await f.store.pcPoll(f.pair.deviceId,f.time)).job;
 await f.store.pcResult(f.pair.deviceId,j.id,j.lease,{tabs:[{tabId:7,title:'Example Domain',url:'https://example.com/'}]},null,f.time);
 const tools=pcTools(f.store,f.key,f.pair.deviceId,{turnTag:'chat:close',now:()=>f.time});
 const result=await tools.run('close_tab',{tabId:7});assert.equal(result.status,'awaiting-approval');const d=await f.store.pcDevice(f.pair.deviceId);assert.match(d.jobs[result.jobId].target.label,/Example Domain/);assert.equal(d.jobs[result.jobId].args.tabId,7);
 await assert.rejects(tools.run('close_tab',{tabId:99}));assert.throws(()=>pcCommand('close_tab',{}));assert.throws(()=>pcCommand('reload',{tabId:7,url:'https://other.test'}));
});
test('tab capability questions do not close a tab or consume an inference',async()=>{
 const reply=await ultraReply([{role:'user',content:'Can you close tabs?'}],{ultraKey:'fixture',pcContext:{features:['close_tab']}},{cloud:{pc:{run:()=>{throw Error('No task requested');}}},fetcher:()=>{throw Error('No inference needed');}});assert.match(reply.text,/Tell me which tab/);assert.equal(reply.activity.length,0);
});

test('PC heartbeat and action budgets are independent of the old exhausted write bucket',async()=>{
 const f=await fixture();const minute=Math.floor(f.time/60000),day=Math.floor(f.time/86400000);
 await f.memory.db.ref('nebulaRateLimits/pc_agent_'+f.pair.deviceId+'_write').set({minute,day,minuteCount:60,dayCount:5000});
 const handler=createPcHandler({getStore:async()=>f.store,now:()=>f.time,config:{origins:[]}});
 const call=op=>handler(new Request('https://api.test/api/nebula/pc/agent/'+f.pair.deviceId+'/'+op,{method:'POST',headers:{Authorization:'Bearer '+f.pair.token,'Content-Type':'application/json'},body:'{}'}));
 assert.equal((await call('poll')).status,200);
 await f.memory.db.ref('nebulaRateLimits/pc_agent_'+f.pair.deviceId+'_pc-heartbeat').set({minute,day,minuteCount:120,dayCount:1000});
 const limited=await call('poll');assert.equal(limited.status,429);assert.equal(limited.headers.get('Retry-After'),'60');assert.equal((await limited.json()).retryAfterSeconds,60);
 assert.equal((await call('stop')).status,200);assert.equal((await f.store.pcDevice(f.pair.deviceId)).revoked,true);
});
test('normal all-day polling fits the dedicated heartbeat budget while abuse is throttled',async()=>{
 const {db}=memoryDatabase(),store=createStore(db);const time=Date.UTC(2026,10,7);
 // A full day of the old four-second polling pattern must not exhaust a connection.
 for(let i=0;i<21600;i++)assert.equal(await store.allow('device',time+i*4000,'pc-heartbeat'),true);
 assert.equal(await store.allow('device',time+21599*4000,'pc-action'),true);
 for(let i=0;i<119;i++)assert.equal(await store.allow('burst',time,'pc-heartbeat'),true);
 assert.equal(await store.allow('burst',time,'pc-heartbeat'),true);assert.equal(await store.allow('burst',time,'pc-heartbeat'),false);
});


test('play-any-song starts browser work and recovers a known pre-dispatch click failure',async()=>{
 const actions=[],snapshot1=randomUUID(),snapshot2=randomUUID();let round=0;
 const steps=[{action:'inspect',arguments:{}},{action:'click',arguments:{snapshotId:snapshot1,elementId:'e1'}},{action:'inspect',arguments:{}},{action:'click',arguments:{snapshotId:snapshot2,elementId:'e2'}},{action:'inspect',arguments:{}}];
 const reply=await ultraReply([{role:'user',content:'play any song'}],{ultraKey:'fixture'},{cloud:{pc:{run:async(action,args)=>{
  actions.push(action);
  if(actions.length===2)return {error:'PC_TARGET_DISABLED'};
  if(action==='inspect')return {status:'completed',result:{snapshotId:actions.length===1?snapshot1:snapshot2,tabId:7,elements:[{id:actions.length===1?'e1':'e2',label:'Play song'}],text:actions.length===5?'Player is playing':'Search results'}};
  return {status:'completed',result:{target:'Play song'}};
 }}},fetcher:async(_u,init)=>{
  const b=JSON.parse(init.body);if(round===0)assert.equal(b.tool_choice.function.name,'pc_browser');
  const step=steps[round++];return Response.json({choices:[{message:step?{tool_calls:[{id:'music-'+round,function:{name:'pc_browser',arguments:JSON.stringify(step)}}]}:{content:'The song is playing.'}}]});
 }});
 assert.deepEqual(actions,['inspect','click','inspect','click','inspect']);
 assert.equal(reply.text,'The song is playing.');assert.ok(reply.activity.some(x=>x.code==='PC_TARGET_DISABLED'));
});

test('an uncertain click is never automatically replayed',async()=>{
 let actions=0,inferences=0;
 const reply=await ultraReply([{role:'user',content:'Click the Play button'}],{ultraKey:'fixture'},{cloud:{pc:{run:async()=>{actions++;return {error:'PC_CLICK_UNCONFIRMED'};}}},fetcher:async()=>{
  inferences++;return Response.json({choices:[{message:{tool_calls:[{id:'uncertain',function:{name:'pc_browser',arguments:JSON.stringify({action:'click',arguments:{snapshotId:randomUUID(),elementId:'e1'}})}}]}}]});
 }});
 assert.equal(actions,1);assert.equal(inferences,1);assert.match(reply.text,/outcome is unconfirmed/);
});


test('reading views require the new extension and distinct views never reuse stale snapshots',async()=>{
 const f=await fixture();let captured=[];
 const tools=pcTools(f.store,f.key,f.pair.deviceId,{now:()=>f.time,turnTag:'views:turn',wait:async()=>{const {job}=await f.store.pcPoll(f.pair.deviceId,f.time);captured.push(job);await f.store.pcResult(f.pair.deviceId,job.id,job.lease,{...snapshot(),view:job.args.view},null,f.time);}});
 await assert.rejects(tools.run('inspect',{view:'links'}),e=>e.code==='PC_EXTENSION_UPDATE_REQUIRED');
 await f.store.pcUpgrade(f.pair.deviceId,f.time,6);
 const page=await tools.run('inspect',{view:'page'}),links=await tools.run('inspect',{view:'links'});
 assert.notEqual(page.jobId,links.jobId);assert.equal(captured.length,2);assert.equal((await tools.run('inspect',{view:'links'})).jobId,links.jobId);
 await tools.run('navigate',{url:'https://www.youtube.com/results?search_query=Kai+Cenat',newTab:true},{preferExistingTab:true});
 assert.equal(captured.at(-1).args.newTab,false);assert.equal(captured.at(-1).args.reuseTab,true);
 await tools.run('navigate',{url:'https://www.youtube.com/results?search_query=Kai+Cenat',newTab:true},{preferExistingTab:false});assert.equal(captured.at(-1).args.newTab,true);
 assert.throws(()=>pcCommand('inspect',{view:'arbitrary-selector'}));
});
