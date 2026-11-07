import {test} from 'node:test';
import assert from 'node:assert/strict';
import {compactContext,compactToolResult,fitProviderBody} from '../lib/reply-budget.mjs';
import {ultraReply} from '../lib/ultra.mjs';
const json=message=>Response.json({choices:[{message}]});
test('long chats keep owner rules, the original goal and the current ZIP without editing saved history',()=>{
 const messages=[{role:'system',content:'Owner policy must remain exact.'},{role:'system',optionalContext:true,content:'Context '+ 'x'.repeat(15000)},{role:'user',content:'Does Publix near Chesterfield sell lamb chops?'},...Array.from({length:18},(_,i)=>({role:i%2?'user':'assistant',content:'Earlier discussion '+i+' '+ 'z'.repeat(1800)})),{role:'user',content:'23832'}];
 const before=JSON.stringify(messages),result=compactContext(messages);assert.equal(result.shortened,true);assert.equal(result.messages[0].content,messages[0].content);assert.equal(result.messages.at(-1).content,'23832');assert.ok(result.messages.some(m=>m.content.includes('Publix')));assert.equal(JSON.stringify(messages),before);assert.ok(Buffer.byteLength(JSON.stringify(result.messages))<14000);
});
test('oversized current requests fail clearly rather than dropping part of the current question',()=>assert.throws(()=>compactContext([{role:'user',content:'x'.repeat(18000)}]),e=>e.code==='MODEL_CONTEXT_LIMIT'));
test('large tool results are bounded, valid JSON, marked incomplete and leave the saved results intact',()=>{
 const data={text:'t'.repeat(14000),source:'s'.repeat(18000),url:'https://example.com/',network:Array.from({length:50},()=>({status:200})),notice:'Untrusted data.'},before=JSON.stringify(data),small=compactToolResult(data);assert.ok(Buffer.byteLength(JSON.stringify(small))<6500);assert.equal(small.contextTruncated,true);assert.equal(JSON.stringify(data),before);
 const calls=[{id:'t1',type:'function',function:{name:'read_webpage',arguments:'{"url":"https://example.com/"}'}}],body={messages:[{role:'system',content:'owner rules'},{role:'user',content:'Check the page.'},{role:'assistant',content:null,tool_calls:calls},{role:'tool',tool_call_id:'t1',content:JSON.stringify(data)}],tools:[]},fitted=fitProviderBody(body);assert.equal(fitted.body.messages[2].tool_calls[0].id,'t1');assert.equal(fitted.body.messages[3].tool_call_id,'t1');assert.ok(Buffer.byteLength(JSON.stringify(fitted.body))<22500);assert.equal(body.messages[3].content,JSON.stringify(data));
});
test('Ultra retries the current inference with backup capacity without re-running completed tools',async()=>{
 let calls=0,lookups=0;const models=[],statuses=[];
 const result=await ultraReply([{role:'user',content:'Read this public page and summarize it.'}],{ultraKey:'secret',selectedModel:'nebula-ultra',onProgress:s=>statuses.push(s)},{cloud:{read:async()=>{lookups++;return {url:'https://example.com/',text:'Verified page text.'};}},fetcher:async(_,init)=>{const b=JSON.parse(init.body);models.push(b.model);assert.equal(init.headers.Authorization,'Bearer secret');assert.ok(b.max_completion_tokens<=2048);if(++calls===1)return json({content:null,tool_calls:[{id:'read1',type:'function',function:{name:'read_webpage',arguments:'{"url":"https://example.com/"}'}}]});assert.ok(b.messages.some(m=>m.role==='tool'&&m.tool_call_id==='read1'));return calls===2?new Response('rate limit',{status:429}):json({content:'The page says verified page text.'});}});
 assert.equal(lookups,1);assert.equal(models.at(-1),'openai/gpt-oss-20b');assert.equal(statuses.length,1);assert.ok(result.text);
});
test('a retail ZIP follow-up requires search and retains the retailer and location context',async()=>{
 let round=0,searches=0;const result=await ultraReply([{role:'user',content:'Find Publix near Chesterfield that carries lamb chops.'},{role:'assistant',content:'What is your ZIP code?'},{role:'user',content:'23832'}],{ultraKey:'test',selectedModel:'nebula-ultra'},{cloud:{search:async q=>{searches++;assert.match(q,/23832/);return {results:[{title:'Official store locator',url:'https://www.publix.com/locations',description:'Use the official store locator. Stock is not confirmed.'}]};}},fetcher:async(_,init)=>{const b=JSON.parse(init.body);assert.ok(b.messages.some(m=>m.content?.includes('Publix')));assert.match(b.messages[0].content,/never substitute illustrative or invented entries/);if(round++===0){assert.equal(b.tool_choice.function.name,'search_web');return json({content:null,tool_calls:[{id:'search1',type:'function',function:{name:'search_web',arguments:'{"query":"Publix official store locator near 23832"}'}}]});}return json({content:'Use the official Publix store locator for 23832. Stock needs confirmation from the store.'});}});assert.equal(searches,1);assert.equal(result.sources[0].url,'https://www.publix.com/locations');
});
test('Ultra does not retry an authentication failure or repeatedly cycle through capacity failures',async()=>{
 for(const status of [401,429]){let calls=0;await assert.rejects(ultraReply([{role:'user',content:'Hello there.'}],{ultraKey:'test',selectedModel:'nebula-ultra'},{fetcher:async()=>{calls++;return new Response('private',{status});}}));assert.equal(calls,status===401?1:2);}
});

 test('large PC observations retain actionable identifiers through both budget passes',()=>{
  const page={elements:[{id:'e1',role:'button',label:'Compose'}],network:Array.from({length:40},()=>({url:'https://example.com/'+ 'x'.repeat(1700)})),snapshotId:'97cfdf7e-96fa-40e0-ba7a-a63892d111b3',tabId:7,url:'https://example.com/'};
  const data={jobId:'a'.repeat(32),status:'completed',result:page},before=JSON.stringify(data);
  const first=compactToolResult(data),second=compactToolResult(first,2500);
  assert.equal(second.result.snapshotId,page.snapshotId);assert.equal(second.result.tabId,7);assert.equal(second.result.elements[0].id,'e1');assert.equal(second.status,'completed');assert.ok(Buffer.byteLength(JSON.stringify(second))<=2500);assert.equal(JSON.stringify(data),before);
 });

test('long browser followups fit without dropping recent control references or current instruction',()=>{
 const latest='send it',page={status:'completed',result:{snapshotId:'97cfdf7e-96fa-40e0-ba7a-a63892d111b3',tabId:7,elements:Array.from({length:24},(_,i)=>({id:'e'+(i+1),label:'Control '+i+' '+ 'x'.repeat(110),role:'button'}))}};
 const body={messages:[{role:'system',content:'Owner policy '+ 's'.repeat(7000)},...Array.from({length:10},(_,i)=>({role:i%2?'assistant':'user',content:'Previous draft conversation '+ 'm'.repeat(1200)})),{role:'user',content:latest},{role:'assistant',content:null,tool_calls:[{id:'read',function:{name:'pc_browser',arguments:'{}'}}]},{role:'tool',tool_call_id:'read',content:JSON.stringify(page)}],tools:[{type:'function',function:{name:'pc_browser',description:'Schema '+ 't'.repeat(4000)}}]};
 const fitted=fitProviderBody(body);assert.ok(Buffer.byteLength(JSON.stringify({messages:fitted.body.messages,tools:fitted.body.tools}))<=22000);assert.equal(fitted.body.messages.findLast(m=>m.role==='user').content,latest);const result=JSON.parse(fitted.body.messages.at(-1).content);assert.equal(result.result.snapshotId,page.result.snapshotId);assert.ok(result.result.elements.length);assert.equal(fitted.body.messages[0].content,body.messages[0].content);
});
