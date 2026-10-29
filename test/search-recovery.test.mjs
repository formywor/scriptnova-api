import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webSearch} from '../lib/cloud-services.mjs';
test('search recovers from quota failure and uses executed source evidence, never generated claims',async()=>{
 let primary=0,backup=0;
 const c={sparkKey:'quota-test',ultraKey:'private-backup'};
 const fetcher=async(url,init)=>{
  if(String(url).includes('googleapis')){primary++;return Response.json({error:{message:'private upstream response'}},{status:429});}
  backup++;const b=JSON.parse(init.body);assert.equal(init.headers.Authorization,'Bearer private-backup');assert.equal(b.tools[0].type,'browser_search');assert.equal(b.reasoning_effort,'low');
  return Response.json({choices:[{message:{content:'INVENTED ADDRESS: 123 Fake Street',reasoning:'hidden',executed_tools:[{name:'browser.search',search_results:{results:[{url:'https://official.example/store',title:'Official store',content:''},{url:'javascript:alert(1)',content:'bad'}]}},{name:'browser.open',search_results:{results:[{url:'https://official.example/store',title:'Official store',content:'Verified source excerpt.'}]}}]}}]});
 };
 for(let i=0;i<2;i++){const r=await webSearch('store near 23832',c,fetcher);assert.equal(r.results.length,1);assert.equal(r.results[0].description,'Verified source excerpt.');assert.doesNotMatch(JSON.stringify(r),/INVENTED|hidden|private-backup|javascript/);}
 assert.equal(primary,1);assert.equal(backup,2);
});
test('search rejects an unsupported generated answer with no executed sources',async()=>{
 await assert.rejects(webSearch('query',{ultraKey:'backup-only'},async()=>Response.json({choices:[{message:{content:'Trust me, here is a store https://example.com'}}]})),e=>e.code==='NO_SEARCH_RESULTS');
});
test('grounded source descriptions only contain passages attributed to that source',async()=>{
 const r=await webSearch('query',{sparkKey:'attribution-check'},async()=>Response.json({candidates:[{content:{parts:[{text:'A supported fact. An unverified invented address.'}]},groundingMetadata:{groundingChunks:[{web:{uri:'https://official.example/one',title:'One'}},{web:{uri:'https://official.example/two',title:'Two'}}],groundingSupports:[{groundingChunkIndices:[0],segment:{text:'A supported fact.'}}]}}]}));
 assert.equal(r.results[0].description,'A supported fact.');assert.equal(r.results[1].description,'');assert.doesNotMatch(JSON.stringify(r),/invented address/);
});
test('both search routes failing produces an explicit failure with no fabricated results',async()=>{
 let calls=0;await assert.rejects(webSearch('query',{searchKey:'brave-failure',ultraKey:'backup'},async()=>{calls++;return Response.json({error:'sensitive upstream message'},{status:503});}),e=>e.code==='CLOUD_SERVICE_UNAVAILABLE');assert.equal(calls,2);
});
