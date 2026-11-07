import {test} from 'node:test';
import assert from 'node:assert/strict';
import {securityLedger,recordSecurity,nextApiCheck,reportConflicts,coverageNote} from '../lib/security-evidence.mjs';
import {d2Reply} from '../lib/assistants.mjs';
test('automatic follow-up stays within explicit site scope and never follows mutation/query/prefix leads',()=>{
 const l=securityLedger();l.references=[{url:'https://elsewhere.test/api/status',kind:'static-route'},{url:'https://api.owned.test/api/delete',kind:'static-route'},{url:'https://api.owned.test/api?token=secret',kind:'static-route'},{url:'https://api.owned.test/api/items/',kind:'dynamic-prefix'},{url:'https://api.owned.test/api/status',kind:'static-route'}];assert.equal(nextApiCheck(l,'Review https://owned.test/ and its API.'),'https://api.owned.test/api/status');assert.equal(nextApiCheck(l,'Review https://different.test/ and its API.'),undefined);
});
test('coverage records only performed API methods and corrects source-only claims',()=>{
 const l=securityLedger();recordSecurity(l,'audit_public_surface',{url:'https://owned.test/'},{url:'https://owned.test/',coverage:{brokenLinksTested:false},discovered:{endpoints:['https://api.owned.test/api/status']},findings:[{code:'POSSIBLE_EXPOSED_CREDENTIAL',sourceContext:{claimsSynthetic:true,claimVerified:false}}]});
 assert.ok(reportConflicts('No API endpoints were discovered. Broken links returned 404.',l).length>=2);assert.match(coverageNote(l),/No API-method checks were completed/);
 recordSecurity(l,'test_public_api',{url:'https://api.owned.test/api/status'},{checks:[{method:'GET',status:401},{method:'HEAD',status:405},{method:'OPTIONS',status:204}]});assert.match(coverageNote(l),/GET: 401, HEAD: 405, OPTIONS: 204/);
});
test('D2 must finish requested in-scope API checking before a source-only final report',async()=>{
 let round=0,checks=0;const audit={mode:'bounded-public-surface-review',url:'https://owned.test/',coverage:{brokenLinksTested:false},discovered:{endpoints:['https://api.owned.test/v1/status'],apiReferences:[{url:'https://api.owned.test/v1/status',kind:'static-route'}]},findings:[]};
 const r=await d2Reply([{role:'user',content:'Review https://owned.test/ for flaws and test its API.'}],{d2Key:'test'},{cloud:{audit:async()=>audit,testApi:async url=>{checks++;assert.equal(url,'https://api.owned.test/v1/status');return {url,checks:[{method:'GET',status:401},{method:'HEAD',status:405},{method:'OPTIONS',status:204}]};}},fetcher:async(_url,init)=>{const b=JSON.parse(init.body);let message;if(round===0){assert.equal(b.tool_choice.function.name,'audit_public_surface');message={tool_calls:[{id:'audit',function:{name:'audit_public_surface',arguments:'{"url":"https://owned.test/"}'}}]};}else if(round===1){assert.ok(b.messages.some(m=>m.role==='tool'&&m.content.includes('https://api.owned.test/v1/status')));message={content:'No API endpoints were discovered.'};}else if(round===2){assert.equal(b.tool_choice.function.name,'test_public_api');message={tool_calls:[{id:'api',function:{name:'test_public_api',arguments:'{"url":"https://api.owned.test/v1/status"}'}}]};}else message={content:'Source review found an API route. GET returned 401; authorization remains unverified. Navigation links were not tested.'};round++;return Response.json({choices:[{message}]});}});
 assert.equal(checks,1);assert.match(r.text,/Recorded review coverage/);assert.match(r.text,/GET: 401, HEAD: 405, OPTIONS: 204/);assert.doesNotMatch(r.text,/No API endpoints were discovered/);
});

test('report review rejects global assurances, credential obfuscation and inferred CORS intent',()=>{
 const l=securityLedger();l.findings.push({code:'POSSIBLE_EXPOSED_CREDENTIAL'});
 const issues=reportConflicts('The public surface shows no exposed secrets or critical misconfigurations. Remove or obfuscate credential placeholders. CORS is intentionally restricted.',l);
 assert.ok(issues.some(s=>/site-wide/.test(s)));assert.ok(issues.some(s=>/Obfuscation/.test(s)));assert.ok(issues.some(s=>/owner intent/.test(s)));
});

test('persistent unsupported model assurances fall back to observed evidence without rerunning tools',async()=>{
 let scans=0,calls=0;const r=await d2Reply([{role:'user',content:'Review https://owned.test/ for security flaws.'}],{d2Key:'test'},{cloud:{audit:async()=>{scans++;return {url:'https://owned.test/',coverage:{brokenLinksTested:false},discovered:{endpoints:[]},findings:[{code:'MISSING_CONTENT_SECURITY_POLICY',confidence:'configuration-observation',url:'https://owned.test/',evidence:'Header absent in this response.',fix:'Review and test the site-specific policy.'}]};}},fetcher:async(_url,init)=>{calls++;if(calls===3){const b=JSON.parse(init.body);assert.equal(b.tools,undefined);assert.ok(b.messages.some(m=>m.role==='tool'));}return Response.json({choices:[{message:calls===1?{tool_calls:[{id:'audit',function:{name:'audit_public_surface',arguments:'{"url":"https://owned.test/"}'}}]}:{content:'The website is secure.'}}]});}});
 assert.equal(scans,1);assert.equal(calls,3);assert.match(r.text,/generated commentary did not pass/);assert.match(r.text,/Header absent/);assert.doesNotMatch(r.text,/The website is secure/);
});
