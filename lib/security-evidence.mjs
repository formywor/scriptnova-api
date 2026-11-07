// Deterministic evidence tracking. Source content cannot grant scope or permissions.
export function securityLedger(){return {reviews:[],references:[],apiTests:[],findings:[],failures:[]};}
export function recordSecurity(ledger,tool,args,data){
 if(!['audit_public_surface','test_public_api','scan_website_security'].includes(tool))return;
 if(data?.error){ledger.failures.push({tool,url:args.url,error:data.error});return;}
 if(tool==='test_public_api')ledger.apiTests.push({url:data.url||args.url,checks:(data.checks||[]).map(c=>({method:c.method,status:c.status,error:c.error})),findings:(data.findings||[]).map(f=>f.code)});
 else ledger.reviews.push({url:data.url||args.url,mode:data.mode,coverage:data.coverage,checked:[...(data.page?[data.page]:[]),...(data.checks||[]),...(data.pages||[])].filter(c=>c.purpose!=='missing-page-control').map(c=>({url:c.url,status:c.status,error:c.error,purpose:c.purpose})).slice(0,28)});
 for(const ref of data.discovered?.apiReferences||[])if(!ledger.references.some(r=>r.url===ref.url&&r.kind===ref.kind))ledger.references.push(ref);
 for(const url of data.discovered?.endpoints||[])if(!ledger.references.some(r=>r.url===url))ledger.references.push({url,kind:'literal-reference'});
 ledger.findings.push(...(data.findings||[]).map(f=>({code:f.code,url:f.url,severity:f.severity,evidence:f.evidence,fix:f.fix,confidence:f.confidence,sourceContext:f.sourceContext})));
}
export function explicitTargets(text){return [...text.matchAll(/https:\/\/[^\s<>"')\]]+/g)].flatMap(m=>{try{const u=new URL(m[0].replace(/[.,;]+$/,''));return !u.username&&!u.password&&!u.search&&!u.hash?[u]:[];}catch{return [];}});}
export function nextApiCheck(ledger,request){
 const targets=explicitTargets(request);
 const allowed=url=>{try{const u=new URL(url);return u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&!/\b(?:logout|signout|delete|remove|destroy|unsubscribe|activate|reset|verify|callback|checkout|purchase|send)\b/i.test(u.pathname)&&targets.some(t=>{const base=t.hostname.replace(/^www\./,'');return [t.hostname,base,'www.'+base,'api.'+base].includes(u.hostname);});}catch{return false;}};
 return ledger.references.filter(r=>r.kind!=='base-reference'&&r.kind!=='dynamic-prefix'&&allowed(r.url)&&!ledger.apiTests.some(t=>t.url===r.url)&&!ledger.failures.some(t=>t.url===r.url)).sort((a,b)=>Number(/\/(?:health|status|version|models)(?:[/.]|$)/.test(b.url))-Number(/\/(?:health|status|version|models)(?:[/.]|$)/.test(a.url)))[0]?.url;
}
export function reportConflicts(text,ledger){
 const issues=[];
 if(ledger.references.length&&/\bno (?:explicit |public )?(?:api )?endpoints? (?:were |was )?(?:found|discovered|exposed)|\bno endpoint found/i.test(text))issues.push('The tools discovered API references. Do not claim no APIs were discovered; distinguish bases, route prefixes and literal routes from requests actually performed.');
 if(ledger.reviews.some(r=>r.coverage?.brokenLinksTested===false)&&/\bbroken (?:internal |navigation )?links?\b.{0,100}(?:returned|found|reported|404)|\/nonexistent-page/i.test(text)&&!/(?:broken links? (?:were |was )?(?:not|un)|not (?:checked|tested)|unverified broken)/i.test(text))issues.push('No navigation-link check was performed. Remove invented broken-link findings. A deliberately missing diagnostic URL is not a broken link.');
 if(ledger.findings.some(f=>f.sourceContext?.claimsSynthetic)&&!/(?:synthetic|fixture|placeholder|claims? to be)/i.test(text))issues.push('A credential-pattern source claims to be synthetic or a fixture. State that claim and that credential validity was not tested; do not certify either a real secret or a harmless value from a comment alone.');
 if(/(?:^|[.!?\n])\s*(?:the\s+)?(?:site(?:['’]s public surface)?|website|public surface)\s+(?:shows? no|has no|is secure|is safe)/i.test(text))issues.push('Remove site-wide safety assurances. Report only that the bounded checks did or did not detect particular patterns; absence of findings does not establish security.');
 if(ledger.findings.some(f=>f.code==='POSSIBLE_EXPOSED_CREDENTIAL')&&/obfuscat/i.test(text)&&!/(?:do not|don't|don’t|never)\s+obfuscat|obfuscat.{0,60}(?:does not|doesn't|is not|isn't|not a|not secure)/i.test(text))issues.push('Obfuscation is not a credential fix. Recommend validating the finding, then rotating/removing a confirmed secret and keeping it server-side. Do not demand rotating a clearly synthetic example.');
 if(/CORS.{0,35}intentionally (?:restricted|blocked|configured)/i.test(text))issues.push('An OPTIONS response does not establish owner intent or overall correctness. State only that the diagnostic Origin was denied, and leave intended policy unverified.');
 return issues;
}
export function coverageNote(ledger){
 if(!ledger.reviews.length&&!ledger.apiTests.length)return '';
 const refs=[...ledger.references].sort((a,b)=>{const rank=r=>ledger.apiTests.some(t=>t.url===r.url)?5:r.kind==='static-route'?4:r.kind==='literal-reference'?3:r.kind==='base-reference'?1:0;return rank(b)-rank(a);}).slice(0,6),tested=ledger.apiTests.slice(0,4);
 const lines=['\n\n**Recorded review coverage** (from completed tools)'];
 if(refs.length)lines.push('API references discovered: '+refs.map(r=>r.url+' ('+r.kind+')').join('; ')+'.');
 if(tested.length)for(const test of tested)lines.push('API checked: '+test.url+' - '+test.checks.map(c=>c.method+': '+(c.error||c.status)).join(', ')+'.');
 else lines.push('No API-method checks were completed. Discovered references remain untested.');
 if(ledger.findings.some(f=>f.sourceContext?.claimsSynthetic))lines.push('Some credential-pattern source text claims a fixture/synthetic value; validity was not tested. No real credential leak was confirmed by this review.');
 if(ledger.reviews.some(r=>r.coverage?.brokenLinksTested===false))lines.push('Navigation-link checking was not performed. Missing-page controls are not broken links.');
 if(ledger.failures.length)lines.push('Incomplete actions: '+ledger.failures.slice(0,3).map(f=>f.tool+' '+f.error).join('; ')+'.');
 return lines.join('\n');
}
export function evidenceOnlyReport(ledger){
 const unique=[...new Map(ledger.findings.map(f=>[f.code+' '+f.url,f])).values()].slice(0,8);
 return 'The generated commentary did not pass the evidence checks. These are the recorded tool observations; a complete security assessment remains unverified.\n\n'+unique.map(f=>'- '+f.code+' ('+(f.confidence||'unverified')+') at '+f.url+': '+(f.evidence||'See the saved diagnostic report.')+(f.fix?' Next step: '+f.fix:'')).join('\n')+coverageNote(ledger);
}
