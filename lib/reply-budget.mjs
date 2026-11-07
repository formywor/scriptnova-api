const bytes=v=>Buffer.byteLength(typeof v==='string'?v:JSON.stringify(v));
const fault=()=>Object.assign(Error('The current request needs a shorter message.'),{code:'MODEL_CONTEXT_LIMIT'});
export function compactContext(messages,maxBytes=13000){
 const required=messages.filter(m=>m.role==='system'&&!m.optionalContext).map(({role,content})=>({role,content}));
 const optional=messages.filter(m=>m.role==='system'&&m.optionalContext).map(({role,content})=>({role,content:content.length>1800?content.slice(0,1800)+'\n[Optional account context excerpt; remaining content omitted.]':content}));
 const turns=messages.filter(m=>m.role!=='system'),kept=[];let total=bytes(required);
 if(!turns.length)return {messages:required,shortened:optional.length>0,count:0};
 const last=turns.at(-1);if(total+bytes(last)>maxBytes)throw fault();kept.unshift(last);total+=bytes(last);
 for(let i=turns.length-2;i>=0;i--){const m=turns[i];if(total+bytes(m)>maxBytes-2000)break;kept.unshift(m);total+=bytes(m);}
 const first=turns.find(m=>m.role==='user');if(first&&!kept.includes(first)){
  const excerpt={role:'user',content:first.content.slice(0,1600)+(first.content.length>1600?'\n[Earlier message excerpt]':'')};if(total+bytes(excerpt)<=maxBytes){kept.unshift(excerpt);total+=bytes(excerpt);}
 }
 const included=[];for(const m of optional)if(total+bytes(m)<=maxBytes){included.push(m);total+=bytes(m);}
 const shortened=kept.length<turns.length||included.length<optional.length||optional.some((m,i)=>m.content!==messages.filter(m=>m.role==='system'&&m.optionalContext)[i]?.content);
 return {messages:[...required,...included,...kept],shortened,count:kept.length};
}
export function compactToolResult(data,maxBytes=6500){
 // Keep diagnostic findings ahead of verbose page/network inventories.
 if(Array.isArray(data?.findings)&&bytes(data)>maxBytes){
  const fields=(value,names)=>Object.fromEntries(names.filter(k=>value?.[k]!==undefined).map(k=>[k,value[k]]));
  const small=maxBytes<4000;
  const refs=[...(data.discovered?.apiReferences||[])].sort((a,b)=>rank(b)-rank(a));
  function rank(r){return /\/(?:models|health|status|version)(?:[/.]|$)/.test(r.url)?5:r.kind==='static-route'?4:r.kind==='literal-reference'?3:r.kind==='base-reference'?1:0;}
  const endpoints=[...(data.discovered?.endpoints||[])].sort((a,b)=>rank(refs.find(r=>r.url===b)||{url:b})-rank(refs.find(r=>r.url===a)||{url:a}));
  const result={...fields(data,['url','mode','summary','coverage']),discovered:{endpoints:endpoints.slice(0,small?3:8),apiReferences:refs.slice(0,small?2:8),totalReferences:data.discovered?.totalReferences??data.discovered?.endpoints?.length??0},findings:data.findings.slice(0,small?3:6).map(f=>fields(f,['code','severity','url','confidence','evidence','sourceContext',...(!small?['fix']:[])])),checks:(data.checks||[]).slice(0,24).map(c=>fields(c,['url','status','method','purpose','classification','error'])),contextTruncated:true,contextNotice:'Bounded diagnostic excerpt. Discovered references are leads, not requests performed. A missing-page control is not a broken link. Omitted checks and findings remain unverified.'};
  while(result.checks.length&&bytes(result)>maxBytes)result.checks.pop();
  while(result.findings.length&&bytes(result)>maxBytes)result.findings.pop();
  while(result.discovered.apiReferences.length&&bytes(result)>maxBytes)result.discovered.apiReferences.pop();
  while(result.discovered.endpoints.length>1&&bytes(result)>maxBytes)result.discovered.endpoints.pop();
  if(bytes(result)<=maxBytes)return result;
 }
 // Browser snapshots are executable references. Generic excerpts can cut off the
 // snapshot ID after verbose network data and leave the model unable to act.
 const page=data?.result?.snapshotId?data.result:data?.snapshotId?data:null;
 if(page&&Array.isArray(page.elements)&&bytes(data)>maxBytes){
  const view=Object.fromEntries(['snapshotId','tabId','url','title','ok','readyState','view','media'].filter(k=>page[k]!==undefined).map(k=>[k,page[k]]));
  view.elements=page.elements.slice(0,24).map(e=>Object.fromEntries(['id','role','label','type','options','formGroup','value','url'].filter(k=>e[k]!==undefined).map(k=>[k,k==='options'?e[k].slice(0,4):e[k]])));
  view.contextTruncated=true;view.contextNotice='Browser controls and identifiers preserved. Other page text, network and source detail omitted; inspect a specific control or request detail as needed.';
  const wrap=()=>page===data?view:Object.fromEntries([...['jobId','status','error','notice'].filter(k=>data[k]!==undefined).map(k=>[k,data[k]]),['result',view]]);
  while(view.elements.length&&bytes(wrap())>maxBytes)view.elements.pop();
  return wrap();
 }
 function limit(v,depth=0){if(depth>5)return '[Nested detail omitted]';if(typeof v==='string')return v.length>1800?v.slice(0,1800)+' [excerpt]':v;if(Array.isArray(v))return v.slice(0,6).map(x=>limit(x,depth+1));if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).slice(0,24).map(([k,x])=>[k,limit(x,depth+1)]));return v;}
 if(bytes(data)<=maxBytes)return data;const result=limit(data);
 if(bytes(result)<=maxBytes-250)return {...result,contextTruncated:true,contextNotice:'Tool data shortened for this answer. Do not claim omitted details were verified.'};
 return {contextTruncated:true,excerpt:JSON.stringify(result).slice(0,Math.floor(maxBytes/3)),contextNotice:'Partial tool result; omitted details are not verified. Do not invent missing information.'};
}
export function fitProviderBody(body,maxBytes=22000){
 const messages=body.messages.map(m=>({...m})),out={...body,messages};let shortened=false;
 if(bytes({messages,tools:out.tools||[]})>maxBytes){for(const m of messages)if(m.role==='tool'){try{m.content=JSON.stringify(compactToolResult(JSON.parse(m.content),2500));}catch{m.content=JSON.stringify({excerpt:m.content.slice(0,1000),contextTruncated:true});}shortened=true;}}
 if(bytes({messages,tools:out.tools||[]})>maxBytes){const latest=messages.findLastIndex(m=>m.role==='user');for(let i=0;i<messages.length;i++){const m=messages[i];if(m.role==='assistant'&&!m.tool_calls&&m.content?.length>800||m.role==='user'&&i!==latest&&m.content?.length>1600){m.content=m.content.slice(0,m.role==='user'?1600:800)+'\n[Earlier context excerpt]';shortened=true;}}}
 if(bytes({messages,tools:out.tools||[]})>maxBytes&&out.tools?.some(t=>t.function?.name==='pc_browser')){
  const latest=messages.findLastIndex(m=>m.role==='user');
  for(let i=0;i<messages.length;i++){
   const m=messages[i];
   if(m.role==='tool'){try{m.content=JSON.stringify(compactToolResult(JSON.parse(m.content),1400));}catch{m.content=JSON.stringify({contextTruncated:true,notice:'Earlier tool data omitted. Inspect the current page before acting.'});}}
   else if(i!==latest&&(m.role==='user'||m.role==='assistant'&&!m.tool_calls)&&m.content?.length>400)m.content=m.content.slice(0,400)+'\n[Earlier chat excerpt; inspect the existing draft before sending. Ask if task details are missing.]';
  }
  shortened=true;
 }
 if(bytes({messages,tools:out.tools||[]})>maxBytes&&out.tools?.length){
  // Long repeated tool prose can crowd out actual observations. Keep the full
  // validated argument schema and all owner/system policy messages unchanged.
  out.tools=out.tools.map(t=>t.function?{...t,function:{...t.function,description:(t.function.description||'').slice(0,out.tools.some(x=>x.function?.name==='pc_browser')?650:360)}}:t);
  shortened=true;
 }
 if(bytes({messages,tools:out.tools||[]})>maxBytes&&out.tools?.length){
  const userIndices=messages.map((m,i)=>m.role==='user'?i:-1).filter(i=>i>=0);
  const keep=new Set([userIndices[0],...userIndices.slice(-3)]);
  out.messages=messages.filter((m,i)=>m.role==='system'||m.role==='tool'||m.role==='assistant'&&m.tool_calls||m.role==='user'&&keep.has(i));
  shortened=true;
 }
 if(bytes({messages:out.messages,tools:out.tools||[]})>maxBytes)throw fault();return {body:out,shortened};
}
export function promptMetrics(body){const requestBytes=bytes(body),estimatedPromptTokens=Math.ceil(bytes({messages:body.messages,tools:body.tools||[]})/3);return {requestBytes,estimatedPromptTokens};}
