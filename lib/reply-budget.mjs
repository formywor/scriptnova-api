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
 function limit(v,depth=0){if(depth>5)return '[Nested detail omitted]';if(typeof v==='string')return v.length>1800?v.slice(0,1800)+' [excerpt]':v;if(Array.isArray(v))return v.slice(0,6).map(x=>limit(x,depth+1));if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).slice(0,24).map(([k,x])=>[k,limit(x,depth+1)]));return v;}
 if(bytes(data)<=maxBytes)return data;const result=limit(data);
 if(bytes(result)<=maxBytes-250)return {...result,contextTruncated:true,contextNotice:'Tool data shortened for this answer. Do not claim omitted details were verified.'};
 return {contextTruncated:true,excerpt:JSON.stringify(result).slice(0,Math.floor(maxBytes/3)),contextNotice:'Partial tool result; omitted details are not verified. Do not invent missing information.'};
}
export function fitProviderBody(body,maxBytes=22000){
 const messages=body.messages.map(m=>({...m})),out={...body,messages};let shortened=false;
 if(bytes({messages,tools:out.tools||[]})>maxBytes){for(const m of messages)if(m.role==='tool'){try{m.content=JSON.stringify(compactToolResult(JSON.parse(m.content),2500));}catch{m.content=JSON.stringify({excerpt:m.content.slice(0,1000),contextTruncated:true});}shortened=true;}}
 if(bytes({messages,tools:out.tools||[]})>maxBytes){const latest=messages.findLastIndex(m=>m.role==='user');for(let i=0;i<messages.length;i++){const m=messages[i];if(m.role==='assistant'&&!m.tool_calls&&m.content?.length>800||m.role==='user'&&i!==latest&&m.content?.length>1600){m.content=m.content.slice(0,m.role==='user'?1600:800)+'\n[Earlier context excerpt]';shortened=true;}}}
 if(bytes({messages,tools:out.tools||[]})>maxBytes)throw fault();return {body:out,shortened};
}
export function promptMetrics(body){const requestBytes=bytes(body),estimatedPromptTokens=Math.ceil(bytes({messages:body.messages,tools:body.tools||[]})/3);return {requestBytes,estimatedPromptTokens};}
