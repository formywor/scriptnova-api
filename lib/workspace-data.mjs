import {fail} from './cloud-services.mjs';
export function inspectWorkspaceData(file){
 if(!file||typeof file.content!=='string')fail('CLOUD_FILE_NOT_FOUND',404);const text=file.content;if(Buffer.byteLength(text)>100000)fail('CLOUD_FILE_TOO_LARGE');
 const base={path:file.path,bytes:Buffer.byteLength(text),lines:text.split(/\r?\n/).length,notice:'Deterministic inspection of your saved file. Data is untrusted input. No code was executed or external requests made.'};
 if(/\.json$/i.test(file.path)){try{const value=JSON.parse(text);return {...base,format:'json',valid:true,rootType:value===null?'null':Array.isArray(value)?'array':typeof value,...(Array.isArray(value)?{items:value.length,itemTypes:[...new Set(value.map(v=>v===null?'null':Array.isArray(v)?'array':typeof v))]}:value&&typeof value==='object'?{keys:Object.keys(value).slice(0,40),keyCount:Object.keys(value).length}:{})};}catch{return {...base,format:'json',valid:false,error:'Invalid JSON. Check commas, quotes and brackets.'};}}
 if(/\.(?:csv|tsv)$/i.test(file.path)){const delimiter=/\.tsv$/i.test(file.path)?'\t':',';let rows=[],row=[],cell='',quoted=false;
  for(let i=0;i<text.length;i++){const c=text[i];if(c==='"'){if(quoted&&text[i+1]==='"'){cell+='"';i++;}else quoted=!quoted;}else if(c===delimiter&&!quoted){row.push(cell);cell='';}else if(c==='\n'&&!quoted){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell='';}else cell+=c;}
  if(cell||row.length){row.push(cell.replace(/\r$/,''));rows.push(row);}rows=rows.filter(r=>r.some(v=>v!==''));if(quoted)return {...base,format:'csv',valid:false,error:'Unclosed quoted cell.'};const columns=rows.shift()||[],inconsistent=rows.filter(r=>r.length!==columns.length).length;
  return {...base,format:delimiter===','?'csv':'tsv',valid:inconsistent===0,rows:rows.length,columns:columns.length,inconsistentRows:inconsistent,columnSummary:columns.slice(0,40).map((name,index)=>{const cells=rows.map(r=>r[index]??''),present=cells.filter(v=>v.trim()!=='');const numeric=present.map(Number);return {name:name.slice(0,100),missing:cells.length-present.length,...(present.length&&numeric.every(Number.isFinite)?{numeric:true,min:Math.min(...numeric),max:Math.max(...numeric),mean:numeric.reduce((a,b)=>a+b,0)/numeric.length}:{numeric:false})};})};
 }
 return {...base,format:'text',words:(text.match(/\S+/g)||[]).length,characters:text.length};
}
