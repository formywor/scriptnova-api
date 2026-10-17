import {createHash} from 'node:crypto';
const sensitive=/\b(password|api.?key|private.?key|access.?token|my name|call me|my address|my phone|my email|birthday|social security|credit card|system prompt|developer message)\b|https?:|@|\[(?:(?:email|credential|number) removed|REDACTED)|(?:hf_|gsk_|AQ\.|AIza|sk-)[A-Za-z0-9_-]{15,}|ignore.{0,30}instructions|override.{0,30}rules/i;
export function checkedTeachingPair(question,answer){
 if(typeof question!=='string'||typeof answer!=='string')return null;
 question=question.trim();answer=answer.trim();
 if(question.length<3||answer.length<3||question.length>400||answer.length>900||sensitive.test(question+' '+answer)||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]/.test(question+answer))return null;
 const arithmetic=question.match(/(?:^|\s)(-?\d{1,5})\s*([+*-])\s*(-?\d{1,5})(?:\s|[?!.]|$)/);
 if(arithmetic){const [,a,op,b]=arithmetic;const expected=op==='+'?+a + +b:op==='-'?+a - +b:+a * +b;const numbers=answer.match(/-?\d+(?:\.\d+)?/g);if(!numbers||Number(numbers.at(-1))!==expected)return null;}
 return [{role:'user',content:question},{role:'assistant',content:answer}];
}
export function reviewTrainingRows(owners,accounts,time=Date.now()){
 const rows=[],seen=new Set();let size=0;
 for(const owner of Object.values(owners||{})){
  if(owner?.revoked)continue;
  for(const sample of Object.values(owner?.samples||{})){
   const p=accounts[sample?.accountKey];
   if(!p?.improve||!p.externalReview||(p.trainingGeneration||0)!==sample.generation||sample.qualityChecked!==true||!Number.isFinite(sample.createdAt)||sample.createdAt>time||sample.createdAt<time-7*86400000)continue;
   const messages=checkedTeachingPair(sample.messages?.[0]?.content,sample.messages?.[1]?.content);if(!messages)continue;
   const id=createHash('sha256').update(JSON.stringify(messages)).digest('hex');if(seen.has(id))continue;
   const row={id,splitGroup:'review-'+id,reviewStatus:'approved',source:{kind:'teacher',trainingAllowed:true,origin:'consented-user-review',curriculum:'v6-reviewed',validation:'two-pass-review-v1'},messages};
   const bytes=Buffer.byteLength(JSON.stringify(row));if(rows.length>=64||size+bytes>120000)return rows;size+=bytes;seen.add(id);rows.push(row);
  }
 }
 return rows;
}
export async function readReviewTraining(db,time=Date.now()){
 const owners=(await db.ref('nebulaReviewTraining/v1').orderByKey().limitToFirst(32).get()).val()||{};
 for(const [id,owner] of Object.entries(owners))if(!owner?.revoked&&(await db.ref('nebulaTraining/v1/'+id+'/revoked').get()).val()===true)owner.revoked=true;
 const keys=new Set();for(const owner of Object.values(owners))if(!owner?.revoked)for(const s of Object.values(owner?.samples||{}))if(/^[a-f0-9]{64}$/.test(s?.accountKey||''))keys.add(s.accountKey);
 const accounts={};for(const key of keys)accounts[key]=(await db.ref('nebulaAccounts/v1/'+key).get()).val();
 return {format:'nebula-reviewed-training-1',rows:reviewTrainingRows(owners,accounts,time),requiresFreshConsent:true};
}
