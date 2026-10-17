// Only aggregate categories leave the account store. Model answers are never labels.
import {createHash} from 'node:crypto';
export const TOPICS=['identity','math','memory','language'];
export function topicFor(content){
 const text=String(content).slice(0,16000).toLowerCase();
 return /\b(who are you|your name|introduce yourself)\b/.test(text)?'identity':
  /\b(calculate|add|subtract|sum|multiply|divide)\b|\d\s*[+*/−-]\s*\d/.test(text)?'math':
  /\b(my name|call me|remember|what colou?r|repeat|which name)\b/.test(text)?'memory':'language';
}
export function learningTopics(training,accounts,now=Date.now()){
 const counts=Object.fromEntries(TOPICS.map(key=>[key,0]));let eligible=0;
 for(const owner of Object.values(training||{})){
  if(owner?.revoked)continue;
  for(const turns of Object.values(owner?.samples||{}))for(const sample of Object.values(turns||{})){
   const source=sample?.source,profile=accounts?.[source?.accountKey];
   if(source?.kind!=='user'||profile?.improve!==true||(profile.trainingGeneration||0)!==source.generation||sample.consentVersion!==1)continue;
   if(!Number.isFinite(sample.createdAt)||sample.createdAt<now-7*86400000||sample.createdAt>now)continue;
   const category=sample.topic;
   if(!TOPICS.includes(category))continue;
   counts[category]++;eligible++;
  }
 }
 return {format:'nebula-topics-1',counts:Object.fromEntries(TOPICS.map(key=>[key,Math.min(10000,Math.floor(counts[key]/5)*5)])),
  eligible:Math.min(10000,Math.floor(eligible/5)*5),windowDays:7,rawChatsExported:false};
}
export async function readLearningTopics(db,now=Date.now()){
 // Read a bounded metadata index, never a tree of full conversation bodies.
 const pivot=createHash('sha256').update(String(Math.floor(now/3600000))).digest('hex');
 const ref=db.ref('nebulaLearning/v1');
 const training=(await ref.orderByKey().startAt(pivot).limitToFirst(100).get()).val()||{};
 if(Object.keys(training).length<100)Object.assign(training,(await ref.orderByKey().limitToFirst(100-Object.keys(training).length).get()).val()||{});
 const keys=new Set();
 for(const owner of Object.values(training))if(!owner?.revoked)for(const turns of Object.values(owner?.samples||{}))for(const sample of Object.values(turns||{})){
  const key=sample?.source?.accountKey;if(/^[a-f0-9]{64}$/.test(key||''))keys.add(key);
 }
 const accounts={};const list=[...keys];
 for(let offset=0;offset<list.length;offset+=10)await Promise.all(list.slice(offset,offset+10).map(async key=>{accounts[key]=(await db.ref('nebulaAccounts/v1/'+key).get()).val();}));
 return learningTopics(training,accounts,now);
}
