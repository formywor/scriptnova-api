import {readFileSync} from 'node:fs';
let release='unavailable';
try{release=JSON.parse(readFileSync(new URL('../model-assets/release.json',import.meta.url))).sha256;}catch{}
export const reviewRevision=config=>config.modelRevision||(config.modelMode==='embedded'?release:config.modelName);
// Only explicitly consented exchanges from this exact published checkpoint qualify.
export function reviewPlan(chat,revision,state,time,generation=0){
 const pairs=[];
 for(let i=0;i<chat.messages.length;i++){
  const u=chat.messages[i],a=chat.messages[i+1];
  if(u.role==='user'&&u.reviewEligible===true&&a?.role==='assistant'&&a.replyTo===u.id&&a.modelId==='nebula-v4'&&a.modelRevision===revision&&a.reviewGeneration===generation)pairs.push({u,a});
 }
 const last=pairs.at(-1);if(!last)return {eligible:false};
 const fresh=pairs.filter(p=>(p.a.createdAt||0)>(state?.reviewedThrough||0));
 if(!fresh.length)return {eligible:false};
 const tail=pairs.slice(-5),heavy=tail.length===5&&last.a.createdAt-tail[0].a.createdAt<5*60000;
 const idle=heavy?10*60000:5*60000,needed=heavy?8:3;
 return {eligible:true,due:fresh.length>=needed||time-last.a.createdAt>=idle,retryAt:last.a.createdAt+idle,pairs,last,through:last.a.createdAt};
}
