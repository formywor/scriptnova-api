import {REVIEW_INSTRUCTIONS,readReviewJson,validateReview} from './review-format.mjs';
// Optional external review. No provider call occurs without separate account consent.
const fail=(code,status=400)=>{throw Object.assign(Error(code),{code,status});};
export async function reviewAnswer({messages,key,model,fetcher=fetch}){
 if(!key||!/^gemini-[a-z0-9.-]{1,80}$/.test(model||''))fail('REVIEW_UNAVAILABLE',503);
 const response=await fetcher('https://generativelanguage.googleapis.com/v1beta/models/'+model+':generateContent',{
  method:'POST',redirect:'error',headers:{'Content-Type':'application/json','x-goog-api-key':key},signal:AbortSignal.timeout(18000),
  body:JSON.stringify({systemInstruction:{parts:[{text:REVIEW_INSTRUCTIONS}]},
    contents:[{role:'user',parts:[{text:JSON.stringify({dialogue:messages})}]}],generationConfig:{responseMimeType:'application/json',maxOutputTokens:2048,temperature:0}})});
 if(!response.ok)fail(response.status===429?'REVIEW_RATE_LIMITED':'REVIEW_UNAVAILABLE',503);
 const envelope=await readReviewJson(response);
 let content;try{content=JSON.parse(envelope.candidates[0].content.parts.filter(p=>typeof p.text==='string'&&!p.thought).map(p=>p.text).join(''));}catch{fail('REVIEW_UNAVAILABLE',503);}
 return validateReview(content);
}
