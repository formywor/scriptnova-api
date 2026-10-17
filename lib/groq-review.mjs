import {REVIEW_INSTRUCTIONS,readReviewJson,validateReview} from './review-format.mjs';
const fail=code=>{throw Object.assign(Error(code),{code,status:503});};
export async function reviewGroq({messages,key,model,fetcher=fetch}){
 if(!key||!/^[a-zA-Z0-9_./-]{1,100}$/.test(model||''))fail('REVIEW_UNAVAILABLE');
 const response=await fetcher('https://api.groq.com/openai/v1/chat/completions',{
  method:'POST',redirect:'error',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},signal:AbortSignal.timeout(18000),
  body:JSON.stringify({model,messages:[{role:'system',content:REVIEW_INSTRUCTIONS},{role:'user',content:JSON.stringify({dialogue:messages})}],response_format:{type:'json_object'},...(model.startsWith('openai/gpt-oss-')?{reasoning_effort:'low'}:{}),temperature:0,max_completion_tokens:2048})});
 if(!response.ok)fail(response.status===429?'REVIEW_RATE_LIMITED':'REVIEW_UNAVAILABLE');
 const envelope=await readReviewJson(response);let result;
 try{result=JSON.parse(envelope.choices[0].message.content);}catch{fail('REVIEW_UNAVAILABLE');}
 return validateReview(result);
}
