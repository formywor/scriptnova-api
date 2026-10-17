import {reviewAnswer} from './gemini-review.mjs';
import {reviewGroq} from './groq-review.mjs';
export function reviewProviders(config){return [
 {name:'groq',key:config.reviewGroqKey,model:config.reviewGroqModel||'openai/gpt-oss-20b'},
 {name:'gemini',key:config.reviewKey,model:config.reviewModel}
].filter(p=>p.key&&p.model);}
export function createReviewRouter({config,store,now=Date.now,transports={groq:reviewGroq,gemini:reviewAnswer}}){
 return async ({messages,preferredProvider})=>{
  const providers=reviewProviders(config),order=await store.reviewProviderOrder(providers.map(p=>p.name),now(),preferredProvider);
  let error;
  for(const name of order){const p=providers.find(p=>p.name===name);if(!p)continue;
   try{const value=await transports[name]({messages,key:p.key,model:p.model});await store.reviewProviderSuccess(name,now());return {...value,provider:name};}
   catch(e){error=e;await store.reviewProviderFailure(name,now());}
  }
  throw Object.assign(Error('REVIEW_UNAVAILABLE'),{code:error?.code==='REVIEW_RATE_LIMITED'||!order.length?'REVIEW_RATE_LIMITED':'REVIEW_UNAVAILABLE',status:503});
 };
}
