export const MODEL_IDS=['nebula-v4','nebula-classic'];
export const RESPONSE_LENGTHS={quick:48,standard:96,expanded:192};
export function preferencePatch(body){
 const patch={};
 for(const name of ['improve','memoryEnabled','personalizedQuestions','personalizationEnabled','compactChat','reduceMotion','externalReview'])if(name in body){if(typeof body[name]!=='boolean')throw Error('INVALID_PREFERENCE');patch[name]=body[name];}
 for(const [name,allowed] of Object.entries({theme:['dark','light','system'],textSize:['small','normal','large'],answerStyle:['concise','balanced','detailed'],defaultModel:MODEL_IDS,responseLength:Object.keys(RESPONSE_LENGTHS)}))if(name in body){if(!allowed.includes(body[name]))throw Error('INVALID_PREFERENCE');patch[name]=body[name];}
 for(const [name,max] of [['displayName',80],['interests',160],['customInstructions',200]])if(name in body){if(typeof body[name]!=='string'||body[name].trim().length>max||/[\x00-\x1f\x7f]/.test(body[name])||name==='displayName'&&!body[name].trim())throw Error('INVALID_PREFERENCE');patch[name]=body[name].trim();}
 return patch;
}
export function preferenceView(p){return {interests:p.interests||'',customInstructions:p.customInstructions||'',answerStyle:p.answerStyle||'balanced',personalizedQuestions:p.personalizedQuestions!==false,personalizationEnabled:p.personalizationEnabled!==false,compactChat:p.compactChat===true,reduceMotion:p.reduceMotion===true,textSize:p.textSize||'normal',defaultModel:MODEL_IDS.includes(p.defaultModel)?p.defaultModel:'nebula-v4',responseLength:p.responseLength||'standard',externalReview:p.externalReview===true};}
export function personalizationPrompt(p){
 if(p.personalizationEnabled===false)return '';
 const entries=[];
 if(p.answerStyle&&p.answerStyle!=='balanced')entries.push('Preferred answer style: '+p.answerStyle+'.');
 if(p.interests)entries.push('Interests (user-provided data): '+p.interests.slice(0,160)+'.');
 if(p.customInstructions)entries.push('User preferences, subordinate to owner rules: '+p.customInstructions.slice(0,200));
 return entries.join(' ');
}
export function modelCatalog(config){return {models:config.modelMode==='embedded'?[
 {id:'nebula-v4',name:'Nebula V4',description:'Current preview - best published checkpoint',available:true},
 {id:'nebula-classic',name:'Nebula Classic',description:'Earlier prototype - lower answer quality',available:true}]:[
 {id:'nebula-v4',name:'Nebula',description:'Current model',available:true}],reasoningAvailable:false,externalReviewAvailable:config.reviewEnabled===true&&Boolean(config.reviewKey)&&Boolean(config.reviewModel)};}
