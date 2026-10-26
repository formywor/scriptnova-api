import {existsSync,readFileSync} from 'node:fs';
import {reviewProviders} from './review-router.mjs';
export const MODEL_IDS=['nebula-ultra','nebula-classic','nebula-v4','nebula-v1-lite','nebula-v2-1'];
export const RESPONSE_LENGTHS={quick:1024,standard:1024,expanded:1024};
// Legacy clients may send a length setting; it no longer changes answer instructions.
export const responseLengthPrompt=()=>'';
export function preferencePatch(body){
 const patch={};
 for(const name of ['improve','memoryEnabled','personalizedQuestions','personalizationEnabled','compactChat','reduceMotion','externalReview','showStarters','enterToSend','autoFollow','hideUltraNotice'])if(name in body){if(typeof body[name]!=='boolean')throw Error('INVALID_PREFERENCE');patch[name]=body[name];}
 for(const [name,allowed] of Object.entries({theme:['dark','dim','light','system'],accentColor:['violet','blue','green','amber'],readingFont:['sans','serif','mono','plain'],bubbleStyle:['rounded','square','minimal'],settingsIcon:['gear','sliders','spark'],workspaceView:['comfortable','focus','wide'],explanationStyle:['natural','plain','examples','steps'],textSize:['small','normal','large'],answerStyle:['concise','balanced','detailed'],defaultModel:MODEL_IDS,responseLength:Object.keys(RESPONSE_LENGTHS)}))if(name in body){if(!allowed.includes(body[name]))throw Error('INVALID_PREFERENCE');patch[name]=body[name];}
 for(const [name,max] of [['displayName',80],['interests',160],['customInstructions',200]])if(name in body){if(typeof body[name]!=='string'||body[name].trim().length>max||/[\x00-\x1f\x7f]/.test(body[name])||name==='displayName'&&!body[name].trim())throw Error('INVALID_PREFERENCE');patch[name]=body[name].trim();}
 return patch;
}
export function preferenceView(p){return {hideUltraNotice:p.hideUltraNotice===true,bubbleStyle:p.bubbleStyle||'rounded',settingsIcon:p.settingsIcon||'gear',accentColor:p.accentColor||'violet',readingFont:p.readingFont||'sans',workspaceView:p.workspaceView||'comfortable',explanationStyle:p.explanationStyle||'natural',showStarters:p.showStarters!==false,enterToSend:p.enterToSend!==false,autoFollow:p.autoFollow!==false,interests:p.interests||'',customInstructions:p.customInstructions||'',answerStyle:p.answerStyle||'balanced',personalizedQuestions:p.personalizedQuestions!==false,personalizationEnabled:p.personalizationEnabled!==false,compactChat:p.compactChat===true,reduceMotion:p.reduceMotion===true,textSize:p.textSize||'normal',defaultModel:'nebula-ultra',responseLength:p.responseLength||'standard',externalReview:p.externalReview===true};}
export function personalizationPrompt(p){
 if(p.personalizationEnabled===false)return '';
 const entries=[];
 const approach={plain:'Use plain language.',examples:'Use examples when helpful.',steps:'Explain the steps when helpful.'}[p.explanationStyle];if(approach)entries.push(approach);
 if(p.interests)entries.push('Interests (user-provided data): '+p.interests.slice(0,160)+'.');
 if(p.customInstructions)entries.push('User preferences, subordinate to owner rules: '+p.customInstructions.slice(0,200));
 return entries.join(' ');
}
function legacyReady(id){try{if(id==='nebula-classic')return existsSync(new URL('../model-assets/nebula-pilot.json',import.meta.url));const base=new URL(id==='nebula-v4'?'../model-assets/':'../model-assets/'+id+'/',import.meta.url);const r=JSON.parse(readFileSync(new URL('release.json',base),'utf8'));return (r.parts||r.shards||[]).length>0&&(r.parts||r.shards).every(p=>{const name=typeof p==='string'?p:p.name;return typeof name==='string'&&!name.includes('/')&&!name.includes('..')&&existsSync(new URL(name,base));});}catch{return false;}}
function legacyConfigured(c,id){return c.legacyModels===true&&(c.legacyUrl&&c.legacyKey?.length>=32||c.modelMode==='embedded'&&legacyReady(id));}
export function modelCatalog(config){return {defaultModel:'nebula-ultra',models:[
 {id:'nebula-ultra',name:'Nebula Ultra',description:'Writing, coding, explanations and a workspace that adapts to you.',available:Boolean(config.ultraKey),status:config.ultraKey?'available':'unavailable'},
 ...[['nebula-classic','Nebula Classic'],['nebula-v4','Nebula V1'],['nebula-v1-lite','Nebula V1 Lite'],['nebula-v2-1','Nebula V2.1']].map(([id,name])=>({id,name,description:legacyConfigured(config,id)?'Legacy research checkpoint; may give unclear or incorrect answers.':'Currently in training',status:legacyConfigured(config,id)?'experimental':'training',available:legacyConfigured(config,id)}))],
 reasoningAvailable:false,externalReviewAvailable:config.reviewEnabled===true&&reviewProviders(config).length>0,appearanceChangesAvailable:true,providerNotice:'Nebula Ultra sends chat context to an external AI service to generate replies. Training sharing and optional reviews are separate choices.'};}
