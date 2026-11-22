import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const WORDS=new Set(readFileSync(fileURLToPath(new URL('./data-en-US.txt',import.meta.url)),'utf8').split(/\r?\n/).map(s=>s.trim().toLowerCase()).filter(Boolean));
const BLOCKED=new Set([
 'ass','arse','asshole','bastard','bitch','bollocks','bullshit','cunt','damn','dick','dickhead','douche','fack','fag','faggot','fuck','fucker','fucking','motherfucker','nigga','nigger','piss','prick','pussy','shit','slut','spic','twat','whore','wop',
 'kike','chink','gook','wetback','beaner','coon','cracker','retard','tranny','dyke','fairy','heeb','raghead','towelhead','zipperhead'
]);
const CONFUSABLES=new Map(Object.entries({
 'а':'a','ɑ':'a','α':'a','в':'b','Ь':'b','β':'b','с':'c','ϲ':'c','С':'c','ԁ':'d','ԛ':'q','е':'e','ё':'e','ε':'e','ҽ':'e','ғ':'f','ց':'g','ɡ':'g','һ':'h','н':'h','і':'i','ї':'i','ı':'i','ι':'i','ј':'j','κ':'k','к':'k','ӏ':'l','ⅼ':'l','м':'m','ո':'n','п':'n','о':'o','ο':'o','օ':'o','р':'p','ρ':'p','զ':'q','г':'r','ѕ':'s','տ':'s','т':'t','τ':'t','υ':'u','ս':'u','ν':'v','ѵ':'v','ԝ':'w','х':'x','χ':'x','у':'y','γ':'y','ᴢ':'z','ž':'z'
}));
const LEET={'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a','$':'s','!':'i'};
const REVIEW_CONTEXT=/\b(?:kill|die|race|racial|ethnic|slur|hate|nazi|terror|bomb|shoot|threat|harass|go after|hurt them|hurt you)\b/i;

function fold(input){
 return String(input).normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF]/g,'').replace(/æ/gi,m=>m==='æ'?'ae':'AE').replace(/œ/gi,m=>m==='œ'?'oe':'OE').replace(/ß/g,'ss').replace(/[\u0300-\u036f]/g,'').replace(/[\u0400-\u052f\u0370-\u03ff]/g,c=>CONFUSABLES.get(c)||c).toLowerCase();
}
function lexical(input){
 const normalized=fold(input).replace(/([a-z])[0134578@$!](?=[a-z])/g,(_,a,d)=>a+LEET[d]);
 if(/[\p{L}]/u.test(normalized.replace(/[a-z]/g,'')))return {ok:false,category:'non_english_alphabet'};
 const tokens=(normalized.match(/[a-z]+(?:'[a-z]+)*/g)||[]).map(w=>w.replace(/'{2,}/g,"'").replace(/(.)\1{2,}/g,'$1'));
 if(!tokens.length)return {ok:false,category:'no_english_words'};
 for(let i=0;i<tokens.length;i++){
  const word=tokens[i].replace(/^'+|'+$/g,'');if(!word)continue;
  if(BLOCKED.has(word))return {ok:false,category:'blocked_word',word};
  if(!WORDS.has(word))return {ok:false,category:'not_in_english_dictionary',word};
  let combined='';for(let j=i;j<Math.min(tokens.length,i+8);j++){combined+=tokens[j].replaceAll("'",'');if(combined.length>18)break;if(BLOCKED.has(combined))return {ok:false,category:'blocked_obfuscation',word:combined};}
 }
 const cleaned=normalized.replace(/[^a-z0-9'.,!?;: -]/g,' ').replace(/\s+/g,' ').trim();
 if(!cleaned)return {ok:false,category:'no_english_words'};
 return {ok:true,text:cleaned,needsAiReview:REVIEW_CONTEXT.test(cleaned)};
}

export function moderateEnglishText(text,{aiEnabled=false}={}){
 if(typeof text!=='string'||!text.trim())return {decision:'block',category:'empty_message'};
 if(text.length>280)return {decision:'block',category:'message_too_long'};
 const v=lexical(text);if(!v.ok)return {decision:'block',category:v.category,detectedWord:v.word||null};
 return {decision:'allow',category:v.needsAiReview?(aiEnabled?'ai_review_needed':'review_required'):'dictionary_match',text:v.text,needsAiReview:v.needsAiReview};
}

export function ttsAiModelAllowed(model,config){
 if(!model||model==='nebula-d2'||model==='nebula-d2-lite')return false;
 const models=Array.isArray(config?.models)?config.models:config?.availableModels;
 if(Array.isArray(models))return models.some(m=>m.id===model&&m.available===true);
 return false;
}

export const TTS_WORDLIST_VERSION='SCOWL-US-rel-2026.02.25';
