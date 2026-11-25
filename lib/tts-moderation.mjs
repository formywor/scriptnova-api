import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const WORDS=new Set(readFileSync(fileURLToPath(new URL('./data-en-US.txt',import.meta.url)),'utf8').split(/\r?\n/).map(s=>s.trim().toLowerCase()).filter(Boolean));
const BLOCKED=new Set([
 'ass','arse','asshole','bastard','bitch','bollocks','bullshit','cunt','damn','dick','dickhead','douche','fack','fag','faggot','fuck','fucker','fucking','motherfucker','nigga','nigger','piss','prick','pussy','shit','slut','spic','twat','whore','wop',
 'kike','chink','gook','wetback','beaner','coon','cracker','retard','tranny','dyke','fairy','heeb','raghead','towelhead','zipperhead'
]);
const SAFE_SLANG=new Set(['wsg','wsp','sup','yo','lol','lmao','lmfao','rofl','brb','btw','omg','idk','imo','imho','ngl','fr','rn','wyd','wya','hbu','ikr','tbh','gg','ggs','wp','ez','afk','irl','smh','lowkey','highkey','sus','sheesh','bet','lit','vibe','vibes','bro','bruh','nah','yep','yup','yall','tho','gonna','wanna','gotta','kinda','sorta','wassup','hello','hey','hiya']);
const CONFUSABLES=new Map(Object.entries({
 'а':'a','ɑ':'a','α':'a','в':'b','Ь':'b','β':'b','с':'c','ϲ':'c','С':'c','ԁ':'d','ԛ':'q','е':'e','ё':'e','ε':'e','ҽ':'e','ғ':'f','ց':'g','ɡ':'g','һ':'h','н':'h','і':'i','ї':'i','ı':'i','ι':'i','ј':'j','κ':'k','к':'k','ӏ':'l','ⅼ':'l','м':'m','ո':'n','п':'n','о':'o','ο':'o','օ':'o','р':'p','ρ':'p','զ':'q','г':'r','ѕ':'s','տ':'s','т':'t','τ':'t','υ':'u','ս':'u','ν':'v','ѵ':'v','ԝ':'w','х':'x','χ':'x','у':'y','γ':'y','ᴢ':'z','ž':'z'
}));
const LEET={'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a','$':'s','!':'i'};
const REVIEW_CONTEXT=/\b(?:kill|die|race|racial|ethnic|slur|hate|nazi|terror|bomb|shoot|threat|harass|go after|hurt them|hurt you)\b/i;
const EMOJI=/[\p{Extended_Pictographic}\p{Regional_Indicator}\u{1F3FB}-\u{1F3FF}]/u;
const URL_LIKE=/(?:https?:\/\/|www\.)\S+|\b[a-z0-9-]+\.(?:com|net|org|gg|io|co|tv|me|app|dev|xyz|link|live|info|biz)\b/i;

function fold(input){
 return String(input).normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF]/g,'').replace(/æ/gi,m=>m==='æ'?'ae':'AE').replace(/œ/gi,m=>m==='œ'?'oe':'OE').replace(/ß/g,'ss').replace(/[\u0300-\u036f]/g,'').replace(/[\u0400-\u052f\u0370-\u03ff]/g,c=>CONFUSABLES.get(c)||c).toLowerCase();
}
function lexical(input,options={}){
 const settings=options&&typeof options==='object'?options:{},allowEmoji=settings.allowEmoji!==false,allowOtherLanguages=settings.allowOtherLanguages===true,allowSlang=settings.allowSlang!==false,strictness=['strict','balanced','relaxed'].includes(settings.strictness)?settings.strictness:'balanced';
 const original=String(input).normalize('NFKC'),hasEmoji=EMOJI.test(original);if(hasEmoji&&!allowEmoji)return {ok:false,category:'emoji_not_allowed'};
 if(settings.skipLinks===true&&URL_LIKE.test(original))return {ok:false,category:'links_not_allowed'};
 const normalized=fold(original).replace(/([a-z])[0134578@$!](?=[a-z])/g,(_,a,d)=>a+LEET[d]);
 const custom=(Array.isArray(settings.blockKeywords)?settings.blockKeywords:[]).slice(0,100).map(v=>fold(v).replace(/[^\p{L}\p{N}]+/gu,' ').trim()).filter(Boolean),normalizedForPhrase=normalized.replace(/[^\p{L}\p{N}]+/gu,' ').trim();
 for(const phrase of custom)if((' '+normalizedForPhrase+' ').includes(' '+phrase+' '))return {ok:false,category:'custom_keyword',word:phrase};
 const approved=(Array.isArray(settings.allowWords)?settings.allowWords:[]).slice(0,100).map(value=>fold(value).trim()),approvedHandles=new Set(approved.filter(value=>/^@[\p{L}\p{N}_]{1,30}$/u.test(value)).map(value=>value.slice(1))),allowedWords=new Set(approved.filter(value=>!value.startsWith('@')).flatMap(value=>value.match(/[\p{L}\p{N}]+/gu)||[])),mentionedWords=new Set();
 for(const match of normalized.matchAll(/(?<![\p{L}\p{N}_])@([\p{L}\p{N}_]{1,30})/gu))if(approvedHandles.has(match[1]))for(const word of match[1].match(/[\p{L}\p{N}]+/gu)||[])mentionedWords.add(word);
 const foreignTokens=(normalized.match(/[\p{L}]+/gu)||[]).filter(word=>/[^a-z]/u.test(word)),nonEnglish=foreignTokens.length>0;if(nonEnglish&&!allowOtherLanguages&&foreignTokens.some(word=>!allowedWords.has(word)&&!mentionedWords.has(word)))return {ok:false,category:'non_english_alphabet'};
 const tokens=(normalized.match(/[a-z]+(?:'[a-z]+)*/g)||[]).map(w=>w.replace(/'{2,}/g,"'").replace(/(.)\1{2,}/g,'$1'));
 if(!tokens.length){if(nonEnglish&&(allowOtherLanguages||foreignTokens.every(word=>allowedWords.has(word)||mentionedWords.has(word)))||allowEmoji&&hasEmoji)return {ok:true,text:original.replace(/[\u0000-\u001f\u007f-\u009f\u200B-\u200F\u2060\uFEFF]/g,' ').replace(/\s+/g,' ').trim()};return {ok:false,category:'no_english_words'};}
 for(let i=0;i<tokens.length;i++){
  const word=tokens[i].replace(/^'+|'+$/g,'');if(!word)continue;
  if(BLOCKED.has(word))return {ok:false,category:'blocked_word',word};
  if(!WORDS.has(word)&&!allowedWords.has(word)&&!mentionedWords.has(word)&&!(allowSlang&&SAFE_SLANG.has(word))&&strictness!=='relaxed')return {ok:false,category:'not_in_english_dictionary',word};
  let combined='';for(let j=i;j<Math.min(tokens.length,i+8);j++){combined+=tokens[j].replaceAll("'",'');if(combined.length>18)break;if(BLOCKED.has(combined))return {ok:false,category:'blocked_obfuscation',word:combined};}
 }
 const cleaned=original.replace(/[\u0000-\u001f\u007f-\u009f\u200B-\u200F\u2060\uFEFF]/g,' ').replace(/\s+/g,' ').trim();
 if(!cleaned)return {ok:false,category:'no_english_words'};
 return {ok:true,text:cleaned,needsAiReview:REVIEW_CONTEXT.test(cleaned)};
}

export function moderateEnglishText(text,options={}){
 if(typeof text!=='string'||!text.trim())return {decision:'block',category:'empty_message'};
 if(text.length>Math.min(280,Number.isFinite(options.maxSpeechLength)?options.maxSpeechLength:280))return {decision:'block',category:'message_too_long'};
 const v=lexical(text,options);if(!v.ok)return {decision:'block',category:v.category,detectedWord:v.word||null};
 return {decision:'allow',category:v.needsAiReview?(options.aiEnabled?'ai_review_needed':'review_required'):'dictionary_match',text:v.text,needsAiReview:v.needsAiReview};
}

export function ttsAiModelAllowed(model,config){
 if(!model||model==='nebula-d2'||model==='nebula-d2-lite')return false;
 const models=Array.isArray(config?.models)?config.models:config?.availableModels;
 if(Array.isArray(models))return models.some(m=>m.id===model&&m.available===true);
 return false;
}

export const TTS_WORDLIST_VERSION='SCOWL-US-rel-2026.02.25';
