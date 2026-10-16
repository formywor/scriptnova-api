import {readFileSync} from 'node:fs';
export function validateRules(value){
  if(!value||!Array.isArray(value.instructions)||!value.instructions.length||value.instructions.some(x=>typeof x!=='string'||!x.trim())||value.instructions.join('\n').length>16000)throw Error('Invalid owner rules');
  if(!Number.isInteger(value.maxReplyCharacters)||value.maxReplyCharacters<1||value.maxReplyCharacters>100000)throw Error('Invalid reply limit');
  if(!Array.isArray(value.blockedOutputPhrases)||value.blockedOutputPhrases.length>100||value.blockedOutputPhrases.some(x=>typeof x!=='string'||!x.trim()||x.length>200))throw Error('Invalid blocked phrases');
  if(typeof value.blockedReply!=='string'||!value.blockedReply.trim()||value.blockedReply.length>value.maxReplyCharacters||value.blockedOutputPhrases.some(x=>value.blockedReply.toLowerCase().includes(x.toLowerCase())))throw Error('Invalid policy reply');
  return value;
}
export function ownerRules(extra=process.env.NEBULA_OWNER_INSTRUCTIONS||''){
  const value=JSON.parse(readFileSync(new URL('../nebula-rules.json',import.meta.url),'utf8'));
  if(extra){if(typeof extra!=='string')throw Error('Invalid owner instructions');value.instructions.push(extra);}
  return validateRules(value);
}
export function enforceReply(text,rules){
  const filtered=text.length>rules.maxReplyCharacters||rules.blockedOutputPhrases.some(phrase=>text.toLowerCase().includes(phrase.toLowerCase()));
  return {text:filtered?rules.blockedReply:text,filtered};
}
