'use strict';
const defaults={screenEnabled:true,audioEnabled:true,captionsEnabled:true,visualMode:'balanced',customWords:[],allowedWords:[],retentionDays:30,quietHours:{enabled:false,start:'21:00',end:'07:00',days:[0,1,2,3,4,5,6],timezone:'America/New_York',domains:[]}};
function policy(input={}) {
 const p={...defaults,...input};
 for(const k of ['screenEnabled','audioEnabled','captionsEnabled'])if(typeof p[k]!=='boolean')throw Error('Choose on or off for each detector.');
 if(!['balanced','strict'].includes(p.visualMode)||![7,30,90].includes(p.retentionDays))throw Error('Invalid detection or retention setting.');
 for(const k of ['customWords','allowedWords']){if(!Array.isArray(p[k])||p[k].length>50||p[k].some(w=>typeof w!=='string'||! /^[a-z]{2,30}$/.test(w)))throw Error('Use up to 50 English whole words.');p[k]=[...new Set(p[k])];}
 const q={...defaults.quietHours,...p.quietHours};
 if(typeof q.enabled!=='boolean'||![q.start,q.end].every(v=>/^([01]\d|2[0-3]):[0-5]\d$/.test(v))||q.start===q.end)throw Error('Choose different valid schedule times.');
 if(!Array.isArray(q.days)||!q.days.length||q.days.some(d=>!Number.isInteger(d)||d<0||d>6))throw Error('Choose valid schedule days.');
 try{new Intl.DateTimeFormat('en',{timeZone:q.timezone}).format();}catch{throw Error('Invalid schedule time zone.');}
 if(!Array.isArray(q.domains)||q.domains.length>30||q.domains.some(s=>typeof s!=='string'||s.length>253||! /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(s)))throw Error('Use site names such as youtube.com, without https or paths.');
 p.quietHours={enabled:q.enabled,start:q.start,end:q.end,days:[...new Set(q.days)],timezone:q.timezone,domains:[...new Set(q.domains)]};
 return Object.fromEntries(Object.keys(defaults).map(k=>[k,p[k]]));
}
function excepted(url,exceptions,page,at=Date.now()/1000){try{const p=page(url);return exceptions.some(e=>e.until>at&&(e.key===p.key||(e.domain&&(p.host===e.domain||p.host.endsWith('.'+e.domain)))));}catch{return false;}}
module.exports={policy,excepted,defaults};
