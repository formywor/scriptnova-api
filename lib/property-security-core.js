"use strict";
(function(scope){
function inside(box,w,h,z){const x=(box[0]+box[2]/2)/w,y=(box[1]+box[3])/h;return x>=z.x&&x<=z.x+z.w&&y>=z.y&&y<=z.y+z.h;}
function presence(track,hits,{now,w,h,zone,holdMs=3000}){
 const active=track.lastSeen!=null&&now-track.lastSeen<=holdMs;
 const eligible=hits.filter(p=>p.score>=(active?.35:.45)&&(active||inside(p.bbox,w,h,zone)));
 if(eligible.length){const previous=track.box;eligible.sort((a,b)=>previous?distance(a.bbox,previous)-distance(b.bbox,previous):b.score-a.score);return {lastSeen:now,box:eligible[0].bbox,present:true,raw:true};}
 return {...track,present:active,raw:false};
}
function distance(a,b){return Math.hypot(a[0]+a[2]/2-b[0]-b[2]/2,a[1]+a[3]/2-b[1]-b[3]/2);}
function step(s,{present,armed,connected,now,grace,countdown,response,warningDone=true}){
 if(!armed||!connected)return {phase:"idle",since:now,event:["warning","countdown","alarm"].includes(s.phase)?"cancel":""};
 if(!present)return {phase:"idle",since:now,event:s.phase==="idle"?"":"cancel"};
 if(s.phase==="cooldown")return now<s.until?{...s,event:""}:{phase:"warning",since:now,event:response==="alarm"?"warn":""};
 if(s.phase==="idle")return {phase:"confirm",since:now,event:""};
 if(s.phase==="confirm"&&now-s.since>=600)return response==="record"?{phase:"observing",since:now,event:"record"}:{phase:"warning",since:now,event:"warn"};
 if(s.phase==="warning"&&warningDone&&now-s.since>=grace*1000)return {phase:"countdown",since:now,event:"countdown"};
 if(s.phase==="countdown"&&now-s.since>=countdown*1000)return {phase:"alarm",since:now,event:"alarm"};
 if(s.phase==="alarm"&&now-s.since>=15000)return {phase:"cooldown",since:now,until:now+30000,event:"cancel"};
 return {...s,event:""};
}
function spokenCode(text){const words=String(text).toLowerCase().replace(/[.,!?-]/g," ").trim();if(/^\d{4}$/.test(words.replace(/\s/g,"")))return words.replace(/\s/g,"");const names={zero:"0",oh:"0",one:"1",two:"2",to:"2",too:"2",three:"3",four:"4",for:"4",five:"5",six:"6",seven:"7",eight:"8",nine:"9"};const parts=words.split(/\s+/);return parts.length===4&&parts.every(p=>p in names)?parts.map(p=>names[p]).join(""):"";}
function voiceStep(state,text,now){
 if(state.until>now){const code=spokenCode(text);return code?{...state,event:"verify",code}:{...state,event:""};}
 if(/\bcancel\b/i.test(text))return {until:now+15000,event:"challenge"};
 return {until:0,event:""};
}
function clipWindow(trigger,lastSeen,now){return {start:Math.max(0,trigger-10000),end:Math.min(now,lastSeen+5000)};}
const api={inside,presence,step,spokenCode,voiceStep,clipWindow};if(typeof module!=="undefined"&&module.exports)module.exports=api;else scope.PropertySecurityCore=api;
})(typeof window!=="undefined"?window:globalThis);
