const MAX_TIME=86400;
function fail(message,status=400){throw Object.assign(new Error(message),{status});}
function number(n,min,max){if(typeof n!=='number'||!Number.isFinite(n)||n<min||n>max)fail('Number outside allowed range.');return n;}
export function initialRoom(now=Date.now(),movieUrl='https://scriptnovaa.com/movie.mkv'){
  return {movie:{url:movieUrl,title:'Movie night'},remaining:0,position:0,running:false,updatedAt:now,
    message:'Time is up! Send a gift on TikTok LIVE to keep the movie going.',
    rules:[{id:'rosa',label:'🌹 Rosa',giftName:'Rosa',seconds:4,action:'add'},
      {id:'gift99',label:'🕊 99-coin gift',giftName:'',seconds:55,action:'add'},
      {id:'gift299',label:'💖 299-coin gift',giftName:'',seconds:0,action:'toggle'}],giftEvents:[],lastGift:null};
}
export function settleRoom(old,now=Date.now()){
  const state=structuredClone(old);state.rules||=[];state.giftEvents||=[];
  const effectiveNow=Math.max(now,state.updatedAt);
  if(state.running){const elapsed=(effectiveNow-state.updatedAt)/1000;const used=Math.min(elapsed,state.remaining);state.remaining=Math.max(0,state.remaining-used);state.position+=used;if(state.remaining===0)state.running=false;}
  state.updatedAt=effectiveNow;return state;
}
export function publicRoom(old,now=Date.now()){
  const {giftEvents,...safe}=settleRoom(old,now);return {...safe,serverTime:now};
}
export function controlRoom(old,body,now=Date.now()){
  const state=settleRoom(old,now);
  switch(body.action){
    case 'addTime':state.remaining=Math.max(0,Math.min(MAX_TIME,state.remaining+number(body.seconds,-MAX_TIME,MAX_TIME)));if(!state.remaining)state.running=false;break;
    case 'setTime':state.remaining=number(body.seconds,0,MAX_TIME);if(!state.remaining)state.running=false;break;
    case 'play':if(!state.movie)fail('Add a movie first.');if(state.remaining<=0)fail('Add time first.');state.running=true;break;
    case 'pause':state.running=false;break;
    case 'seek':state.position=number(body.position,0,604800);break;
    case 'movie':{
      let url;try{url=new URL(body.url);}catch{fail('Use a full HTTPS movie URL.');}if(url.protocol!=='https:')fail('Use a full HTTPS movie URL.');
      state.movie={url:url.href,title:String(body.title||'Movie night').slice(0,120)};state.position=0;state.running=false;break;
    }
    case 'remove':state.movie=null;state.position=0;state.running=false;break;
    case 'message':state.message=String(body.message||'Send a gift to keep watching.').slice(0,500);break;
    case 'rules':{
      if(!Array.isArray(body.rules)||body.rules.length>30)fail('Use up to 30 gift wishes.');
      const ids=new Set(),names=new Set();state.rules=body.rules.map(r=>{
        if(!r||!/^[a-zA-Z0-9_-]{1,40}$/.test(r.id)||ids.has(r.id))fail('Unique wish IDs required.');ids.add(r.id);
        if(!['add','toggle'].includes(r.action))fail('Invalid gift action.');
        const giftName=String(r.giftName||'').trim().slice(0,80),name=giftName.toLowerCase();if(name&&names.has(name))fail('Use each automatic gift name only once.');if(name)names.add(name);
        return {id:r.id,label:String(r.label||'Gift').slice(0,80),giftName,seconds:number(r.seconds,0,MAX_TIME),action:r.action};
      });break;
    }
    default:fail('Unknown action.');
  }
  return state;
}
export function giftRoom(old,body,now=Date.now()){
  if(typeof body.eventId!=='string'||body.eventId.length<1||body.eventId.length>200)fail('Unique eventId required.');
  const count=number(body.count??1,1,10000);if(!Number.isInteger(count))fail('Gift count must be an integer.');
  const state=settleRoom(old,now);
  if(state.giftEvents.includes(body.eventId))return {state,duplicate:true};
  const rule=state.rules.find(r=>r.id===body.ruleId);if(!rule)fail('Unknown gift wish.');
  if(rule.action==='add'){state.remaining=Math.min(MAX_TIME,state.remaining+rule.seconds*count);if(state.movie&&state.remaining>0)state.running=true;}
  else if(count%2===1)state.running=!!state.movie&&state.remaining>0&&!state.running;
  state.lastGift={label:rule.label,count,at:now};state.giftEvents.push(body.eventId);state.giftEvents=state.giftEvents.slice(-10000);
  return {state,duplicate:false};
}
