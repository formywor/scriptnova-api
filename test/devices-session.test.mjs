import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{Session}=require('../../main-website/devices-session.js');
const base={mode:'wake',wakePhrase:'Hey Nebula',camera:false,microphone:false,ocr:false,questions:true,menus:true,people:false,autoRespond:true,cloudText:true,cooldownSeconds:30,scanSeconds:15,output:'text'};
const defer=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {resolve,promise};};
function fixture(extra={}){const events=[],answers=[],requests=[];let stopped=0,timers=0;const a={setInterval:()=>++timers,clearInterval:()=>{},setTimeout:()=>++timers,clearTimeout:()=>{},video:()=>{},stopOcr:()=>{},cancelSpeech:()=>{},people:()=>{},render:x=>events.push(x),answer:r=>answers.push(r),camera:async()=>({getTracks:()=>[{stop:()=>stopped++}]}),request:async b=>{requests.push(b);return {text:'A reply'};},...extra};return {session:new Session(a),events,answers,requests,get stopped(){return stopped;}};}
test('wake phrase gates speech, supports activation, and adaptive mode accepts new speech',async()=>{
 const f=fixture();await f.session.start(base);f.session.hear('random background speech');await Promise.resolve();assert.equal(f.requests.length,0);
 f.session.hear('Hey Nebula how are you');await new Promise(setImmediate);assert.equal(f.requests.length,1);
 f.session.activate();f.session.hear('A different question');await new Promise(setImmediate);assert.equal(f.requests.length,1); // cooldown applies to automatic speech
 await f.session.start({...base,mode:'adaptive'});f.session.hear('Tell me about plants');await new Promise(setImmediate);assert.equal(f.requests.length,2);f.session.stop();
});
test('stop releases late permission streams and aborts pending replies without rendering them',async()=>{
 const camera=defer(),reply=defer();let released=0,signal;
 const f=fixture({camera:()=>camera.promise,request:(_,s)=>{signal=s;return reply.promise;}});
 const start=f.session.start({...base,camera:true});f.session.stop();camera.resolve({getTracks:()=>[{stop:()=>released++}]});await start;assert.equal(released,1);
 await f.session.start(base);const pending=f.session.respond('Hi');f.session.stop();assert.equal(signal.aborted,true);reply.resolve({text:'late private answer'});await pending;assert.equal(f.answers.length,0);
});
test('denied permissions and unsupported speech remain explicit and typed input still works',async()=>{
 const f=fixture({camera:async()=>{throw Error('NotAllowedError');}});await f.session.start({...base,camera:true,microphone:true});assert.match(f.session.media.camera,/denied/);assert.equal(f.session.media.microphone,'unsupported');await f.session.respond('Typed question');assert.equal(f.answers.length,1);f.session.stop();
});
test('duplicate automatic answers and cooldown are enforced; retries work after API failure',async()=>{
 let now=100000,failed=true;const f=fixture({clock:()=>now,request:async()=>{if(failed)throw Error('API failed');return {text:'Success'};}});await f.session.start(base);
 await f.session.respond('same',{automatic:true});assert.equal(f.answers.length,0);failed=false;await f.session.respond('same',{automatic:true});assert.equal(f.answers.length,1);
 now+=60000;await f.session.respond('same',{automatic:true});assert.equal(f.answers.length,1);await f.session.respond('new',{automatic:true});assert.equal(f.answers.length,2);f.session.stop();
});
test('manual mode captures text without automatic requests, and privacy blocks cloud calls',async()=>{
 const f=fixture();await f.session.start({...base,mode:'adaptive',autoRespond:false});f.session.hear('hello');assert.equal(f.requests.length,0);
 await f.session.start({...base,cloudText:false});await f.session.respond('hello');assert.equal(f.requests.length,0);f.session.stop();
});
test('OCR rejects unclear text, suppresses unchanged scenes and discards late OCR after stop',async()=>{
 let read=0,confidence=90;const f=fixture({frame:()=>({}),fingerprint:()=> 'same',ocr:async()=>{read++;return {text:'Which choice is the correct one? A or B?',confidence};}});
 await f.session.start({...base,mode:'adaptive',camera:true,ocr:true});await f.session.scan();await f.session.scan();assert.equal(read,1);assert.equal(f.requests.length,1);
 confidence=10;await f.session.scan(true);assert.equal(f.requests.length,1);assert.match(f.events.findLast(x=>x.message)?.message,/unclear/);
 const pending=defer();f.session.a.ocr=()=>pending.promise;const scan=f.session.scan(true);f.session.stop();pending.resolve({text:'late scene private text',confidence:99});await scan;assert.equal(f.requests.length,1);
});
test('pausing cancels recognition restarts, tracks, timers and speech playback',async()=>{
 let clear=0,abort=0,cancel=0;const rec={start(){this.onstart?.();},abort(){abort++;}};
 const f=fixture({recognition:()=>rec,clearInterval:()=>clear++,clearTimeout:()=>clear++,cancelSpeech:()=>cancel++});await f.session.start({...base,camera:true,microphone:true});f.session.pause();assert.equal(f.session.phase,'paused');assert.ok(clear>=2&&abort>=1&&cancel>=1&&f.stopped===1);assert.equal(rec.onend,null);
});
