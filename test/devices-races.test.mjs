import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{Session}=require('../../main-website/devices-session.js');
const defer=()=>{let resolve;return {promise:new Promise(r=>resolve=r),get resolve(){return resolve;}};};
const base={mode:'wake',wakePhrase:'Hey Nebula',camera:false,microphone:true,ocr:false,questions:true,menus:true,people:false,autoRespond:true,cloudText:true,cooldownSeconds:1,scanSeconds:15,output:'text'};
function stream(kind){let stopped=0;const track={kind,readyState:'live',enabled:true,stop(){stopped++;this.readyState='ended';}};return {get stopped(){return stopped;},getTracks:()=>[track],getAudioTracks:()=>kind==='audio'?[track]:[],getVideoTracks:()=>kind==='video'?[track]:[]};}
function engine(extra={}){return new Session({setInterval:()=>1,clearInterval(){},setTimeout:()=>1,clearTimeout(){},microphone:async()=>stream('audio'),camera:async()=>stream('video'),render(){},video(){},cancelSpeech(){},stopOcr(){},request:async()=>({text:'Answer'}),...extra});}
test('camera denial preserves active microphone capture and local meter; pause releases both resources',async()=>{
 const mic=stream('audio');let metered=0,closed=0;const s=engine({camera:async()=>{throw Object.assign(Error('Camera denied'),{code:'denied'});},microphone:async()=>mic,meter:()=>{metered++;return ()=>closed++;}});
 await s.start({...base,camera:true});assert.equal(s.media.camera,'denied');assert.equal(s.media.microphone,'active');assert.equal(s.media.transcription,'unsupported');assert.equal(metered,1);s.pause();assert.equal(mic.stopped,1);assert.equal(closed,1);
});
test('late microphone permission result after resume cannot replace the new capture or leak old tracks',async()=>{
 const old=defer(),oldStream=stream('audio'),newStream=stream('audio');let calls=0;const s=engine({microphone:()=>++calls===1?old.promise:Promise.resolve(newStream)});
 const first=s.start(base);s.pause();await s.start(base);old.resolve(oldStream);await first;assert.equal(oldStream.stopped,1);assert.equal(newStream.stopped,0);assert.equal(s.micStream,newStream);s.stop();assert.equal(newStream.stopped,1);
});
test('API speaking suppresses old recognition events and reuses the existing capture with a new recognizer',async()=>{
 let calls=0,captures=0;const recs=[],spoken=defer();const s=engine({microphone:async()=>{captures++;return stream('audio');},recognition:()=>{const r={start(track){assert.equal(track.kind,'audio');this.onstart?.();},abort(){}};recs.push(r);return r;},request:async()=>{calls++;return {text:'An answer'};},speak:()=>spoken.promise});
 await s.start({...base,output:'both'});const stale=recs[0].onresult;const reply=s.respond('Hello');await new Promise(setImmediate);assert.equal(s.speaking,true);spoken.resolve();await reply;assert.equal(captures,1);assert.equal(recs.length,2);
 stale({resultIndex:0,results:[Object.assign([{transcript:'Hey Nebula repeated speaker audio'}],{isFinal:true})]});await new Promise(setImmediate);assert.equal(calls,1);s.stop();
});
test('a superseded voice completion cannot resume recognition during newer API audio',async()=>{
 const one=defer(),two=defer();let n=0;const s=engine({speak:()=>++n===1?one.promise:two.promise});await s.start({...base,microphone:false});const first=s.playVoice('first'),second=s.playVoice('second');one.resolve();await first;assert.equal(s.speaking,true);two.resolve();await second;assert.equal(s.speaking,false);s.stop();
});
