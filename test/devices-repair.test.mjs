import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {devicesConfig,publicDevicesConfig,synthesizeVoice} from '../lib/devices-voice.mjs';
import {createDevicesHandler} from '../lib/devices.mjs';
import {createStore} from '../lib/firebase.mjs';
import {memoryDatabase} from './helpers/database.mjs';
import {cloudConfig} from '../lib/cloud-services.mjs';
const require=createRequire(import.meta.url),{Media}=require('../../main-website/devices-media.js'),{Connection}=require('../../main-website/devices-connection.js'),{Voice,chunks}=require('../../main-website/devices-audio.js');
const defer=()=>{let resolve;return {promise:new Promise(r=>resolve=r),get resolve(){return resolve;}};},tick=()=>new Promise(setImmediate);
const voiceConfig=devicesConfig({GROQ_API_KEY:'secret-test-only'}),wav=Buffer.concat([Buffer.from('RIFF'),Buffer.alloc(4),Buffer.from('WAVE'),Buffer.alloc(12)]);
test('API voice uses existing configured provider, fixed host/model, allowlisted voice and bounded valid audio',async()=>{
 assert.equal(voiceConfig.voice.configured,true);assert.equal(JSON.stringify(publicDevicesConfig(voiceConfig)).includes('secret-test'),false);
 let calls=0;const fetcher=async(url,init)=>{calls++;assert.equal(url,'https://api.groq.com/openai/v1/audio/speech');assert.equal(init.headers.Authorization,'Bearer secret-test-only');assert.equal(JSON.parse(init.body).model,'canopylabs/orpheus-v1-english');assert.ok(init.signal);return new Response(wav,{headers:{'Content-Type':'audio/wav'}});};
 const result=await synthesizeVoice({text:'Hello',voice:'troy',consent:true},voiceConfig.voice,{fetcher});assert.equal(result.bytes.length,wav.length);
 for(const body of [{text:'Hello',voice:'https://evil.test',consent:true},{text:'x'.repeat(201),voice:'troy',consent:true},{text:'Hello',voice:'troy',consent:false}])await assert.rejects(()=>synthesizeVoice(body,voiceConfig.voice,{fetcher}));assert.equal(calls,1);
 await assert.rejects(()=>synthesizeVoice({text:'Hello',voice:'troy',consent:true},voiceConfig.voice,{fetcher:async()=>new Response('not audio',{headers:{'Content-Type':'audio/wav'}})}));
 const eleven=devicesConfig({NEBULA_TTS_PROVIDER:'elevenlabs',ELEVENLABS_API_KEY:'test',NEBULA_TTS_VOICES:'[{"id":"approved123","label":"Approved"}]'});assert.equal(eleven.voice.configured,true);
 await synthesizeVoice({text:'Hello',voice:'approved123',consent:true},eleven.voice,{fetcher:async(url,init)=>{assert.match(url,/^https:\/\/api.elevenlabs.io\/v1\/text-to-speech\/approved123/);assert.equal(init.headers['xi-api-key'],'test');return new Response(Buffer.concat([Buffer.from('ID3'),Buffer.alloc(15)]),{headers:{'Content-Type':'audio/mpeg'}});}});
});
test('authenticated Devices voice route has no chat/training storage, and unconfigured voice is explicit',async()=>{
 const {db,records}=memoryDatabase(),store=createStore(db);const app=createDevicesHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice'}),config:cloudConfig({}),devices:voiceConfig,fetcher:async()=>new Response(wav,{headers:{'Content-Type':'audio/wav'}})});
 const request=(token=true)=>new Request('https://api.test/api/nebula/devices/voice',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer test.jwt.alice'}:{})},body:JSON.stringify({text:'Private spoken answer',voice:'troy',consent:true})});
 assert.equal((await app(request(false))).status,401);const r=await app(request());assert.equal(r.status,200);assert.equal(r.headers.get('content-type'),'audio/wav');assert.ok([...records.keys()].every(k=>k.startsWith('nebulaRateLimits/')));assert.ok(!JSON.stringify([...records]).includes('Private spoken answer'));
 const missing=createDevicesHandler({getStore:async()=>store,verifyToken:async()=>({uid:'alice'}),config:cloudConfig({}),devices:devicesConfig({})});const absent=await missing(request());assert.equal((await absent.json()).code,'API_VOICE_NOT_CONFIGURED');
});
test('capture checks secure context and policy, remembers denial and verifies live selected tracks',async()=>{
 let requests=0;const win={isSecureContext:true,document:{},navigator:{mediaDevices:{getUserMedia:async constraints=>{requests++;assert.equal(constraints.audio.deviceId.exact,'selected');throw Object.assign(Error('denied'),{name:'NotAllowedError'});}}}};
 const media=new Media(win);await assert.rejects(()=>media.acquire('microphone','selected'),e=>e.code==='denied');await assert.rejects(()=>media.acquire('microphone','selected'));assert.equal(requests,1);media.retry();await assert.rejects(()=>media.acquire('microphone','selected'));assert.equal(requests,2);
 win.document.permissionsPolicy={allowsFeature:()=>false};await assert.rejects(()=>media.acquire('camera'),e=>e.code==='blocked');assert.equal(requests,2);win.document={};win.isSecureContext=false;await assert.rejects(()=>media.acquire('camera'),e=>e.code==='insecure');win.isSecureContext=true;win.navigator.mediaDevices.getUserMedia=async()=>{throw new DOMException('Missing camera','NotFoundError');};await assert.rejects(()=>media.acquire('camera'),e=>e.code==='no-device');
});
test('Bluetooth remains disabled without selected documented protocol; chooser is synchronous and incompatible devices disconnect',async()=>{
 let calls=0,disconnected=0;const states=[],protocol={serviceUuid:'service',infoUuid:'info',controlUuid:'control',protocol:'nebula-ble-control',version:1,model:'test'};
 const device={name:'Not proof of compatibility',addEventListener(){},removeEventListener(){},gatt:{async connect(){return {getPrimaryService:async()=>{throw Error('incompatible');}};},disconnect(){disconnected++;}}};
 const c=new Connection({requestDevice(){calls++;return Promise.resolve(device);}},s=>states.push(s));await c.connect(null);assert.equal(calls,0);const p=c.connect(protocol);assert.equal(calls,1);await p;assert.equal(c.state,'disconnected');assert.equal(disconnected,1);assert.match(states.at(-1).message,/could not be verified/);
 const cancel=new Connection({requestDevice:()=>Promise.reject(Object.assign(Error(),{name:'NotFoundError'}))},s=>states.push(s));await cancel.connect(protocol);assert.match(states.at(-1).message,/cancelled/);
 assert.equal(devicesConfig({}).glasses.configured,false);
});
test('compatible protocol is checked before connected; unexpected disconnect and forget remain deliberate',async()=>{
 let listener,forgot=0;const states=[],p={serviceUuid:'service',infoUuid:'info',controlUuid:'control',protocol:'nebula-ble-control',version:1,model:'reviewed-model'};
 const device={name:'Friendly name',addEventListener(_,fn){listener=fn;},removeEventListener(){},forget:async()=>forgot++,gatt:{disconnect(){},connect:async()=>({getPrimaryService:async()=>({getCharacteristic:async id=>id==='info'?{properties:{read:true},readValue:async()=>new DataView(new TextEncoder().encode(JSON.stringify({protocol:p.protocol,version:1,model:p.model})).buffer)}:{properties:{write:true}}})})}};
 const c=new Connection({requestDevice:()=>Promise.resolve(device)},s=>states.push(s));await c.connect(p);assert.equal(c.state,'connected');listener();assert.equal(c.state,'disconnected unexpectedly');await c.forget();assert.equal(forgot,1);
});
test('API audio exposes autoplay Play, chunks safely, cancels stale fetches and revokes object URLs',async()=>{
 const states=[],revoked=[];let tries=0;const audio={play:()=>++tries===1?Promise.reject(Object.assign(Error(),{name:'NotAllowedError'})):Promise.resolve(),pause(){},removeAttribute(){},load(){}};
 const v=new Voice({render:(s,m)=>states.push(s),audio:()=>audio,request:async()=>new Blob(['audio']),create:()=> 'blob:test',revoke:u=>revoked.push(u)});
 const cap={configured:true,maxCharacters:200,voices:[{id:'troy'}]},settings={voiceConsent:true,volume:50};const playing=v.speak('Hello',settings,cap);await tick();assert.equal(states.at(-1),'blocked');v.play();await tick();assert.equal(states.at(-1),'playing');audio.onended();await playing;assert.equal(revoked.length,1);
 const pending=defer();v.a.request=()=>pending.promise;const stale=v.speak('Old',settings,cap);v.stop();pending.resolve(new Blob(['late']));await stale;assert.equal(revoked.length,1);
 assert.ok(chunks('Long sentence '.repeat(50),200).every(s=>s.length<=200));
});
test('microphone meter context is prepared during the click and released on denial or stop',()=>{
 let created=0,closed=0;class Context{constructor(){created++;}resume(){return Promise.resolve();}close(){closed++;return Promise.resolve();}createMediaStreamSource(){return {connect(){},disconnect(){}};}createAnalyser(){return {fftSize:256,getByteTimeDomainData:array=>array.fill(128),disconnect(){}};}}
 const media=new Media({AudioContext:Context,requestAnimationFrame:()=>1,cancelAnimationFrame(){}});media.prepareMeter();assert.equal(created,1);media.releasePending();assert.equal(closed,1);media.prepareMeter();const stop=media.meter({},()=>{});assert.equal(created,2);stop();assert.equal(closed,2);
});
