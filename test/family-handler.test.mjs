import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {createFamilyHandler} from '../lib/family-handler.mjs';
const env={PIN_PEPPER:'pin-secret-for-local-tests-only',SESSION_PEPPER:'session-secret-for-local-tests-only'};
function database(seed){let data=structuredClone(seed);const clone=x=>x===undefined?null:structuredClone(x);
 const snap=x=>({val:()=>clone(x),exists:()=>x!==null&&x!==undefined});
 function ref(path=''){const keys=path.split('/').filter(Boolean);const read=()=>{let v=data;for(const key of keys)v=v?.[key];return clone(v);};
  function write(value){if(!keys.length){data=clone(value)||{};return;}let v=data;for(const key of keys.slice(0,-1))v=v[key]||={};if(value===null)delete v[keys.at(-1)];else v[keys.at(-1)]=clone(value);}
  return {child:p=>ref(path+'/'+p),get:async()=>snap(read()),set:async value=>write(value),remove:async()=>write(null),update:async values=>{for(const[k,v]of Object.entries(values))await ref(path+'/'+k).set(v);},transaction:async fn=>{const value=fn(read());if(value===undefined)return {committed:false,snapshot:snap(read())};write(value);return {committed:true,snapshot:snap(read())};}};}
 return {ref,get data(){return data;}};
}
function fixture(){const pin='1234567',salt='a'.repeat(32);const credential={salt,hash:crypto.scryptSync(pin+env.PIN_PEPPER,salt,64).toString('hex')};
 const db=database({usernames:{iii_dev:{accountId:'original-owner'}},accounts:{'original-owner':{username:'iii_dev',pinCredential:credential}},nebulaAccounts:{v1:{untouched:{theme:'dark'}}}});
 const handler=createFamilyHandler({getDatabase:async()=>db,env});
 const call=async(path,body,token='',grant='',origin='https://scriptnovaa.com')=>handler(new Request('https://api.scriptnovaa.com/api/family/'+path,{method:body===undefined?'GET':'POST',headers:{Origin:origin,Authorization:'Bearer '+token,'X-Family-Grant':grant,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})}));
 return {db,call,pin};
}
test('Family login, remembered grant, short pairing, heartbeat and controls preserve Nebula data',async()=>{
 const f=fixture(),before=structuredClone(f.db.data.nebulaAccounts);
 const login=await (await f.call('login',{username:'iii_dev',pin:f.pin})).json();assert(login.loginToken);
 const unlocked=await (await f.call('unlock',{pin:f.pin,remember:true},login.loginToken)).json();assert(unlocked.grant);assert(unlocked.expires>Date.now()/1000+29*86400);
 const pairing=await (await f.call('pairing',{test:true},login.loginToken,unlocked.grant)).json();assert.match(pairing.code,/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
 const device=await (await f.call('device/pair',{code:pairing.code,name:'Restoration test'})).json();assert(device.token);
 const response=await f.call('device/heartbeat',{version:'0.3.6',status:{screen:'Local test'}},device.token);assert.equal(response.status,200);
 const state=await (await f.call('state',undefined,login.loginToken,unlocked.grant)).json();assert.equal(state.devices.length,1);assert(state.devices[0].test);
 assert.deepEqual(f.db.data.nebulaAccounts,before);assert.equal(f.db.data.loginSessions,undefined);
});
test('original sessions still work, revocation and account restrictions still apply',async()=>{
 const f=fixture(),token='existing-parent-token',key=crypto.createHmac('sha256',env.SESSION_PEPPER).update(token).digest('hex');
 await f.db.ref('loginSessions/'+key).set({accountId:'original-owner',expiresAt:Date.now()+60000});
 assert.equal((await f.call('unlock',{pin:f.pin},token)).status,200);
 await f.db.ref('loginSessions/'+key+'/revoked').set(true);assert.equal((await f.call('unlock',{pin:f.pin},token)).status,401);
 await f.db.ref('accounts/original-owner/accountStatus').set('BANNED');assert.equal((await f.call('login',{username:'iii_dev',pin:f.pin})).status,403);
});
test('unknown users, wrong PINs, untrusted origins and missing authentication fail closed',async()=>{
 const f=fixture();assert.equal((await f.call('login',{username:'someone_else',pin:f.pin})).status,401);
 assert.equal((await f.call('login',{username:'iii_dev',pin:'wrong'})).status,401);
 assert.equal((await f.call('state')).status,401);
 assert.equal((await f.call('login',{username:'iii_dev',pin:f.pin},'','','https://evil.example')).status,403);
});
test('public signed updates and CORS do not require or initialize the database',async()=>{
 const handler=createFamilyHandler({getDatabase:async()=>{throw Error('must not initialize');},env:{},fetcher:async()=>new Response(JSON.stringify({version:'0.3.6',url:'https://github.com/example',sha256:'a'.repeat(64),signature:'signed'}))});
 const response=await handler(new Request('https://api.scriptnovaa.com/api/family/update'));assert.equal(response.status,200);assert.equal((await response.json()).version,'0.3.6');
 const preflight=await handler(new Request('https://api.scriptnovaa.com/api/family/state',{method:'OPTIONS',headers:{Origin:'https://scriptnovaa.com'}}));assert.equal(preflight.status,204);assert.match(preflight.headers.get('Access-Control-Allow-Headers'),/X-Family-Grant/);
});
test('body limits and safe failures do not disclose backend details',async()=>{
 const f=fixture();assert.equal((await f.call('login',{padding:'x'.repeat(70*1024)})).status,413);
 const handler=createFamilyHandler({getDatabase:async()=>{throw Error('SECRET must not leak');}});
 const response=await handler(new Request('https://api.scriptnovaa.com/api/family/state'));assert.equal(response.status,503);assert(!JSON.stringify(await response.json()).includes('SECRET'));
});
