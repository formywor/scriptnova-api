import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {createFamilyHandler} from '../lib/family-handler.mjs';
function fixture(seed={}){
 let data=structuredClone(seed);const clone=x=>x===undefined?null:structuredClone(x),snap=x=>({val:()=>clone(x),exists:()=>x!==null&&x!==undefined});
 function ref(path=''){const keys=path.split('/').filter(Boolean),read=()=>{let v=data;for(const k of keys)v=v?.[k];return clone(v);};function write(value){let v=data;for(const k of keys.slice(0,-1))v=v[k]||={};if(value===null)delete v[keys.at(-1)];else v[keys.at(-1)]=clone(value);}return {child:p=>ref(path+'/'+p),get:async()=>snap(read()),set:async v=>write(v),remove:async()=>write(null),update:async values=>{for(const[k,v]of Object.entries(values))await ref(path+'/'+k).set(v);},transaction:async fn=>{const v=fn(read());if(v===undefined)return {committed:false,snapshot:snap(read())};write(v);return {committed:true,snapshot:snap(read())};}};}
 const pin='7318',salt='a'.repeat(32),pepper='b'.repeat(64),revision='c'.repeat(32),hash=crypto.scryptSync(pin+pepper,salt,64).toString('hex');
 const config={salt,pepper,revision,hash},env={SESSION_PEPPER:'local-test-session-secret-not-production',FAMILY_PIN_AUTH:JSON.stringify(config)};
 const db={ref},handler=createFamilyHandler({getDatabase:async()=>db,env});
 const call=async(path,body,token='',grant='',ip='203.0.113.1',useHandler=handler)=>useHandler(new Request('https://api.scriptnovaa.com/api/family/'+path,{method:body===undefined?'GET':'POST',headers:{Origin:'https://scriptnovaa.com',Authorization:'Bearer '+token,'X-Family-Grant':grant,'X-Vercel-Forwarded-For':ip,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})}));
 return {call,pin,config,env,db,get data(){return data;}};
}
test('PIN-only access needs no account, saves a session and can unlock, pair and read state',async()=>{
 const f=fixture({nebulaAccounts:{v1:{owner:{theme:'dark'}}}}),before=structuredClone(f.data.nebulaAccounts);
 const login=await (await f.call('login',{pin:f.pin,remember:true})).json();assert(login.loginToken);
 const unlocked=await (await f.call('unlock',{pin:f.pin,remember:true},login.loginToken)).json();assert(unlocked.grant);
 const pairing=await (await f.call('pairing',{},login.loginToken,unlocked.grant)).json();assert.match(pairing.code,/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
 const state=await (await f.call('state',undefined,login.loginToken,unlocked.grant)).json();assert.deepEqual(state.devices,[]);
 assert.deepEqual(f.data.nebulaAccounts,before);assert.equal(f.data.accounts,undefined);assert.equal(f.data.usernames,undefined);
 const session=Object.values(f.data.familyProtection.pinSessions)[0];assert(session.expiresAt>Date.now()+29*86400000);
});
test('existing Family profile survives even after its old website account was deleted',async()=>{
 const owner='a'.repeat(64),f=fixture({familyProtection:{owners:{[owner]:{settings:{automaticReview:true},devices:{}}}}});
 const login=await (await f.call('login',{pin:f.pin})).json();assert(login.loginToken);assert.equal(f.data.familyProtection.parentAccess.ownerHash,owner);
 const unlocked=await (await f.call('unlock',{pin:f.pin},login.loginToken)).json();
 const state=await (await f.call('state',undefined,login.loginToken,unlocked.grant)).json();assert.equal(state.settings.automaticReview,true);
});
test('ambiguous multiple profiles fail closed instead of attaching a random family',async()=>{
 const f=fixture({familyProtection:{owners:{['a'.repeat(64)]:{},['b'.repeat(64)]:{}}}});
 assert.equal((await f.call('login',{pin:f.pin})).status,409);assert.equal(f.data.familyProtection.parentAccess,undefined);
});
test('a sixth wrong-PIN attempt is blocked and no sessions are created',async()=>{
 const f=fixture();for(let i=0;i<5;i++)assert.equal((await f.call('login',{pin:'0000'})).status,401);
 assert.equal((await f.call('login',{pin:f.pin})).status,429);assert.equal(f.data.familyProtection.pinSessions,undefined);
});
test('short sessions expire and PIN rotation revokes existing sessions',async()=>{
 const f=fixture(),login=await (await f.call('login',{pin:f.pin})).json();
 const key=Object.keys(f.data.familyProtection.pinSessions)[0],session=f.data.familyProtection.pinSessions[key];assert(session.expiresAt<Date.now()+601000);
 const rotated=createFamilyHandler({getDatabase:async()=>f.db,env:{...f.env,FAMILY_PIN_AUTH:JSON.stringify({...f.config,revision:'d'.repeat(32)})}});
 assert.equal((await f.call('state',undefined,login.loginToken,'','203.0.113.1',rotated)).status,401);
 session.expiresAt=1;assert.equal((await f.call('state',undefined,login.loginToken)).status,401);
});
test('old account sessions and caller-provided owner values cannot bypass the family PIN',async()=>{
 const f=fixture();assert.equal((await f.call('state',undefined,'old-account-token')).status,401);
 assert.equal((await f.call('login',{pin:'0000',ownerHash:'a'.repeat(64),username:'iii_dev'})).status,401);
});
