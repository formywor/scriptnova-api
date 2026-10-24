import { timingSafeEqual } from 'node:crypto';
import { initialRoom, publicRoom, controlRoom, giftRoom } from './movie-state.mjs';
const ROOM_PATH='scriptnovaaMovie/v1/room';
function secure(a,b){if(!a||!b)return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
function fail(message,status=400){throw Object.assign(new Error(message),{status});}
async function readBody(request){
  if(Number(request.headers.get('content-length'))>65536)fail('Request too large.',413);
  const reader=request.body?.getReader();if(!reader)fail('JSON body required.');let size=0;const chunks=[];
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>65536){await reader.cancel();fail('Request too large.',413);}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}
  let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail('Invalid JSON.');}if(!body||typeof body!=='object'||Array.isArray(body))fail('JSON object required.');return body;
}
// Inject the existing API's Firebase Admin connection. No Nebula data is read or written.
export function createMovieHandler({getAdminDatabase,env=process.env,clock=Date.now}){
  return async request=>{
    const headers=new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Vary':'Origin'});
    const reply=(status,body)=>new Response(body===null?null:JSON.stringify(body),{status,headers});
    try{
      const origin=request.headers.get('origin');
      const allowed=(env.MOVIE_ALLOWED_ORIGINS||'https://scriptnovaa.com,https://www.scriptnovaa.com').split(',').map(x=>x.trim());
      if(origin){if(!allowed.includes(origin))fail('Origin is not allowed.',403);headers.set('Access-Control-Allow-Origin',origin);}
      headers.set('Access-Control-Allow-Headers','Authorization,Content-Type');headers.set('Access-Control-Allow-Methods','GET,POST,OPTIONS');
      if(request.method==='OPTIONS')return reply(204,null);
      const route=new URL(request.url).pathname;
      if(!['/movie-api/state','/movie-api/control','/movie-api/gift'].includes(route))fail('Not found.',404);
      const isState=route==='/movie-api/state';
      if(request.method!==(isState?'GET':'POST'))fail('Method not allowed.',405);
      if(!isState){
        const key=env[route.endsWith('/gift')?'MOVIE_GIFT_KEY':'MOVIE_ADMIN_KEY'];
        if(!key||key.length<32)fail('The host must configure the movie keys in Vercel.',503);
        if(!secure(request.headers.get('authorization')?.replace(/^Bearer /,''),key))fail('Incorrect movie key.',401);
      }
      const body=isState?null:await readBody(request);
      const db=await getAdminDatabase();const ref=db.ref(ROOM_PATH);
      const initial=()=>initialRoom(clock(),env.MOVIE_DEFAULT_URL);
      if(isState||body?.action==='verify')return reply(200,publicRoom((await ref.get()).val()||initial(),clock()));
      // Firebase can first invoke a transaction with a cold local cache (null).
      // Seed that first optimistic pass from an actual read; retries use the latest data.
      const seed=(await ref.get()).val()||initial();
      let duplicate=false;
      const result=await ref.transaction(old=>{
        const state=old||seed;
        if(route.endsWith('/gift')){const updated=giftRoom(state,body,clock());duplicate=updated.duplicate;return updated.state;}
        return controlRoom(state,body,clock());
      },undefined,false);
      if(!result.committed)fail('Movie update conflicted. Retry the action.',409);
      const state=publicRoom(result.snapshot.val(),clock());
      return reply(200,route.endsWith('/gift')?{duplicate,state}:state);
    }catch(error){return reply(error.status||503,{error:error.status?error.message:'Movie storage is unavailable. Check the Firebase configuration in Vercel.'});}
  };
}
