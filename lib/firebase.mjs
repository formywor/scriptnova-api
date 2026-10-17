import {createWorkspaceStore} from './workspace.mjs';
let storePromise,appPromise;
export async function getStore() {
  if(!storePromise)storePromise=connect().catch(e=>{storePromise=undefined;throw e;});
  return storePromise;
}
async function connect() {
  if(!process.env.FIREBASE_DATABASE_URL?.trim())throw Object.assign(new Error('Storage unavailable'),{code:'DATABASE_URL_MISSING'});
  const app=await getAdminApp();
  const {getDatabase}=await import('firebase-admin/database');
  return createStore(getDatabase(app));
}
export async function getAdminDatabase(){
  const app=await getAdminApp();const {getDatabase}=await import('firebase-admin/database');return getDatabase(app);
}
export async function getCheckpointBucket(){
  const name=process.env.NEBULA_CHECKPOINT_BUCKET?.trim();
  if(!name||!/^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/.test(name))throw Object.assign(new Error('Checkpoint storage unavailable'),{code:'CHECKPOINT_BUCKET_MISSING'});
  const app=await getAdminApp();const {getStorage}=await import('firebase-admin/storage');
  return getStorage(app).bucket(name);
}
async function getAdminApp() {
  if(!appPromise)appPromise=initialize().catch(e=>{appPromise=undefined;throw e;});
  return appPromise;
}
async function initialize() {
  const options=adminOptionsFromEnv(process.env);
  const {initializeApp,cert,getApps}=await import('firebase-admin/app');
  const app=getApps().find(a=>a.name==='nebula')||initializeApp({credential:cert(options.credentials),projectId:options.credentials.projectId,...(options.databaseURL?{databaseURL:options.databaseURL}:{})},'nebula');
  return app;
}
export function adminOptionsFromEnv(env) {
  const projectId=env.FIREBASE_PROJECT_ID?.trim(),clientEmail=env.FIREBASE_CLIENT_EMAIL?.trim();
  let privateKey=env.FIREBASE_PRIVATE_KEY?.trim()||'';
  // Support either a PEM or a JSON-quoted PEM copied into an environment field.
  if(privateKey.startsWith('"')){try{const parsed=JSON.parse(privateKey);if(typeof parsed==='string')privateKey=parsed;}catch{}}
  if(privateKey.startsWith("'")&&privateKey.endsWith("'"))privateKey=privateKey.slice(1,-1);
  privateKey=privateKey.replace(/\\r\\n/g,'\n').replace(/\\n/g,'\n').trim();
  if(!projectId||!clientEmail||!privateKey.startsWith('-----BEGIN PRIVATE KEY-----')||!privateKey.endsWith('-----END PRIVATE KEY-----'))throw Object.assign(new Error('Authentication configuration unavailable'),{code:'app/invalid-credential'});
  return {credentials:{projectId,clientEmail,privateKey},databaseURL:env.FIREBASE_DATABASE_URL?.trim()||undefined};
}
export function createTokenVerifier({loadAuth=()=>import('firebase-admin/auth'),getApp=getAdminApp}={}) {
  return async token=>{
    let stage='sdk_import';
    try {
      const {getAuth}=await loadAuth();
      stage='admin_initialization';const app=await getApp();
      stage='token_verification';return await getAuth(app).verifyIdToken(token,true);
    }catch(error){
      // Preserve only typed metadata. Do not copy SDK messages or full stacks.
      throw Object.assign(new Error('Authentication verification failed'),{code:error?.code,authStage:stage,errorType:error?.name==='TypeError'?'TypeError':'Error'});
    }
  };
}
export const verifyToken=createTokenVerifier();
export function createStore(db) {
  return {
    ...createWorkspaceStore(db),
    async account(key,time) {
      const ref=db.ref(`nebulaAccounts/v1/${key}`);
      const result=await ref.transaction(old=>old||{createdAt:time,improve:true,memoryEnabled:false,theme:'dark',trainingGeneration:0},undefined,false);
      return result.snapshot.val();
    },
    async preferences(key,patch,time) {
      if(typeof patch==='boolean')patch={improve:patch};
      const result=await db.ref(`nebulaAccounts/v1/${key}`).transaction(old=>({...old,createdAt:old?.createdAt||time,trainingGeneration:old?.trainingGeneration||0,...patch,updatedAt:time}),undefined,false);
      return result.snapshot.val();
    },
    async rotateTraining(key,time) {
      const result=await db.ref(`nebulaAccounts/v1/${key}`).transaction(old=>({...old,createdAt:old?.createdAt||time,improve:false,trainingGeneration:(Number(old?.trainingGeneration)||0)+1,updatedAt:time}),undefined,false);
      return result.snapshot.val();
    },
    async allow(key,time,lane='question') {
      // Two current windows in one stable key; no unbounded timestamp-key accumulation.
      const minute=Math.floor(time/60000),day=Math.floor(time/86400000);
      const limits=lane==='read'?[240,20000]:lane==='write'?[60,5000]:[12,300];
      const result=await db.ref(`nebulaRateLimits/${lane==='question'?key:key+'_'+lane}`).transaction(old=>{
        const state=old||{};const minuteCount=state.minute===minute?Number(state.minuteCount)||0:0;const dayCount=state.day===day?Number(state.dayCount)||0:0;
        if(minuteCount>=limits[0]||dayCount>=limits[1])return;
        return {minute,day,minuteCount:minuteCount+1,dayCount:dayCount+1,updatedAt:time};
      },undefined,false);
      return result.committed;
    },
    async save(owner,chat,turn,sample){
      const result=await db.ref(`nebulaTraining/v1/${owner}`).transaction(old=>{
        if(old?.revoked)return;
        const state=old||{count:0,samples:{}};
        const previous=state.samples?.[chat]?.[turn];
        if(!previous&&Number(state.count)>=200)return;
        state.samples ||= {};state.samples[chat] ||= {};
        state.samples[chat][turn]={...sample,createdAt:previous?.createdAt||sample.createdAt};
        if(!previous)state.count=(Number(state.count)||0)+1;
        return state;
      },undefined,false);
      if(result.committed&&sample.source?.kind==='user'){
        const {topicFor}=await import('./learning.mjs');
        const value={source:sample.source,consentVersion:sample.consentVersion,createdAt:sample.createdAt,
          topic:topicFor(sample.messages.find(m=>m.role==='user')?.content||'')};
        await db.ref(`nebulaLearning/v1/${owner}`).transaction(old=>{
          if(old?.revoked)return;
          const state=old||{samples:{}};state.samples||={};state.samples[chat]||={};state.samples[chat][turn]=value;return state;
        },undefined,false);
      }
      return result.committed;
    },
    async reviewCandidate(owner,chat,turn){const data=(await db.ref(`nebulaTraining/v1/${owner}`).get()).val();return data?.revoked?null:data?.samples?.[chat]?.[turn]||null;},
    async allowReview(key,time){
      const result=await db.ref(`nebulaReviewBudget/v1/${key}`).transaction(old=>{const state=old&&time-old.started<48*3600000?old:{started:time,count:0};if(state.count>=3)return;return {...state,count:state.count+1};},undefined,false);return result.committed;
    },
    async saveReview(owner,chat,turn,review){
      const result=await db.ref(`nebulaTraining/v1/${owner}`).transaction(old=>{if(!old)return null;if(old.revoked||!old.samples?.[chat]?.[turn])return;old.samples[chat][turn].review=review;return old;},undefined,false);return result.committed&&!!result.snapshot.val()?.samples?.[chat]?.[turn]?.review;
    },
    // A permanent tombstone blocks an in-flight reply from restoring deleted samples.
    async deleteOwner(owner){await db.ref(`nebulaTraining/v1/${owner}`).set({revoked:true});await db.ref(`nebulaLearning/v1/${owner}`).set({revoked:true});},
  };
}
