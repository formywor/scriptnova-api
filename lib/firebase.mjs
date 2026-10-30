import {createDeveloperApiStore} from './developer-api-store.mjs';
import {createBenefitsStore} from './developer-benefits.mjs';
import {createDeskStore} from './desk.mjs';
import {createGalleryStore} from './gallery.mjs';
import {createEnvironmentStore} from './cloud-environment.mjs';
import {createPlanStore} from './public-plans.mjs';
import {createDeveloperStore} from './developer.mjs';
import {createDevicesStore} from './devices.mjs';
import {createCloudStore} from './cloud-jobs.mjs';
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
export async function developerUserByEmail(email){const {getAuth}=await import('firebase-admin/auth');const user=await getAuth(await getAdminApp()).getUserByEmail(email);return {uid:user.uid};}
export function createStore(db) {
  return {
    ...createWorkspaceStore(db),...createDeskStore(db),...createDeveloperApiStore(db),...createBenefitsStore(db),
    ...createPlanStore(db),
    ...createDeveloperStore(db),
      ...createDevicesStore(db),
    ...createCloudStore(db),
    ...createGalleryStore(db),...createEnvironmentStore(db),
    async account(key,time) {
      const ref=db.ref(`nebulaAccounts/v1/${key}`);
      const existing=(await ref.get()).val();if(existing)return existing;
      const result=await ref.transaction(old=>old||{createdAt:time,improve:true,externalReview:true,memoryEnabled:false,theme:'dark',trainingGeneration:0},undefined,false);
      return result.snapshot.val();
    },
    async preferences(key,patch,time) {
      if(typeof patch==='boolean')patch={improve:patch};
      const result=await db.ref(`nebulaAccounts/v1/${key}`).transaction(old=>({...old,createdAt:old?.createdAt||time,trainingGeneration:old?.trainingGeneration||0,...(patch.improve===true&&!old?.externalReviewManual&&old?.externalReview!==false?{externalReview:true}:{}),...patch,...('externalReview' in patch?{externalReviewManual:true}:{}),updatedAt:time}),undefined,false);
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
    async reviewProviderOrder(names,time,preferred){
      let order=[];
      await db.ref('nebulaReviewRouting/v1').transaction(old=>{
        const state=old||{cursor:0,providers:{}};state.providers||={};
        const ready=names.filter(name=>!(state.providers[name]?.nextAt>time));
        const start=ready.length?(Number(state.cursor)||0)%ready.length:0;
        order=ready.slice(start).concat(ready.slice(0,start));
        if(preferred&&order.includes(preferred))order=[preferred,...order.filter(n=>n!==preferred)];
        if(!preferred)state.cursor=((Number(state.cursor)||0)+1)%1000000;
        return state;
      },undefined,false);return order;
    },
    async reviewProviderSuccess(name,time){
      await db.ref('nebulaReviewRouting/v1').transaction(old=>{const state=old||{cursor:0,providers:{}};state.providers||={};state.providers[name]={failures:0,nextAt:0,updatedAt:time};return state;},undefined,false);
    },
    async reviewProviderFailure(name,time){
      await db.ref('nebulaReviewRouting/v1').transaction(old=>{const state=old||{cursor:0,providers:{}};state.providers||={};const failures=Math.min(5,(Number(state.providers[name]?.failures)||0)+1);state.providers[name]={failures,nextAt:time+Math.min(900000,60000*2**(failures-1)),updatedAt:time};return state;},undefined,false);
    },
    async reviewState(key,chat){return (await db.ref(`nebulaReviews/v2/${key}/${chat}`).get()).val();},
    async claimReview(key,chat,time,through){
      const gate=await db.ref(`nebulaReviewBudget/v2/${key}`).transaction(old=>{if(old?.nextAt>time)return;return {nextAt:time+60000};},undefined,false);
      if(!gate.committed)return false;
      const result=await db.ref(`nebulaReviews/v2/${key}/${chat}`).transaction(old=>{if(old?.nextAt>time||old?.reviewedThrough>=through)return;return {...old,lease:time,nextAt:time+120000};},undefined,false);
      return result.committed;
    },
    async finishReview(key,chat,time,through,success){
      await db.ref(`nebulaReviews/v2/${key}/${chat}`).transaction(old=>{if(old?.lease!==time)return;return {...old,lease:null,nextAt:time+(success?300000:600000),...(success?{reviewedThrough:through}: {})};},undefined,false);
    },
    async saveReview(owner,chat,turn,review){
      const result=await db.ref(`nebulaTraining/v1/${owner}`).transaction(old=>{if(!old)return null;if(old.revoked||!old.samples?.[chat]?.[turn])return;old.samples[chat][turn].review=review;return old;},undefined,false);const saved=result.committed&&!!result.snapshot.val()?.samples?.[chat]?.[turn]?.review;
      const sample=result.snapshot.val()?.samples?.[chat]?.[turn];
      if(saved&&review.qualityChecked===true&&sample?.source?.kind==='user'){
        const id=chat+'_'+turn;
        await db.ref(`nebulaReviewTraining/v1/${owner}`).transaction(old=>{if(old?.revoked)return;const state=old||{samples:{}};state.samples||={};state.samples[id]={accountKey:sample.source.accountKey,generation:sample.source.generation,createdAt:review.createdAt,qualityChecked:true,messages:review.teachingMessages};return state;},undefined,false);
      }
      return saved;
    },
    // A permanent tombstone blocks an in-flight reply from restoring deleted samples.
    async deleteOwner(owner){await db.ref(`nebulaTraining/v1/${owner}`).set({revoked:true});await db.ref(`nebulaLearning/v1/${owner}`).set({revoked:true});await db.ref(`nebulaReviewTraining/v1/${owner}`).set({revoked:true});},
  };
}
