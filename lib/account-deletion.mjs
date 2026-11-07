import {accountOwner} from './accounts.mjs';
// Content erasure keeps minimal quota/security counters and deletion tombstones.
// Those contain no chat text and prevent stale clients from restoring deleted data.
export async function eraseAccountData(store,db,key,uid,time){
 const previous=await store.account(key,time);
 await store.rotateTraining(key,time);
 await store.clearChats(key,time);
 for(let i=0;i<=(previous.trainingGeneration||0);i++)await store.deleteOwner(accountOwner(uid,i));
 const devices=await store.pcList(key);
 for(const device of devices)await db.ref('nebulaPc/v1/devices/'+device.id).remove();
 const keys=await store.apiKeys(key);
 for(const item of keys)await db.ref('nebulaDeveloperApi/v1/keys/'+item.id).remove();
 const paths=[`nebulaMemory/v1/${key}`,`nebulaDesk/v1/${key}`,`nebulaGallery/v1/${key}`,`nebulaEnvironment/v1/${key}`,`nebulaCloud/v1/${key}`,`nebulaCloudConnections/v1/${key}`,`nebulaCloudOAuth/v1/${key}`,`nebulaDevices/v1/${key}`,`nebulaReviews/v2/${key}`,`nebulaPc/v1/accounts/${key}`,`nebulaPc/v1/preferences/${key}`,`nebulaDeveloperApi/v1/accounts/${key}`];
 await Promise.all(paths.map(path=>db.ref(path).remove()));
 const profile={createdAt:previous.createdAt,trainingGeneration:(previous.trainingGeneration||0)+1,improve:false,externalReview:false,externalReviewManual:true,memoryEnabled:false,updatedAt:time};
 await db.ref(`nebulaAccounts/v1/${key}`).set(profile);
 return profile;
}
