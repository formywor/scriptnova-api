import {getAdminDatabase,getCheckpointBucket} from './firebase.mjs';
let pending;
export async function researchServices(){
  if(!pending)pending=connect().catch(error=>{pending=undefined;throw error;});
  return pending;
}
async function connect(){
  const db=await getAdminDatabase(),bucket=await getCheckpointBucket();
  return createResearchStorage(db,bucket);
}
export function createResearchStorage(db,bucket){
  const ref=db.ref('nebulaResearch/v1/main');
  const object=file=>bucket.file(`nebula-research/v1/${file.id}.pt`);
  return {
    async read(){return (await ref.get()).val();},
    async update(fn){
      // A new serverless instance can receive a speculative null cache value.
      // Returning null lets Firebase compare with the server and retry; throwing
      // here would prevent a valid existing lease from ever being read.
      let error;
      const result=await ref.transaction(old=>{try{error=null;return fn(old);}catch(e){error=e;return old==null?null:undefined;}},undefined,false);
      if(error)throw error;
      return result.snapshot.val();
    },
    async upload(file){
      const headers={'content-type':'application/octet-stream','content-length':String(file.bytes),
        'content-md5':file.md5,'x-goog-if-generation-match':'0','x-goog-meta-sha256':file.sha256};
      const [url]=await object(file).getSignedUrl({version:'v4',action:'write',expires:file.expiresAt,
        contentType:headers['content-type'],contentMd5:file.md5,
        extensionHeaders:{'content-length':headers['content-length'],'x-goog-if-generation-match':'0','x-goog-meta-sha256':file.sha256}});
      return {url,headers};
    },
    async verify(file){
      const [metadata]=await object(file).getMetadata();
      return Number(metadata.size)===file.bytes&&metadata.md5Hash===file.md5&&metadata.metadata?.sha256===file.sha256;
    },
    async download(file){const [url]=await object(file).getSignedUrl({version:'v4',action:'read',expires:Date.now()+15*60000});return url;},
    async remove(file){await object(file).delete({ignoreNotFound:true});},
  };
}
