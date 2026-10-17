// Private operator command. Never expose this as a public HTTP route.
import {mkdir,writeFile,rename,readFile} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {getAdminDatabase} from '../lib/firebase.mjs';

export function selectContributions(training,accounts){
  const rows=[];
  for(const [owner,value] of Object.entries(training||{})){
    if(value.revoked)continue;
    for(const [chatId,turns] of Object.entries(value.samples||{}))for(const [turnId,sample]of Object.entries(turns||{})){
      const source=sample.source,profile=accounts?.[source?.accountKey];
      if(!source||source.kind!=='user'||!profile||profile.improve!==true||(profile.trainingGeneration||0)!==source.generation||sample.consentVersion!==1)continue;
      if(!Array.isArray(sample.messages)||!sample.messages.length)continue;
      rows.push({id:createHash('sha256').update(owner+':'+chatId+':'+turnId).digest('hex'),reviewStatus:'pending',messages:sample.review?.verdict==='needs_correction'&&sample.review.correctedReply?[sample.messages[0],{role:'assistant',content:sample.review.correctedReply}]:sample.messages,...(sample.review?{teacherReview:{provider:'gemini',verdict:sample.review.verdict}}:{}),source:{...source,owner,chatId,turnId}});
    }
  }
  return rows;
}
async function snapshot(){const db=await getAdminDatabase();const [a,t]=await Promise.all([db.ref('nebulaAccounts/v1').get(),db.ref('nebulaTraining/v1').get()]);return{accounts:a.val()||{},training:t.val()||{},createdAt:Date.now()};}
async function atomic(path,text){await mkdir(dirname(path),{recursive:true});await writeFile(path+'.tmp',text,{mode:0o600});await rename(path+'.tmp',path);}
export async function main(argv=process.argv.slice(2)){
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'../model');
  const command=argv[0];
  if(!['export','train'].includes(command)){console.log('node --env-file=.env scripts/model-data.mjs export\nnode --env-file=.env scripts/model-data.mjs train --data model/data/approved.jsonl --output model/checkpoints/nebula.pt [--steps 500]\nRechecks current Firebase sharing consent before every training run. Python executable: NEBULA_PYTHON. Review and prepare examples with python model/cli.py.');return;}
  const current=await snapshot();
  if(command==='export'){
    const path=resolve(root,'data/user-pending.jsonl');const rows=selectContributions(current.training,current.accounts);await atomic(path,rows.map(r=>JSON.stringify(r)).join('\n')+'\n');console.log(JSON.stringify({pendingExamples:rows.length}));return;
  }
  const args=argv.slice(1);
  if(args.includes('--snapshot'))throw Error('The consent snapshot is always generated fresh');
  const path=resolve(root,'data/current-consent.snapshot.json');await atomic(path,JSON.stringify(current));
  const code=await new Promise((done,reject)=>{const child=spawn(process.env.NEBULA_PYTHON||'python',[resolve(root,'train.py'),...args,'--snapshot',path],{stdio:'inherit',shell:false});child.on('error',reject);child.on('exit',done);});
  if(code!==0)throw Error('Model training did not finish');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error('Model data operation failed. Check private server credentials and local configuration.');process.exitCode=1;});
