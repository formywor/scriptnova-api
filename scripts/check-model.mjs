// Fail the deployment before a missing model release can reach visitors.
import {loadReleaseArtifact,NativeNebula} from '../lib/native-model.mjs';
import {readFileSync} from 'node:fs';
import {loadGraphRelease} from '../lib/onnx-model.mjs';
import {createRequire} from 'node:module';
if(process.env.NEBULA_VALIDATE_TRAINING_MODELS!=='true'){
 console.log(JSON.stringify({modelReleaseChecked:false,reason:'LEGACY_MODELS_CURRENTLY_IN_TRAINING',activeModel:'nebula-ultra'}));
}else try{
 const {release,artifact}=loadReleaseArtifact();
 new NativeNebula(artifact);
 new NativeNebula(JSON.parse(readFileSync(new URL('../model-assets/nebula-pilot.json',import.meta.url),'utf8')));
 const ort=createRequire(import.meta.url)('onnxruntime-node');
 const graphs=[];for(const id of ['nebula-v1-lite','nebula-v2-1']){const {release:r,bytes}=loadGraphRelease(id);const session=await ort.InferenceSession.create(bytes,{executionProviders:['cpu'],intraOpNumThreads:1,interOpNumThreads:1});await session.release();graphs.push({id,parameters:r.parameters,parts:r.parts.length});}
 console.log(JSON.stringify({graphs,modelReleaseChecked:true,version:release.version,parts:release.shards.length}));
}catch(error){
 const code=/^MODEL_[A-Z_]{1,60}$/.test(error?.code||'')?error.code:'MODEL_ARTIFACT_INVALID';
 console.error(JSON.stringify({modelReleaseChecked:false,reason:code,fix:'Upload the complete model-assets folder, including both model subfolders, and install server dependencies.'}));
 process.exitCode=1;
}
