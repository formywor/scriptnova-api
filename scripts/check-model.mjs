// Fail the deployment before a missing model release can reach visitors.
import {loadReleaseArtifact,NativeNebula} from '../lib/native-model.mjs';
try{
 const {release,artifact}=loadReleaseArtifact();
 new NativeNebula(artifact);
 console.log(JSON.stringify({modelReleaseChecked:true,version:release.version,parts:release.shards.length}));
}catch(error){
 const code=/^MODEL_[A-Z_]{1,60}$/.test(error?.code||'')?error.code:'MODEL_ARTIFACT_INVALID';
 console.error(JSON.stringify({modelReleaseChecked:false,reason:code,fix:'Upload model-assets/release.json and all six .part files into model-assets/ at the API repository root.'}));
 process.exitCode=1;
}
