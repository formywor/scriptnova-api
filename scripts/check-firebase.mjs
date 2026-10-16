// Import the real installed SDK without credentials or network calls.
// Disabling require(ESM) reproduces the stricter serverless module boundary.
const checks=[
  ['app',()=>import('firebase-admin/app'),['initializeApp','cert','getApps']],
  ['auth',()=>import('firebase-admin/auth'),['getAuth']],
  ['database',()=>import('firebase-admin/database'),['getDatabase']],
];
let failed=false;
for(const [name,load,exports] of checks){
  try{
    const sdk=await load();
    if(exports.some(key=>typeof sdk[key]!=='function'))throw Object.assign(new Error('SDK exports unavailable'),{code:'SDK_EXPORT_MISSING'});
    console.log(`Firebase ${name} import: OK`);
  }catch(error){
    const code=/^[A-Z_]{1,80}$/.test(error?.code||'')?error.code:'SDK_IMPORT_FAILED';
    console.error(`Firebase ${name} import: ${code}`);failed=true;
  }
}
if(failed)process.exitCode=1;
