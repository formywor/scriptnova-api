// Disposable security-review fixtures. No store, credentials, user content or provider access.
export function createAuditLabHandler({enabled=()=>process.env.NEBULA_AUDIT_LAB_ENABLED==='true'}={}){
 return async request=>{
  const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Access-Control-Allow-Origin':'*','X-Nebula-Lab':'synthetic-data-only'}});
  if(!enabled())return json({code:'NOT_FOUND'},404);
  if(!['GET','HEAD','OPTIONS'].includes(request.method))return json({code:'METHOD_NOT_ALLOWED'},405);
  if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET, HEAD, OPTIONS'}});
  const path=new URL(request.url).pathname.replace('/api/nebula/audit-lab','');
  let body,status=200;
  if(path==='/debug')body={lab:true,synthetic:true,build:'lab-review-1',debug:true,trace:'Error: fixture failure\n    at LabRecord.load (/srv/fictional-lab/records.js:42:9)',recordEndpoint:'https://api.scriptnovaa.com/api/nebula/audit-lab/records/1001'};
  else if(/^\/records\/(1001|1002)$/.test(path)){const id=path.split('/').at(-1);body={lab:true,synthetic:true,id,workspace:id==='1001'?'fictional-workspace-a':'fictional-workspace-b',visibility:'private-in-demo-design',text:'Synthetic test record. No real user or account data.'};}
  else {body={code:'NOT_FOUND'};status=404;}
  const response=json(body,status);return request.method==='HEAD'?new Response(null,{status,headers:response.headers}):response;
 };
}
