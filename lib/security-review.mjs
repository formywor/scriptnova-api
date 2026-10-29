import {owner} from './developer.mjs';
import {inspectPublic} from './developer-tools.mjs';
import {publicPageUrl} from './cloud-tools.mjs';
export function securityAccess(identity,config,grant){return !!identity&&(owner(identity,config)||identity.email_verified===true&&grant?.tier==='invite'&&grant?.status==='active');}
export async function scanSecurity(url,{identity,config={},grant,signal,reader}={}){
 if(!securityAccess(identity,config,grant))throw Object.assign(Error('Invite required'),{code:'SECURITY_INVITE_REQUIRED',status:403});
 const u=publicPageUrl(url);
 return inspectPublic(u.href,{signal,...(reader?{reader}:{})});
}
