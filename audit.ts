import { q } from './db.js';
export async function audit(req:any,action:string,entityType?:string,entityId?:string,details:any={}){ await q('INSERT INTO audit_logs(user_id,action,entity_type,entity_id,ip_address,user_agent,details) VALUES($1,$2,$3,$4,$5,$6,$7)',[req.user?.id,action,entityType||null,entityId||null,req.ip,req.get('user-agent')||null,details]); }
