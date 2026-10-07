import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

function key(){
  const raw=process.env.SENSITIVE_DATA_KEY || '';
  if(!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error('SENSITIVE_DATA_KEY must be a 64-character hex value');
  return Buffer.from(raw,'hex');
}

export function encryptSensitive(value:string){
  const iv=randomBytes(12);
  const cipher=createCipheriv('aes-256-gcm',key(),iv);
  const encrypted=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
  const tag=cipher.getAuthTag();
  return Buffer.concat([iv,tag,encrypted]).toString('base64');
}

export function decryptSensitive(payload:string){
  const data=Buffer.from(payload,'base64');
  const iv=data.subarray(0,12);
  const tag=data.subarray(12,28);
  const encrypted=data.subarray(28);
  const decipher=createDecipheriv('aes-256-gcm',key(),iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted),decipher.final()]).toString('utf8');
}

export function maskSensitive(value:string){
  if(value.length<=4) return '••••';
  return '•••••••• '+value.slice(-4);
}
