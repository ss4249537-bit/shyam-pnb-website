import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { q } from './db.js';

const COOKIE='shyam_session';
const sessions=new Map<string,{userId:string;expires:number}>();
export async function hashPassword(p:string){ return argon2.hash(p,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1}); }
export async function verifyPassword(hash:string,p:string){ return argon2.verify(hash,p); }
export function issueSession(userId:string,res:Response){ const token=randomBytes(48).toString('base64url'); sessions.set(token,{userId,expires:Date.now()+8*60*60*1000}); res.cookie(COOKIE,token,{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:8*60*60*1000,path:'/'}); return token; }
export function clearSession(req:Request,res:Response){ const t=req.cookies?.[COOKIE]; if(t)sessions.delete(t); res.clearCookie(COOKIE,{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',path:'/'}); }
export async function requireAuth(req:Request,res:Response,next:NextFunction){ const t=req.cookies?.[COOKIE]; const s=t?sessions.get(t):undefined; if(!s||s.expires<Date.now()){ if(t)sessions.delete(t); return res.status(401).json({error:'Authentication required'}); } const r=await q('SELECT id,username,role,is_active FROM users WHERE id=$1',[s.userId]); if(!r.rows[0]?.is_active)return res.status(401).json({error:'User inactive'}); (req as any).user=r.rows[0]; next(); }
export function requireRole(...roles:string[]){ return (req:Request,res:Response,next:NextFunction)=> roles.includes((req as any).user?.role)?next():res.status(403).json({error:'Insufficient permission'}); }
export const csrfToken=(req:Request)=>{ const existing=req.cookies?.shyam_csrf; return existing || randomBytes(32).toString('hex'); };
export function setCsrf(req:Request,res:Response){ const t=csrfToken(req); res.cookie('shyam_csrf',t,{httpOnly:false,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:8*60*60*1000,path:'/'}); return t; }
export function checkCsrf(req:Request,res:Response,next:NextFunction){ if(['GET','HEAD','OPTIONS'].includes(req.method))return next(); const c=req.cookies?.shyam_csrf; const h=req.get('x-csrf-token'); if(!c||!h||c!==h)return res.status(403).json({error:'CSRF validation failed'}); next(); }
