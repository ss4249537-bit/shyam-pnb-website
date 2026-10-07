import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { q, withTransaction } from './db.js';
import { hashPassword, verifyPassword, issueSession, clearSession, requireAuth, requireRole, setCsrf, checkCsrf } from './auth.js';
import { audit } from './audit.js';
import { encryptSensitive, decryptSensitive, maskSensitive } from './sensitive.js';

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '4mb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 400, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const today = () => new Date().toISOString().slice(0, 10);
const isAdmin = (u:any) => u?.role === 'ADMIN';
const isOperator = (u:any) => u?.role === 'OPERATOR';
const PUBLIC_CONTACT = process.env.PUBLIC_CONTACT || '9621543891';

async function ensureOwnerAdmin() {
  const username = process.env.ADMIN_USERNAME || '';
  const password = process.env.ADMIN_PASSWORD || '';
  if (!username || !password || password.length < 12) {
    console.warn('ADMIN_USERNAME/ADMIN_PASSWORD are not configured; owner Admin bootstrap skipped.');
    return;
  }
  const r = await q<any>('SELECT id,role FROM users WHERE username=$1', [username]);
  if (!r.rowCount) {
    const h = await hashPassword(password);
    await q(`INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,'ADMIN')`, [username, 'Owner Admin', h]);
  } else if (r.rows[0].role !== 'ADMIN') {
    await q(`UPDATE users SET role='ADMIN' WHERE id=$1`, [r.rows[0].id]);
  }
}

function subscriptionActive(s:any) {
  return !!s && ['ACTIVE'].includes(s.status) && !!s.current_period_end && new Date(s.current_period_end) > new Date();
}
async function getSubscription(userId:string) {
  const r = await q<any>('SELECT * FROM subscriptions WHERE user_id=$1', [userId]);
  return r.rows[0] || null;
}
function paidAccess(req:any,res:any,next:any) {
  if (isAdmin(req.user)) return next();
  if (!isOperator(req.user)) return res.status(403).json({ error: 'Operator access required' });
  getSubscription(req.user.id).then(s => {
    if (subscriptionActive(s)) return next();
    res.status(402).json({ error: 'Active subscription required. Please pay ₹1 first or renew with ₹29.' });
  }).catch(() => res.status(500).json({ error: 'Subscription check failed' }));
}
function ownClause(req:any, column='created_by') { return isAdmin(req.user) ? { sql:'', params:[] } : { sql:` AND ${column}=$1`, params:[req.user.id] }; }
async function assertOpenOwned(dayId:string, user:any) {
  const r = await q<any>('SELECT * FROM business_days WHERE id=$1', [dayId]);
  const d = r.rows[0];
  if (!d) throw new Error('Business day not found');
  if (d.status !== 'OPEN') throw new Error('Day is closed/locked');
  if (!isAdmin(user) && d.operator_id !== user.id) throw new Error('This day belongs to another operator');
  return d;
}

app.get('/api/public-config', async (_req,res) => {
  const r = await q<any>(`SELECT key,value FROM app_settings WHERE key IN ('public_contact','site_title')`);
  const cfg:any = { public_contact: PUBLIC_CONTACT, site_title:'SHYAM PNB PRO' };
  for (const x of r.rows) cfg[x.key] = x.value;
  res.json(cfg);
});

app.get('/api/health', (_req,res) => res.json({ ok:true, service:'SHYAM PNB PRO' }));
app.get('/api/csrf', (req,res) => res.json({ token:setCsrf(req,res) }));

app.post('/api/auth/signup', authLimiter, async (req,res) => {
  const { name, mobile, password, confirmPassword } = req.body || {};
  if (!String(name||'').trim() || !/^\d{10}$/.test(String(mobile||'')) || typeof password !== 'string' || password.length < 12 || password !== confirmPassword) {
    return res.status(400).json({ error:'Name, valid 10 digit mobile, 12+ character password and matching confirm password are required.' });
  }
  const exists = await q<any>('SELECT id FROM users WHERE username=$1', [String(mobile)]);
  if (exists.rowCount) return res.status(409).json({ error:'This mobile number is already registered.' });
  const h = await hashPassword(password);
  const u = await q<any>(`INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,'OPERATOR') RETURNING id,username,display_name,role`, [String(mobile), String(name).trim(), h]);
  issueSession(u.rows[0].id,res);
  await audit({ user:u.rows[0], ip:req.ip, get:(h:string)=>req.get(h) }, 'SIGNUP', 'USER', u.rows[0].id);
  res.status(201).json({ user:u.rows[0] });
});

app.post('/api/auth/login', authLimiter, async (req,res) => {
  const { username, password } = req.body || {};
  const r = await q<any>('SELECT * FROM users WHERE username=$1', [String(username||'')]);
  const u = r.rows[0];
  if (!u || !u.is_active || (u.locked_until && new Date(u.locked_until) > new Date())) return res.status(401).json({ error:'Invalid credentials or temporarily locked' });
  const ok = await verifyPassword(u.password_hash, String(password||''));
  if (!ok) {
    const n = Number(u.failed_login_count||0)+1;
    await q('UPDATE users SET failed_login_count=$1,locked_until=CASE WHEN $1>=5 THEN now()+interval \'15 minutes\' ELSE locked_until END WHERE id=$2', [n,u.id]);
    return res.status(401).json({ error:'Invalid credentials' });
  }
  await q('UPDATE users SET failed_login_count=0,locked_until=NULL WHERE id=$1',[u.id]);
  issueSession(u.id,res);
  await audit({ user:u, ip:req.ip, get:(h:string)=>req.get(h) }, 'LOGIN', 'USER', u.id);
  res.json({ user:{ id:u.id, username:u.username, display_name:u.display_name, role:u.role } });
});
app.post('/api/auth/logout', requireAuth, checkCsrf, async(req,res) => { await audit(req,'LOGOUT','USER',req.user.id); clearSession(req,res); res.json({ok:true}); });
app.get('/api/me', requireAuth, async(req,res)=>res.json({user:req.user}));

app.get('/api/subscription', requireAuth, async(req,res) => {
  if (isAdmin(req.user)) return res.json({ status:'ADMIN_FREE', trial_amount:1, recurring_amount:29, current_period_end:null });
  const s = await getSubscription(req.user.id);
  res.json(s ? { ...s, trial_amount:1, recurring_amount:29 } : { status:'NONE', trial_amount:1, recurring_amount:29, plan_code:'PRO_MONTHLY' });
});

app.post('/api/subscription/payment-request', requireAuth, requireRole('OPERATOR'), checkCsrf, async(req,res) => {
  const requestedAmount = Number(req.body?.amount);
  if (![1,29].includes(requestedAmount)) return res.status(400).json({error:'Payment amount must be ₹1 or ₹29.'});
  const s = await getSubscription(req.user.id);
  if (requestedAmount === 1 && s && subscriptionActive(s)) return res.status(409).json({error:'Your subscription is already active.'});
  if (requestedAmount === 29 && (!s || subscriptionActive(s))) return res.status(409).json({error: s ? '₹29 renewal is only needed after the current period ends.' : 'Please complete the ₹1 first-month payment.'});
  const pending = await q<any>(`SELECT id FROM subscription_payments WHERE user_id=$1 AND amount_paise=$2 AND status='PENDING' LIMIT 1`, [req.user.id, requestedAmount*100]);
  if (pending.rowCount) return res.status(409).json({error:'A payment verification request is already pending.'});
  const r = await q<any>(`INSERT INTO subscriptions(user_id,plan_code,status,trial_amount_paise,recurring_amount_paise,auto_renew)
    VALUES($1,'PRO_MONTHLY','PENDING_PAYMENT',100,2900,false)
    ON CONFLICT(user_id) DO UPDATE SET status='PENDING_PAYMENT',updated_at=now() RETURNING *`, [req.user.id]);
  res.json({subscription:r.rows[0], amount:requestedAmount, qr_url:'/paytm-qr.png', merchant:'Paytm Business QR', message:`Scan the Paytm QR, pay ₹${requestedAmount}, then submit UTR/Transaction ID.`});
});

app.post('/api/subscription/payment-submit', requireAuth, requireRole('OPERATOR'), checkCsrf, async(req,res) => {
  const amount = Number(req.body?.amount);
  const utr = String(req.body?.utr||'').trim();
  const paidAt = String(req.body?.paid_at||'').trim();
  if (![1,29].includes(amount)) return res.status(400).json({error:'Payment amount must be ₹1 or ₹29.'});
  if (!/^[A-Za-z0-9._\/-]{6,80}$/.test(utr)) return res.status(400).json({error:'Enter a valid UTR / Transaction ID.'});
  if (!paidAt || Number.isNaN(Date.parse(paidAt))) return res.status(400).json({error:'Payment date/time is required.'});
  const s = await getSubscription(req.user.id);
  if (amount===1 && s && subscriptionActive(s)) return res.status(409).json({error:'Subscription already active.'});
  if (amount===29 && (!s || subscriptionActive(s))) return res.status(409).json({error:'₹29 renewal is not due yet.'});
  const dup = await q<any>('SELECT id,user_id,status FROM subscription_payments WHERE LOWER(provider_payment_id)=LOWER($1) LIMIT 1',[utr]);
  if (dup.rowCount) return res.status(409).json({error:'This UTR / Transaction ID has already been submitted.'});
  const sub = s || (await q<any>(`INSERT INTO subscriptions(user_id,plan_code,status,trial_amount_paise,recurring_amount_paise,auto_renew) VALUES($1,'PRO_MONTHLY','PENDING_PAYMENT',100,2900,false) RETURNING *`,[req.user.id])).rows[0];
  const p = await q<any>(`INSERT INTO subscription_payments(subscription_id,user_id,provider,provider_payment_id,amount_paise,currency,status,payment_time,submitted_at)
    VALUES($1,$2,'PAYTM_QR',$3,$4,'INR','PENDING',$5,now()) RETURNING id,provider_payment_id,amount_paise,status,payment_time,submitted_at`, [sub.id,req.user.id,utr,amount*100,new Date(paidAt)]);
  await q(`UPDATE subscriptions SET status='PENDING_PAYMENT',updated_at=now() WHERE user_id=$1`,[req.user.id]);
  await audit(req,'SUBSCRIPTION_PAYMENT_SUBMITTED','SUBSCRIPTION_PAYMENT',p.rows[0].id,{amount,provider:'PAYTM_QR'});
  res.status(201).json(p.rows[0]);
});

app.get('/api/admin/subscription-payments', requireAuth, requireRole('ADMIN'), async(_req,res) => {
  const r = await q<any>(`SELECT p.id,p.user_id,u.username,u.display_name,p.provider_payment_id,p.amount_paise,p.status,p.payment_time,p.submitted_at,p.verified_at,p.admin_note
    FROM subscription_payments p JOIN users u ON u.id=p.user_id ORDER BY CASE WHEN p.status='PENDING' THEN 0 ELSE 1 END,p.submitted_at DESC LIMIT 500`);
  res.json(r.rows);
});
app.post('/api/admin/subscription-payments/:id/decision', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res) => {
  const decision=String(req.body?.decision||'').toUpperCase(); const note=String(req.body?.note||'').trim().slice(0,500);
  if(!['APPROVE','REJECT'].includes(decision))return res.status(400).json({error:'Decision must be APPROVE or REJECT.'});
  try{
    const result=await withTransaction(async(client)=>{
      const p=await client.query<any>('SELECT * FROM subscription_payments WHERE id=$1 FOR UPDATE',[req.params.id]);
      if(!p.rowCount)throw new Error('Payment not found');
      const pay=p.rows[0]; if(pay.status!=='PENDING')throw new Error('This payment has already been processed.');
      if(decision==='REJECT'){
        await client.query(`UPDATE subscription_payments SET status='REJECTED',verified_at=now(),verified_by=$1,admin_note=$2 WHERE id=$3`,[req.user.id,note,pay.id]);
        const pending=await client.query<any>(`SELECT count(*)::int c FROM subscription_payments WHERE user_id=$1 AND status='PENDING'`,[pay.user_id]);
        if(!pending.rows[0].c)await client.query(`UPDATE subscriptions SET status=CASE WHEN current_period_end>now() THEN 'ACTIVE' ELSE 'EXPIRED' END,updated_at=now() WHERE user_id=$1`,[pay.user_id]);
        return {status:'REJECTED'};
      }
      const sub=await client.query<any>('SELECT * FROM subscriptions WHERE user_id=$1 FOR UPDATE',[pay.user_id]);
      if(!sub.rowCount)throw new Error('Subscription record missing');
      const old=sub.rows[0]; const start=old.current_period_end&&new Date(old.current_period_end)>new Date()?new Date(old.current_period_end):new Date(); const end=new Date(start.getTime()+30*24*60*60*1000);
      await client.query(`UPDATE subscription_payments SET status='APPROVED',verified_at=now(),verified_by=$1,admin_note=$2 WHERE id=$3 AND status='PENDING'`,[req.user.id,note,pay.id]);
      await client.query(`UPDATE subscriptions SET status='ACTIVE',trial_started_at=CASE WHEN $1=100 THEN COALESCE(trial_started_at,$2) ELSE trial_started_at END,trial_ends_at=CASE WHEN $1=100 THEN $3 ELSE trial_ends_at END,current_period_start=$2,current_period_end=$3,auto_renew=false,updated_at=now() WHERE user_id=$4`,[pay.amount_paise,start,end,pay.user_id]);
      return {status:'APPROVED',current_period_end:end};
    });
    await audit(req,`SUBSCRIPTION_PAYMENT_${result.status}`,'SUBSCRIPTION_PAYMENT',req.params.id,{amount:undefined,note});
    res.json({ok:true,...result});
  }catch(e:any){res.status(409).json({error:e.message});}
});

app.get('/api/dashboard', requireAuth, async(req,res) => {
  const date=String(req.query.date||today());
  const filter=isAdmin(req.user)?'':` AND t.created_by=$2`;
  const params=isAdmin(req.user)?[date]:[date,req.user.id];
  const r=await q<any>(`SELECT COALESCE(sum(CASE WHEN t.transaction_type='DEPOSIT' THEN t.amount ELSE 0 END),0) deposit,
    COALESCE(sum(CASE WHEN t.transaction_type='WITHDRAWAL' THEN t.amount ELSE 0 END),0) withdrawal,
    COALESCE(sum(CASE WHEN t.transaction_type='SERVICE' THEN t.amount ELSE 0 END),0) service,count(t.id)::int transactions
    FROM transactions t JOIN business_days b ON b.id=t.business_day_id WHERE b.record_date=$1${filter}`,[...params]);
  res.json(r.rows[0]||{deposit:0,withdrawal:0,service:0,transactions:0});
});

app.get('/api/days', requireAuth, async(req,res)=>{
  const date=req.query.date?String(req.query.date):null;
  const params:any[]=[]; let where='';
  if (date) { where=' WHERE b.record_date=$1'; params.push(date); }
  if (!isAdmin(req.user)) { where += date ? ' AND b.operator_id=$2' : ' WHERE b.operator_id=$1'; params.push(req.user.id); }
  const r=await q<any>(`SELECT b.*,COALESCE((SELECT sum(amount) FROM transactions WHERE business_day_id=b.id AND transaction_type='WITHDRAWAL'),0) withdrawal,
    COALESCE((SELECT sum(amount) FROM transactions WHERE business_day_id=b.id AND transaction_type='DEPOSIT'),0) deposit,
    COALESCE((SELECT sum(amount) FROM service_records WHERE business_day_id=b.id),0) service,
    u.username operator FROM business_days b LEFT JOIN users u ON u.id=b.operator_id${where} ORDER BY b.record_date DESC LIMIT 200`,params);
  res.json(date ? (r.rows[0]||null) : r.rows);
});
app.post('/api/days', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{
  const {record_date,opening_cash=0}=req.body||{}; if(!record_date)return res.status(400).json({error:'Date required'});
  const r=await q<any>(`INSERT INTO business_days(record_date,operator_id,opening_cash) VALUES($1,$2,$3)
    ON CONFLICT (operator_id,record_date) DO UPDATE SET opening_cash=EXCLUDED.opening_cash,updated_at=now() WHERE business_days.status='OPEN' RETURNING *`,[record_date,req.user.id,Number(opening_cash)]);
  if(!r.rowCount)return res.status(409).json({error:'Day is already closed/locked'});
  await audit(req,'UPSERT','BUSINESS_DAY',r.rows[0].id,{record_date}); res.json(r.rows[0]);
});
app.delete('/api/days/:id', requireAuth, requireRole('ADMIN','OPERATOR'), checkCsrf, async(req,res)=>{
  const d=await q<any>('SELECT * FROM business_days WHERE id=$1',[req.params.id]); if(!d.rowCount)return res.status(404).json({error:'Day not found'}); if(!isAdmin(req.user)&&d.rows[0].operator_id!==req.user.id)return res.status(403).json({error:'Not your day'}); if(d.rows[0].status!=='OPEN')return res.status(409).json({error:'Only open day can be deleted'}); await q('DELETE FROM business_days WHERE id=$1',[req.params.id]); await audit(req,'DELETE','BUSINESS_DAY',req.params.id); res.json({ok:true});
});
app.delete('/api/days', requireAuth, requireRole('ADMIN','OPERATOR'), checkCsrf, async(req,res)=>{ if(isAdmin(req.user)) await q(`DELETE FROM business_days WHERE status='OPEN'`); else await q(`DELETE FROM business_days WHERE status='OPEN' AND operator_id=$1`,[req.user.id]); res.json({ok:true}); });
app.post('/api/days/:id/close', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{
  try { const d=await assertOpenOwned(req.params.id,req.user); const sums=await q<any>(`SELECT COALESCE((SELECT sum(CASE WHEN transaction_type='DEPOSIT' THEN amount WHEN transaction_type='WITHDRAWAL' THEN -amount ELSE 0 END) FROM transactions WHERE business_day_id=$1),0) tx_net FROM business_days WHERE id=$1`,[d.id]); const expected=Number(d.opening_cash)+Number(sums.rows[0].tx_net); const physical=Number(req.body.physical_cash||0); const diff=physical-expected; const r=await q<any>(`UPDATE business_days SET status='CLOSED',closed_at=now(),physical_cash=$1,expected_cash=$2,short_excess=$3,difference_reason=$4,updated_at=now() WHERE id=$5 AND status='OPEN' RETURNING *`,[physical,expected,diff,req.body.difference_reason||null,d.id]); await audit(req,'CLOSE','BUSINESS_DAY',d.id,{physical,expected,diff}); res.json(r.rows[0]); } catch(e:any){res.status(409).json({error:e.message});}
});

app.post('/api/customers', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{
  const {name,mobile,account_ref,aadhaar,notes}=req.body||{}; if(!String(name||'').trim())return res.status(400).json({error:'Name required'}); if(aadhaar && !/^\d{12}$/.test(String(aadhaar)))return res.status(400).json({error:'Aadhaar must be exactly 12 digits'});
  const dupSql=isAdmin(req.user)?`SELECT id FROM customers WHERE ($1<>'' AND mobile=$1) OR ($2<>'' AND account_ref=$2) LIMIT 1`:`SELECT id FROM customers WHERE created_by=$3 AND (($1<>'' AND mobile=$1) OR ($2<>'' AND account_ref=$2)) LIMIT 1`;
  const dupParams=isAdmin(req.user)?[mobile||'',account_ref||'']:[mobile||'',account_ref||'',req.user.id]; const dup=await q<any>(dupSql,dupParams); if(dup.rowCount)return res.status(409).json({error:'Possible duplicate mobile/account'});
  const value=String(aadhaar||''); const enc=value?encryptSensitive(value):null; const r=await q<any>(`INSERT INTO customers(name,mobile,account_ref,aadhaar_last4,aadhaar_encrypted,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,mobile,account_ref,aadhaar_last4,created_at`,[String(name).trim(),mobile||null,account_ref||null,value?value.slice(-4):null,enc,notes||null,req.user.id]); await audit(req,'CREATE','CUSTOMER',r.rows[0].id,{sensitive_id_stored:!!enc}); res.status(201).json(r.rows[0]);
});
app.get('/api/customers', requireAuth, paidAccess, async(req,res)=>{
  const s=String(req.query.q||''); const where=isAdmin(req.user)?'':' AND created_by=$2'; const params=isAdmin(req.user)?[`%${s}%`]:[`%${s}%`,req.user.id]; const r=await q<any>(`SELECT id,name,mobile,account_ref,aadhaar_last4,created_at FROM customers WHERE (name ILIKE $1 OR mobile ILIKE $1 OR account_ref ILIKE $1)${where} ORDER BY created_at DESC LIMIT 100`,params); res.json(r.rows.map((x:any)=>({...x,aadhaar:x.aadhaar_last4?maskSensitive('12345678'+x.aadhaar_last4):null})));
});
app.post('/api/customers/:id/reveal-sensitive', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res)=>{ const pin=String(req.body?.pin||''); if(!pin||pin!==String(process.env.ADMIN_DAILY_PIN||''))return res.status(401).json({error:'Invalid Admin PIN'}); const r=await q<any>('SELECT id,aadhaar_encrypted FROM customers WHERE id=$1',[req.params.id]); if(!r.rowCount||!r.rows[0].aadhaar_encrypted)return res.status(404).json({error:'Sensitive ID not found'}); const value=decryptSensitive(r.rows[0].aadhaar_encrypted); await audit(req,'REVEAL_SENSITIVE_ID','CUSTOMER',r.rows[0].id); res.json({aadhaar:value,expires_in_seconds:60}); });

app.post('/api/transactions', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{try{const{business_day_id,customer_id,transaction_type,amount,account_ref,description}=req.body||{}; if(!business_day_id||!['DEPOSIT','WITHDRAWAL','SERVICE'].includes(transaction_type)||!(Number(amount)>0))return res.status(400).json({error:'Invalid transaction'}); await assertOpenOwned(business_day_id,req.user); if(customer_id){const c=await q<any>('SELECT id FROM customers WHERE id=$1'+(isAdmin(req.user)?'':' AND created_by=$2'),isAdmin(req.user)?[customer_id]:[customer_id,req.user.id]);if(!c.rowCount)return res.status(403).json({error:'Customer not found in your account'});} const acc=String(account_ref||''); if(acc&&!/^\d{1,20}$/.test(acc))return res.status(400).json({error:'Aadhaar / Account must contain digits only, maximum 20 digits'}); const r=await q<any>('INSERT INTO transactions(business_day_id,customer_id,transaction_type,amount,account_ref,description,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[business_day_id,customer_id||null,transaction_type,Number(amount),acc||null,description||null,req.user.id]); await audit(req,'CREATE','TRANSACTION',r.rows[0].id,{transaction_type,amount:Number(amount)}); res.status(201).json(r.rows[0]);}catch(e:any){res.status(409).json({error:e.message});}});
app.post('/api/daily-transactions/unlock', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res)=>{ const pin=String(req.body?.pin||''); const expected=process.env.ADMIN_DAILY_PIN||''; if(!expected||pin!==expected)return res.status(401).json({error:'Invalid Admin PIN'}); const date=String(req.body?.date||today()); const r=await q<any>(`SELECT t.id,t.created_at,t.transaction_type,t.amount,t.account_ref,t.description,c.name customer_name,c.mobile,c.aadhaar_encrypted,c.aadhaar_last4,u.username operator FROM transactions t LEFT JOIN customers c ON c.id=t.customer_id LEFT JOIN users u ON u.id=t.created_by JOIN business_days b ON b.id=t.business_day_id WHERE b.record_date=$1 ORDER BY t.created_at DESC`,[date]); const out=r.rows.map((x:any)=>{let a=null;try{a=x.aadhaar_encrypted?decryptSensitive(x.aadhaar_encrypted):null}catch{} return {...x,aadhaar:a||maskSensitive('12345678'+(x.aadhaar_last4||''))};}); await audit(req,'UNLOCK_DAILY_TRANSACTIONS','TRANSACTION',undefined,{date}); res.json({date,rows:out}); });
app.get('/api/transactions', requireAuth, paidAccess, async(req,res)=>{ const date=String(req.query.date||today()); const own=isAdmin(req.user)?'':' AND t.created_by=$2'; const params=isAdmin(req.user)?[date]:[date,req.user.id]; const r=await q<any>(`SELECT t.id,t.created_at,t.transaction_type,t.amount,t.account_ref,t.description,c.name customer_name,c.mobile,b.record_date,u.username operator FROM transactions t JOIN business_days b ON b.id=t.business_day_id LEFT JOIN customers c ON c.id=t.customer_id LEFT JOIN users u ON u.id=t.created_by WHERE b.record_date=$1${own} ORDER BY t.created_at DESC`,params); res.json(r.rows); });

app.post('/api/services', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{try{const{business_day_id,customer_id,service_name,amount=0,reference_no,mobile,account_ref,mode}=req.body||{}; await assertOpenOwned(business_day_id,req.user); if(!String(service_name||'').trim())return res.status(400).json({error:'Service name required'}); if(mobile && !/^\d{10}$/.test(String(mobile)))return res.status(400).json({error:'Mobile must be 10 digits'}); if(account_ref && !/^\d{1,20}$/.test(String(account_ref)))return res.status(400).json({error:'Aadhaar / Account must contain digits only, maximum 20 digits'}); if(customer_id){const c=await q<any>('SELECT id FROM customers WHERE id=$1'+(isAdmin(req.user)?'':' AND created_by=$2'),isAdmin(req.user)?[customer_id]:[customer_id,req.user.id]);if(!c.rowCount)return res.status(403).json({error:'Customer not found in your account'});} const r=await q<any>('INSERT INTO service_records(business_day_id,customer_id,service_name,amount,reference_no,mobile,account_ref,mode,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[business_day_id,customer_id||null,String(service_name).trim(),Number(amount),reference_no||null,mobile||null,account_ref||null,mode||null,req.user.id]); await audit(req,'CREATE','SERVICE_RECORD',r.rows[0].id); res.status(201).json(r.rows[0]);}catch(e:any){res.status(409).json({error:e.message});}});
app.patch('/api/services/:id/status', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{const status=String(req.body?.status||'OPEN');if(!['OPEN','COMPLETED','CANCELLED'].includes(status))return res.status(400).json({error:'Invalid status'});const r=await q<any>(`UPDATE service_records SET status=$1 WHERE id=$2${isAdmin(req.user)?'':' AND created_by=$3'} RETURNING *`,isAdmin(req.user)?[status,req.params.id]:[status,req.params.id,req.user.id]);if(!r.rowCount)return res.status(404).json({error:'Service record not found'});await audit(req,'UPDATE_STATUS','SERVICE_RECORD',r.rows[0].id,{status});res.json(r.rows[0]);});
app.get('/api/services', requireAuth, paidAccess, async(req,res)=>{const date=String(req.query.date||today());const params=isAdmin(req.user)?[date]:[date,req.user.id];const own=isAdmin(req.user)?'':' AND s.created_by=$2';const r=await q<any>(`SELECT s.id,s.created_at,s.service_name,s.amount,s.reference_no,s.status,c.name customer_name FROM service_records s JOIN business_days b ON b.id=s.business_day_id LEFT JOIN customers c ON c.id=s.customer_id WHERE b.record_date=$1${own} ORDER BY s.created_at DESC`,params);res.json(r.rows);});

app.get('/api/reports', requireAuth, paidAccess, async(req,res)=>{const from=String(req.query.from||today()),to=String(req.query.to||from);const own=isAdmin(req.user)?'':' AND b.operator_id=$3';const params=isAdmin(req.user)?[from,to]:[from,to,req.user.id];const r=await q<any>(`SELECT b.record_date,b.status,u.username operator,COALESCE(sum(CASE WHEN t.transaction_type='DEPOSIT' THEN t.amount ELSE 0 END),0) deposit,COALESCE(sum(CASE WHEN t.transaction_type='WITHDRAWAL' THEN t.amount ELSE 0 END),0) withdrawal,COALESCE(sum(CASE WHEN t.transaction_type='SERVICE' THEN t.amount ELSE 0 END),0) service,count(t.id)::int transactions FROM business_days b LEFT JOIN users u ON u.id=b.operator_id LEFT JOIN transactions t ON t.business_day_id=b.id WHERE b.record_date BETWEEN $1 AND $2${own} GROUP BY b.record_date,b.status,u.username ORDER BY b.record_date DESC`,params);res.json(r.rows);});
app.get('/api/reports/complete', requireAuth, paidAccess, async(req,res)=>{const date=String(req.query.date||today());const own=isAdmin(req.user)?'':' AND b.operator_id=$2';const params=isAdmin(req.user)?[date]:[date,req.user.id];const day=await q<any>(`SELECT b.*,u.username operator,COALESCE((SELECT sum(amount) FROM transactions WHERE business_day_id=b.id AND transaction_type='WITHDRAWAL'),0) withdrawal,COALESCE((SELECT sum(amount) FROM transactions WHERE business_day_id=b.id AND transaction_type='DEPOSIT'),0) deposit,COALESCE((SELECT sum(amount) FROM service_records WHERE business_day_id=b.id),0) service FROM business_days b LEFT JOIN users u ON u.id=b.operator_id WHERE b.record_date=$1${own}`,params);if(!day.rowCount)return res.status(404).json({error:'Day not found'});const d=day.rows[0];const own2=isAdmin(req.user)?'':' AND created_by=$2';const p2=isAdmin(req.user)?[d.id]:[d.id,req.user.id];const [tx,services,cash]=await Promise.all([q<any>(`SELECT * FROM transactions WHERE business_day_id=$1${own2} ORDER BY created_at`,p2),q<any>(`SELECT * FROM service_records WHERE business_day_id=$1${own2} ORDER BY created_at`,p2),q<any>('SELECT denomination,quantity,denomination*quantity amount FROM cash_denominations WHERE business_day_id=$1 ORDER BY denomination DESC',[d.id])]);res.json({day:d,transactions:tx.rows,services:services.rows,cash:cash.rows});});
app.post('/api/cash/denominations', requireAuth, requireRole('ADMIN','OPERATOR'), paidAccess, checkCsrf, async(req,res)=>{const date=String(req.body.date||today());const d=await q<any>('SELECT id,status,operator_id FROM business_days WHERE record_date=$1'+(isAdmin(req.user)?'':' AND operator_id=$2'),isAdmin(req.user)?[date]:[date,req.user.id]);if(!d.rowCount)return res.status(404).json({error:'Business day not found'});if(d.rows[0].status!=='OPEN')return res.status(409).json({error:'Day is closed/locked'});for(const x of req.body.denominations||[])await q(`INSERT INTO cash_denominations(business_day_id,denomination,quantity) VALUES($1,$2,$3) ON CONFLICT(business_day_id,denomination) DO UPDATE SET quantity=EXCLUDED.quantity`,[d.rows[0].id,Number(x.denomination),Math.max(0,Number(x.quantity))]);await audit(req,'UPSERT','CASH_DENOMINATION',d.rows[0].id);res.json({ok:true});});

app.get('/api/customer-backup', requireAuth, requireRole('OPERATOR'), async(req,res)=>{const [c,t,s,d]=await Promise.all([q<any>('SELECT id,name,mobile,account_ref,aadhaar_last4,created_at FROM customers WHERE created_by=$1 ORDER BY created_at DESC',[req.user.id]),q<any>('SELECT * FROM transactions WHERE created_by=$1 ORDER BY created_at DESC',[req.user.id]),q<any>('SELECT * FROM service_records WHERE created_by=$1 ORDER BY created_at DESC',[req.user.id]),q<any>('SELECT * FROM business_days WHERE operator_id=$1 ORDER BY record_date DESC',[req.user.id])]);res.json({exported_at:new Date().toISOString(),operator:{username:req.user.username,display_name:req.user.display_name},customers:c.rows,transactions:t.rows,services:s.rows,business_days:d.rows});});
app.post('/api/backups', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res)=>{const tables=['users','customers','business_days','transactions','cash_denominations','service_records','subscriptions','subscription_payments'];const payload:any={};for(const t of tables){if(t==='users')payload[t]=(await q<any>(`SELECT id,username,display_name,role,is_active,created_at,updated_at FROM users`)).rows;else payload[t]=(await q<any>(`SELECT * FROM ${t}`)).rows;}const checksum=crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');const v=await q<any>('SELECT COALESCE(max(backup_version),0)+1 v FROM app_backups');const r=await q<any>('INSERT INTO app_backups(created_by,backup_version,checksum,payload) VALUES($1,$2,$3,$4) RETURNING id,backup_version,checksum,created_at',[req.user.id,v.rows[0].v,checksum,payload]);await audit(req,'CREATE','BACKUP',r.rows[0].id);res.status(201).json(r.rows[0]);});
app.get('/api/backups', requireAuth, requireRole('ADMIN'), async(_req,res)=>{const r=await q<any>('SELECT id,backup_version,checksum,created_at FROM app_backups ORDER BY created_at DESC LIMIT 50');res.json(r.rows);});

app.get('/api/users', requireAuth, requireRole('ADMIN'), async(_req,res)=>{const r=await q<any>(`SELECT id,username,display_name,role,is_active,created_at FROM users ORDER BY created_at`);res.json(r.rows);});
app.post('/api/users', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res)=>{const{username,password,role='OPERATOR'}=req.body||{};if(!username||typeof password!=='string'||password.length<12||role!=='OPERATOR')return res.status(400).json({error:'Only Operator users may be created here; Admin is owner-only.'});try{const h=await hashPassword(password);const r=await q<any>('INSERT INTO users(username,password_hash,role) VALUES($1,$2,\'OPERATOR\') RETURNING id,username,role,is_active,created_at',[username,h]);res.status(201).json(r.rows[0]);}catch{res.status(409).json({error:'Username already exists'});}});
app.get('/api/site-settings', requireAuth, requireRole('ADMIN'), async(_req,res)=>{const r=await q<any>('SELECT key,value,updated_at FROM app_settings ORDER BY key');res.json(r.rows);});
app.post('/api/site-settings', requireAuth, requireRole('ADMIN'), checkCsrf, async(req,res)=>{const{key,value}=req.body||{};if(!/^[a-zA-Z0-9_.-]{1,120}$/.test(String(key||'')))return res.status(400).json({error:'Invalid setting key'});await q(`INSERT INTO app_settings(key,value,updated_by,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()`,[key,JSON.stringify(value),req.user.id]);res.json({ok:true});});
app.get('/api/audit', requireAuth, requireRole('ADMIN'), async(_req,res)=>{const r=await q<any>('SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500');res.json(r.rows);});

app.use((err:any,_req:any,res:any,_next:any)=>{console.error(err);res.status(500).json({error:'Internal server error'});});
const clientDist=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../client/dist');
app.use(express.static(clientDist,{index:'index.html'}));
app.get(/^(?!\/api).*/,(_req,res)=>res.sendFile(path.join(clientDist,'index.html')));
const port=Number(process.env.PORT||4000);
ensureOwnerAdmin().then(()=>app.listen(port,()=>console.log(`SHYAM PNB API listening on ${port}`))).catch(e=>{console.error('Startup failed:',e);process.exit(1);});
