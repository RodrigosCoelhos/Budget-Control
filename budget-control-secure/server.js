import 'dotenv/config';
import express from 'express';
import pg from 'pg';
import { readFileSync } from 'node:fs';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import {randomBytes,createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

if(!process.env.DATABASE_URL) throw Error('Configure DATABASE_URL');
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    ca: readFileSync(
      new URL('./supabase-ca.crt', import.meta.url),
      'utf8'
    ),
    rejectUnauthorized: true
  }
});
const app=express(); app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:'5mb'}));app.use(cookieParser());
const origin=process.env.APP_ORIGIN||'http://localhost:3000';
app.use('/api',(req,res,next)=>{if(!['GET','HEAD','OPTIONS'].includes(req.method)&&req.get('origin')!==origin)return res.status(403).json({error:'Unauthorized origin'});next()});
const authLimit=rateLimit({windowMs:15*60*1000,limit:15,standardHeaders:'draft-7',legacyHeaders:false});
const sha=s=>createHash('sha256').update(s).digest('hex');
const token=()=>randomBytes(32).toString('hex');
const cookieOptions={httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/'};
const asyncRoute=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const err=(res,msg,status=400)=>res.status(status).json({error:msg});
async function auth(req,res,next){try{const raw=req.cookies.bc_session;if(!raw)return err(res,'Authentication required',401);const {rows}=await pool.query(`SELECT u.id,u.username,u.name,u.email,u.role,u.can_create,u.can_edit,u.can_delete FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true`,[sha(raw)]);if(!rows[0])return err(res,'Invalid session',401);req.user=rows[0];next()}catch(e){next(e)}}
const admin=(req,res,next)=>req.user.role==='admin'?next():err(res,'Administrator access required',403);
const isAdmin=u=>u.role==='admin';
async function projectAccess(u,id){if(isAdmin(u))return (await pool.query('SELECT 1 FROM projects WHERE id=$1 AND archived_at IS NULL',[id])).rowCount>0;return (await pool.query('SELECT 1 FROM project_members m JOIN projects p ON p.id=m.project_id WHERE m.project_id=$1 AND m.user_id=$2 AND p.archived_at IS NULL',[id,u.id])).rowCount>0}
function validExpense(b){return typeof b.title==='string'&&b.title.trim().length>0&&b.title.length<=120&&typeof b.category==='string'&&b.category.trim().length>0&&b.category.length<=80&&Number.isFinite(Number(b.amount))&&Number(b.amount)>0&&Number(b.amount)<=999999999999&&typeof b.method==='string'&&b.method.trim().length>0&&b.method.length<=80&&/^\d{4}-\d{2}-\d{2}$/.test(b.date)&&!Number.isNaN(Date.parse(b.date))}
async function categoryAllowed(name, previous=null){
  const {rows}=await pool.query('SELECT active FROM expense_categories WHERE name=$1',[name]);
  return !!rows[0]?.active || (previous!==null && previous===name);
}
app.get('/api/categories',auth,asyncRoute(async(req,res)=>{
  const {rows}=await pool.query('SELECT id,name FROM expense_categories WHERE active=true ORDER BY sort_order,name');
  res.json(rows);
}));
app.get('/api/admin/categories',auth,admin,asyncRoute(async(req,res)=>{
  const {rows}=await pool.query(`SELECT c.id,c.name,c.active,COUNT(e.id)::int AS expense_count FROM expense_categories c LEFT JOIN expenses e ON e.category=c.name GROUP BY c.id ORDER BY c.active DESC,c.sort_order,c.name`);
  res.json(rows);
}));
app.post('/api/admin/categories',auth,admin,asyncRoute(async(req,res)=>{
  const name=String(req.body.name||'').trim();
  if(!name||name.length>80)return err(res,'Category name must be 1–80 characters');
  const {rows}=await pool.query('INSERT INTO expense_categories(name,sort_order) VALUES($1,(SELECT COALESCE(MAX(sort_order),0)+1 FROM expense_categories)) ON CONFLICT(name) DO NOTHING RETURNING id,name,active',[name]);
  if(!rows[0])return err(res,'This category already exists',409);
  res.status(201).json(rows[0]);
}));
app.patch('/api/admin/categories/:id',auth,admin,asyncRoute(async(req,res)=>{
  const name=String(req.body.name||'').trim();
  if(!name||name.length>80)return err(res,'Category name must be 1–80 characters');
  const client=await pool.connect();
  try {await client.query('BEGIN');
    const old=(await client.query('SELECT * FROM expense_categories WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];
    if(!old){await client.query('ROLLBACK');return err(res,'Category not found',404)}
    if(!old.active)return err(res,'Inactive categories cannot be renamed',409);
    if(old.name===name){await client.query('COMMIT');return res.json(old)}
    const used=(await client.query('SELECT 1 FROM expenses WHERE category=$1 LIMIT 1',[old.name])).rowCount>0;
    let rows;
    if(used){
      // Keep the historical label attached to existing expenses.
      await client.query('UPDATE expense_categories SET active=false WHERE id=$1',[old.id]);
      rows=(await client.query('INSERT INTO expense_categories(name,sort_order) VALUES($1,$2) ON CONFLICT(name) DO NOTHING RETURNING id,name,active',[name,old.sort_order])).rows;
    }else{
      rows=(await client.query('UPDATE expense_categories SET name=$1 WHERE id=$2 AND NOT EXISTS(SELECT 1 FROM expense_categories WHERE name=$1) RETURNING id,name,active',[name,old.id])).rows;
    }
    if(!rows[0]){await client.query('ROLLBACK');return err(res,'This category already exists',409)}
    await client.query('COMMIT');res.json(rows[0]);
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.delete('/api/admin/categories/:id',auth,admin,asyncRoute(async(req,res)=>{
  const {rows}=await pool.query('UPDATE expense_categories SET active=false WHERE id=$1 AND active=true RETURNING id',[req.params.id]);
  if(!rows[0])return err(res,'Category not found or already inactive',404);
  res.json({ok:true});
}));
const userFields='id,username,name,email,role,can_create,can_edit,can_delete,active';
// Receipt images are stored in PostgreSQL, not on the Render filesystem.
const MAX_RECEIPT_BYTES=3*1024*1024;
function receiptFromRequest(b){
  if(b.receipt===undefined||b.receipt===null||b.receipt==='')return null;
  if(typeof b.receipt!=='object'||Array.isArray(b.receipt))throw Object.assign(new Error('Invalid receipt'),{status:400});
  const {data,mime}=b.receipt;
  if(typeof data!=='string'||typeof mime!=='string'||data.length>Math.ceil(MAX_RECEIPT_BYTES*4/3)+8||!/^([A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data))throw Object.assign(new Error('Invalid image or image too large (maximum 3 MB)'),{status:400});
  const bytes=Buffer.from(data,'base64');
  if(!bytes.length||bytes.length>MAX_RECEIPT_BYTES)throw Object.assign(new Error('Image too large (maximum 3 MB)'),{status:400});
  const jpg=bytes.length>3&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
  const png=bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  const webp=bytes.length>=12&&bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP';
  const actual=jpg?'image/jpeg':png?'image/png':webp?'image/webp':null;
  if(!actual||mime!==actual)throw Object.assign(new Error('Use a valid JPG, PNG or WebP image'),{status:400});
  return {bytes,mime:actual};
}

// A criação de contas é exclusiva da administração.
app.post('/api/auth/register',(_req,res)=>err(res,'Public registration is disabled. Accountct the administrator.',403));
app.post('/api/auth/login',authLimit,asyncRoute(async(req,res)=>{const {login,password}=req.body;if(typeof login!=='string'||typeof password!=='string')return err(res,'Invalid credentials',401);const {rows}=await pool.query('SELECT * FROM users WHERE (lower(username)=lower($1) OR lower(email)=lower($1)) AND active=true',[login]);if(!rows[0]||!(await bcrypt.compare(password,rows[0].password_hash)))return err(res,'Invalid credentials',401);const raw=token();await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '7 days') ON CONFLICT (user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,expires_at=EXCLUDED.expires_at",[sha(raw),rows[0].id]);res.cookie('bc_session',raw,{...cookieOptions,maxAge:7*86400000});res.json({message:'Signed in successfully'})}));
app.post('/api/auth/logout',auth,asyncRoute(async(req,res)=>{await pool.query('DELETE FROM sessions WHERE token_hash=$1',[sha(req.cookies.bc_session)]);res.clearCookie('bc_session',cookieOptions);res.json({ok:true})}));
app.get('/api/me',auth,(req,res)=>res.json(req.user));
async function sendMail(to,subject,text){if(!process.env.SMTP_HOST)throw Error('SMTP is not configured');const transport=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:Number(process.env.SMTP_PORT)===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});await transport.sendMail({from:process.env.SMTP_FROM,to,subject,text})}
app.post('/api/auth/recover-username',authLimit,asyncRoute(async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();if(!process.env.SMTP_HOST)return err(res,'Email recovery is not configured yet',503);const {rows}=await pool.query('SELECT username,email FROM users WHERE lower(email)=$1 AND active=true',[email]);if(rows[0])await sendMail(rows[0].email,'Budget Control — User',`Your username is: ${rows[0].username}`);res.json({message:'If the account exists, you will receive an email.'})}));
app.post('/api/auth/forgot-password',authLimit,asyncRoute(async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();if(!process.env.SMTP_HOST)return err(res,'Email recovery is not configured yet',503);const {rows}=await pool.query('SELECT id,email FROM users WHERE lower(email)=$1 AND active=true',[email]);if(rows[0]){const raw=token();await pool.query("INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')",[sha(raw),rows[0].id]);await sendMail(rows[0].email,'Budget Control — Reset password',`Aceda a ${origin}/?reset=${raw} (válido durante 30 minutos).`)}res.json({message:'If the account exists, you will receive an email.'})}));
app.post('/api/auth/reset-password',authLimit,asyncRoute(async(req,res)=>{const {token:raw,password}=req.body;if(typeof raw!=='string'||typeof password!=='string'||password.length<10||password.length>128)return err(res,'Invalid request');const client=await pool.connect();try{await client.query('BEGIN');const {rows}=await client.query('DELETE FROM reset_tokens WHERE token_hash=$1 AND expires_at>now() RETURNING user_id',[sha(raw)]);if(!rows[0]){await client.query('ROLLBACK');return err(res,'Invalid or expired link',400)}await client.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await bcrypt.hash(password,12),rows[0].user_id]);await client.query('DELETE FROM sessions WHERE user_id=$1',[rows[0].user_id]);await client.query('COMMIT');res.json({message:'Password updated'})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.get('/api/projects',auth,asyncRoute(async(req,res)=>{const {rows}=await pool.query(`SELECT p.id,p.name,p.budget::float8 AS budget,COALESCE(sum(e.amount),0)::float8 AS spent FROM projects p LEFT JOIN expenses e ON e.project_id=p.id WHERE p.archived_at IS NULL AND ($1::boolean OR EXISTS(SELECT 1 FROM project_members m WHERE m.project_id=p.id AND m.user_id=$2)) GROUP BY p.id ORDER BY p.name`,[isAdmin(req.user),req.user.id]);res.json(rows)}));
app.get('/api/projects/:id/expenses',auth,asyncRoute(async(req,res)=>{if(!await projectAccess(req.user,req.params.id))return err(res,'Project access denied',403);const {rows}=await pool.query(`SELECT e.id,e.project_id,e.owner_id,e.title,e.category,e.amount::float8 AS amount,e.method,to_char(e.expense_date,'YYYY-MM-DD') AS date,u.name AS owner_name,(e.receipt_data IS NOT NULL) AS has_receipt FROM expenses e JOIN users u ON u.id=e.owner_id WHERE e.project_id=$1 AND ($2::boolean OR e.owner_id=$3) ORDER BY e.expense_date DESC,e.created_at DESC`,[req.params.id,isAdmin(req.user),req.user.id]);res.json(rows)}));
app.get('/api/projects/:id/summary',auth,asyncRoute(async(req,res)=>{if(!await projectAccess(req.user,req.params.id))return err(res,'Project access denied',403);const {rows}=await pool.query('SELECT category,sum(amount)::float8 AS total FROM expenses WHERE project_id=$1 GROUP BY category',[req.params.id]);res.json(rows)}));
app.post('/api/expenses',auth,asyncRoute(async(req,res)=>{const b=req.body;if(!isAdmin(req.user)&&!req.user.can_create)return err(res,'Creating expenses is not permitted',403);if(typeof b.project_id!=='string'||!await projectAccess(req.user,b.project_id))return err(res,'Project access denied',403);if(!validExpense(b))return err(res,'Invalid expense details');if(!await categoryAllowed(b.category))return err(res,'Select an active category');const receipt=receiptFromRequest(b);try{const {rows}=await pool.query('INSERT INTO expenses(project_id,owner_id,title,category,amount,method,expense_date,receipt_data,receipt_mime) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',[b.project_id,req.user.id,b.title.trim(),b.category,b.amount,b.method.trim(),b.date,receipt?.bytes||null,receipt?.mime||null]);res.status(201).json(rows[0])}catch(e){if(e.code==='23505'&&e.constraint==='expenses_exact_duplicate_unique')return err(res,'Duplicate expense: identical details and receipt already exist',409);throw e}}));
app.patch('/api/expenses/:id',auth,asyncRoute(async(req,res)=>{if(!isAdmin(req.user)&&!req.user.can_edit)return err(res,'Editing expenses is not permitted',403);if(!validExpense(req.body))return err(res,'Invalid expense details');const current=await pool.query('SELECT category FROM expenses WHERE id=$1',[req.params.id]);if(!current.rows[0])return err(res,'Expense not found',404);if(!await categoryAllowed(req.body.category,current.rows[0].category))return err(res,'Select an active category');const receipt=receiptFromRequest(req.body);try{const {rows}=await pool.query(`UPDATE expenses SET title=$1,category=$2,amount=$3,method=$4,expense_date=$5,receipt_data=CASE WHEN $9::boolean THEN $10::bytea ELSE receipt_data END,receipt_mime=CASE WHEN $9::boolean THEN $11::text ELSE receipt_mime END WHERE id=$6 AND ($7::boolean OR (owner_id=$8 AND EXISTS(SELECT 1 FROM project_members WHERE project_id=expenses.project_id AND user_id=$8))) RETURNING id`,[req.body.title.trim(),req.body.category,req.body.amount,req.body.method.trim(),req.body.date,req.params.id,isAdmin(req.user),req.user.id,!!receipt,receipt?.bytes||null,receipt?.mime||null]);if(!rows[0])return err(res,'Expense not found or access denied',404);res.json(rows[0])}catch(e){if(e.code==='23505'&&e.constraint==='expenses_exact_duplicate_unique')return err(res,'Duplicate expense: identical details and receipt already exist',409);throw e}}));
app.get('/api/expenses/:id/receipt',auth,asyncRoute(async(req,res)=>{
  const {rows}=await pool.query(`SELECT e.receipt_data,e.receipt_mime FROM expenses e WHERE e.id=$1 AND e.receipt_data IS NOT NULL AND ($2::boolean OR (e.owner_id=$3 AND EXISTS (SELECT 1 FROM project_members m JOIN projects p ON p.id=m.project_id WHERE m.project_id=e.project_id AND m.user_id=$3 AND p.archived_at IS NULL)))`,[req.params.id,isAdmin(req.user),req.user.id]);
  if(!rows[0])return err(res,'Receipt not found or access denied',404);
  res.set({'Content-Type':rows[0].receipt_mime,'Content-Disposition':'inline; filename="comprovativo"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});
  res.send(rows[0].receipt_data);
}));
app.delete('/api/expenses/:id',auth,asyncRoute(async(req,res)=>{if(!isAdmin(req.user)&&!req.user.can_delete)return err(res,'Deleting expenses is not permitted',403);const {rowCount}=await pool.query(`DELETE FROM expenses WHERE id=$1 AND ($2::boolean OR (owner_id=$3 AND EXISTS(SELECT 1 FROM project_members WHERE project_id=expenses.project_id AND user_id=$3)))`,[req.params.id,isAdmin(req.user),req.user.id]);if(!rowCount)return err(res,'Expense not found or access denied',404);res.json({ok:true})}));
app.post('/api/admin/users',auth,admin,asyncRoute(async(req,res)=>{
  const {username,name,email,password}=req.body||{};
  if(typeof name!=='string'||!name.trim()||name.length>100)return err(res,'Invalid full name (1–100 characters).');
  if(typeof username!=='string'||!/^[a-zA-Z0-9_.-]{3,40}$/.test(username.trim()))return err(res,'Invalid username: use 3–40 letters, numbers, periods, hyphens or underscores.');
  if(typeof email!=='string'||email.length>200||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))return err(res,'Invalid email address.');
  if(typeof password!=='string'||password.length<12||password.length>128)return err(res,'Password must contain 12–128 characters.');
  try{
    const {rows}=await pool.query(`INSERT INTO users(username,name,email,password_hash,role,can_create,can_edit,can_delete,active) VALUES($1,$2,$3,$4,'user',false,false,false,true) RETURNING ${userFields}`,[username.trim(),name.trim(),email.trim().toLowerCase(),await bcrypt.hash(password,12)]);
    res.status(201).json(rows[0]);
  }catch(e){if(e.code==='23505')return err(res,'Username or email already exists',409);throw e}
}));
app.get('/api/admin/users',auth,admin,asyncRoute(async(req,res)=>res.json((await pool.query(`SELECT ${userFields} FROM users WHERE active=true ORDER BY name`)).rows)));
app.patch('/api/admin/users/:id',auth,admin,asyncRoute(async(req,res)=>{const b=req.body;if(typeof b.can_create!=='boolean'||typeof b.can_edit!=='boolean'||typeof b.can_delete!=='boolean')return err(res,'Invalid permissions');const {rows}=await pool.query(`UPDATE users SET can_create=$1,can_edit=$2,can_delete=$3 WHERE id=$4 AND role='user' RETURNING ${userFields}`,[b.can_create,b.can_edit,b.can_delete,req.params.id]);if(!rows[0])return err(res,'User not found',404);res.json(rows[0])}));
app.get('/api/admin/projects/:id/members',auth,admin,asyncRoute(async(req,res)=>res.json((await pool.query('SELECT user_id FROM project_members WHERE project_id=$1',[req.params.id])).rows.map(x=>x.user_id))));
app.put('/api/admin/projects/:id/members/:userId',auth,admin,asyncRoute(async(req,res)=>{const exists=await pool.query("SELECT 1 FROM users WHERE id=$1 AND role='user'",[req.params.userId]);if(!exists.rowCount)return err(res,'Invalid user',404);const project=await pool.query('SELECT 1 FROM projects WHERE id=$1 AND archived_at IS NULL',[req.params.id]);if(!project.rowCount)return err(res,'Invalid project',404);await pool.query('INSERT INTO project_members(project_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.params.id,req.params.userId]);res.json({ok:true})}));
app.delete('/api/admin/projects/:id/members/:userId',auth,admin,asyncRoute(async(req,res)=>{await pool.query('DELETE FROM project_members WHERE project_id=$1 AND user_id=$2',[req.params.id,req.params.userId]);res.json({ok:true})}));
app.post('/api/admin/projects',auth,admin,asyncRoute(async(req,res)=>{const {name,budget}=req.body;if(typeof name!=='string'||!name.trim()||name.length>120||!Number.isFinite(Number(budget))||Number(budget)<0)return err(res,'Invalid project');res.status(201).json((await pool.query('INSERT INTO projects(name,budget) VALUES($1,$2) RETURNING id',[name.trim(),budget])).rows[0])}));
app.patch('/api/admin/projects/:id',auth,admin,asyncRoute(async(req,res)=>{if(!Number.isFinite(Number(req.body.budget))||Number(req.body.budget)<0)return err(res,'Invalid budget');const {rows}=await pool.query('UPDATE projects SET budget=$1 WHERE id=$2 RETURNING id',[req.body.budget,req.params.id]);if(!rows[0])return err(res,'Project not found',404);res.json(rows[0])}));
// Eliminação segura: desativação/arquivo preserva expenses e histórico financeiro.
app.delete('/api/admin/users/:id',auth,admin,asyncRoute(async(req,res)=>{
  if(req.params.id===req.user.id)return err(res,'You cannot deactivate your own account',403);
  const client=await pool.connect();
  try {await client.query('BEGIN');
    const {rows}=await client.query("UPDATE users SET active=false WHERE id=$1 AND role='user' AND active=true RETURNING id",[req.params.id]);
    if(!rows[0]){await client.query('ROLLBACK');return err(res,'User not found or already deactivated',404)}
    await client.query('DELETE FROM sessions WHERE user_id=$1',[req.params.id]);
    await client.query('DELETE FROM reset_tokens WHERE user_id=$1',[req.params.id]);
    await client.query('DELETE FROM project_members WHERE user_id=$1',[req.params.id]);
    await client.query('COMMIT');res.json({ok:true,message:'User deactivated; history preserved'});
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.delete('/api/admin/projects/:id',auth,admin,asyncRoute(async(req,res)=>{
  const {rows}=await pool.query('UPDATE projects SET archived_at=now() WHERE id=$1 AND archived_at IS NULL RETURNING id',[req.params.id]);
  if(!rows[0])return err(res,'Project not found or already archived',404);
  res.json({ok:true,message:'Project archived; expenses preserved'});
}));
app.get('/api/admin/expenses',auth,admin,asyncRoute(async(req,res)=>{const {user_id='',project_id='',category='',date_from='',date_to='',search=''}=req.query;if([user_id,project_id,category,date_from,date_to,search].some(v=>typeof v!=='string'||v.length>150))return err(res,'Invalid report filters');if((date_from&&!/^\d{4}-\d{2}-\d{2}$/.test(date_from))||(date_to&&!/^\d{4}-\d{2}-\d{2}$/.test(date_to)))return err(res,'Invalid date filter');const {rows}=await pool.query(`SELECT e.id,e.project_id,e.owner_id,e.title,e.category,e.amount::float8 AS amount,e.method,to_char(e.expense_date,'YYYY-MM-DD') AS date,u.name AS owner_name,p.name AS project_name,(e.receipt_data IS NOT NULL) AS has_receipt FROM expenses e JOIN users u ON u.id=e.owner_id JOIN projects p ON p.id=e.project_id WHERE ($1::text='' OR e.owner_id::text=$1) AND ($2::text='' OR e.project_id::text=$2) AND ($3::text='' OR e.category=$3) AND ($4::text='' OR e.expense_date >= NULLIF($4,'')::date) AND ($5::text='' OR e.expense_date <= NULLIF($5,'')::date) AND ($6::text='' OR e.title ILIKE '%' || $6 || '%' OR e.method ILIKE '%' || $6 || '%') ORDER BY e.expense_date DESC,e.created_at DESC`,[user_id,project_id,category,date_from,date_to,search]);res.json(rows)}));
app.use(express.static(path.join(path.dirname(fileURLToPath(import.meta.url)),'public')));
app.use((e,req,res,next)=>{console.error(e);res.status(e.status||500).json({error:e.status?e.message:'Internal server error'})});
const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`Budget Control: ${origin}`));
