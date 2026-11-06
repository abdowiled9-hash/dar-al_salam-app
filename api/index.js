import crypto from 'node:crypto';
import {neon} from '@neondatabase/serverless';

const cookieName='dar_session';
const cookieOptions='; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000';
const now=()=>new Date().toISOString();
const makeHash=password=>{const salt=crypto.randomBytes(16).toString('hex');return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`};
const checkHash=(password,stored)=>{if(!stored)return false;const [salt,hex]=stored.split(':');if(!salt||!hex)return false;const actual=crypto.scryptSync(String(password||''),salt,64);const expected=Buffer.from(hex,'hex');return actual.length===expected.length&&crypto.timingSafeEqual(actual,expected)};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sqlClient=()=>{if(!process.env.DATABASE_URL)throw new Error('إعداد قاعدة البيانات غير مكتمل. أضف DATABASE_URL إلى Vercel.');return neon(process.env.DATABASE_URL)};

async function loadDb(sql){
  await sql`CREATE TABLE IF NOT EXISTS nursery_state (id TEXT PRIMARY KEY, data JSONB NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS nursery_recovery_attempts (ip TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, blocked_until BIGINT NOT NULL DEFAULT 0)`;
  let rows=await sql`SELECT data FROM nursery_state WHERE id='main'`;
  if(!rows.length){
    const password=process.env.INITIAL_ADMIN_PASSWORD;
    if(!password)throw new Error('أضف INITIAL_ADMIN_PASSWORD إلى إعدادات Vercel أولًا.');
    const seed={users:[{id:'u-admin',name:process.env.INITIAL_ADMIN_NAME||'مشرف دار السلام',username:process.env.INITIAL_ADMIN_USERNAME||'admin',passwordHash:makeHash(password),role:'admin',title:'مشرف الحضانة',active:true,mustChangePassword:true,sessionVersion:0}],tasks:[],announcements:[],attendance:[]};
    await sql`INSERT INTO nursery_state(id,data) VALUES ('main',${JSON.stringify(seed)}::jsonb) ON CONFLICT(id) DO NOTHING`;
    rows=await sql`SELECT data FROM nursery_state WHERE id='main'`;
  }
  return rows[0].data;
}
async function saveDb(sql,db){await sql`UPDATE nursery_state SET data=${JSON.stringify(db)}::jsonb WHERE id='main'`}
function safeUser(user){if(!user)return null;const {passwordHash,password,sessionVersion,...safe}=user;return safe}
function publicDb(db,user=null){const staff=user?.role==='staff';return {...db,users:(staff?[user]:db.users).map(safeUser),tasks:staff?db.tasks.filter(t=>t.assignee===user.id):db.tasks,attendance:staff?db.attendance.filter(a=>a.userId===user.id):db.attendance}}
function body(req){if(req.body&&typeof req.body==='object')return req.body;if(typeof req.body==='string'){try{return JSON.parse(req.body)}catch{}}return {}}
function send(res,status,value,headers={}){res.statusCode=status;res.setHeader('Cache-Control','no-store');for(const [key,val] of Object.entries(headers))res.setHeader(key,val);if(typeof value==='string'){res.setHeader('Content-Type','text/plain; charset=utf-8');res.end(value)}else{res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(value))}}
function cookieValue(req){const entry=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(`${cookieName}=`));try{return entry?decodeURIComponent(entry.slice(cookieName.length+1)):''}catch{return ''}}
function makeSession(user){const payload=Buffer.from(JSON.stringify({id:user.id,version:user.sessionVersion||0,exp:Date.now()+30*86400000})).toString('base64url');const signature=crypto.createHmac('sha256',process.env.AUTH_SECRET).update(payload).digest('base64url');return `${payload}.${signature}`}
function verifySession(token){try{if(!process.env.AUTH_SECRET)return null;const [payload,signature]=token.split('.');if(!payload||!signature)return null;const expected=Buffer.from(crypto.createHmac('sha256',process.env.AUTH_SECRET).update(payload).digest('base64url'));const actual=Buffer.from(signature);if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual))return null;const session=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));return session.exp>Date.now()?session:null}catch{return null}}
function routeName(req){const url=new URL(req.url,'https://local.invalid');return (url.searchParams.get('path')||url.pathname.replace(/^\/api\/?/,'')).replace(/\/$/,'')}
function getIp(req){return String(req.headers['x-forwarded-for']||req.headers['x-real-ip']||'unknown').split(',')[0].trim().slice(0,120)}

export default async function handler(req,res){
  const route=routeName(req);
  if(route==='healthz'&&req.method==='GET'){send(res,200,{ok:true});return}
  if(req.method==='POST'&&route==='logout'){send(res,200,{ok:true},{'Set-Cookie':`${cookieName}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`});return}
  try{
    const sql=sqlClient();
    let db=await loadDb(sql);
    if(req.method==='POST'&&route==='login'){
      const {username,password,role}=body(req);const user=db.users.find(u=>String(u.username||'').toLowerCase()===String(username||'').trim().toLowerCase());
      if(!user||user.active===false||user.role!==role||!(user.passwordHash?checkHash(password,user.passwordHash):user.password===password)){send(res,401,{error:'بيانات الدخول غير صحيحة أو الحساب غير نشط.'});return}
      if(user.password){user.passwordHash=makeHash(user.password);delete user.password;await saveDb(sql,db)}
      if(!process.env.AUTH_SECRET){send(res,503,{error:'إعداد الجلسات غير مكتمل. أضف AUTH_SECRET إلى Vercel.'});return}
      send(res,200,{user:safeUser(user),db:publicDb(db,user)},{'Set-Cookie':`${cookieName}=${encodeURIComponent(makeSession(user))}${cookieOptions}`});return
    }
    if(req.method==='POST'&&route==='admin/recover-password'){
      const {username,recoveryCode,newPassword}=body(req);const configured=process.env.ADMIN_RECOVERY_CODE;const admin=db.users.find(u=>u.role==='admin'&&String(u.username||'').toLowerCase()===String(username||'').trim().toLowerCase()&&u.active!==false);const ip=getIp(req);
      if(!configured){send(res,503,{error:'استعادة كلمة المرور غير مفعّلة. أضف ADMIN_RECOVERY_CODE إلى Production في Vercel.'});return}
      const [attempt]=await sql`SELECT attempts,blocked_until FROM nursery_recovery_attempts WHERE ip=${ip}`;
      if(attempt&&Number(attempt.blocked_until)>Date.now()){send(res,429,{error:'محاولات كثيرة. حاول بعد ١٥ دقيقة.'});return}
      const entered=Buffer.from(String(recoveryCode||'')),expected=Buffer.from(configured);const valid=entered.length===expected.length&&crypto.timingSafeEqual(entered,expected);
      if(!admin||!valid){await sql`INSERT INTO nursery_recovery_attempts(ip,attempts,blocked_until) VALUES(${ip},1,0) ON CONFLICT(ip) DO UPDATE SET attempts=CASE WHEN nursery_recovery_attempts.attempts+1>=5 THEN 0 ELSE nursery_recovery_attempts.attempts+1 END,blocked_until=CASE WHEN nursery_recovery_attempts.attempts+1>=5 THEN ${Date.now()+15*60*1000} ELSE nursery_recovery_attempts.blocked_until END`;send(res,400,{error:'اسم المستخدم أو رمز الاستعادة غير صحيح.'});return}
      if(String(newPassword||'').length<8){send(res,400,{error:'كلمة المرور الجديدة يجب أن تكون ٨ أحرف على الأقل.'});return}
      admin.passwordHash=makeHash(String(newPassword));admin.mustChangePassword=false;admin.sessionVersion=(admin.sessionVersion||0)+1;delete admin.password;await saveDb(sql,db);await sql`DELETE FROM nursery_recovery_attempts WHERE ip=${ip}`;send(res,200,{ok:true});return
    }
    if(req.method==='GET'&&route==='state'){
      const session=verifySession(cookieValue(req));const user=session&&db.users.find(u=>u.id===session.id&&(u.sessionVersion||0)===session.version);
      if(!user){send(res,200,{user:null,db:null});return}send(res,200,{user:safeUser(user),db:publicDb(db,user)});return
    }
    const session=verifySession(cookieValue(req));const me=session&&db.users.find(u=>u.id===session.id&&(u.sessionVersion||0)===session.version);
    if(!me){send(res,401,{error:'انتهت الجلسة. سجّل الدخول مرة أخرى.'});return}
    if(req.method==='POST'&&route==='attendance/punch'){
      if(me.role!=='staff'){send(res,403,{error:'تسجيل الحضور متاح من حساب الموظف.'});return}
      const {date}=body(req);if(!/^\d{4}-\d{2}-\d{2}$/.test(String(date||''))){send(res,400,{error:'تاريخ الحضور غير صالح.'});return}
      let record=db.attendance.find(a=>a.userId===me.id&&a.date===date);
      if(!record){record={id:`att-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,userId:me.id,userName:me.name,date,checkIn:now(),checkOut:null};db.attendance.push(record)}else if(!record.checkOut)record.checkOut=now();else{send(res,409,{error:'تم تسجيل الحضور والانصراف اليوم بالفعل.'});return}
      await saveDb(sql,db);send(res,200,{user:safeUser(me),db:publicDb(db,me),attendance:record});return
    }
    if(req.method==='POST'&&route==='tasks/toggle'){
      const {id}=body(req);const task=db.tasks.find(t=>t.id===id);if(!task){send(res,404,{error:'المهمة غير موجودة.'});return}if(me.role!=='admin'&&task.assignee!==me.id){send(res,403,{error:'لا يمكنك تغيير مهمة موظف آخر.'});return}
      task.status=task.status==='done'?'open':'done';await saveDb(sql,db);send(res,200,{user:safeUser(me),db:publicDb(db,me),task});return
    }
    if(req.method==='PUT'&&route==='state'){
      const incoming=body(req);if(!Array.isArray(incoming.users)||!Array.isArray(incoming.tasks)||!Array.isArray(incoming.announcements)||!Array.isArray(incoming.attendance)){send(res,400,{error:'البيانات المرسلة غير مكتملة.'});return}
      if(me.role!=='admin'){
        if(!same(incoming.users,publicDb(db,me).users)||!same(incoming.announcements,db.announcements)||incoming.tasks.length!==db.tasks.length){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}
        const taskMap=new Map(incoming.tasks.map(t=>[t.id,t]));for(const old of db.tasks){const next=taskMap.get(old.id);if(!next){send(res,403,{error:'لا يمكن للموظف حذف المهام أو إضافتها.'});return}const {status:oldStatus,...oldShape}=old,{status:newStatus,...newShape}=next;if(!same(oldShape,newShape)||(old.assignee!==me.id&&oldStatus!==newStatus)||!['open','done'].includes(newStatus)){send(res,403,{error:'لا يمكنك تعديل هذه البيانات.'});return}}
        const attendanceMap=new Map(incoming.attendance.map(a=>[a.id,a]));if(attendanceMap.size!==incoming.attendance.length||incoming.attendance.length<db.attendance.length){send(res,403,{error:'لا يمكن حذف سجلات الحضور أو تكرارها.'});return}
        for(const old of db.attendance){const next=attendanceMap.get(old.id);if(!next){send(res,403,{error:'لا يمكن حذف سجلات الحضور.'});return}if(old.userId!==me.id){if(!same(old,next)){send(res,403,{error:'لا يمكنك تعديل سجل حضور موظف آخر.'});return}}else{const {checkOut:oldOut,...oldShape}=old,{checkOut:newOut,...newShape}=next;if(!same(oldShape,newShape)||(oldOut&&oldOut!==newOut)||(!oldOut&&newOut&&Number.isNaN(Date.parse(newOut)))){send(res,403,{error:'يمكنك تسجيل انصرافك فقط بعد حضورك.'});return}}}
        const previousIds=new Set(db.attendance.map(a=>a.id));for(const record of incoming.attendance){if(previousIds.has(record.id))continue;if(record.userId!==me.id||!/^\d{4}-\d{2}-\d{2}$/.test(String(record.date||''))||!record.checkIn||record.checkOut){send(res,403,{error:'يمكنك تسجيل حضورك فقط.'});return}}
        db.tasks=db.tasks.map(t=>({...t,status:taskMap.get(t.id).status}));db.attendance=incoming.attendance;await saveDb(sql,db);send(res,200,{user:safeUser(me),db:publicDb(db,me)});return
      }
      const prior=new Map(db.users.map(u=>[u.id,u]));const users=incoming.users.map(u=>{const old=prior.get(u.id);if(old)return {...old,name:String(u.name||old.name),username:String(u.username||old.username),role:old.role,title:String(u.title||''),active:u.active!==false,mustChangePassword:old.mustChangePassword===true};if(!u.password||String(u.password).length<8)throw new Error('كلمة مرور الموظف يجب أن تكون ٨ أحرف على الأقل.');return {id:String(u.id),name:String(u.name||'موظف'),username:String(u.username||'').trim(),passwordHash:makeHash(String(u.password)),role:'staff',title:String(u.title||'موظف'),active:u.active!==false,mustChangePassword:false,sessionVersion:0}});
      if(!users.some(u=>u.id===me.id)){send(res,400,{error:'لا يمكن حذف حساب المشرف المسجل.'});return}for(const u of users){if(!u.username){send(res,400,{error:'اسم المستخدم مطلوب.'});return}}if(new Set(users.map(u=>u.username.toLowerCase())).size!==users.length){send(res,400,{error:'اسم المستخدم مستخدم بالفعل.'});return}
      db={users,tasks:incoming.tasks,announcements:incoming.announcements,attendance:incoming.attendance};await saveDb(sql,db);const updated=db.users.find(u=>u.id===me.id);send(res,200,{user:safeUser(updated),db:publicDb(db)});return
    }
    if(req.method==='GET'&&route==='backup'){
      if(me.role!=='admin'){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}send(res,200,{format:'dar-alsalam-backup-v1',exportedAt:now(),db},{'Content-Disposition':'attachment; filename="dar-alsalam-backup.json"'});return
    }
    if(req.method==='POST'&&route==='restore'){
      if(me.role!=='admin'){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}const payload=body(req);const restored=payload.format==='dar-alsalam-backup-v1'?payload.db:payload;
      if(!restored||!Array.isArray(restored.users)||!Array.isArray(restored.tasks)||!Array.isArray(restored.announcements)||!Array.isArray(restored.attendance)){send(res,400,{error:'ملف النسخة الاحتياطية غير صالح.'});return}
      const admins=restored.users.filter(u=>u.role==='admin'&&u.active!==false&&u.passwordHash);if(!admins.some(u=>u.id===me.id)){send(res,400,{error:'النسخة لا تحتوي حساب المشرف الحالي. لم يتم تغيير البيانات.'});return}
      const usernames=restored.users.map(u=>String(u.username||'').toLowerCase());if(usernames.some(x=>!x)||new Set(usernames).size!==usernames.length){send(res,400,{error:'النسخة تحتوي أسماء مستخدمين فارغة أو مكررة.'});return}
      db={users:restored.users.map(u=>u.id===me.id?{...u,sessionVersion:me.sessionVersion||0}:u),tasks:restored.tasks,announcements:restored.announcements,attendance:restored.attendance};await saveDb(sql,db);send(res,200,{user:safeUser(db.users.find(u=>u.id===me.id)),db:publicDb(db)});return
    }
    if(req.method==='POST'&&route==='change-password'){
      const {currentPassword,newPassword}=body(req);const valid=me.passwordHash?checkHash(currentPassword,me.passwordHash):me.password===currentPassword;if(!valid){send(res,400,{error:'كلمة المرور الحالية غير صحيحة.'});return}if(String(newPassword||'').length<8){send(res,400,{error:'كلمة المرور الجديدة يجب أن تكون ٨ أحرف على الأقل.'});return}
      me.passwordHash=makeHash(String(newPassword));delete me.password;me.mustChangePassword=false;await saveDb(sql,db);send(res,200,{user:safeUser(me)});return
    }
    send(res,404,{error:'المسار غير موجود.'});
  }catch(error){console.error('Dar Al-Salam API error:',error?.message||'unknown');send(res,500,{error:error?.message||'حدث خطأ أثناء الاتصال بالخادم.'})}
}
