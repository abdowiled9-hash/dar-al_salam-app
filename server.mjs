import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import {fileURLToPath} from 'node:url';

const root=path.dirname(fileURLToPath(import.meta.url));
const dataDir=path.resolve(process.env.DATA_DIR||root);
fs.mkdirSync(dataDir,{recursive:true});
const dataPath=path.join(dataDir,'data.json');
const sessions=new Map();
const recoveryAttempts=new Map();
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8'};
const now=()=>new Date().toISOString();
const makeHash=password=>{const salt=crypto.randomBytes(16).toString('hex');return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`};
const checkHash=(password,stored)=>{if(!stored)return false;const [salt,hex]=stored.split(':');if(!salt||!hex)return false;const actual=crypto.scryptSync(password,salt,64);const expected=Buffer.from(hex,'hex');return actual.length===expected.length&&crypto.timingSafeEqual(actual,expected)};
function loadDb(){if(fs.existsSync(dataPath)){try{return JSON.parse(fs.readFileSync(dataPath,'utf8'))}catch{}}
 const username=process.env.INITIAL_ADMIN_USERNAME||'admin',password=process.env.INITIAL_ADMIN_PASSWORD||(process.env.NODE_ENV==='production'?'':'1234');if(!password)throw new Error('INITIAL_ADMIN_PASSWORD must be set before first production startup.');
 const db={users:[{id:'u-admin',name:process.env.INITIAL_ADMIN_NAME||'مشرف دار السلام',username,passwordHash:makeHash(password),role:'admin',title:'مشرف الحضانة',active:true,mustChangePassword:true}],tasks:[],announcements:[],attendance:[]};writeDb(db);return db}
let db=loadDb();
function writeDb(value){fs.writeFileSync(dataPath,JSON.stringify(value,null,2),'utf8')}
function publicDb(user=null){const staff=user?.role==='staff';return {...db,users:(staff?[user]:db.users).map(({passwordHash,password,...u})=>u),tasks:staff?db.tasks.filter(t=>t.assignee===user.id):db.tasks,attendance:staff?db.attendance.filter(a=>a.userId===user.id):db.attendance}}
function userFor(req){const cookies=Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)));return sessions.get(cookies.dar_session)||null}
function send(res,status,body,headers={}){const payload=typeof body==='string'?body:JSON.stringify(body);res.writeHead(status,{'Content-Type':typeof body==='string'?'text/plain; charset=utf-8':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(payload)}
function readBody(req){return new Promise((resolve,reject)=>{let text='';req.on('data',chunk=>{text+=chunk;if(text.length>2_000_000){reject(new Error('الطلب كبير جدًا'));req.destroy()}});req.on('end',()=>{try{resolve(text?JSON.parse(text):{})}catch{reject(new Error('بيانات الطلب غير صالحة'))}});req.on('error',reject)})}
function safeUser(user){if(!user)return null;const {passwordHash,password,...safe}=user;return safe}
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');
 try{
  if(req.method==='GET'&&url.pathname==='/healthz'){send(res,200,'ok');return}
  if(req.method==='POST'&&url.pathname==='/api/login'){
   const {username,password,role}=await readBody(req);const user=db.users.find(u=>u.username.toLowerCase()===String(username||'').trim().toLowerCase());
   if(!user||!user.active||user.role!==role||!(user.passwordHash?checkHash(password,user.passwordHash):user.password===password)){send(res,401,{error:'بيانات الدخول غير صحيحة أو الحساب غير نشط.'});return}
   if(user.password){user.passwordHash=makeHash(user.password);delete user.password}
   const token=crypto.randomBytes(32).toString('hex');sessions.set(token,user.id);const secure=process.env.NODE_ENV==='production'?'; Secure':'';send(res,200,{user:safeUser(user),db:publicDb(user)},{'Set-Cookie':`dar_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`});return
  }
  if(req.method==='POST'&&url.pathname==='/api/admin/recover-password'){
   const ip=req.headers['x-forwarded-for']?.split(',')[0]?.trim()||req.socket.remoteAddress||'unknown';const attempt=recoveryAttempts.get(ip)||{count:0,until:0};if(attempt.until>Date.now()){send(res,429,{error:'محاولات كثيرة. حاول بعد ١٥ دقيقة.'});return}if(attempt.until)recoveryAttempts.delete(ip);
   const {username,recoveryCode,newPassword}=await readBody(req);const configured=process.env.ADMIN_RECOVERY_CODE;const submitted=String(recoveryCode||'');const submittedBytes=Buffer.from(submitted),configuredBytes=Buffer.from(configured||'');const validCode=Boolean(configured)&&submittedBytes.length===configuredBytes.length&&crypto.timingSafeEqual(submittedBytes,configuredBytes);const admin=db.users.find(u=>u.role==='admin'&&u.username.toLowerCase()===String(username||'').trim().toLowerCase()&&u.active!==false);
   if(!configured){send(res,503,{error:'استعادة كلمة المرور غير مفعّلة. يجب على مالك الاستضافة ضبط رمز استعادة للمشرف.'});return}
   if(!admin||!validCode){attempt.count++;if(attempt.count>=5){attempt.until=Date.now()+15*60*1000;attempt.count=0}recoveryAttempts.set(ip,attempt);send(res,400,{error:'اسم المشرف أو رمز الاستعادة غير صحيح.'});return}
   if(String(newPassword||'').length<8){send(res,400,{error:'كلمة المرور الجديدة يجب أن تكون ٨ أحرف على الأقل.'});return}
   admin.passwordHash=makeHash(String(newPassword));delete admin.password;admin.mustChangePassword=false;writeDb(db);for(const [token,userId] of sessions)if(userId===admin.id)sessions.delete(token);recoveryAttempts.delete(ip);send(res,200,{ok:true});return
  }
  if(req.method==='POST'&&url.pathname==='/api/logout'){const token=(req.headers.cookie||'').match(/(?:^|;\s*)dar_session=([^;]+)/)?.[1];if(token)sessions.delete(decodeURIComponent(token));const secure=process.env.NODE_ENV==='production'?'; Secure':'';send(res,200,{ok:true},{'Set-Cookie':`dar_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`});return}
  if(url.pathname.startsWith('/api/')){
   const active=userFor(req);const me=active?db.users.find(u=>u.id===active):null;
   if(req.method==='GET'&&url.pathname==='/api/state'){if(!me){send(res,200,{user:null,db:null});return}send(res,200,{user:safeUser(me),db:publicDb(me)});return}
   if(!me){send(res,401,{error:'انتهت الجلسة. سجّل الدخول مرة أخرى.'});return}
   if(req.method==='POST'&&url.pathname==='/api/attendance/punch'){
    if(me.role!=='staff'){send(res,403,{error:'تسجيل الحضور متاح من حساب الموظف.'});return}
    const {date}=await readBody(req);if(!/^\d{4}-\d{2}-\d{2}$/.test(String(date||''))){send(res,400,{error:'تاريخ الحضور غير صالح.'});return}
    let record=db.attendance.find(a=>a.userId===me.id&&a.date===date);
    if(!record){record={id:`att-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,userId:me.id,userName:me.name,date,checkIn:now(),checkOut:null};db.attendance.push(record)}
    else if(!record.checkOut)record.checkOut=now();
    else{send(res,409,{error:'تم تسجيل الحضور والانصراف اليوم بالفعل.'});return}
    writeDb(db);send(res,200,{user:safeUser(me),db:publicDb(me),attendance:record});return
   }
   if(req.method==='POST'&&url.pathname==='/api/tasks/toggle'){
    const {id}=await readBody(req);const task=db.tasks.find(t=>t.id===id);if(!task){send(res,404,{error:'المهمة غير موجودة.'});return}
    if(me.role!=='admin'&&task.assignee!==me.id){send(res,403,{error:'لا يمكنك تغيير مهمة موظف آخر.'});return}
    task.status=task.status==='done'?'open':'done';writeDb(db);send(res,200,{user:safeUser(me),db:publicDb(me),task});return
   }
   if(req.method==='PUT'&&url.pathname==='/api/state'){
    const incoming=await readBody(req);if(!Array.isArray(incoming.users)||!Array.isArray(incoming.tasks)||!Array.isArray(incoming.announcements)||!Array.isArray(incoming.attendance)){send(res,400,{error:'البيانات المرسلة غير مكتملة.'});return}
    if(me.role!=='admin'){
     const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
     if(!same(incoming.users,publicDb(me).users)||!same(incoming.announcements,db.announcements)||incoming.tasks.length!==db.tasks.length){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}
     const taskMap=new Map(incoming.tasks.map(t=>[t.id,t]));
     for(const old of db.tasks){const next=taskMap.get(old.id);if(!next){send(res,403,{error:'لا يمكن للموظف حذف المهام أو إضافتها.'});return}const {status:oldStatus,...oldShape}=old,{status:newStatus,...newShape}=next;if(!same(oldShape,newShape)||(old.assignee!==me.id&&oldStatus!==newStatus)||!['open','done'].includes(newStatus)){send(res,403,{error:'لا يمكنك تعديل هذه البيانات.'});return}}
     const attendanceMap=new Map(incoming.attendance.map(a=>[a.id,a]));if(attendanceMap.size!==incoming.attendance.length||incoming.attendance.length<db.attendance.length){send(res,403,{error:'لا يمكن حذف سجلات الحضور أو تكرارها.'});return}
     for(const old of db.attendance){const next=attendanceMap.get(old.id);if(!next){send(res,403,{error:'لا يمكن حذف سجلات الحضور.'});return}if(old.userId!==me.id){if(!same(old,next)){send(res,403,{error:'لا يمكنك تعديل سجل حضور موظف آخر.'});return}}else{const {checkOut:oldOut,...oldShape}=old,{checkOut:newOut,...newShape}=next;if(!same(oldShape,newShape)||(oldOut&&oldOut!==newOut)||(!oldOut&&newOut&&Number.isNaN(Date.parse(newOut)))){send(res,403,{error:'يمكنك تسجيل انصرافك فقط بعد حضورك.'});return}}}
     const previousIds=new Set(db.attendance.map(a=>a.id));for(const record of incoming.attendance){if(previousIds.has(record.id))continue;if(record.userId!==me.id||!/^\d{4}-\d{2}-\d{2}$/.test(String(record.date||''))||!record.checkIn||record.checkOut){send(res,403,{error:'يمكنك تسجيل حضورك فقط.'});return}}
     db.tasks=db.tasks.map(t=>({...t,status:taskMap.get(t.id).status}));db.attendance=incoming.attendance;writeDb(db);send(res,200,{user:safeUser(me),db:publicDb(me)});return
    }
    const prior=new Map(db.users.map(u=>[u.id,u]));const users=incoming.users.map(u=>{const old=prior.get(u.id);if(old)return {...old,name:String(u.name||old.name),username:String(u.username||old.username),role:old.role,title:String(u.title||''),active:u.active!==false,mustChangePassword:old.mustChangePassword===true};if(!u.password||String(u.password).length<8)throw new Error('كلمة مرور الموظف يجب أن تكون ٨ أحرف على الأقل.');return {id:String(u.id),name:String(u.name||'موظف'),username:String(u.username||'').trim(),passwordHash:makeHash(String(u.password)),role:'staff',title:String(u.title||'موظف'),active:u.active!==false,mustChangePassword:false}});
    if(!users.some(u=>u.id===me.id)){send(res,400,{error:'لا يمكن حذف حساب المشرف المسجل.'});return}
    for(const u of users){if(!u.username){send(res,400,{error:'اسم المستخدم مطلوب.'});return}}
    if(new Set(users.map(u=>u.username.toLowerCase())).size!==users.length){send(res,400,{error:'اسم المستخدم مستخدم بالفعل.'});return}
    db={users,tasks:incoming.tasks,announcements:incoming.announcements,attendance:incoming.attendance};writeDb(db);send(res,200,{user:safeUser(db.users.find(u=>u.id===me.id)),db:publicDb()});return
   }
   if(req.method==='GET'&&url.pathname==='/api/backup'){
    if(me.role!=='admin'){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}
    send(res,200,{format:'dar-alsalam-backup-v1',exportedAt:now(),db},{'Content-Disposition':'attachment; filename="dar-alsalam-backup.json"'});return
   }
   if(req.method==='POST'&&url.pathname==='/api/restore'){
    if(me.role!=='admin'){send(res,403,{error:'هذه الخاصية متاحة للمشرف فقط.'});return}
    const payload=await readBody(req);const restored=payload.format==='dar-alsalam-backup-v1'?payload.db:payload;
    if(!restored||!Array.isArray(restored.users)||!Array.isArray(restored.tasks)||!Array.isArray(restored.announcements)||!Array.isArray(restored.attendance)){send(res,400,{error:'ملف النسخة الاحتياطية غير صالح.'});return}
    const admins=restored.users.filter(u=>u.role==='admin'&&u.active!==false&&u.passwordHash);if(!admins.some(u=>u.id===me.id)){send(res,400,{error:'النسخة لا تحتوي حساب المشرف الحالي. لم يتم تغيير البيانات.'});return}
    const usernames=restored.users.map(u=>String(u.username||'').toLowerCase());if(usernames.some(x=>!x)||new Set(usernames).size!==usernames.length){send(res,400,{error:'النسخة تحتوي أسماء مستخدمين فارغة أو مكررة.'});return}
    db={users:restored.users,tasks:restored.tasks,announcements:restored.announcements,attendance:restored.attendance};writeDb(db);send(res,200,{user:safeUser(db.users.find(u=>u.id===me.id)),db:publicDb()});return
   }
   if(req.method==='POST'&&url.pathname==='/api/change-password'){
    const {currentPassword,newPassword}=await readBody(req);const valid=me.passwordHash?checkHash(currentPassword,me.passwordHash):me.password===currentPassword;if(!valid){send(res,400,{error:'كلمة المرور الحالية غير صحيحة.'});return}if(String(newPassword||'').length<8){send(res,400,{error:'كلمة المرور الجديدة يجب أن تكون ٨ أحرف على الأقل.'});return}me.passwordHash=makeHash(newPassword);delete me.password;me.mustChangePassword=false;writeDb(db);send(res,200,{user:safeUser(me)});return
   }
   send(res,404,{error:'المسار غير موجود.'});return
  }
  let target=decodeURIComponent(url.pathname);if(target==='/')target='/index.html';const file=path.resolve(root,'.'+target);if(!file.startsWith(root+path.sep)){send(res,403,'Forbidden');return}if(!fs.existsSync(file)||!fs.statSync(file).isFile()){send(res,404,'Not found');return}res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache'});fs.createReadStream(file).pipe(res);
 }catch(error){send(res,400,{error:error.message||'حدث خطأ أثناء حفظ البيانات.'})}
});
const preferredPort=Number(process.env.PORT)||8080;
function listen(port){server.once('error',error=>{if(error.code==='EADDRINUSE'&&!process.env.PORT){console.log(`Port ${port} is busy; trying ${port+1}.`);listen(port+1);return}console.error(error.message);process.exitCode=1});server.listen(port,'0.0.0.0',()=>{console.log(`Dar Al-Salam is running at http://localhost:${port}`);for(const entry of Object.values(os.networkInterfaces()).flat().filter(x=>x&&x.family==='IPv4'&&!x.internal))console.log(`Phone address: http://${entry.address}:${port}`);console.log('Keep this window open while using the app.');})}
listen(preferredPort);
