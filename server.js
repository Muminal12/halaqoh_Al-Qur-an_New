require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_IN_PRODUCTION';
const COOKIE = 'halaqoh_session';

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(path.join(__dirname, 'data', 'halaqoh.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'ustadz' CHECK(role IN ('admin','ustadz')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, name),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('Setoran','Murajaah')),
  surah TEXT NOT NULL,
  ayah TEXT NOT NULL,
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
);
`);
try { db.exec("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1"); } catch(e) {}

const defaultStudents = ['Rizki','Amri','Haikal','Salman','Arkan','Daniyal',"Ja'far",'Ahmad','Fahmi','Fauzan','Ilham','Rafi','Yusuf'];
function ensureAdmin(){
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin12345';
  const name = process.env.ADMIN_NAME || 'Administrator';
  const found = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if(!found){
    const hash = bcrypt.hashSync(password, 12);
    db.prepare('INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,?)').run(name,username,hash,'admin');
  }
}
ensureAdmin();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit:'100kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,'public')));

function sign(user){ return jwt.sign({id:user.id,username:user.username,role:user.role,name:user.name}, JWT_SECRET, {expiresIn:'7d'}); }
function auth(req,res,next){
  const token = req.cookies[COOKIE];
  if(!token) return res.status(401).json({error:'Belum login'});
  try{ req.user=jwt.verify(token,JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({error:'Sesi tidak valid atau sudah berakhir'}); }
}
function adminOnly(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'Khusus admin'}); next(); }
function safeUser(u){ return {id:u.id,name:u.name,username:u.username,role:u.role,active:u.active!==0}; }

app.post('/api/auth/register', (req,res)=>{
  const name=String(req.body.name||'').trim();
  const username=String(req.body.username||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  if(name.length<2 || !/^[a-z0-9_.-]{3,30}$/.test(username) || password.length<6)
    return res.status(400).json({error:'Nama, username, atau password tidak memenuhi aturan.'});
  if(db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({error:'Username sudah digunakan.'});
  const hash=bcrypt.hashSync(password,12);
  const info=db.prepare('INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,?)').run(name,username,hash,'ustadz');
  const user=db.prepare('SELECT id,name,username,role FROM users WHERE id=?').get(info.lastInsertRowid);
  const insert=db.prepare('INSERT INTO students(user_id,name) VALUES(?,?)');
  const tx=db.transaction(()=>defaultStudents.forEach(s=>insert.run(user.id,s))); tx();
  res.status(201).json({user:safeUser(user)});
});

app.post('/api/auth/login',(req,res)=>{
  const username=String(req.body.username||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  const user=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!user || !user.active || !bcrypt.compareSync(password,user.password_hash)) return res.status(401).json({error:'Username atau password salah.'});
  const token=sign(user);
  res.cookie(COOKIE,token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*24*60*60*1000});
  res.json({user:safeUser(user)});
});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie(COOKIE);res.json({ok:true});});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:req.user}));

app.get('/api/dashboard',auth,(req,res)=>{
  const students=db.prepare('SELECT id,name FROM students WHERE user_id=? ORDER BY name').all(req.user.id);
  const records=db.prepare(`SELECT r.id,r.date,r.type,r.surah,r.ayah,r.note,s.name student FROM records r JOIN students s ON s.id=r.student_id WHERE r.user_id=? ORDER BY r.id DESC`).all(req.user.id);
  const today=new Date().toISOString().slice(0,10);
  const weekAgo=new Date(Date.now()-7*864e5).toISOString().slice(0,10);
  res.json({students,records,stats:{students:students.length,today:records.filter(r=>r.date===today&&r.type==='Setoran').length,murajaah:records.filter(r=>r.date===today&&r.type==='Murajaah').length,week:records.filter(r=>r.date>=weekAgo).length}});
});

app.post('/api/students',auth,(req,res)=>{
  const name=String(req.body.name||'').trim();
  if(name.length<2) return res.status(400).json({error:'Nama santri tidak valid.'});
  try{const x=db.prepare('INSERT INTO students(user_id,name) VALUES(?,?)').run(req.user.id,name);res.status(201).json(db.prepare('SELECT id,name FROM students WHERE id=?').get(x.lastInsertRowid));}
  catch(e){res.status(409).json({error:'Santri sudah ada.'});}
});
app.delete('/api/students/:id',auth,(req,res)=>{
  const id=Number(req.params.id);
  const x=db.prepare('DELETE FROM students WHERE id=? AND user_id=?').run(id,req.user.id);
  if(!x.changes) return res.status(404).json({error:'Santri tidak ditemukan.'});
  res.json({ok:true});
});
app.post('/api/records',auth,(req,res)=>{
  const studentId=Number(req.body.studentId); const date=String(req.body.date||'');
  const type=req.body.type==='Murajaah'?'Murajaah':'Setoran'; const surah=String(req.body.surah||'').trim(); const ayah=String(req.body.ayah||'').trim(); const note=String(req.body.note||'').trim();
  const student=db.prepare('SELECT id,name FROM students WHERE id=? AND user_id=?').get(studentId,req.user.id);
  if(!student || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !surah || !ayah) return res.status(400).json({error:'Data setoran belum lengkap.'});
  const x=db.prepare('INSERT INTO records(user_id,student_id,date,type,surah,ayah,note) VALUES(?,?,?,?,?,?,?)').run(req.user.id,studentId,date,type,surah,ayah,note);
  res.status(201).json(db.prepare(`SELECT r.id,r.date,r.type,r.surah,r.ayah,r.note,s.name student FROM records r JOIN students s ON s.id=r.student_id WHERE r.id=?`).get(x.lastInsertRowid));
});
app.delete('/api/records/:id',auth,(req,res)=>{const x=db.prepare('DELETE FROM records WHERE id=? AND user_id=?').run(Number(req.params.id),req.user.id); if(!x.changes)return res.status(404).json({error:'Setoran tidak ditemukan.'});res.json({ok:true});});

app.post('/api/account/reset',auth,(req,res)=>{
  const tx=db.transaction(()=>{
    db.prepare('DELETE FROM records WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM students WHERE user_id=?').run(req.user.id);
    const ins=db.prepare('INSERT INTO students(user_id,name) VALUES(?,?)');
    defaultStudents.forEach(s=>ins.run(req.user.id,s));
  });
  tx(); res.json({ok:true});
});

app.get('/api/admin/users',auth,adminOnly,(req,res)=>{
  const users=db.prepare(`SELECT u.id,u.name,u.username,u.role,u.active,u.created_at,
    (SELECT COUNT(*) FROM students s WHERE s.user_id=u.id) student_count,
    (SELECT COUNT(*) FROM records r WHERE r.user_id=u.id) record_count,
    (SELECT COUNT(*) FROM records r WHERE r.user_id=u.id AND r.type='Murajaah') murajaah_count
    FROM users u ORDER BY CASE WHEN u.role='admin' THEN 0 ELSE 1 END,u.id DESC`).all();
  const totals=db.prepare(`SELECT (SELECT COUNT(*) FROM users WHERE role='ustadz') ustadz_count, (SELECT COUNT(*) FROM students) student_count, (SELECT COUNT(*) FROM records) record_count`).get();
  res.json({users,totals});
});
app.post('/api/admin/users',auth,adminOnly,(req,res)=>{
  const name=String(req.body.name||'').trim(),username=String(req.body.username||'').trim().toLowerCase(),password=String(req.body.password||'');
  if(name.length<2 || !/^[a-z0-9_.-]{3,30}$/.test(username) || password.length<6)return res.status(400).json({error:'Data akun tidak valid.'});
  try{const x=db.prepare('INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,?)').run(name,username,bcrypt.hashSync(password,12),'ustadz'); const u=db.prepare('SELECT id,name,username,role FROM users WHERE id=?').get(x.lastInsertRowid); const insert=db.prepare('INSERT INTO students(user_id,name) VALUES(?,?)'); const tx=db.transaction(()=>defaultStudents.forEach(s=>insert.run(u.id,s)));tx();res.status(201).json({user:safeUser(u)});}catch(e){res.status(409).json({error:'Username sudah digunakan.'});}
});

app.patch('/api/admin/users/:id/status',auth,adminOnly,(req,res)=>{
  const id=Number(req.params.id);
  const user=db.prepare('SELECT id,role,active FROM users WHERE id=?').get(id);
  if(!user) return res.status(404).json({error:'Akun tidak ditemukan.'});
  if(user.role==='admin') return res.status(400).json({error:'Akun admin utama tidak dapat dinonaktifkan.'});
  const active=req.body.active ? 1 : 0;
  db.prepare('UPDATE users SET active=? WHERE id=?').run(active,id);
  res.json({ok:true,active:!!active});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`Halaqoh Al Qur'an running on http://localhost:${PORT}`));
