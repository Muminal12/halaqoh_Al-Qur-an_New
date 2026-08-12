const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const db = new Database(process.env.DB_FILE || './data/halaqoh.db');
db.pragma('journal_mode=WAL');
db.pragma('foreign_keys=ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','ustadz')),
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS halaqoh(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  ustadz_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  halaqoh_id INTEGER REFERENCES halaqoh(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS records(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  ustadz_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  surah TEXT NOT NULL,
  ayat TEXT NOT NULL,
  note TEXT,
  record_date TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);

const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const now = () => new Date().toISOString();
const clean = value => String(value ?? '').trim();
const normalizeUsername = value => clean(value).toLowerCase();

// Admin credentials can be configured safely in Railway Variables.
const ADMIN_USERNAME = normalizeUsername(process.env.ADMIN_USERNAME || 'admin');
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || 'admin123');
const ADMIN_NAME = clean(process.env.ADMIN_NAME || 'Administrator');

const existingAdmin = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
if (!existingAdmin) {
  db.prepare('INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,\'admin\')')
    .run(ADMIN_NAME, ADMIN_USERNAME, hash(ADMIN_PASSWORD));
} else {
  // Keep the single admin account synchronized with Railway Variables.
  db.prepare("UPDATE users SET name=?, username=?, password_hash=?, active=1 WHERE id=? AND role='admin'")
    .run(ADMIN_NAME, ADMIN_USERNAME, hash(ADMIN_PASSWORD), existingAdmin.id);
}

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
function auth(req, res, next) {
  const user = sessions.get(req.cookies.halaqoh);
  if (!user) return res.status(401).json({ error: 'Belum login' });
  req.user = user;
  next();
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Khusus Admin' });
  next();
}
function required(value, label) {
  const v = clean(value);
  if (!v) throw new Error(`${label} wajib diisi`);
  return v;
}

app.get('/api/health', (req, res) => res.json({ ok: true, app: 'Halaqoh Al-Quran' }));

app.post('/api/login', (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u || !u.active || u.password_hash !== hash(password)) {
    return res.status(401).json({ error: 'Username atau password salah' });
  }
  const sid = crypto.randomBytes(32).toString('hex');
  const user = { id: u.id, name: u.name, username: u.username, role: u.role };
  sessions.set(sid, user);
  res.cookie('halaqoh', sid, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 12 });
  res.json({ user });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete(req.cookies.halaqoh);
  res.clearCookie('halaqoh').json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(req.user));

// There is intentionally NO public registration endpoint.
// Only Admin can create Ustadz accounts.
app.get('/api/users', auth, admin, (req, res) => {
  res.json(db.prepare("SELECT id,name,username,active FROM users WHERE role='ustadz' ORDER BY name").all());
});
app.post('/api/users', auth, admin, (req, res) => {
  try {
    const name = required(req.body.name, 'Nama');
    const username = normalizeUsername(required(req.body.username, 'Username'));
    const password = String(req.body.password || '');
    if (password.length < 6) throw new Error('Password minimal 6 karakter');
    const r = db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'ustadz')")
      .run(name, username, hash(password));
    res.json({ id: r.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message.includes('UNIQUE') ? 'Username sudah digunakan' : e.message });
  }
});
app.patch('/api/users/:id', auth, admin, (req, res) => {
  db.prepare("UPDATE users SET active=? WHERE id=? AND role='ustadz'").run(req.body.active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

app.get('/api/halaqoh', auth, (req, res) => {
  if (req.user.role === 'admin') {
    return res.json(db.prepare("SELECT h.*,u.name ustadz_name FROM halaqoh h LEFT JOIN users u ON u.id=h.ustadz_id ORDER BY h.name").all());
  }
  res.json(db.prepare("SELECT h.*,u.name ustadz_name FROM halaqoh h LEFT JOIN users u ON u.id=h.ustadz_id WHERE h.ustadz_id=? ORDER BY h.name").all(req.user.id));
});
app.post('/api/halaqoh', auth, admin, (req, res) => {
  try {
    const name = required(req.body.name, 'Nama kelompok');
    const ustadzId = Number(req.body.ustadz_id) || null;
    if (!ustadzId || !db.prepare("SELECT id FROM users WHERE id=? AND role='ustadz' AND active=1").get(ustadzId)) throw new Error('Pilih Ustadz yang aktif');
    const r = db.prepare('INSERT INTO halaqoh(name,ustadz_id) VALUES(?,?)').run(name, ustadzId);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.patch('/api/halaqoh/:id', auth, admin, (req, res) => {
  try {
    const name = required(req.body.name, 'Nama kelompok');
    const ustadzId = Number(req.body.ustadz_id) || null;
    if (!ustadzId || !db.prepare("SELECT id FROM users WHERE id=? AND role='ustadz' AND active=1").get(ustadzId)) throw new Error('Pilih Ustadz yang aktif');
    db.prepare('UPDATE halaqoh SET name=?,ustadz_id=? WHERE id=?').run(name, ustadzId, req.params.id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/halaqoh/:id', auth, admin, (req, res) => {
  db.prepare('UPDATE students SET halaqoh_id=NULL WHERE halaqoh_id=?').run(req.params.id);
  db.prepare('DELETE FROM halaqoh WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/students', auth, (req, res) => {
  if (req.user.role === 'admin') {
    return res.json(db.prepare("SELECT s.*,h.name halaqoh_name,u.name ustadz_name FROM students s LEFT JOIN halaqoh h ON h.id=s.halaqoh_id LEFT JOIN users u ON u.id=h.ustadz_id WHERE s.active=1 ORDER BY s.name").all());
  }
  res.json(db.prepare("SELECT s.*,h.name halaqoh_name FROM students s JOIN halaqoh h ON h.id=s.halaqoh_id WHERE h.ustadz_id=? AND s.active=1 ORDER BY s.name").all(req.user.id));
});
app.post('/api/students', auth, admin, (req, res) => {
  try {
    const name = required(req.body.name, 'Nama santri');
    const halaqohId = Number(req.body.halaqoh_id) || null;
    const r = db.prepare('INSERT INTO students(name,halaqoh_id) VALUES(?,?)').run(name, halaqohId);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.patch('/api/students/:id', auth, admin, (req, res) => {
  db.prepare('UPDATE students SET halaqoh_id=? WHERE id=?').run(Number(req.body.halaqoh_id) || null, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/students/:id', auth, admin, (req, res) => {
  db.prepare('UPDATE students SET active=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// One-time/intentional reset button. Protected by Admin and requires explicit confirmation text.
app.post('/api/admin/reset-data', auth, admin, (req, res) => {
  if (req.body.confirm !== 'KOSONGKAN SEMUA DATA') return res.status(400).json({ error: 'Konfirmasi tidak sesuai' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM records').run();
    db.prepare('DELETE FROM students').run();
    db.prepare('DELETE FROM halaqoh').run();
  });
  tx();
  res.json({ ok: true });
});

app.post('/api/records', auth, (req, res) => {
  const s = db.prepare("SELECT s.id,h.ustadz_id FROM students s LEFT JOIN halaqoh h ON h.id=s.halaqoh_id WHERE s.id=? AND s.active=1").get(req.body.student_id);
  if (!s || (req.user.role !== 'admin' && s.ustadz_id !== req.user.id)) return res.status(403).json({ error: 'Santri bukan bagian halaqoh Anda' });
  try {
    const type = ['hafalan','murajaah'].includes(req.body.type) ? req.body.type : (() => { throw new Error('Jenis setoran tidak valid'); })();
    const surah = required(req.body.surah, 'Surah');
    const ayat = required(req.body.ayat, 'Ayat');
    const r = db.prepare("INSERT INTO records(student_id,ustadz_id,type,surah,ayat,note,record_date,created_at) VALUES(?,?,?,?,?,?,?,?)")
      .run(s.id, req.user.id, type, surah, ayat, clean(req.body.note), clean(req.body.record_date) || new Date().toISOString().slice(0,10), now());
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

function dates(period, d) {
  const x = new Date((d || new Date().toISOString().slice(0,10)) + 'T00:00:00');
  let a, b;
  if (period === 'weekly') { const n=(x.getDay()+6)%7; a=new Date(x); a.setDate(x.getDate()-n); b=new Date(a); b.setDate(a.getDate()+6); }
  else if (period === 'semester') { const y=x.getFullYear(); a=x.getMonth()<6?new Date(y,0,1):new Date(y,6,1); b=x.getMonth()<6?new Date(y,5,30):new Date(y,11,31); }
  else { a=new Date(x.getFullYear(),x.getMonth(),1); b=new Date(x.getFullYear(),x.getMonth()+1,0); }
  return [a.toISOString().slice(0,10), b.toISOString().slice(0,10)];
}
app.get('/api/recap', auth, (req, res) => {
  const [a,b]=dates(req.query.period||'monthly', req.query.date);
  let q="SELECT s.name,COUNT(CASE WHEN r.type='hafalan' THEN 1 END) hafalan,COUNT(CASE WHEN r.type='murajaah' THEN 1 END) murajaah FROM students s LEFT JOIN records r ON r.student_id=s.id AND r.record_date BETWEEN ? AND ? LEFT JOIN halaqoh h ON h.id=s.halaqoh_id WHERE s.active=1";
  const p=[a,b];
  if(req.user.role==='ustadz'){q+=' AND h.ustadz_id=?';p.push(req.user.id)}
  q+=' GROUP BY s.id ORDER BY s.name';
  res.json({start:a,end:b,rows:db.prepare(q).all(...p)});
});
app.get('/api/records', auth, (req, res) => {
  let q="SELECT r.*,s.name student_name FROM records r JOIN students s ON s.id=r.student_id LEFT JOIN halaqoh h ON h.id=s.halaqoh_id WHERE 1=1",p=[];
  if(req.user.role==='ustadz'){q+=' AND r.ustadz_id=?';p.push(req.user.id)}
  q+=' ORDER BY r.record_date DESC,r.id DESC';
  res.json(db.prepare(q).all(...p));
});

app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
