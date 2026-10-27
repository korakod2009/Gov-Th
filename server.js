require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const SQLiteStore = SQLiteStoreFactory(session);
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const secret = process.env.SESSION_SECRET || '';
if (secret.length < 32) {
  console.error('SESSION_SECRET must be at least 32 characters. Copy .env.example to .env and set a strong secret.');
  process.exit(1);
}

const db = new Database(path.join(__dirname, 'election.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    number INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    party TEXT NOT NULL,
    slogan TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '#2563eb',
    active INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY,
    roblox_user_id TEXT NOT NULL UNIQUE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    event TEXT NOT NULL,
    actor_id TEXT,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
`);
const candidateCount = db.prepare('SELECT COUNT(*) AS n FROM candidates').get().n;
if (!candidateCount) {
  const insert = db.prepare('INSERT INTO candidates (number,name,party,slogan,color) VALUES (?,?,?,?,?)');
  const seed = db.transaction(() => {
    insert.run(1, 'นายธนภัทร วัฒนากุล', 'พรรคก้าวไกล', 'เปลี่ยนวันนี้ เพื่ออนาคตที่ดีกว่า', '#2563eb');
    insert.run(2, 'นายศรัณย์ เรืองวิทย์', 'พรรคพลังไทย', 'สร้างชาติ สร้างโอกาส ให้ทุกคน', '#dc2626');
    insert.run(3, 'นายกิตติพงศ์ สุขสวัสดิ์', 'พรรคประชาธิปไตยใหม่', 'คนรุ่นใหม่ สร้างการเปลี่ยนแปลง', '#059669');
    insert.run(4, 'นายอัครินทร์ ชัยวัฒน์', 'พรรครวมพลังชาติ', 'รวมพลัง สร้างชาติ ให้เติบโต', '#d49a19');
  });
  seed();
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // Add a strict CSP before production deployment.
app.use(express.json({ limit: '10kb' }));
app.use(session({
  name: 'rp-election.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'strict', secure: isProduction, maxAge: 1000 * 60 * 60 * 4 }
}));
app.use('/api/', rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const audit = db.prepare('INSERT INTO audit_log(event,actor_id,detail) VALUES (?,?,?)');
const adminIds = new Set((process.env.ADMIN_ROBLOX_IDS || '').split(',').map(s => s.trim()).filter(Boolean));
const requireLogin = (req, res, next) => {
  if (!req.session.user || !/^\d{1,20}$/.test(String(req.session.user.robloxUserId || ''))) {
    return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ Roblox ที่ผ่านการยืนยันตัวตนก่อน' });
  }
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.user || !adminIds.has(String(req.session.user.robloxUserId))) return res.status(403).json({ error: 'เฉพาะผู้ดูแลระบบที่ได้รับอนุญาต' });
  next();
};

app.get('/api/status', (req, res) => {
  res.json({
    electionOpen: process.env.ELECTION_OPEN === 'true',
    authenticated: Boolean(req.session.user),
    user: req.session.user ? { displayName: req.session.user.displayName || 'ผู้เล่น', robloxUserId: req.session.user.robloxUserId } : null,
    authReady: false,
    message: 'ระบบลงคะแนนจะยังไม่เปิดจนกว่าจะติดตั้ง Roblox OAuth/OIDC ที่ตรวจสอบตัวตนฝั่งเซิร์ฟเวอร์เรียบร้อย'
  });
});

app.get('/api/candidates', (req, res) => {
  const rows = db.prepare('SELECT id, number, name, party, slogan, color FROM candidates WHERE active = 1 ORDER BY number').all();
  res.json(rows);
});

app.get('/api/results', (req, res) => {
  const rows = db.prepare(`SELECT c.id, c.number, c.name, c.party, COUNT(v.id) AS votes
    FROM candidates c LEFT JOIN votes v ON v.candidate_id = c.id
    WHERE c.active = 1 GROUP BY c.id ORDER BY c.number`).all();
  res.json({ results: rows, totalVotes: rows.reduce((sum, row) => sum + row.votes, 0) });
});

// Intentionally fail closed: never trust a Roblox ID supplied by the browser.
// Implement verified Roblox OAuth/OIDC callback and set req.session.user only after server-side validation.
app.get('/auth/roblox', (_req, res) => res.status(503).send('ยังไม่ได้ตั้งค่า Roblox OAuth/OIDC อย่างปลอดภัย จึงปิดการเข้าสู่ระบบไว้'));
app.post('/api/vote', requireLogin, (req, res) => {
  if (process.env.ELECTION_OPEN !== 'true') return res.status(403).json({ error: 'ขณะนี้ยังไม่เปิดลงคะแนน' });
  const candidateId = Number(req.body.candidateId);
  if (!Number.isSafeInteger(candidateId)) return res.status(400).json({ error: 'ข้อมูลผู้สมัครไม่ถูกต้อง' });
  const candidate = db.prepare('SELECT id FROM candidates WHERE id = ? AND active = 1').get(candidateId);
  if (!candidate) return res.status(400).json({ error: 'ไม่พบผู้สมัครที่เลือก' });
  try {
    // UNIQUE(roblox_user_id) is the final server-side guarantee against duplicate votes.
    const castVote = db.transaction(() => {
      db.prepare('INSERT INTO votes (roblox_user_id, candidate_id) VALUES (?, ?)')
        .run(String(req.session.user.robloxUserId), candidateId);
      audit.run('vote_cast', String(req.session.user.robloxUserId), `candidate_id=${candidateId}`);
    });
    castVote();
    res.json({ ok: true, message: 'บันทึกคะแนนเรียบร้อยแล้ว ไม่สามารถลงคะแนนซ้ำได้' });
  } catch (err) {
    if (String(err.code || '').includes('SQLITE_CONSTRAINT_UNIQUE')) {
      audit.run('duplicate_vote_blocked', String(req.session.user.robloxUserId), 'duplicate vote attempt');
      return res.status(409).json({ error: 'บัญชีนี้ลงคะแนนไปแล้ว ระบบไม่อนุญาตให้ลงคะแนนซ้ำ' });
    }
    console.error(err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในการบันทึกคะแนน' });
  }
});

app.get('/api/admin/audit', requireLogin, requireAdmin, (_req, res) => {
  res.json(db.prepare('SELECT event, actor_id, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 200').all());
});

app.listen(port, () => console.log(`Roblox RP Election starter running at http://localhost:${port}`));
