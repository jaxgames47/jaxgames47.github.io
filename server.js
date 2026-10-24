const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const SECRET = process.env.JWT_SECRET;
const DB_URL = process.env.DATABASE_URL;
if (!SECRET || !DB_URL) {
  console.error('Missing JWT_SECRET or DATABASE_URL environment variable.');
  process.exit(1);
}

// Websites allowed to talk to this server
const ORIGINS = ['https://jaxgames47.github.io'];

const app = express();
app.use(cors({ origin: (o, cb) => cb(null, !o || ORIGINS.includes(o) || /^http:\/\/localhost/.test(o)) }));
app.use(express.json({ limit: '10kb' }));

const pool = new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });
const q = (sql, params) => pool.query(sql, params);
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });

async function init() {
  await q(`create table if not exists users(
    id serial primary key, username text not null, username_lower text unique not null,
    pass_hash text not null, created_at timestamptz default now())`);
  await q(`create table if not exists friendships(
    id serial primary key,
    requester int references users(id) on delete cascade,
    addressee int references users(id) on delete cascade,
    status text not null default 'pending', unique(requester, addressee))`);
  await q(`create table if not exists messages(
    id serial primary key,
    sender int references users(id) on delete cascade,
    recipient int references users(id) on delete cascade,
    text text not null, created_at timestamptz default now())`);
  await q(`create index if not exists msg_pair on messages(sender, recipient, id)`);
}

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error: 'Please sign in again.' }); }
}
const sign = u => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '30d' });
const findUser = async name => (await q('select id, username from users where username_lower=$1', [String(name || '').toLowerCase()])).rows[0];
const areFriends = async (a, b) => (await q(
  `select 1 from friendships where status='accepted' and ((requester=$1 and addressee=$2) or (requester=$2 and addressee=$1))`, [a, b])).rowCount > 0;

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/signup', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Username must be 3-20 letters, numbers or underscores.' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await q('insert into users(username, username_lower, pass_hash) values($1,$2,$3) returning id, username',
      [username, username.toLowerCase(), hash]);
    res.json({ token: sign(r.rows[0]), username: r.rows[0].username });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That username is taken.' });
    throw e;
  }
}));

app.post('/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const r = await q('select * from users where username_lower=$1', [String(username || '').toLowerCase()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(password || ''), u.pass_hash))) return res.status(401).json({ error: 'Wrong username or password.' });
  res.json({ token: sign(u), username: u.username });
}));

app.get('/me', auth, (req, res) => res.json({ username: req.user.username }));

app.get('/friends', auth, wrap(async (req, res) => {
  const me = req.user.id;
  const r = await q(
    `select f.status, f.requester, u.username from friendships f
     join users u on u.id = case when f.requester=$1 then f.addressee else f.requester end
     where f.requester=$1 or f.addressee=$1 order by u.username_lower`, [me]);
  res.json({
    friends: r.rows.filter(x => x.status === 'accepted').map(x => x.username),
    incoming: r.rows.filter(x => x.status === 'pending' && x.requester !== me).map(x => x.username),
    outgoing: r.rows.filter(x => x.status === 'pending' && x.requester === me).map(x => x.username),
  });
}));

app.post('/friends/request', auth, wrap(async (req, res) => {
  const me = req.user.id;
  const other = await findUser(req.body && req.body.username);
  if (!other) return res.status(404).json({ error: 'No player with that username.' });
  if (other.id === me) return res.status(400).json({ error: 'You can’t add yourself.' });
  const ex = (await q(`select * from friendships where (requester=$1 and addressee=$2) or (requester=$2 and addressee=$1)`, [me, other.id])).rows[0];
  if (ex) {
    if (ex.status === 'accepted') return res.status(409).json({ error: 'You’re already friends.' });
    if (ex.requester === other.id) {
      await q(`update friendships set status='accepted' where id=$1`, [ex.id]);
      return res.json({ status: 'accepted' });
    }
    return res.status(409).json({ error: 'Request already sent.' });
  }
  await q('insert into friendships(requester, addressee) values($1,$2)', [me, other.id]);
  res.json({ status: 'pending' });
}));

app.post('/friends/accept', auth, wrap(async (req, res) => {
  const other = await findUser(req.body && req.body.username);
  if (!other) return res.status(404).json({ error: 'No player with that username.' });
  const r = await q(`update friendships set status='accepted' where requester=$1 and addressee=$2 and status='pending'`, [other.id, req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'No request from that player.' });
  res.json({ ok: true });
}));

app.post('/friends/remove', auth, wrap(async (req, res) => {
  const other = await findUser(req.body && req.body.username);
  if (!other) return res.status(404).json({ error: 'No player with that username.' });
  await q(`delete from friendships where (requester=$1 and addressee=$2) or (requester=$2 and addressee=$1)`, [req.user.id, other.id]);
  res.json({ ok: true });
}));

app.get('/chat/:username', auth, wrap(async (req, res) => {
  const other = await findUser(req.params.username);
  if (!other || !(await areFriends(req.user.id, other.id))) return res.status(403).json({ error: 'You can only chat with friends.' });
  const after = parseInt(req.query.after, 10) || 0;
  const r = await q(
    `select m.id, u.username as sender, m.text, m.created_at from messages m join users u on u.id=m.sender
     where ((m.sender=$1 and m.recipient=$2) or (m.sender=$2 and m.recipient=$1)) and m.id>$3
     order by m.id desc limit 50`, [req.user.id, other.id, after]);
  res.json({ messages: r.rows.reverse() });
}));

app.post('/chat/:username', auth, wrap(async (req, res) => {
  const other = await findUser(req.params.username);
  if (!other || !(await areFriends(req.user.id, other.id))) return res.status(403).json({ error: 'You can only chat with friends.' });
  const text = String((req.body && req.body.text) || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'Message is empty.' });
  const r = await q('insert into messages(sender, recipient, text) values($1,$2,$3) returning id', [req.user.id, other.id, text]);
  res.json({ id: r.rows[0].id });
}));

const PORT = process.env.PORT || 3000;
init().then(() => app.listen(PORT, () => console.log('Server running on', PORT)))
  .catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
