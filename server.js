'use strict';
// Shitpost — anonymous text board for Latvian students.
// Zero dependencies: Node >= 22.13 (built-in node:sqlite).
//
// Privacy design:
//  * No accounts, no names, no tripcodes, no cookies for posters.
//  * IP addresses are NEVER written to disk or logs. For spam limits and bans
//    the server keeps a "poster tag" = HMAC(ip, secret). The secret lives only
//    in RAM and is replaced every TAG_ROTATE_DAYS (and on every restart), so
//    after rotation nobody — including the admin — can link a tag back to an IP.
//  * Tags are wiped from old posts once they can no longer be used for bans.
//  * No request logging, no analytics, no third-party scripts/fonts, no JS at all.

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

// ---------- config ----------
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const MOD_PASSWORD = process.env.MOD_PASSWORD || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // set when behind nginx/caddy
const SECURE_COOKIES = process.env.SECURE_COOKIES === '1';
const SITE_NAME = 'Shitpost';
const TAG_ROTATE_DAYS = 7;
const THREADS_PER_PAGE = 10;
const MAX_PAGES = 10;
const BUMP_LIMIT = 300;
const REPLY_LIMIT = 500;
const MAX_BODY = 2000;
const MAX_SUBJECT = 80;
const THREAD_COOLDOWN = 60_000;
const REPLY_COOLDOWN = 15_000;

// ---------- Tor onion service ----------
// Tor forwards .onion traffic to a SEPARATE local port (ONION_PORT). Everything arriving
// there is treated as a Tor visitor. Tor visitors have no IP we could see, so they all share
// one identity: bans can't target them, and posting limits are shared by all Tor users
// together (plus a CAPTCHA on every post).
const ONION_PORT = process.env.ONION_PORT ? Number(process.env.ONION_PORT) : 0; // 0 = disabled
const ONION_ADDRESS = (process.env.ONION_ADDRESS || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
const CAPTCHA_ALL = process.env.CAPTCHA_ALL === '1'; // also require CAPTCHA on the normal site
const TOR_THREADS_PER_10MIN = Number(process.env.TOR_THREADS_PER_10MIN || 5);
const TOR_REPLIES_PER_MIN = Number(process.env.TOR_REPLIES_PER_MIN || 12);

const BOARDS = {
  b:     { title: 'Viss kas', desc: 'Jebkas, kas neder citur' },
  skola: { title: 'Skola', desc: 'Skolas dzīve, stundas, starpbrīži' },
  eks:   { title: 'Eksāmeni un mācības', desc: 'CE, mājasdarbi, palīdzība' },
  sp:    { title: 'Spēles', desc: 'Datorspēles un konsoles' },
  muz:   { title: 'Mūzika', desc: 'Ko tu klausies?' },
  tech:  { title: 'Tehnoloģijas', desc: 'Datori, telefoni, programmēšana' },
  ats:   { title: 'Attiecības un dzīve', desc: 'Padomi, problēmas, sajūtas' },
};

// ---------- db ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'board.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    board TEXT NOT NULL,
    thread INTEGER,              -- NULL = this post is a thread (OP)
    subject TEXT,
    body TEXT NOT NULL,
    created INTEGER NOT NULL,
    bumped INTEGER NOT NULL,
    tag TEXT,                    -- rotating HMAC, wiped after rotation
    deleted INTEGER NOT NULL DEFAULT 0,
    locked INTEGER NOT NULL DEFAULT 0,
    sticky INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS posts_board ON posts(board, thread, deleted, sticky, bumped);
  CREATE INDEX IF NOT EXISTS posts_thread ON posts(thread, id);
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS bans (
    tag TEXT PRIMARY KEY,
    reason TEXT,
    expires INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    body TEXT NOT NULL,
    created INTEGER NOT NULL
  );
`);

const q = {
  insert: db.prepare('INSERT INTO posts (board, thread, subject, body, created, bumped, tag) VALUES (?,?,?,?,?,?,?)'),
  bump: db.prepare('UPDATE posts SET bumped = ? WHERE id = ?'),
  get: db.prepare('SELECT * FROM posts WHERE id = ?'),
  threads: db.prepare('SELECT * FROM posts WHERE board = ? AND thread IS NULL AND deleted = 0 ORDER BY sticky DESC, bumped DESC LIMIT ? OFFSET ?'),
  threadCount: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE board = ? AND thread IS NULL AND deleted = 0'),
  replies: db.prepare('SELECT * FROM posts WHERE thread = ? AND deleted = 0 ORDER BY id'),
  lastReplies: db.prepare('SELECT * FROM (SELECT * FROM posts WHERE thread = ? AND deleted = 0 ORDER BY id DESC LIMIT 3) ORDER BY id'),
  replyCount: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE thread = ? AND deleted = 0'),
  oldThreads: db.prepare('SELECT id FROM posts WHERE board = ? AND thread IS NULL AND deleted = 0 AND sticky = 0 ORDER BY bumped DESC LIMIT -1 OFFSET ?'),
  del: db.prepare('UPDATE posts SET deleted = 1 WHERE id = ? OR thread = ?'),
  setFlag: db.prepare('UPDATE posts SET locked = ?, sticky = ? WHERE id = ?'),
  report: db.prepare('INSERT INTO reports (post, reason, created) VALUES (?,?,?)'),
  reports: db.prepare(`SELECT r.id AS rid, r.reason, r.created AS rcreated, p.* FROM reports r JOIN posts p ON p.id = r.post
                       WHERE p.deleted = 0 ORDER BY r.id DESC LIMIT 200`),
  clearReports: db.prepare('DELETE FROM reports WHERE post = ?'),
  recent: db.prepare('SELECT * FROM posts WHERE deleted = 0 ORDER BY id DESC LIMIT 100'),
  ban: db.prepare('INSERT OR REPLACE INTO bans (tag, reason, expires) VALUES (?,?,?)'),
  getBan: db.prepare('SELECT * FROM bans WHERE tag = ? AND expires > ?'),
  wipeTags: db.prepare('UPDATE posts SET tag = NULL WHERE tag IS NOT NULL AND tag NOT LIKE ?'),
  purgeBans: db.prepare('DELETE FROM bans WHERE expires <= ? OR tag NOT LIKE ?'),
  purgeDeleted: db.prepare('DELETE FROM posts WHERE deleted = 1 AND created < ?'),
  suggest: db.prepare('INSERT INTO suggestions (body, created) VALUES (?,?)'),
  suggestions: db.prepare('SELECT * FROM suggestions ORDER BY id DESC LIMIT 300'),
  suggestionCount: db.prepare('SELECT COUNT(*) AS n FROM suggestions'),
  delSuggestion: db.prepare('DELETE FROM suggestions WHERE id = ?'),
};

// ---------- anonymous poster tags (RAM-only secret) ----------
let tagSecret, tagEpoch;
function rotateTagSecret() {
  tagSecret = crypto.randomBytes(32);
  tagEpoch = crypto.randomBytes(3).toString('hex'); // prefix so stale tags are recognisable
  // Old tags can never be recomputed now — remove them so they serve no purpose.
  q.wipeTags.run(tagEpoch + ':%');
  q.purgeBans.run(Date.now(), tagEpoch + ':%');
  rateLimit.clear();
}
const rateLimit = new Map();
rotateTagSecret();
setInterval(rotateTagSecret, TAG_ROTATE_DAYS * 86400_000).unref();
// Deleted posts are removed from disk entirely after 3 days.
setInterval(() => q.purgeDeleted.run(Date.now() - 3 * 86400_000), 3600_000).unref();

function clientIp(req) {
  let ip = req.socket.remoteAddress || '';
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (xff.length) ip = xff[xff.length - 1];
  }
  ip = ip.replace(/^::ffff:/, '');
  if (ip.includes(':')) ip = ip.split(':').slice(0, 4).join(':'); // IPv6 → /64
  return ip;
}
function posterTag(req) {
  if (req.isTor) return tagEpoch + ':tor'; // all Tor users look the same — by design
  return tagEpoch + ':' + crypto.createHmac('sha256', tagSecret).update(clientIp(req)).digest('hex').slice(0, 24);
}
const isTorTag = tag => typeof tag === 'string' && tag.endsWith(':tor');

// Shared sliding-window limits for all Tor posters together.
const torWindows = { t: [], r: [] };
let torPaused = false; // moderator "panic switch"
function torAllow(kind, limit, windowMs) {
  const now = Date.now();
  const w = torWindows[kind] = torWindows[kind].filter(x => now - x < windowMs);
  if (w.length >= limit) return Math.ceil((windowMs - (now - w[0])) / 1000);
  w.push(now);
  return 0;
}

// ---------- CAPTCHA (self-made, no external service, no JavaScript) ----------
const CAPTCHA_CHARS = 'ACDEFHJKMNPRTUVWXY34679'; // no look-alikes (0/O, 1/I/L, 2/Z, 5/S, 8/B)
const GLYPHS = {
  A: '01110100011000111111100011000110001', C: '01111100001000010000100001000001111',
  D: '11110100011000110001100011000111110', E: '11111100001000011110100001000011111',
  F: '11111100001000011110100001000010000', H: '10001100011000111111100011000110001',
  J: '00111000100001000010000101001001100', K: '10001100101010011000101001001010001',
  M: '10001110111010110101100011000110001', N: '10001110011010110011100011000110001',
  P: '11110100011000111110100001000010000', R: '11110100011000111110101001001010001',
  T: '11111001000010000100001000010000100', U: '10001100011000110001100011000101110',
  V: '10001100011000110001100010101000100', W: '10001100011000110101101011101110001',
  X: '10001100010101000100010101000110001', Y: '10001100010101000100001000010000100',
  3: '11110000010000101110000010000111110', 4: '00010001100101010010111110001000010',
  6: '01110100001000011110100011000101110', 7: '11111000010001000100010000100001000',
  9: '01110100011000101111000010000101110',
};
const captchas = new Map(); // id -> { answer, exp }  (RAM only, one-time use)
setInterval(() => { const now = Date.now(); for (const [k, v] of captchas) if (v.exp < now) captchas.delete(k); }, 60_000).unref();

function newCaptcha() {
  if (captchas.size > 20_000) captchas.delete(captchas.keys().next().value);
  const id = crypto.randomBytes(12).toString('hex');
  let answer = '';
  for (let i = 0; i < 5; i++) answer += CAPTCHA_CHARS[crypto.randomInt(CAPTCHA_CHARS.length)];
  captchas.set(id, { answer, exp: Date.now() + 20 * 60_000 });
  return id;
}
function checkCaptcha(id, given) {
  const c = captchas.get(String(id || ''));
  captchas.delete(String(id || '')); // one try per image
  return !!(c && c.exp > Date.now() && String(given || '').trim().toUpperCase() === c.answer);
}
function captchaSvg(answer) {
  const r = (a, b) => a + Math.random() * (b - a);
  const W = 200, H = 64, px = 4;
  let out = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="${W}" height="${H}" fill="#fbf3ea"/>`;
  const noise = () => {
    let s = '';
    for (let i = 0; i < 70; i++) s += `<rect x="${r(0, W).toFixed(1)}" y="${r(0, H).toFixed(1)}" width="${r(2, 4.5).toFixed(1)}" height="${r(2, 4.5).toFixed(1)}" fill="hsl(${r(10, 40) | 0},${r(40, 80) | 0}%,${r(30, 60) | 0}%)" opacity="${r(.35, .8).toFixed(2)}"/>`;
    for (let i = 0; i < 5; i++) s += `<path d="M${r(0, 30).toFixed(0)} ${r(0, H).toFixed(0)} Q${r(50, 150).toFixed(0)} ${r(-20, H + 20).toFixed(0)} ${r(170, W).toFixed(0)} ${r(0, H).toFixed(0)}" stroke="hsl(${r(10, 40) | 0},60%,40%)" stroke-width="${r(1, 2.2).toFixed(1)}" fill="none" opacity=".6"/>`;
    return s;
  };
  out += noise();
  [...answer].forEach((ch, i) => {
    const g = GLYPHS[ch];
    const x = 14 + i * 36 + r(-4, 4), y = 14 + r(-6, 6);
    out += `<g transform="translate(${x.toFixed(1)} ${y.toFixed(1)}) rotate(${r(-13, 13).toFixed(1)} 10 14) skewX(${r(-8, 8).toFixed(1)})" fill="hsl(${r(10, 30) | 0},${r(60, 90) | 0}%,${r(22, 38) | 0}%)">`;
    for (let k = 0; k < 35; k++) if (g[k] === '1')
      out += `<rect x="${((k % 5) * px + r(-.7, .7)).toFixed(1)}" y="${(((k / 5) | 0) * px + r(-.7, .7)).toFixed(1)}" width="${r(3.6, 5).toFixed(1)}" height="${r(3.6, 5).toFixed(1)}"/>`;
    out += '</g>';
  });
  return out + noise() + '</svg>';
}
const needsCaptcha = req => !!(req.isTor || CAPTCHA_ALL);
function captchaField(req) {
  if (!needsCaptcha(req)) return '';
  const id = newCaptcha();
  return `<div class="captcha"><img src="/captcha/${id}.svg" width="200" height="64" alt="Drošības kods (5 burti/cipari)">
  <input type="hidden" name="captcha_id" value="${id}">
  <input name="captcha" required maxlength="5" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="Kods no bildes"></div>`;
}

// ---------- form tokens (anti-CSRF / anti-bot, stateless, no cookies) ----------
const formKey = crypto.randomBytes(32);
function formToken() {
  const t = Date.now().toString(36);
  return t + '.' + crypto.createHmac('sha256', formKey).update(t).digest('hex').slice(0, 20);
}
function checkFormToken(tok) {
  const [t, sig] = String(tok || '').split('.');
  if (!t || !sig) return false;
  const good = crypto.createHmac('sha256', formKey).update(t).digest('hex').slice(0, 20);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false;
  const age = Date.now() - parseInt(t, 36);
  return age > 2000 && age < 6 * 3600_000; // humans need at least 2s to write something
}

// ---------- mod sessions (RAM only) ----------
const modSessions = new Set();
function isMod(req) {
  const m = /(?:^|;\s*)mod=([a-f0-9]{64})/.exec(req.headers.cookie || '');
  return !!(m && modSessions.has(m[1]));
}

// ---------- rendering ----------
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function formatBody(body, board) {
  return esc(body).split('\n').map(line => {
    let html = line.replace(/&gt;&gt;(\d{1,10})/g, (_, n) => {
      const p = q.get.get(Number(n));
      if (!p || p.deleted) return `<span class="dead">&gt;&gt;${n}</span>`;
      const t = p.thread || p.id;
      return `<a class="ref" href="/${p.board}/thread/${t}#p${n}">&gt;&gt;${n}</a>`;
    });
    if (/^&gt;(?!&gt;\d)/.test(line)) html = `<span class="quote">${html}</span>`;
    return html;
  }).join('<br>');
}

function fmtTime(ms) {
  const d = new Date(ms);
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function renderPost(p, { op = false, mod = false } = {}) {
  const t = p.thread || p.id;
  return `<article class="post ${op ? 'op' : 'reply'}" id="p${p.id}">
  <header>
    ${op && p.subject ? `<span class="subject">${esc(p.subject)}</span>` : ''}
    <span class="anon">Anonīms</span>
    <time>${fmtTime(p.created)}</time>
    <a class="num" href="/${p.board}/thread/${t}#p${p.id}">Nr. ${p.id}</a>
    ${op && p.sticky ? '<span class="badge">piesprausts</span>' : ''}
    ${op && p.locked ? '<span class="badge">slēgts</span>' : ''}
    <a class="report" href="/report/${p.id}">ziņot</a>
    ${mod ? modButtons(p) : ''}
  </header>
  <div class="body">${formatBody(p.body, p.board)}</div>
</article>`;
}

function modButtons(p) {
  const f = (action, label) => `<form method="post" action="/mod/${action}/${p.id}" class="inline"><button>${label}</button></form>`;
  const bans = isTorTag(p.tag) ? '<span class="badge" title="Tor lietotājus nevar bloķēt">Tor</span>'
    : f('ban1', 'bans 1d') + f('ban7', 'bans 7d');
  return `<span class="modtools">${f('delete', 'dzēst')}${bans}${
    p.thread ? '' : f('sticky', p.sticky ? 'atspraust' : 'piespraust') + f('lock', p.locked ? 'atslēgt' : 'slēgt')}</span>`;
}

function postForm(board, thread, req, prefill = {}) {
  if (req.isTor && torPaused) return '<p class="locked">Rakstīšana caur Tor šobrīd ir īslaicīgi apturēta. Lasīt var.</p>';
  return `<form class="postform" method="post" action="/${board}/post">
  <input type="hidden" name="token" value="${formToken()}">
  ${thread ? `<input type="hidden" name="thread" value="${thread}">` : `<input name="subject" maxlength="${MAX_SUBJECT}" placeholder="Tēma (nav obligāta)" value="${esc(prefill.subject || '')}">`}
  <textarea name="body" required maxlength="${MAX_BODY}" rows="5" placeholder="${thread ? 'Tava atbilde…' : 'Sāc jaunu pavedienu…'}">${esc(prefill.body || '')}</textarea>
  <div class="hp" aria-hidden="true"><label>Neaizpildi šo <input name="website" tabindex="-1" autocomplete="off"></label></div>
  ${captchaField(req)}
  <button>${thread ? 'Atbildēt' : 'Izveidot pavedienu'}</button>
  <span class="hint">Tu vienmēr esi “Anonīms”. &gt;teksts = citāts, &gt;&gt;123 = saite uz ziņu. <a href="/noteikumi">Noteikumi</a></span>
</form>`;
}

function layout(title, content, req) {
  const mod = isMod(req);
  const nav = Object.keys(BOARDS).map(b => `<a href="/${b}/">/${b}/</a>`).join(' ');
  return `<!doctype html>
<html lang="lv"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<meta name="robots" content="noindex">
<title>${esc(title)} — ${SITE_NAME}</title>
<link rel="stylesheet" href="/style.css">
</head><body>
<nav class="top"><a class="logo" href="/">${SITE_NAME}</a> <span class="boards">${nav}</span>
<span class="right"><a href="/ieteikumi">ieteikumi</a> · <a href="/noteikumi">noteikumi</a> · <a href="/privatums">privātums</a>${mod ? ' · <a href="/mod">MOD</a>' : ''}</span></nav>
<main>${content}</main>
<footer>${SITE_NAME} · Mēs neglabājam IP adreses, nelietojam sīkdatnes un izsekotājus. · <a href="/privatums">Kā tas strādā</a>${
  req.isTor ? '<br>🧅 Tu esi savienots caur Tor.' : ONION_ADDRESS ? `<br>🧅 Tor adrese: <code>${esc(ONION_ADDRESS)}</code>` : ''}</footer>
</body></html>`;
}

// ---------- pages ----------
function homePage(req) {
  const list = Object.entries(BOARDS).map(([k, b]) => {
    const n = q.threadCount.get(k).n;
    return `<li><a href="/${k}/"><b>/${k}/</b> ${esc(b.title)}</a><span>${esc(b.desc)} · ${n} pavedieni</span></li>`;
  }).join('');
  return layout('Sākums', `<section class="hero"><h1>${SITE_NAME}</h1>
<p>Anonīms forums Latvijas skolēniem. Bez reģistrācijas, bez vārdiem, bez IP adrešu glabāšanas.</p></section>
<ul class="boardlist">${list}</ul>
<section class="box"><h2>Pirms raksti</h2><p>Anonimitāte ir, lai tu varētu runāt brīvi — nevis lai kādu sāpinātu.
Neraksti klasesbiedru vai skolotāju vārdus, adreses, bildes vai draudus. Ja kāds raksta par tevi — spied “ziņot”, un mēs to dzēsīsim.
Ja tev ir grūti: <b>Bērnu un pusaudžu uzticības tālrunis 116111</b> (bezmaksas, anonīmi, 24/7).</p></section>`, req);
}

function boardPage(req, board, page) {
  const b = BOARDS[board];
  const mod = isMod(req);
  const total = q.threadCount.get(board).n;
  const pages = Math.max(1, Math.min(MAX_PAGES, Math.ceil(total / THREADS_PER_PAGE)));
  const threads = q.threads.all(board, THREADS_PER_PAGE, page * THREADS_PER_PAGE);
  const html = threads.map(t => {
    const n = q.replyCount.get(t.id).n;
    const last = q.lastReplies.all(t.id);
    const omitted = n - last.length;
    return `<div class="thread">${renderPost(t, { op: true, mod })}
${omitted > 0 ? `<p class="omitted">${omitted} atbildes paslēptas. <a href="/${board}/thread/${t.id}">Atvērt pavedienu</a></p>` : ''}
${last.map(r => renderPost(r, { mod })).join('')}
<p class="open"><a href="/${board}/thread/${t.id}">→ Atvērt (${n} atbildes)</a></p></div>`;
  }).join('') || '<p class="empty">Šeit vēl nekā nav. Esi pirmais!</p>';
  const pager = Array.from({ length: pages }, (_, i) =>
    i === page ? `<b>[${i + 1}]</b>` : `<a href="/${board}/?p=${i}">[${i + 1}]</a>`).join(' ');
  return layout(`/${board}/ ${b.title}`, `<header class="boardhead"><h1>/${board}/ — ${esc(b.title)}</h1><p>${esc(b.desc)}</p></header>
${postForm(board, null, req)}${html}<nav class="pager">${pager}</nav>`, req);
}

function threadPage(req, board, id) {
  const op = q.get.get(id);
  if (!op || op.deleted || op.thread || op.board !== board) return null;
  const mod = isMod(req);
  const replies = q.replies.all(id);
  const form = op.locked ? '<p class="locked">Šis pavediens ir slēgts.</p>'
    : replies.length >= REPLY_LIMIT ? '<p class="locked">Pavediens ir pilns.</p>' : postForm(board, id, req);
  return layout(op.subject || `/${board}/ Nr. ${id}`, `<p class="back"><a href="/${board}/">← atpakaļ uz /${board}/</a></p>
<div class="thread full">${renderPost(op, { op: true, mod })}${replies.map(r => renderPost(r, { mod })).join('')}</div>${form}`, req);
}

function rulesPage(req) {
  return layout('Noteikumi', `<section class="box prose"><h1>Noteikumi</h1><ol>
<li><b>Nekādas personas atklāšanas.</b> Neraksti īstus vārdus, uzvārdus, adreses, tālruņus, sociālo tīklu profilus vai bildes ar konkrētiem skolēniem vai skolotājiem.</li>
<li><b>Nekādu draudu un vajāšanas.</b> Draudi kādam, aicinājumi uz vardarbību vai mērķtiecīga ņirgāšanās par konkrētu cilvēku tiek dzēsti un autors bloķēts.</li>
<li><b>Nekā nelikumīga.</b> Seksuāls saturs ar nepilngadīgajiem, narkotiku tirdzniecība, krāpšana — dzēsts nekavējoties.</li>
<li><b>Nav spama.</b> Reklāmas un viena un tā paša teksta plūdi tiek dzēsti.</li>
<li><b>Paliec tēmā.</b> Raksti pareizajā sadaļā; ja nezini kurā — /b/.</li></ol>
<p>Viss pārējais ir atļauts: sūdzēties par skolu, runāt par jūtām, strīdēties, jokot, uzdot “stulbus” jautājumus.</p>
<p>Redzi kaut ko, kas pārkāpj noteikumus? Spied <b>ziņot</b> pie ziņas.</p>
<p>Ja tev ir grūti vai kāds tev dara pāri: <b>116111</b> — Bērnu un pusaudžu uzticības tālrunis (bezmaksas, anonīmi). Ārkārtas gadījumā <b>112</b>.</p></section>`, req);
}

function privacyPage(req) {
  return layout('Privātums', `<section class="box prose"><h1>Kā darbojas anonimitāte</h1>
<ul>
<li>Nav reģistrācijas, lietotājvārdu vai paroļu. Katrs ir “Anonīms”.</li>
<li>Mēs <b>neglabājam tavu IP adresi</b> — ne datubāzē, ne žurnālos.</li>
<li>Lai apturētu spamu, serveris no IP izveido vienvirziena kodu (HMAC). Atslēga atrodas tikai operatīvajā atmiņā un tiek
nomainīta ik ${TAG_ROTATE_DAYS} dienas un katrā restartā; pēc tam vecie kodi tiek izdzēsti un vairs nevienam nav sasaistāmi ar tevi.</li>
<li>Nav sīkdatņu, analītikas, reklāmu, ārēju fontu vai skriptu. Lapa nesatur JavaScript.</li>
<li>Dzēstās ziņas pilnībā izzūd no diska pēc 3 dienām.</li></ul>
${ONION_PORT ? `<h2>🧅 Tor</h2><ul>
<li>Caur Tor serveris tavu IP adresi <b>vispār neredz</b> — pat ne uz mirkli. Tāpat nav redzams, kur atrodas serveris.</li>
<li>Tāpēc Tor lietotājiem katrai ziņai jāieraksta drošības kods, un visiem Tor lietotājiem kopā ir ierobežots ziņu skaits minūtē.</li>
<li>Lejupielādē Tor Browser tikai no oficiālās vietnes torproject.org.</li></ul>` : ''}
<h2>Godīgi par robežām</h2>
<ul>
<li>Tavs interneta pakalpojumu sniedzējs, skolas Wi-Fi vai mobilais operators redz, ka tu apmeklē šo vietni (bet ne to, ko raksti, jo savienojums ir šifrēts).</li>
<li>Ja raksti no skolas datora vai tīkla, skola var redzēt apmeklētās vietnes.</li>
<li>Tavs rakstīšanas stils un detaļas, ko pastāsti, var tevi atklāt. Neraksti lietas, ko zina tikai tu.</li>
<li>Maksimālai anonimitātei izmanto Tor Browser${ONION_ADDRESS ? ` un mūsu .onion adresi: <code>${esc(ONION_ADDRESS)}</code>` : ''}.</li>
<li>Anonimitāte nenozīmē, ka var pārkāpt likumu. Nelikumīgs saturs tiek dzēsts.</li></ul></section>`, req);
}

function suggestionsPage(req, msg) {
  return layout('Ieteikumi', `<section class="box"><h1>Ieteikumi</h1>
<p>Kā uzlabot ${SITE_NAME}? Jauna sadaļa, kļūda, ideja, sūdzība? Raksti šeit. Ieteikumus redz tikai moderatori, un tie ir pilnīgi anonīmi.</p>
${msg ? `<p class="ok">${esc(msg)}</p><p><a href="/ieteikumi">Uzrakstīt vēl vienu</a> · <a href="/">sākums</a></p>` : `<form method="post" action="/ieteikumi" class="postform">
<input type="hidden" name="token" value="${formToken()}">
<textarea name="body" required maxlength="${MAX_BODY}" rows="6" placeholder="Tavs ieteikums…"></textarea>
<div class="hp" aria-hidden="true"><label>Neaizpildi šo <input name="website" tabindex="-1" autocomplete="off"></label></div>
${captchaField(req)}
<button>Nosūtīt ieteikumu</button></form>`}</section>`, req);
}

function modSuggestionsPage(req) {
  const list = q.suggestions.all().map(s => `<div class="post"><header><time>${fmtTime(s.created)}</time>
<form method="post" action="/mod/delsug/${s.id}" class="inline"><button>dzēst</button></form></header>
<div class="body">${esc(s.body).replace(/\n/g, '<br>')}</div></div>`).join('') || '<p>Vēl nav neviena ieteikuma.</p>';
  return layout('Ieteikumi (mod)', `<p class="back"><a href="/mod">← moderācija</a></p><h1>Ieteikumi</h1>${list}`, req);
}

function reportPage(req, id, msg) {
  const p = q.get.get(id);
  if (!p || p.deleted) return null;
  return layout('Ziņot', `<section class="box"><h1>Ziņot par Nr. ${id}</h1>${renderPost(p, { op: !p.thread })}
${msg ? `<p class="ok">${esc(msg)}</p>` : `<form method="post" action="/report/${id}" class="postform">
<input type="hidden" name="token" value="${formToken()}">
<label><input type="radio" name="reason" value="Personas atklāšana / vārdi" required> Atklāj kāda personu (vārds, adrese, bilde)</label>
<label><input type="radio" name="reason" value="Draudi / vajāšana"> Draudi vai vajāšana</label>
<label><input type="radio" name="reason" value="Nelikumīgs saturs"> Nelikumīgs saturs</label>
<label><input type="radio" name="reason" value="Spams"> Spams</label>
<label><input type="radio" name="reason" value="Cits"> Cits</label>
<button>Nosūtīt ziņojumu</button></form>`}</section>`, req);
}

function modPage(req) {
  if (!MOD_PASSWORD) return layout('Mod', '<p class="box">Moderācija izslēgta: iestati MOD_PASSWORD vides mainīgo.</p>', req);
  if (!isMod(req)) return layout('Mod', `<form method="post" action="/mod/login" class="postform box">
<h1>Moderatora pieeja</h1><input type="password" name="password" required autocomplete="current-password"><button>Ieiet</button></form>`, req);
  const reports = q.reports.all();
  const grouped = new Map();
  for (const r of reports) {
    if (!grouped.has(r.id)) grouped.set(r.id, { post: r, reasons: [] });
    grouped.get(r.id).reasons.push(r.reason);
  }
  const rep = [...grouped.values()].map(({ post, reasons }) => `<div class="modrow">
<p class="reasons">${reasons.length}× — ${esc([...new Set(reasons)].join(', '))}
<form method="post" action="/mod/dismiss/${post.id}" class="inline"><button>noraidīt ziņojumus</button></form></p>
<p><a href="/${post.board}/thread/${post.thread || post.id}#p${post.id}">/${post.board}/ Nr. ${post.id}</a></p>
${renderPost(post, { op: !post.thread, mod: true })}</div>`).join('') || '<p>Nav ziņojumu.</p>';
  const recent = q.recent.all().map(p => `<div class="modrow"><a href="/${p.board}/thread/${p.thread || p.id}#p${p.id}">/${p.board}/</a>
${renderPost(p, { op: !p.thread, mod: true })}</div>`).join('');
  return layout('Mod', `<h1>Moderācija</h1>
<form method="post" action="/mod/logout" class="inline"><button>Iziet</button></form>
${ONION_PORT ? `<div class="box"><b>🧅 Tor:</b> ${torPaused ? '<span class="badge">rakstīšana APTURĒTA</span>' : 'rakstīšana atļauta'}
<form method="post" action="/mod/torpause/0" class="inline"><button>${torPaused ? 'Atļaut rakstīt caur Tor' : 'Apturēt rakstīšanu caur Tor'}</button></form>
<p class="hint">Tor lietotājus nevar bloķēt individuāli. Ja kāds caur Tor plūdina, apturi Tor rakstīšanu uz laiku — lasīt joprojām varēs.</p></div>` : ''}
<p><a class="btn" href="/mod/ieteikumi">Ieteikumi (${q.suggestionCount.get().n})</a></p>
<h2>Ziņojumi (${grouped.size})</h2>${rep}<h2>Jaunākās ziņas</h2>${recent}`, req);
}

// ---------- http helpers ----------
const STATIC = { '/style.css': ['text/css; charset=utf-8', fs.readFileSync(path.join(__dirname, 'public', 'style.css'))] };

function send(res, status, body, type = 'text/html; charset=utf-8', extra = {}) {
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Security-Policy': "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    'Cache-Control': 'no-store',
    ...(SECURE_COOKIES ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
    ...extra,
  });
  res.end(body);
}
const redirect = (res, to, extra = {}) => send(res, 303, '', 'text/plain', { Location: to, ...extra });
const errorPage = (req, res, status, msg) =>
  send(res, status, layout('Kļūda', `<section class="box"><h1>${status}</h1><p>${esc(msg)}</p><p><a href="/">sākums</a></p></section>`, req));

function readForm(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 32_768) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')))));
    req.on('error', reject);
  });
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin || origin === 'null') return true; // some privacy browsers strip it; token still protects
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

function clean(s, max) {
  return String(s || '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F​-‏‪-‮⁦-⁩]/g, '')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim()
    .slice(0, max);
}

// ---------- actions ----------
function handlePost(req, res, board, f) {
  if (f.website) return redirect(res, `/${board}/`); // honeypot: silently drop bots
  if (!checkFormToken(f.token)) return errorPage(req, res, 400, 'Forma ir novecojusi vai iesniegta pārāk ātri. Pārlādē lapu un mēģini vēlreiz.');
  if (req.isTor && torPaused) return errorPage(req, res, 503, 'Rakstīšana caur Tor šobrīd ir īslaicīgi apturēta.');
  const tag = posterTag(req);
  const ban = q.getBan.get(tag, Date.now());
  if (ban) return errorPage(req, res, 403, `Tu esi bloķēts līdz ${fmtTime(ban.expires)}. Iemesls: ${ban.reason || 'noteikumu pārkāpums'}.`);
  const body = clean(f.body, MAX_BODY);
  if (body.length < 2) return errorPage(req, res, 400, 'Ziņa ir par īsu.');
  const thread = f.thread ? Number(f.thread) : null;
  if (needsCaptcha(req) && !checkCaptcha(f.captcha_id, f.captcha)) {
    const subject = clean(f.subject, MAX_SUBJECT);
    return send(res, 400, layout('Nepareizs kods', `<section class="box"><h1>Nepareizs drošības kods</h1>
<p>Mēģini vēlreiz ar jauno kodu — tavs teksts ir saglabāts.</p></section>${postForm(board, thread, req, { subject, body })}`, req));
  }
  const cooldown = thread ? REPLY_COOLDOWN : THREAD_COOLDOWN;
  const key = tag + (thread ? ':r' : ':t');
  const last = rateLimit.get(key) || 0;
  if (req.isTor) {
    const wait = thread ? torAllow('r', TOR_REPLIES_PER_MIN, 60_000) : torAllow('t', TOR_THREADS_PER_10MIN, 600_000);
    if (wait) return errorPage(req, res, 429, `Caur Tor šobrīd raksta pārāk daudz cilvēku. Pagaidi ${wait} sekundes.`);
  } else if (Date.now() - last < cooldown) return errorPage(req, res, 429, `Pagaidi ${Math.ceil((cooldown - (Date.now() - last)) / 1000)} sekundes pirms nākamās ziņas.`);

  const now = Date.now();
  if (thread) {
    const op = q.get.get(thread);
    if (!op || op.deleted || op.thread || op.board !== board) return errorPage(req, res, 404, 'Pavediens neeksistē.');
    if (op.locked) return errorPage(req, res, 403, 'Pavediens ir slēgts.');
    const n = q.replyCount.get(thread).n;
    if (n >= REPLY_LIMIT) return errorPage(req, res, 403, 'Pavediens ir pilns.');
    const r = q.insert.run(board, thread, null, body, now, now, tag);
    if (n < BUMP_LIMIT && !/^sage$/i.test(clean(f.subject, 10))) q.bump.run(now, thread);
    rateLimit.set(key, now);
    return redirect(res, `/${board}/thread/${thread}#p${r.lastInsertRowid}`);
  }
  const subject = clean(f.subject, MAX_SUBJECT).replace(/\n/g, ' ');
  const r = q.insert.run(board, null, subject || null, body, now, now, tag);
  rateLimit.set(key, now);
  // prune threads that fell off the last page
  for (const { id } of q.oldThreads.all(board, THREADS_PER_PAGE * MAX_PAGES)) q.del.run(id, id);
  return redirect(res, `/${board}/thread/${r.lastInsertRowid}`);
}

async function handleMod(req, res, action, id) {
  if (action === 'login') {
    const f = await readForm(req);
    const a = crypto.createHash('sha256').update(String(f.password || '')).digest();
    const b = crypto.createHash('sha256').update(MOD_PASSWORD).digest();
    if (!MOD_PASSWORD || !crypto.timingSafeEqual(a, b)) {
      await new Promise(r => setTimeout(r, 1500));
      return errorPage(req, res, 403, 'Nepareiza parole.');
    }
    const tok = crypto.randomBytes(32).toString('hex');
    modSessions.add(tok);
    return redirect(res, '/mod', { 'Set-Cookie': `mod=${tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200${SECURE_COOKIES ? '; Secure' : ''}` });
  }
  if (!isMod(req)) return errorPage(req, res, 403, 'Nav piekļuves.');
  if (action === 'logout') {
    const m = /(?:^|;\s*)mod=([a-f0-9]{64})/.exec(req.headers.cookie || '');
    if (m) modSessions.delete(m[1]);
    return redirect(res, '/', { 'Set-Cookie': 'mod=; Path=/; Max-Age=0' });
  }
  if (action === 'torpause') { torPaused = !torPaused; return redirect(res, '/mod'); }
  if (action === 'delsug') { q.delSuggestion.run(id); return redirect(res, '/mod/ieteikumi'); }
  const p = q.get.get(id);
  if (!p) return errorPage(req, res, 404, 'Ziņa nav atrasta.');
  const back = req.headers.referer && sameOrigin({ headers: { origin: req.headers.referer, host: req.headers.host } }) ? req.headers.referer : '/mod';
  switch (action) {
    case 'delete': q.del.run(p.id, p.thread ? -1 : p.id); q.clearReports.run(p.id); break;
    case 'dismiss': q.clearReports.run(p.id); break;
    case 'ban1': case 'ban7': {
      if (isTorTag(p.tag)) return errorPage(req, res, 400, 'Šī ziņa nāk no Tor — Tor lietotājus nevar bloķēt. Dzēs ziņu vai aptur Tor rakstīšanu.');
      if (!p.tag) return errorPage(req, res, 410, 'Šī ziņa ir pārāk veca — autora kods jau ir dzēsts.');
      const days = action === 'ban1' ? 1 : 7;
      q.ban.run(p.tag, 'noteikumu pārkāpums (Nr. ' + p.id + ')', Date.now() + days * 86400_000);
      q.del.run(p.id, p.thread ? -1 : p.id); q.clearReports.run(p.id);
      break;
    }
    case 'sticky': q.setFlag.run(p.locked, p.sticky ? 0 : 1, p.id); break;
    case 'lock': q.setFlag.run(p.locked ? 0 : 1, p.sticky, p.id); break;
    default: return errorPage(req, res, 404, 'Nezināma darbība.');
  }
  return redirect(res, back);
}

// ---------- router ----------
async function handle(req, res) {
  try {
    const url = new URL(req.url, 'http://x');
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    // Tell Tor Browser users on the normal site that an .onion version exists.
    if (!req.isTor && ONION_ADDRESS) res.setHeader('Onion-Location', `http://${ONION_ADDRESS}${url.pathname}${url.search}`);

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (STATIC[url.pathname]) {
        const [type, buf] = STATIC[url.pathname];
        return send(res, 200, buf, type, { 'Cache-Control': 'public, max-age=3600' });
      }
      const cm = /^\/captcha\/([a-f0-9]{24})\.svg$/.exec(url.pathname);
      if (cm) {
        const c = captchas.get(cm[1]);
        return c ? send(res, 200, captchaSvg(c.answer), 'image/svg+xml') : send(res, 404, '', 'text/plain');
      }
      if (parts.length === 0) return send(res, 200, homePage(req));
      if (parts[0] === 'noteikumi') return send(res, 200, rulesPage(req));
      if (parts[0] === 'privatums') return send(res, 200, privacyPage(req));
      if (parts[0] === 'ieteikumi') return send(res, 200, suggestionsPage(req));
      if (parts[0] === 'mod' && parts[1] === 'ieteikumi') {
        return isMod(req) ? send(res, 200, modSuggestionsPage(req)) : redirect(res, '/mod');
      }
      if (parts[0] === 'mod') return send(res, 200, modPage(req));
      if (parts[0] === 'report' && /^\d+$/.test(parts[1] || '')) {
        const html = reportPage(req, Number(parts[1]));
        return html ? send(res, 200, html) : errorPage(req, res, 404, 'Ziņa nav atrasta.');
      }
      if (BOARDS[parts[0]]) {
        if (parts.length === 1) {
          if (!url.pathname.endsWith('/')) return redirect(res, `/${parts[0]}/`);
          const page = Math.max(0, Math.min(MAX_PAGES - 1, parseInt(url.searchParams.get('p') || '0', 10) || 0));
          return send(res, 200, boardPage(req, parts[0], page));
        }
        if (parts[1] === 'thread' && /^\d+$/.test(parts[2] || '')) {
          const html = threadPage(req, parts[0], Number(parts[2]));
          return html ? send(res, 200, html) : errorPage(req, res, 404, 'Pavediens neeksistē vai ir dzēsts.');
        }
      }
      return errorPage(req, res, 404, 'Lapa nav atrasta.');
    }

    if (req.method === 'POST') {
      if (!sameOrigin(req)) return errorPage(req, res, 403, 'Nederīgs pieprasījums.');
      if (parts[0] === 'mod') return await handleMod(req, res, parts[1], Number(parts[2]));
      const f = await readForm(req);
      if (parts[0] === 'ieteikumi') {
        if (f.website) return redirect(res, '/');
        if (!checkFormToken(f.token)) return errorPage(req, res, 400, 'Forma ir novecojusi vai iesniegta pārāk ātri. Pārlādē lapu.');
        const body = clean(f.body, MAX_BODY);
        if (body.length < 3) return errorPage(req, res, 400, 'Ieteikums ir par īsu.');
        if (needsCaptcha(req) && !checkCaptcha(f.captcha_id, f.captcha)) return errorPage(req, res, 400, 'Nepareizs drošības kods. Atgriezies un mēģini vēlreiz.');
        const sk = posterTag(req) + ':sug';
        if (Date.now() - (rateLimit.get(sk) || 0) < 60_000) return errorPage(req, res, 429, 'Pagaidi minūti pirms nākamā ieteikuma.');
        rateLimit.set(sk, Date.now());
        q.suggest.run(body, Date.now());
        return send(res, 200, suggestionsPage(req, 'Paldies! Tavu ieteikumu redzēs moderatori.'));
      }
      if (parts[0] === 'report' && /^\d+$/.test(parts[1] || '')) {
        const id = Number(parts[1]);
        if (!checkFormToken(f.token)) return errorPage(req, res, 400, 'Forma ir novecojusi. Pārlādē lapu.');
        const p = q.get.get(id);
        if (!p || p.deleted) return errorPage(req, res, 404, 'Ziņa nav atrasta.');
        const rk = posterTag(req) + ':rep:' + id;
        if (!rateLimit.has(rk)) { q.report.run(id, clean(f.reason, 60) || 'Cits', Date.now()); rateLimit.set(rk, Date.now()); }
        return send(res, 200, reportPage(req, id, 'Paldies! Moderators to apskatīs.'));
      }
      if (BOARDS[parts[0]] && parts[1] === 'post') return handlePost(req, res, parts[0], f);
      return errorPage(req, res, 404, 'Lapa nav atrasta.');
    }
    send(res, 405, 'Method not allowed', 'text/plain');
  } catch (err) {
    // Deliberately log only the error message — never request details.
    console.error('error:', err.message);
    if (!res.headersSent) send(res, 500, 'Servera kļūda', 'text/plain');
  }
}

const server = http.createServer((req, res) => { req.isTor = false; handle(req, res); });
server.listen(PORT, HOST, () => {
  console.log(`${SITE_NAME} running on http://${HOST}:${PORT}`);
  if (!MOD_PASSWORD) console.log('WARNING: MOD_PASSWORD not set — you cannot moderate. Set it before going public.');
});

// The onion listener only ever binds to localhost — Tor connects to it from the same machine.
if (ONION_PORT) {
  const onion = http.createServer((req, res) => { req.isTor = true; handle(req, res); });
  onion.listen(ONION_PORT, '127.0.0.1', () => {
    console.log(`Tor (onion) listener on http://127.0.0.1:${ONION_PORT}${ONION_ADDRESS ? ' → http://' + ONION_ADDRESS : ''}`);
  });
}
