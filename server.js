const http = require('http'), fs = require('fs'), path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX = 8; // malha P2P: 8 pessoas por sala é um bom teto
// ICE = como os aparelhos acham um caminho entre si. Só com STUN, quem está atrás de
// CGNAT / NAT simétrico (muito comum em internet de operadora) NÃO consegue conectar:
// entra na sala mas não ouve nem fala. O conserto é um servidor TURN (ver LEIAME-AJUSTES.md).
//   ICE_SERVERS            JSON completo (substitui tudo)
//   TURN_URL / TURN_USER / TURN_PASS      um TURN qualquer (Metered, ExpressTURN, coturn...)
//   CF_TURN_KEY_ID / CF_TURN_API_TOKEN    TURN da Cloudflare (credenciais temporárias automáticas)
const ICE_BASE = process.env.ICE_SERVERS
  ? JSON.parse(process.env.ICE_SERVERS)
  : [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
if (process.env.TURN_URL) {
  ICE_BASE.push({ urls: process.env.TURN_URL.split(',').map(u => u.trim()).filter(Boolean),
    username: process.env.TURN_USER || '', credential: process.env.TURN_PASS || '' });
}
let cfCache = { at: 0, list: [] };
async function iceList() {
  const id = process.env.CF_TURN_KEY_ID, tok = process.env.CF_TURN_API_TOKEN;
  if (!id || !tok) return ICE_BASE;
  if (Date.now() - cfCache.at > 3600e3) {
    try {
      const r = await fetch('https://rtc.live.cloudflare.com/v1/turn/keys/' + encodeURIComponent(id) + '/credentials/generate', {
        method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ttl: 86400 }),
      });
      const j = await r.json();
      if (!j.iceServers) throw new Error('resposta sem iceServers (status ' + r.status + ')');
      const list = [].concat(j.iceServers).map(s => ({ ...s, urls: [].concat(s.urls).filter(u => !/:53(\?|$)/.test(u)) }));
      cfCache = { at: Date.now(), list };
      console.log('TURN da Cloudflare ok');
    } catch (e) { console.error('TURN da Cloudflare falhou:', e.message); cfCache.at = Date.now() - 3000e3; /* tenta de novo em ~10 min */ }
  }
  return [...ICE_BASE, ...cfCache.list];
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json',
  '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav' };
const PUB = path.join(__dirname, 'public');

const srv = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  if (url === '/ice') {
    return iceList().then(l => {
      res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'no-store');
      res.end(JSON.stringify(l));
    }).catch(() => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(ICE_BASE)); });
  }
  if (url.startsWith('/sons/') && !fs.existsSync(path.join(PUB, url))) { res.writeHead(404); return res.end(); }
  let full = path.join(PUB, url === '/' ? 'index.html' : url);
  if (!full.startsWith(PUB + path.sep) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) full = path.join(PUB, 'index.html');
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(500); return res.end('erro'); }
    res.setHeader('content-type', MIME[path.extname(full)] || 'application/octet-stream');
    res.end(data);
  });
});

const wss = new WebSocketServer({ server: srv, maxPayload: 18 * 1024 * 1024 });
const rooms = new Map();
const clients = new Set();
const hist = new Map();
const CH = [
  { id: 'geral', name: 'geral', kind: 'text', def: 1 },
  { id: 'voz-geral', name: 'Geral', kind: 'voice', def: 1 },
];
let next = 1;

// ---------- salvar mensagens e canais (Upstash Redis, grátis) ----------
// Sem isso, tudo some quando o Render reinicia. Precisa de 2 variáveis no Render:
//   UPSTASH_REDIS_REST_URL   e   UPSTASH_REDIS_REST_TOKEN
const UP_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '').replace(/^(?!https?:\/\/)(.+)/, 'https://$1');
const UP_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const SAVE_ON = !!(process.env.UPSTASH_REDIS_REST_URL && UP_TOKEN);
async function up(cmd) {
  const r = await fetch(UP_URL, { method: 'POST', headers: { Authorization: 'Bearer ' + UP_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
// no plano grátis cada gravação aceita ~1 MB: anexos grandes não são guardados (só o nome), e o histórico é aparado se passar do limite
const KEEP_ATT = 150000, KEEP_MAX = 800000;
function slim(m) {
  const keep = [], lost = [];
  (m.att || []).forEach(a => (a.data.length <= KEEP_ATT ? keep : lost).push(a));
  const text = lost.length ? (m.text ? m.text + '\n' : '') + lost.map(a => '📎 ' + a.name + ' (anexo grande, não foi guardado)').join('\n') : m.text;
  return { ...m, text, att: keep };
}
const dirty = new Set();
let flushTimer = 0;
function markDirty(id) {
  if (!SAVE_ON) return;
  dirty.add(id);
  if (!flushTimer) flushTimer = setTimeout(flush, 3000);   // junta várias mudanças numa gravação só
}
async function flush() {
  flushTimer = 0;
  const ids = [...dirty]; dirty.clear();
  for (const id of ids) {
    try {
      if (id === '\0ch') { await up(['SET', 'guri:canais', JSON.stringify(CH)]); continue; }
      const h = hist.get(id);
      if (!h) { await up(['DEL', 'guri:h:' + id]); continue; }
      let arr = h.map(slim), js = JSON.stringify(arr);
      while (js.length > KEEP_MAX && arr.length > 1) { arr.shift(); js = JSON.stringify(arr); }
      await up(['SET', 'guri:h:' + id, js]);
    } catch (e) { console.error('não consegui salvar', id === '\0ch' ? 'canais' : id, e.message); dirty.add(id); }
  }
  if (dirty.size && !flushTimer) flushTimer = setTimeout(flush, 15000);   // tenta de novo daqui a pouco
}
async function loadSaved() {
  if (!SAVE_ON) { console.log('AVISO: sem UPSTASH_REDIS_REST_URL/TOKEN, as mensagens NÃO são salvas.'); return; }
  try {
    const raw = await up(['GET', 'guri:canais']);
    const ch = raw ? JSON.parse(raw) : null;
    if (Array.isArray(ch) && ch.some(c => c.kind === 'text') && ch.some(c => c.kind === 'voice')) { CH.length = 0; ch.forEach(c => CH.push(c)); }
    for (const c of CH.filter(c => c.kind === 'text')) {
      const h = await up(['GET', 'guri:h:' + c.id]);
      if (h) hist.set(c.id, JSON.parse(h).slice(-40));
    }
    console.log('Mensagens e canais carregados do Upstash.');
  } catch (e) { console.error('não consegui carregar o que estava salvo:', e.message); }
}
const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));
const slug = t => t.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'canal';

// aceita JPEG (imagem reduzida) ou GIF animado (limite maior)
const okImg = (v, max, maxGif) => typeof v === 'string' && ((v.startsWith('data:image/jpeg;base64,') && v.length < max) || (v.startsWith('data:image/gif;base64,') && v.length < maxGif)) ? v : '';
function setProf(ws, p) {
  p = p || {};
  ws.prof = { about: String(p.about || '').slice(0, 120), avatar: okImg(p.avatar, 60000, 5.8e6), banner: okImg(p.banner, 120000, 5.8e6),
    color: /^#[0-9a-f]{6}$/i.test(p.color) ? p.color : '' };
}
const pj = c => ({ id: c.id, name: c.nick, prof: c.prof || {} });

function state() {
  const users = [...clients].filter(c => c.nick).map(c => ({ id: c.id, name: c.nick, room: c.room || null, vs: c.vs || {}, act: c.act || null }));
  clients.forEach(c => c.nick && send(c, { type: 'state', channels: CH, users }));
}
function leave(ws) {
  const set = rooms.get(ws.room);
  if (!set) return;
  set.delete(ws.id);
  set.forEach(p => send(p, { type: 'peer-leave', id: ws.id }));
  if (!set.size) rooms.delete(ws.room);
  ws.room = null;
  if (ws.vs) ws.vs = { ...ws.vs, cam: false, screen: false };
  state();
}

wss.on('connection', ws => {
  ws.id = String(next++);
  clients.add(ws);
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'hello') {
      ws.nick = String(m.name || 'Guri').slice(0, 24);
      setProf(ws, m.prof);
      send(ws, { type: 'hello-ok', id: ws.id });
      [...clients].filter(c => c.nick && c !== ws).forEach(c => send(ws, { type: 'profile', ...pj(c) })); // um por um: GIFs grandes não cabem num pacote só
      clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) }));
      state();
    } else if (m.type === 'profile' && ws.nick) {
      ws.nick = String(m.name || ws.nick).slice(0, 24);
      setProf(ws, m.prof);
      clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) }));
      state();
    } else if (!ws.nick) {
      return;
    } else if (m.type === 'chan-add') {
      const name = String(m.name || '').trim().slice(0, 24);
      const kind = m.kind === 'voice' ? 'voice' : 'text';
      if (!name || CH.length >= 30) return;
      let id = slug(name), i = 2;
      while (CH.some(c => c.id === id)) id = slug(name) + '-' + i++;
      CH.push({ id, name: kind === 'text' ? slug(name) : name, kind });
      markDirty('\0ch');
      state();
    } else if (m.type === 'chan-del') {
      const i = CH.findIndex(c => c.id === m.id);
      if (i < 0 || (rooms.get(m.id) || { size: 0 }).size) return;
      if (CH[i].kind === 'text' && CH.filter(c => c.kind === 'text').length <= 1) return; // sempre sobra 1 canal de texto
      CH.splice(i, 1); hist.delete(m.id);
      markDirty('\0ch'); markDirty(m.id);
      state();
    } else if (m.type === 'act') {
      const g = String(m.game || '').slice(0, 40), mu = String(m.music || '').slice(0, 80);
      ws.act = g || mu ? { game: g, music: mu } : null;
      state();
    } else if (m.type === 'ping') {
      send(ws, { type: 'pong', t: m.t });
    } else if (m.type === 'ping-rep') {
      const v = Math.round(+m.ms); if (v >= 0 && v < 60000) ws.ping = v;
    } else if (m.type === 'vstate') {
      // mudo / fone mudo / câmera / tela: aparece ao lado do nome de quem está na chamada
      ws.vs = { mute: !!m.mute, deaf: !!m.deaf, cam: !!m.cam, screen: !!m.screen };
      state();
    } else if (m.type === 'kick') {
      const t = [...clients].find(c => c.id === String(m.id) && c !== ws);
      if (!t) return;
      send(t, { type: 'kicked', by: ws.nick });
      setTimeout(() => t.close(), 200);
    } else if (m.type === 'history') {
      send(ws, { type: 'history', channel: m.channel, msgs: hist.get(m.channel) || [] });
    } else if (m.type === 'msg') {
      if (!CH.some(c => c.id === m.channel && c.kind === 'text')) return;
      const att = (Array.isArray(m.att) ? m.att : []).slice(0, 4)
        .filter(a => a && typeof a.data === 'string' && a.data.startsWith('data:') && a.data.length < 4.3e6)
        .map(a => ({ name: String(a.name).slice(0, 100), type: String(a.type).slice(0, 60), size: +a.size || 0, data: a.data }));
      const st = Number.isInteger(m.st) ? m.st : null;
      const text = String(m.text || '').slice(0, 2000);
      if (!text && !att.length && st === null) return;
      const msg = { uid: ws.id, from: ws.nick, text, att, st, t: Date.now() };
      const h = hist.get(m.channel) || [];
      h.push(msg); if (h.length > 40) h.shift();
      hist.set(m.channel, h);
      markDirty(m.channel);
      clients.forEach(c => c.nick && send(c, { type: 'msg', channel: m.channel, msg }));
    } else if (m.type === 'join') {
      const c = CH.find(c => c.id === m.room && c.kind === 'voice');
      if (!c || ws.room === c.id) return;
      const set = rooms.get(c.id) || new Map();
      if (set.size >= MAX) return send(ws, { type: 'full' });
      if (ws.room) leave(ws);
      ws.room = c.id;
      rooms.set(c.id, set);
      send(ws, { type: 'joined', room: c.id, peers: [...set.values()].map(p => ({ id: p.id, name: p.nick })) });
      set.forEach(p => send(p, { type: 'peer-join', id: ws.id, name: ws.nick }));
      set.set(ws.id, ws);
      state();
    } else if (m.type === 'leave') {
      leave(ws);
    } else if (m.type === 'signal' && ws.room) {
      const t = rooms.get(ws.room).get(String(m.to));
      if (t) send(t, { type: 'signal', from: ws.id, data: m.data });
    }
  });
  ws.on('close', () => { leave(ws); clients.delete(ws); state(); });
});

// a cada 4 s manda para todo mundo o ping de cada pessoa (medido por ela mesma até o servidor)
setInterval(() => {
  const p = {}; clients.forEach(c => { if (c.nick && c.ping !== undefined) p[c.id] = c.ping; });
  clients.forEach(c => c.nick && send(c, { type: 'pings', p }));
}, 4000);

// o Render avisa (SIGTERM) antes de desligar: grava o que faltar
process.on('SIGTERM', async () => { clearTimeout(flushTimer); await flush().catch(() => {}); process.exit(0); });

loadSaved().finally(() => srv.listen(PORT, () => console.log('Discord dos Guri em http://localhost:' + PORT)));
