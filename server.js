const http = require('http'), fs = require('fs'), path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX = 8; // malha P2P: 8 pessoas por sala é um bom teto
const ICE = process.env.ICE_SERVERS
  ? JSON.parse(process.env.ICE_SERVERS)
  : [{ urls: 'stun:stun.l.google.com:19302' }];

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json',
  '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml' };
const PUB = path.join(__dirname, 'public');

const srv = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  if (url === '/ice') {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify(ICE));
  }
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
  { id: 'memes', name: 'memes', kind: 'text', def: 1 },
  { id: 'voz-geral', name: 'Geral', kind: 'voice', def: 1 },
  { id: 'jogatina', name: 'Jogatina', kind: 'voice', def: 1 },
  { id: 'resenha', name: 'Resenha', kind: 'voice', def: 1 },
];
let next = 1;
const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));
const slug = t => t.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'canal';

const okImg = (v, max) => typeof v === 'string' && v.startsWith('data:image/jpeg') && v.length < max ? v : '';
function setProf(ws, p) {
  p = p || {};
  ws.prof = { about: String(p.about || '').slice(0, 120), avatar: okImg(p.avatar, 60000), banner: okImg(p.banner, 120000),
    color: /^#[0-9a-f]{6}$/i.test(p.color) ? p.color : '' };
}
const pj = c => ({ id: c.id, name: c.nick, prof: c.prof || {} });

function state() {
  const users = [...clients].filter(c => c.nick).map(c => ({ id: c.id, name: c.nick, room: c.room || null }));
  clients.forEach(c => c.nick && send(c, { type: 'state', channels: CH, users }));
}
function leave(ws) {
  const set = rooms.get(ws.room);
  if (!set) return;
  set.delete(ws.id);
  set.forEach(p => send(p, { type: 'peer-leave', id: ws.id }));
  if (!set.size) rooms.delete(ws.room);
  ws.room = null;
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
      send(ws, { type: 'profiles', list: [...clients].filter(c => c.nick && c !== ws).map(pj) });
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
      state();
    } else if (m.type === 'chan-del') {
      const i = CH.findIndex(c => c.id === m.id);
      if (i < 0 || (rooms.get(m.id) || { size: 0 }).size) return;
      if (CH[i].kind === 'text' && CH.filter(c => c.kind === 'text').length <= 1) return; // sempre sobra 1 canal de texto
      CH.splice(i, 1); hist.delete(m.id);
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

srv.listen(PORT, () => console.log('Discord dos Pampas em http://localhost:' + PORT));
