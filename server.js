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

const wss = new WebSocketServer({ server: srv });
const rooms = new Map();
let next = 1;
const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));

wss.on('connection', ws => {
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'join' && !ws.room) {
      const room = String(m.room || 'geral').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 30) || 'geral';
      const set = rooms.get(room) || new Map();
      if (set.size >= MAX) return send(ws, { type: 'full' });
      ws.id = String(next++);
      ws.nick = String(m.name || 'Guri').slice(0, 24);
      ws.room = room;
      rooms.set(room, set);
      send(ws, { type: 'joined', id: ws.id, room, peers: [...set.values()].map(p => ({ id: p.id, name: p.nick })) });
      set.forEach(p => send(p, { type: 'peer-join', id: ws.id, name: ws.nick }));
      set.set(ws.id, ws);
    } else if (ws.room) {
      const set = rooms.get(ws.room);
      if (m.type === 'signal') {
        const t = set.get(String(m.to));
        if (t) send(t, { type: 'signal', from: ws.id, data: m.data });
      } else if (m.type === 'chat') {
        const text = String(m.text || '').slice(0, 500);
        if (text) set.forEach(p => send(p, { type: 'chat', from: ws.nick, text }));
      }
    }
  });
  ws.on('close', () => {
    const set = rooms.get(ws.room);
    if (!set) return;
    set.delete(ws.id);
    set.forEach(p => send(p, { type: 'peer-leave', id: ws.id }));
    if (!set.size) rooms.delete(ws.room);
  });
});

srv.listen(PORT, () => console.log('Discord dos Pampas em http://localhost:' + PORT));
