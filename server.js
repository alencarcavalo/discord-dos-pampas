const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');
const dns = require('dns'), net = require('net'), https = require('https'), zlib = require('zlib');

const PORT = process.env.PORT || 3000;

// ---------- senha da turma ----------
// No Render > Environment crie a variável SENHA_TURMA com a senha. Sem ela, o site continua aberto para todo mundo.
const SENHA = String(process.env.SENHA_TURMA || process.env.SENHA || '');
// ADM: no Render > Environment crie a variável ADMIN_SENHA com uma senha SÓ SUA (diferente da da turma). Quem digitar essa senha em
// Configurações > Administração vira ADM (apaga mensagens de qualquer pessoa e expulsa). Sem a variável, ninguém é ADM.
const ADMIN_SENHA = String(process.env.ADMIN_SENHA || '');
const ADMINS = new Set();   // cids (aparelhos) que já entraram como ADM: voltam como ADM sozinhos nas próximas vezes
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const passOk = p => !SENHA || crypto.timingSafeEqual(sha(p), sha(SENHA));
// quem erra a senha 6 vezes seguidas fica 10 minutos bloqueado (evita tentar todas as senhas)
const fails = new Map();
const blocked = ip => { const f = fails.get(ip); return !!f && f.until > Date.now(); };
function failed(ip) {
  const now = Date.now(), f = fails.get(ip) || { n: 0, first: now, until: 0 };
  if (now - f.first > 600e3) { f.n = 0; f.first = now; }
  if (++f.n >= 6) { f.until = now + 600e3; f.n = 0; }
  fails.set(ip, f);
}
setInterval(() => { const now = Date.now(); fails.forEach((f, ip) => { if (f.until < now && now - f.first > 600e3) fails.delete(ip); }); }, 3600e3);
const ipOf = req => String(String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '');
// páginas que só entram com a senha certa (cabeçalho x-senha)
function httpAuth(req, res) {
  if (!SENHA) return true;
  const ip = ipOf(req);
  if (!blocked(ip) && passOk(String(req.headers['x-senha'] || ''))) return true;
  if (!blocked(ip)) failed(ip);
  res.writeHead(401); res.end(); return false;
}
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

// ---------- prévia de link (título + imagem do site) ----------
// O servidor abre a página do link e devolve só título, descrição e imagem. Como o endereço é digitado por
// qualquer pessoa da turma, ele só aceita sites públicos (nada de localhost nem rede interna do Render).

function publicIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && ip.startsWith('192.0.0.')) || (a === 198 && (b === 18 || b === 19)));
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l.startsWith('::ffff:')) { const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); return m ? publicIp(m[1]) : false; }
    return /^[23]/.test(l) && !l.startsWith('2002:') && !l.startsWith('2001:0:') && !l.startsWith('2001:db8');   // só endereços públicos normais
  }
  return false;
}
// a conexão usa exatamente o endereço conferido aqui (assim ninguém troca o endereço no meio do caminho)
function safeLookup(host, opts, cb) {
  dns.lookup(host, { all: true, verbatim: true }, (err, list) => {
    if (err) return cb(err);
    if (!list.length || list.some(a => !publicIp(a.address))) return cb(new Error('bloqueado'));
    if (opts && opts.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}
function fetchSafe(u, want, hops = 0) {
  return new Promise((resolve, reject) => {
    let url; try { url = new URL(u); } catch { return reject(new Error('url')); }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) return reject(new Error('url'));
    if (url.port && url.port !== '80' && url.port !== '443') return reject(new Error('porta'));
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && !publicIp(host)) return reject(new Error('bloqueado'));
    const req = (url.protocol === 'https:' ? https : http).request(url, {
      method: 'GET', lookup: safeLookup, timeout: 5000,
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; DiscordDosGuriBot/1.0; link-preview)', accept: want === 'json' ? 'application/json' : 'text/html,image/*;q=0.8,*/*;q=0.5',
        'accept-language': 'pt-BR,pt;q=0.9,en;q=0.5', 'accept-encoding': 'gzip, deflate, br' }
    }, res => {
      const code = res.statusCode;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        if (hops >= 3) return reject(new Error('redirects'));
        let next; try { next = new URL(res.headers.location, url).href; } catch { return reject(new Error('url')); }
        return fetchSafe(next, want, hops + 1).then(resolve, reject);
      }
      if (code !== 200) { res.resume(); return reject(new Error('status ' + code)); }
      const type = String(res.headers['content-type'] || '').toLowerCase();
      if (want === 'html' && type.startsWith('image/')) { res.resume(); return resolve({ url: url.href, image: true }); }
      if (!type.includes(want)) { res.resume(); return reject(new Error('tipo')); }
      let s = res; const enc = String(res.headers['content-encoding'] || '').toLowerCase();
      if (enc === 'gzip') s = res.pipe(zlib.createGunzip()); else if (enc === 'br') s = res.pipe(zlib.createBrotliDecompress()); else if (enc === 'deflate') s = res.pipe(zlib.createInflate());
      const chunks = []; let n = 0, done = false;
      const finish = () => { if (done) return; done = true; res.destroy(); resolve({ url: url.href, type, body: Buffer.concat(chunks) }); };
      s.on('data', c => { chunks.push(c); n += c.length; if (n > 300e3 || (want === 'html' && c.toString('latin1').toLowerCase().includes('</head>'))) finish(); });
      s.on('end', finish); s.on('error', finish);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—', hellip: '…', laquo: '«', raquo: '»', ordm: 'º', ordf: 'ª', copy: '©',
  aacute: 'á', eacute: 'é', iacute: 'í', oacute: 'ó', uacute: 'ú', Aacute: 'Á', Eacute: 'É', Iacute: 'Í', Oacute: 'Ó', Uacute: 'Ú',
  agrave: 'à', Agrave: 'À', acirc: 'â', ecirc: 'ê', ocirc: 'ô', Acirc: 'Â', Ecirc: 'Ê', Ocirc: 'Ô',
  atilde: 'ã', otilde: 'õ', Atilde: 'Ã', Otilde: 'Õ', ccedil: 'ç', Ccedil: 'Ç', uuml: 'ü', ntilde: 'ñ' };
const unent = s => String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : +e.slice(1); try { return String.fromCodePoint(n); } catch { return ''; } }
  return ENT[e] ?? ENT[e.toLowerCase()] ?? m;
});
const clean = (s, n) => unent(s || '').replace(/\s+/g, ' ').trim().slice(0, n);
const httpsOnly = s => { try { const x = new URL(s); if (x.protocol === 'http:') x.protocol = 'https:'; return x.protocol === 'https:' ? x.href : ''; } catch { return ''; } };
function parseHead(buf, type, base) {
  let cs = (type.match(/charset=([\w-]+)/i) || [])[1] || (buf.subarray(0, 2048).toString('latin1').match(/<meta[^>]+charset=["']?([\w-]+)/i) || [])[1];
  let html; try { html = new TextDecoder(cs || 'utf-8').decode(buf); } catch { html = buf.toString('utf8'); }
  const end = html.search(/<\/head>/i); if (end > 0) html = html.slice(0, end);
  const meta = {};
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const at = {};
    tag.replace(/([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g, (_, k, a, b, c) => { at[k.toLowerCase()] = a ?? b ?? c; return _; });
    const key = String(at.property || at.name || '').toLowerCase();
    if (key && at.content != null && !(key in meta)) meta[key] = at.content;
  }
  const ti = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1];
  let image = ''; try { if (meta['og:image'] || meta['twitter:image']) image = httpsOnly(new URL(unent(meta['og:image'] || meta['twitter:image']), base).href); } catch {}
  const title = clean(meta['og:title'] || meta['twitter:title'] || ti, 140);
  if (!title && !image) return null;
  return { title, desc: clean(meta['og:description'] || meta['twitter:description'] || meta.description, 220), image, site: clean(meta['og:site_name'], 40) || new URL(base).hostname.replace(/^www\./, '') };
}
async function buildPreview(u) {
  const host = new URL(u).hostname.toLowerCase();
  if (/^(www\.|m\.|music\.)?youtube\.com$/.test(host) || host === 'youtu.be') {   // YouTube: título e miniatura pelo oEmbed oficial
    const r = await fetchSafe('https://www.youtube.com/oembed?format=json&url=' + encodeURIComponent(u), 'json');
    const j = JSON.parse(r.body.toString('utf8'));
    return j.title ? { site: 'YouTube', title: clean(j.title, 140), desc: clean(j.author_name, 100), image: httpsOnly(j.thumbnail_url) } : null;
  }
  const r = await fetchSafe(u, 'html');
  if (r.image) return { site: new URL(r.url).hostname.replace(/^www\./, ''), title: '', desc: '', image: httpsOnly(r.url) };
  return parseHead(r.body, r.type, r.url);
}
const PV = new Map(), PV_BUSY = new Map(), PV_RATE = new Map();
function linkPreview(u) {
  const hit = PV.get(u); if (hit && hit.exp > Date.now()) return Promise.resolve(hit.v);
  if (PV_BUSY.has(u)) return PV_BUSY.get(u);
  const p = (async () => {
    let v = null; try { v = await buildPreview(u); } catch {}
    PV.set(u, { v, exp: Date.now() + (v ? 6 * 3600e3 : 10 * 60e3) });
    if (PV.size > 300) PV.delete(PV.keys().next().value);
    return v;
  })().finally(() => PV_BUSY.delete(u));
  PV_BUSY.set(u, p); return p;
}
function previewRate(ip) {   // no máximo 120 prévias por minuto por pessoa
  const now = Date.now(), r = PV_RATE.get(ip) || { n: 0, t: now };
  if (now - r.t > 60e3) { r.n = 0; r.t = now; }
  r.n++; PV_RATE.set(ip, r); return r.n <= 120;
}
setInterval(() => { const now = Date.now(); PV_RATE.forEach((r, ip) => { if (now - r.t > 120e3) PV_RATE.delete(ip); }); }, 600e3);

// "versão" do site: muda sempre que o public/index.html muda. O app compara ao reconectar e se recarrega sozinho quando for outra.
let VER = '';
try { VER = crypto.createHash('md5').update(fs.readFileSync(path.join(PUB, 'index.html'))).digest('hex').slice(0, 10); } catch {}
// ---------- capas: jogo (Steam) e música (iTunes, Deezer e por último YouTube) ----------
const COVC = new Map();   // guarda resultados (achou: 24 h, não achou: poucos minutos) para não repetir a busca
const cget = k => { const h = COVC.get(k); return h && Date.now() - h.at < h.ttl ? h : null; };
const cset = (k, v, ttl) => { if (COVC.size > 500) COVC.delete(COVC.keys().next().value); COVC.set(k, { at: Date.now(), ttl, v }); return v; };
const gnorm = x => String(x || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[™®©:'’.,!?-]+/g, ' ').replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
const gtoks = t => gnorm(t).split(' ').filter(w => w.length > 1 || /\d/.test(w));
const BR_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
async function jget(u) {
  const r = await fetch(u, { headers: { 'user-agent': BR_UA, accept: 'application/json', 'accept-language': 'pt-BR,pt;q=0.9,en;q=0.5' }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error('status ' + r.status);
  return r.json();
}
const GALIAS = { cs2: 'counter strike 2', csgo: 'counter strike global offensive', gta5: 'grand theft auto v', gtav: 'grand theft auto v', pubg: 'pubg battlegrounds', 'gta san andreas': 'grand theft auto san andreas' };
async function steamFind(term) {
  const q = gtoks(term);
  const pick = items => {   // o resultado que mais combina com o nome (precisa combinar bem, para não pôr a capa de outro jogo)
    let best = null, bs = 0;
    for (const it of items) { const t = gtoks(it.name); if (!t.length || !q.length) continue; const sc = q.filter(w => t.includes(w)).length / Math.min(q.length, t.length); if (sc > bs) { best = it; bs = sc; } }
    return bs >= .6 ? best : null;
  };
  try {
    const j = await jget('https://store.steampowered.com/api/storesearch/?cc=br&l=english&term=' + encodeURIComponent(term));
    const b = pick((j.items || []).filter(it => !it.type || it.type === 'app'));
    if (b) return { id: b.id, name: b.name, img: b.tiny_image || '' };
  } catch (e) { console.error('Steam (loja) falhou:', e.message); }
  try {
    const j = await jget('https://steamcommunity.com/actions/SearchApps/' + encodeURIComponent(term));
    const b = pick(Array.isArray(j) ? j : []);
    if (b) return { id: +b.appid, name: b.name, img: b.logo || b.icon || '' };
  } catch (e) { console.error('Steam (comunidade) falhou:', e.message); }
  return null;
}
async function gameCover(name) {
  const key = 'g:' + gnorm(name); if (key === 'g:') return null;
  const h = cget(key); if (h) return h.v;
  const v = await steamFind(GALIAS[gnorm(name)] || gnorm(name));
  console.log('Capa do jogo: "' + name + '" → ' + (v ? v.name + ' (' + v.id + ')' : 'não achei na Steam'));
  return cset(key, v, v ? 24 * 3600e3 : 30 * 60e3);
}
// tira do título o que atrapalha a busca: (Official Video), [Lyrics], "Part. fulano", "feat. ..."
const mclean = t => String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[\(\[][^)\]]*[\)\]]/g, ' ')
  .replace(/\b(official|oficial|video|videoclipe|clipe|lyrics?|letra|audio|ao vivo|live|hd|4k|remaster(ed)?|part|feat|ft|prod)\b.*$/i, ' ').replace(/\s+/g, ' ').trim();
async function musicCover(title, artist) {
  const key = 'm:' + gnorm(title + ' ' + artist); const h = cget(key); if (h) return h.v;
  const ct = mclean(title) || title, want = gtoks(ct);
  const score = n => { const t = gtoks(mclean(n) || n); return want.length && t.length ? want.filter(w => t.includes(w)).length / want.length : 0; };
  const term = (ct + ' ' + artist).trim();
  let img = '', src = '';
  try {
    const j = await jget('https://itunes.apple.com/search?media=music&entity=song&limit=10&country=BR&term=' + encodeURIComponent(term));
    const hit = (j.results || []).find(x => score(x.trackName) >= .6 && x.artworkUrl100);
    if (hit) { img = hit.artworkUrl100.replace('100x100bb', '300x300bb'); src = 'iTunes'; }
  } catch (e) { console.error('capa (iTunes) falhou:', e.message); }
  if (!img) try {
    const j = await jget('https://api.deezer.com/search?limit=10&q=' + encodeURIComponent(term));
    const hit = (j.data || []).find(x => score(x.title) >= .6 && x.album && (x.album.cover_big || x.album.cover_medium));
    if (hit) { img = hit.album.cover_big || hit.album.cover_medium; src = 'Deezer'; }
  } catch (e) { console.error('capa (Deezer) falhou:', e.message); }
  if (!img) try {   // vídeo do YouTube (título cheio de enfeite): usa a miniatura do vídeo
    const r = await ytSearch(term);
    const hit = r.find(x => score(x.title) >= .6);
    if (hit) { img = 'https://i.ytimg.com/vi/' + hit.v + '/mqdefault.jpg'; src = 'YouTube'; }
  } catch (e) { console.error('capa (YouTube) falhou:', e.message); }
  console.log('Capa da música: "' + term + '" → ' + (img ? src : 'não achei'));
  const v = img ? { img } : null;
  return cset(key, v, v ? 24 * 3600e3 : 30 * 60e3);
}
const srv = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  if (url === '/ok') { res.setHeader('cache-control', 'no-store'); return res.end('ok'); }   // só para saber se o servidor já acordou
  if (url === '/preview') {
    if (!httpAuth(req, res)) return;
    let q = ''; try { q = new URL(req.url, 'http://x').searchParams.get('u') || ''; } catch {}
    res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'private, max-age=600');
    if (!/^https?:\/\//i.test(q) || q.length > 600 || !previewRate(ipOf(req))) return res.end('null');
    return linkPreview(q).then(v => res.end(JSON.stringify(v || null)));
  }
  if (url === '/game-cover') {   // capa do jogo que a pessoa está jogando
    if (!httpAuth(req, res)) return;
    let q = ''; try { q = new URL(req.url, 'http://x').searchParams.get('q') || ''; } catch {}
    res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'private, max-age=3600');
    if (!q.trim() || q.length > 60 || !previewRate(ipOf(req))) return res.end('null');
    return gameCover(q).then(v => res.end(JSON.stringify(v || null))).catch(() => res.end('null'));
  }
  if (url === '/music-cover') {   // capa da música que a pessoa está ouvindo
    if (!httpAuth(req, res)) return;
    let t = '', ar = ''; try { const sp = new URL(req.url, 'http://x').searchParams; t = sp.get('t') || ''; ar = sp.get('a') || ''; } catch {}
    res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'private, max-age=3600');
    if (!t.trim() || t.length > 100 || ar.length > 100 || !previewRate(ipOf(req))) return res.end('null');
    return musicCover(t, ar).then(v => res.end(JSON.stringify(v || null))).catch(() => res.end('null'));
  }
  if (url === '/mus-search') {   // busca de música (sala de música)
    if (!httpAuth(req, res)) return;
    let q = ''; try { q = new URL(req.url, 'http://x').searchParams.get('q') || ''; } catch {}
    res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'no-store');
    if (!q.trim() || q.length > 100 || !previewRate(ipOf(req))) return res.end('[]');
    return ytSearch(q).then(v => res.end(JSON.stringify(v))).catch(e => { console.error('busca de música falhou:', e.message); res.writeHead(502); res.end('[]'); });
  }
  if (url === '/need-pass') { res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'no-store'); return res.end(JSON.stringify({ pass: !!SENHA })); }
  const sbm = url.match(/^\/sb\/([a-z0-9]+)$/);   // arquivo de um som do soundboard
  if (sbm) {
    if (!httpAuth(req, res)) return;
    const s = SB.find(x => x.id === sbm[1]);
    if (!s) { res.writeHead(404); return res.end(); }
    const mime = (s.data.match(/^data:([^;,]+)/) || [])[1] || 'audio/mpeg';
    res.writeHead(200, { 'content-type': mime, 'cache-control': 'private, max-age=31536000, immutable' });
    return res.end(Buffer.from(s.data.slice(s.data.indexOf(',') + 1), 'base64'));
  }
  if (url === '/ice') {
    if (!httpAuth(req, res)) return;
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
    if (full.endsWith('.html')) res.setHeader('cache-control', 'no-cache');   // sempre confere se tem versão nova
    res.end(data);
  });
});

// ---------- sala de música ----------
// Uma sala só, para todo mundo. O servidor guarda a fila e "em que ponto a música está"; cada pessoa que está ouvindo toca o mesmo
// vídeo do YouTube (player embutido) e se ajusta ao ponto do servidor. A biblioteca e as playlists ficam salvas no Upstash.
const MUS = { lib: [], pls: [], q: [], cur: null, playing: false, pos: 0, at: 0, prev: [] };
const MUS_MAX = { lib: 300, pls: 30, pl: 200, q: 200 };
const musNow = () => Date.now();
const musPos = () => MUS.playing ? MUS.pos + (musNow() - MUS.at) / 1000 : MUS.pos;
const ytId = s => {   // aceita o id puro (11 letras) ou um link do YouTube
  s = String(s || '').trim();
  if (/^[\w-]{11}$/.test(s)) return s;
  try {
    const u = new URL(s), h = u.hostname.toLowerCase().replace(/^(www|m|music)\./, '');
    if (h === 'youtu.be') { const v = u.pathname.slice(1, 12); return /^[\w-]{11}$/.test(v) ? v : ''; }
    if (h === 'youtube.com') {
      const v = u.searchParams.get('v'); if (v && /^[\w-]{11}$/.test(v)) return v;
      const m = u.pathname.match(/^\/(?:shorts|embed|live|v)\/([\w-]{11})/); if (m) return m[1];
    }
  } catch {}
  return '';
};
const durOk = d => { d = Math.round(+d); return Number.isFinite(d) && d >= 1 && d <= 36000 ? d : 0; };
const mkSong = (o, by) => ({ v: o.v, title: clean(o.title, 120) || 'Sem título', artist: clean(o.artist, 80), dur: durOk(o.dur), by: String(by || '').slice(0, 24) });
const musListeners = () => [...clients].filter(c => c.nick && c.musOn);
function musSt() {
  const p = { type: 'mus-st', cur: MUS.cur, q: MUS.q, playing: MUS.playing, pos: MUS.pos, at: MUS.at, now: musNow(), n: musListeners().length };
  clients.forEach(c => c.nick && send(c, p));
}
const musLibPub = () => ({ type: 'mus-lib', lib: MUS.lib, pls: MUS.pls });
function musLib() { const p = musLibPub(); clients.forEach(c => c.nick && send(c, p)); markDirty('\0mus'); }
function musHello(ws) { send(ws, musLibPub()); send(ws, { type: 'mus-st', cur: MUS.cur, q: MUS.q, playing: MUS.playing, pos: MUS.pos, at: MUS.at, now: musNow(), n: musListeners().length }); }
const musErr = (ws, msg) => send(ws, { type: 'mus-err', msg });
function musStart(item) { MUS.cur = item; MUS.pos = 0; MUS.at = musNow(); MUS.playing = !!item; }
function musAdvance() {
  if (MUS.cur) { MUS.prev.push(MUS.cur); if (MUS.prev.length > 20) MUS.prev.shift(); }
  musStart(MUS.q.shift() || null);
}
function musIdle() {   // ninguém ouvindo: pausa onde está (para a fila não ir passando sozinha)
  if (MUS.playing && !musListeners().length) { MUS.pos = musPos(); MUS.playing = false; musSt(); }
}
const qItem = (s, by) => ({ uid: mkMid(), v: s.v, title: s.title, artist: s.artist, dur: s.dur || 0, by: String(by || '').slice(0, 24) });
function shuffled(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
const musRate = ws => { const n = Date.now(); ws.mr = (ws.mr || []).filter(t => n - t < 5000); if (ws.mr.length >= 30) return false; ws.mr.push(n); return true; };

// busca no YouTube (sem chave de API): usa a mesma busca que o próprio site do YouTube usa
const YS = new Map();
async function ytSearch(q) {
  q = String(q).trim().slice(0, 100);
  const hit = YS.get(q.toLowerCase()); if (hit && hit.exp > Date.now()) return hit.v;
  const r = await fetch('https://www.youtube.com/youtubei/v1/search?prettyPrint=false', {
    method: 'POST', signal: AbortSignal.timeout(8000),
    headers: { 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36', 'accept-language': 'pt-BR,pt;q=0.9,en;q=0.5' },
    body: JSON.stringify({ context: { client: { clientName: 'WEB', clientVersion: '2.20250101.00.00', hl: 'pt-BR', gl: 'BR' } }, query: q }),
  });
  if (!r.ok) throw new Error('status ' + r.status);
  const v = parseYtSearch(await r.json());
  YS.set(q.toLowerCase(), { v, exp: Date.now() + 10 * 60e3 });
  if (YS.size > 200) YS.delete(YS.keys().next().value);
  return v;
}
function parseYtSearch(j) {
  const out = [];
  (function walk(o, d) {
    if (!o || typeof o !== 'object' || out.length >= 12 || d > 14) return;
    if (Array.isArray(o)) return o.forEach(x => walk(x, d + 1));
    if (o.videoRenderer && o.videoRenderer.videoId) {
      const x = o.videoRenderer, txt = t => t && (t.simpleText || (t.runs || []).map(r => r.text).join('')) || '';
      const len = txt(x.lengthText);   // "4:39" ou "1:02:03"; vídeo ao vivo não tem
      if (len && /^[\w-]{11}$/.test(x.videoId)) {
        const p = len.split(':').map(Number);
        const dur = p.length === 3 ? p[0] * 3600 + p[1] * 60 + p[2] : p.length === 2 ? p[0] * 60 + p[1] : 0;
        if (dur > 0 && dur <= 36000) out.push({ v: x.videoId, title: clean(txt(x.title), 120), artist: clean(txt(x.ownerText || x.longBylineText), 80), dur });
      }
      return;
    }
    for (const k in o) walk(o[k], d + 1);
  })(j, 0);
  return out.slice(0, 10);
}
async function ytInfo(v) {   // título e canal de um vídeo (oEmbed oficial)
  const r = await fetchSafe('https://www.youtube.com/oembed?format=json&url=' + encodeURIComponent('https://www.youtube.com/watch?v=' + v), 'json');
  const j = JSON.parse(r.body.toString('utf8'));
  if (!j.title) throw new Error('sem título');
  return { v, title: j.title, artist: String(j.author_name || '').replace(/ - Topic$/, ''), dur: 0 };
}

function musMsg(ws, m) {
  const t = m.type, byV = v => MUS.lib.find(s => s.v === v);
  if (t === 'mus-listen') { ws.musOn = !!m.on; if (!ws.musOn) musIdle(); musSt(); return; }
  if (t === 'mus-ended') {   // o player de alguém chegou ao fim (ou deu erro): passa para a próxima
    if (!MUS.cur || MUS.cur.uid !== m.uid) return;
    if (m.err) { const bad = MUS.cur; musListeners().forEach(c => musErr(c, 'Não deu para tocar "' + bad.title + '" (o dono do vídeo bloqueou). Pulei.')); }
    musAdvance(); return musSt();
  }
  if (t === 'mus-dur') {   // a duração só é conhecida quando o player carrega o vídeo
    const d = durOk(m.dur), v = String(m.v || ''); if (!d) return;
    let ch = false;
    [byV(v), ...(MUS.cur && MUS.cur.v === v ? [MUS.cur] : []), ...MUS.q.filter(x => x.v === v)].forEach(s => { if (s && !s.dur) { s.dur = d; ch = true; } });
    if (ch) { musLib(); musSt(); }
    return;
  }
  if (!musRate(ws)) return;
  if (t === 'mus-add') {
    (async () => {
      const v = ytId(m.v || m.url);
      if (!v) return musErr(ws, 'Esse link não parece ser de um vídeo do YouTube.');
      let s = byV(v);
      if (!s) {
        if (MUS.lib.length >= MUS_MAX.lib) return musErr(ws, 'A biblioteca já tem ' + MUS_MAX.lib + ' músicas (o máximo). Tire alguma.');
        let info = m.title ? { v, title: m.title, artist: m.artist, dur: m.dur } : null;
        if (!info) { try { info = await ytInfo(v); } catch { return musErr(ws, 'Não achei esse vídeo. Confira o link.'); } }
        s = byV(v) || (MUS.lib.push(mkSong(info, ws.nick)), MUS.lib[MUS.lib.length - 1]);
        musLib();
      }
      const then = m.then;
      if (then === 'now') { if (MUS.cur) { MUS.prev.push(MUS.cur); } musStart(qItem(s, ws.nick)); musSt(); }
      else if (then === 'next' || then === 'queue') {
        if (MUS.q.length >= MUS_MAX.q) return musErr(ws, 'A fila está cheia.');
        const it = qItem(s, ws.nick);
        if (!MUS.cur) musStart(it); else if (then === 'next') MUS.q.unshift(it); else MUS.q.push(it);
        musSt();
      }
    })().catch(e => console.error('mus-add:', e.message));
  } else if (t === 'mus-lib-del') {
    const i = MUS.lib.findIndex(s => s.v === m.v); if (i < 0) return;
    MUS.lib.splice(i, 1); MUS.pls.forEach(p => { p.vs = p.vs.filter(x => x !== m.v); });
    musLib();
  } else if (t === 'mus-q-del') {
    const i = MUS.q.findIndex(x => x.uid === m.uid); if (i < 0) return;
    MUS.q.splice(i, 1); musSt();
  } else if (t === 'mus-q-clear') { MUS.q.length = 0; musSt();
  } else if (t === 'mus-q-go') {   // clicou numa música da fila: toca ela agora
    const i = MUS.q.findIndex(x => x.uid === m.uid); if (i < 0) return;
    if (MUS.cur) MUS.prev.push(MUS.cur);
    musStart(MUS.q.splice(i, 1)[0]); musSt();
  } else if (t === 'mus-shuffle') { MUS.q = shuffled(MUS.q); musSt();
  } else if (t === 'mus-toggle') {
    if (!MUS.cur) return;
    const want = m.play === undefined ? !MUS.playing : !!m.play;
    if (want && !MUS.playing) { MUS.playing = true; MUS.at = musNow(); }
    else if (!want && MUS.playing) { MUS.pos = musPos(); MUS.playing = false; }
    musSt();
  } else if (t === 'mus-seek') {
    if (!MUS.cur) return;
    const p = Number(m.pos); if (!Number.isFinite(p)) return;
    MUS.pos = Math.max(0, Math.min(p, MUS.cur.dur ? MUS.cur.dur - 1 : 36000)); MUS.at = musNow(); musSt();
  } else if (t === 'mus-next') { if (MUS.cur) { musAdvance(); musSt(); }
  } else if (t === 'mus-prev') {
    if (!MUS.cur && !MUS.prev.length) return;
    if (!MUS.prev.length || musPos() > 4) { MUS.pos = 0; MUS.at = musNow(); }
    else { const back = MUS.prev.pop(); if (MUS.cur) MUS.q.unshift(MUS.cur); musStart(back); }
    musSt();
  } else if (t === 'mus-pl-new') {
    if (MUS.pls.length >= MUS_MAX.pls) return musErr(ws, 'Já existem ' + MUS_MAX.pls + ' playlists (o máximo).');
    const name = String(m.name || '').trim().slice(0, 40); if (!name) return;
    let vs = [];
    if (m.from === 'queue') vs = [...new Set([MUS.cur, ...MUS.q].filter(Boolean).map(x => x.v))].filter(byV);
    else if (m.v && byV(m.v)) vs = [m.v];
    MUS.pls.push({ id: mkMid(), name, by: ws.nick, vs: vs.slice(0, MUS_MAX.pl) }); musLib();
  } else if (t === 'mus-pl-del') {
    const i = MUS.pls.findIndex(p => p.id === m.id); if (i < 0) return;
    MUS.pls.splice(i, 1); musLib();
  } else if (t === 'mus-pl-ren') {
    const p = MUS.pls.find(p => p.id === m.id), name = String(m.name || '').trim().slice(0, 40); if (!p || !name) return;
    p.name = name; musLib();
  } else if (t === 'mus-pl-add') {
    const p = MUS.pls.find(p => p.id === m.id); if (!p || !byV(m.v) || p.vs.includes(m.v)) return;
    if (p.vs.length >= MUS_MAX.pl) return musErr(ws, 'Essa playlist está cheia.');
    p.vs.push(m.v); musLib();
  } else if (t === 'mus-pl-rm') {
    const p = MUS.pls.find(p => p.id === m.id); if (!p) return;
    p.vs = p.vs.filter(x => x !== m.v); musLib();
  } else if (t === 'mus-pl-play') {
    const p = MUS.pls.find(p => p.id === m.id); if (!p) return;
    let songs = p.vs.map(byV).filter(Boolean); if (!songs.length) return musErr(ws, 'Essa playlist está vazia.');
    if (m.mode === 'shuffle') songs = shuffled(songs);
    const items = songs.map(s => qItem(s, ws.nick));
    if (m.mode === 'add') { MUS.q.push(...items.slice(0, Math.max(0, MUS_MAX.q - MUS.q.length))); if (!MUS.cur) musAdvance(); }
    else { MUS.q = items.slice(0, MUS_MAX.q); musAdvance(); }   // toca a playlist do começo, trocando a fila
    musSt();
  }
}

const wss = new WebSocketServer({ server: srv, maxPayload: 18 * 1024 * 1024 });
const rooms = new Map();
const clients = new Set();
const hist = new Map();
const SB = [];   // sons do soundboard: { id, name, emoji, by, cid, data (data:audio/...;base64) }
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
  const r = await fetch(UP_URL, { method: 'POST', headers: { Authorization: 'Bearer ' + UP_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd), signal: AbortSignal.timeout(6000) });
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
      if (id === '\0adm') { await up(['SET', 'guri:admins', JSON.stringify([...ADMINS])]); continue; }
      if (id === '\0mus') { await up(['SET', 'guri:mus', JSON.stringify({ lib: MUS.lib, pls: MUS.pls })]); continue; }
      if (id === '\0mbl') { await up(['SET', 'guri:mbl', JSON.stringify([...MEMB.keys()])]); continue; }
      if (id.startsWith('\0mb:')) { const pid = id.slice(4), m = MEMB.get(pid); await up(m ? ['SET', 'guri:mb:' + pid, JSON.stringify(slimMemb(m))] : ['DEL', 'guri:mb:' + pid]); continue; }
      if (id === '\0st') { await up(['SET', 'guri:stats', JSON.stringify([...STATS])]); continue; }
      if (id === '\0sbl') { await up(['SET', 'guri:sbl', JSON.stringify(SB.map(s => s.id))]); continue; }
      if (id.startsWith('\0sb:')) { const sid = id.slice(4), s = SB.find(x => x.id === sid); await up(s ? ['SET', 'guri:sb:' + sid, JSON.stringify(s)] : ['DEL', 'guri:sb:' + sid]); continue; }
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
    let listOk = false;
    if (Array.isArray(ch) && ch.some(c => c.kind === 'text') && ch.some(c => c.kind === 'voice')) { CH.length = 0; ch.forEach(c => CH.push(c)); listOk = true; }
    for (const c of CH.filter(c => c.kind === 'text')) {
      const h = await up(['GET', 'guri:h:' + c.id]);
      if (h && !hist.has(c.id)) hist.set(c.id, JSON.parse(h).slice(-40));
    }
    try {   // sala de música: biblioteca e playlists
      const raw = await up(['GET', 'guri:mus']);
      if (raw) { const j = JSON.parse(raw); if (!MUS.lib.length) MUS.lib.push(...(j.lib || [])); if (!MUS.pls.length) MUS.pls.push(...(j.pls || [])); }
    } catch (e) { console.error('não consegui carregar a sala de música:', e.message); }
    try {   // sons do soundboard
      const ids = JSON.parse((await up(['GET', 'guri:sbl'])) || '[]');
      for (const id of ids) { const raw = await up(['GET', 'guri:sb:' + id]); if (raw && !SB.some(s => s.id === id)) SB.push(JSON.parse(raw)); }
    } catch (e) { console.error('não consegui carregar os sons do soundboard:', e.message); }
    try { const r = await up(['GET', 'guri:admins']); if (r) JSON.parse(r).forEach(c => ADMINS.add(c)); } catch (e) { console.error('não consegui carregar os ADMs:', e.message); }
    try {   // emblemas: contadores de cada pessoa
      const raw = await up(['GET', 'guri:stats']);
      if (raw) JSON.parse(raw).forEach(([cid, v]) => { if (!STATS.has(cid)) STATS.set(cid, { ...stOf(cid), ...v }); });
    } catch (e) { console.error('não consegui carregar os emblemas:', e.message); }
    try {   // quem já entrou alguma vez (lista de offline)
      const ids = JSON.parse((await up(['GET', 'guri:mbl'])) || '[]');
      for (const pid of ids) { const raw = await up(['GET', 'guri:mb:' + pid]); if (raw && !MEMB.has(pid)) MEMB.set(pid, JSON.parse(raw)); }
    } catch (e) { console.error('não consegui carregar a lista de membros:', e.message); }
    hist.forEach(fixMids);
    prune();
    console.log('Mensagens e canais carregados do Upstash.');
    if (listOk) cleanOrphans().catch(e => console.error('limpeza do Upstash falhou:', e.message));   // só roda se a lista de canais foi lida com sucesso
  } catch (e) { console.error('não consegui carregar o que estava salvo:', e.message); }
}
const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));

// ---------- mensagens: id, resposta, edição e limpeza das antigas ----------
const mkMid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const snip = x => (x.text || '').replace(/\s+/g, ' ').slice(0, 100) || (x.att && x.att[0] ? '📎 ' + x.att[0].name : x.st != null ? 'Figurinha' : '');
// o que cada pessoa recebe: sem o "cid" de ninguém, só com own = true nas mensagens dela
// reações ficam guardadas como { emoji: [{ c: cid, n: nome }] }; cada pessoa recebe só { n: quantas, me: se foi ela, who: nomes }
const rxPub = (rx, viewer) => {
  const o = {};
  for (const e in rx || {}) { const a = rx[e]; if (a && a.length) o[e] = { n: a.length, me: !!viewer.cid && a.some(x => x.c === viewer.cid), who: a.map(x => x.n).slice(0, 12) }; }
  return o;
};
const okEmoji = e => typeof e === 'string' && e.length > 0 && [...e].length <= 10 && /^[\p{Extended_Pictographic}\p{Emoji_Modifier}‍️]+$/u.test(e) && /\p{Extended_Pictographic}/u.test(e);
const pidOf = cid => cid ? crypto.createHash('sha256').update('pid:' + cid).digest('hex').slice(0, 12) : null;   // id público e FIXO da pessoa (o cid em si nunca é enviado)
// uid = id público de quem mandou (antes era o número da conexão, que recomeça do 1 a cada reinício e fazia a mensagem pegar a foto de outra pessoa)
const pub = (m, viewer) => { const { cid, rx, uid, ...rest } = m; return { ...rest, uid: pidOf(cid), rx: rxPub(rx, viewer), own: !!cid && cid === viewer.cid }; };
const sbPub = viewer => SB.map(s => ({ id: s.id, name: s.name, emoji: s.emoji, by: s.by, own: !!viewer.cid && s.cid === viewer.cid }));
const sendSb = ws => send(ws, { type: 'sb', list: sbPub(ws) });
const sbAll = () => clients.forEach(c => c.nick && sendSb(c));
// mensagens antigas (de antes desta versão) ganham um id estável para poderem ser respondidas
const fixMids = arr => arr.forEach((m, i) => { if (!m.mid) m.mid = 'l' + (+m.t || 0).toString(36) + i; });
// limpeza automática (pode ajustar no Render > Environment; 0 desliga):
//   MSG_TTL_DAYS  = apaga mensagens com mais de N dias   (padrão 30)
//   ATT_TTL_DAYS  = tira imagens/arquivos com mais de N dias e deixa só o texto (padrão 7)
const envDays = (k, def) => (process.env[k] === undefined || process.env[k] === '' ? def : +process.env[k]);
const TTL_DAYS = envDays('MSG_TTL_DAYS', 30), ATT_DAYS = envDays('ATT_TTL_DAYS', 7);
function prune() {
  const now = Date.now();
  hist.forEach((h, id) => {
    let changed = false;
    if (TTL_DAYS > 0) {
      const keep = h.filter(m => m.t >= now - TTL_DAYS * 864e5);
      if (keep.length !== h.length) { h.splice(0, h.length, ...keep); changed = true; }
    }
    if (ATT_DAYS > 0) h.forEach(m => {
      if (m.att && m.att.length && m.t < now - ATT_DAYS * 864e5) {
        m.text = (m.text ? m.text + '\n' : '') + m.att.map(a => '📎 ' + a.name + ' (anexo antigo, removido)').join('\n');
        m.att = []; changed = true;
      }
    });
    if (changed) markDirty(id);
  });
}
// históricos guardados no Upstash de canais que não existem mais
async function cleanOrphans() {
  let cur = '0', n = 0;
  do {
    const [nx, keys] = await up(['SCAN', cur, 'MATCH', 'guri:h:*', 'COUNT', 100]);
    cur = String(nx);
    for (const k of keys) {
      const id = k.slice('guri:h:'.length);
      if (!CH.some(c => c.id === id && c.kind === 'text')) { await up(['DEL', k]); n++; }
    }
  } while (cur !== '0');
  if (n) console.log('Limpeza: ' + n + ' histórico(s) de canal apagado removido(s) do Upstash.');
}
const slug = t => t.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'canal';

// aceita JPEG (imagem reduzida) ou GIF animado (limite maior)
const okImg = (v, max, maxGif) => typeof v === 'string' && ((v.startsWith('data:image/jpeg;base64,') && v.length < max) || (v.startsWith('data:image/gif;base64,') && v.length < maxGif)) ? v : '';
// bordas de foto liberadas (ids iguais aos do index.html)
const FRAMES = ['bandeira', 'erva', 'chimarrao', 'chapeu', 'neon', 'coracao', 'coroa', 'gato', 'galaxia', 'termica', 'touro', 'ferradura', 'corrente', 'caveira', 'tinta', 'chamas', 'cartola', 'palha', 'neitzke', 'cuia-ouro', 'espora', 'brasa-viva', 'lua-noite', 'aurora', 'lenda-pampa'];
// bordas EXCLUSIVAS: só quem cumpriu a missão (chegar no nível l do emblema b) pode usar. O servidor confere, então não dá para burlar.
const FRAME_REQ = { 'cuia-ouro': { b: 'gaucho', l: 2 }, 'espora': { b: 'cine', l: 2 }, 'brasa-viva': { b: 'churras', l: 3 }, 'lua-noite': { b: 'coruja', l: 2 }, 'aurora': { b: 'madruga', l: 2 }, 'lenda-pampa': { b: 'lenda', l: 2 } };
const isAdmCid = cid => !!ADMIN_SENHA && !!cid && ADMINS.has(cid);   // ADM tem tudo liberado (emblemas no nível máximo e todas as bordas)
const frameOpen = (cid, f) => { const r = FRAME_REQ[f]; if (!r || isAdmCid(cid)) return true; const s = cid && STATS.get(cid); return !!s && (s.lv[r.b] || 0) >= r.l; };
const numIn = (v, lo, hi, def) => (Number.isFinite(+v) && v !== null && v !== '' ? Math.min(hi, Math.max(lo, +v)) : def);   // número dentro de um intervalo (zoom/posição da foto)
function setProf(ws, p) {
  p = p || {};
  ws.prof = { about: String(p.about || '').slice(0, 120), avatar: okImg(p.avatar, 60000, 5.8e6), banner: okImg(p.banner, 120000, 5.8e6),
    color: /^#[0-9a-f]{6}$/i.test(p.color) ? p.color : '', frame: FRAMES.includes(p.frame) && frameOpen(ws.cid, p.frame) ? p.frame : '',
    avZ: numIn(p.avZ, .5, 3, 1), avX: numIn(p.avX, 0, 1, .5), avY: numIn(p.avY, 0, 1, .5), avAr: numIn(p.avAr, .2, 5, 1), avR: numIn(p.avR, -360, 360, 0) };
}
// ---------- emblemas e conquistas ----------
// Tudo é contado AQUI no servidor (ninguém consegue "dar" emblema para si mesmo). Cada pessoa (identificada pelo cid do aparelho)
// tem contadores; cada emblema tem 5 níveis, que destravam quando o contador passa do número da lista "tiers".
//   v = min em chamada com a turma | s = min transmitindo tela | c = min com câmera | m = mensagens | r = reações dadas
//   p = sons tocados no soundboard | g = min em chamada com 4+ pessoas | n = min de madrugada (0h-5h) | e = min cedinho (5h-8h)
//   d = dias diferentes que entrou | bs = maior sequência de dias seguidos
const DEFS = [
  { id: 'gaucho', emoji: '🤠', name: 'Gaúcho', desc: 'Passe tempo em chamada de voz com a turma.', key: 'v', unit: 'min', tiers: [60, 300, 1200, 3000, 6000], titles: ['Peão Novo', 'Peão de Estância', 'Capataz', 'Gaúcho Raiz', 'Gaúcho Master'] },
  { id: 'guri', emoji: '🧉', name: 'Guri dos Pampas', desc: 'Apareça por aqui em dias diferentes.', key: 'd', unit: 'dias', tiers: [1, 5, 15, 30, 60], titles: ['Guri Novo', 'Guri de Casa', 'Guri Fiel', 'Guri Raiz', 'Guri dos Pampas'] },
  { id: 'firmeza', emoji: '🔥', name: 'Firmeza', desc: 'Entre vários dias seguidos, sem faltar nenhum.', key: 'bs', unit: 'dias', tiers: [3, 7, 14, 30, 60], titles: ['Pegando Fogo', 'Semana Firme', 'Quinzena Braba', 'Mês de Ferro', 'Inabalável'] },
  { id: 'cine', emoji: '📺', name: 'Cinegrafista', desc: 'Transmita a sua tela em chamada com a turma.', key: 's', unit: 'min', tiers: [30, 120, 600, 1500, 3000], titles: ['Estreante da Tela', 'Sessão da Tarde', 'Diretor', 'Produtor', 'Rede Pampa'] },
  { id: 'cam', emoji: '📷', name: 'Cara Limpa', desc: 'Fique com a câmera ligada em chamada.', key: 'c', unit: 'min', tiers: [15, 60, 300, 900, 2000], titles: ['Deu a Cara', 'Cara Limpa', 'Rosto Conhecido', 'Cara de Casa', 'Astro da Câmera'] },
  { id: 'prosa', emoji: '💬', name: 'Bochincho', desc: 'Mande mensagens nos canais de texto.', key: 'm', unit: 'n', tiers: [10, 100, 500, 1500, 5000], titles: ['Prosa Mansa', 'Conversador', 'Bochincheiro', 'Língua Solta', 'Rei do Bochincho'] },
  { id: 'tri', emoji: '🤙', name: 'Tri Legal', desc: 'Reaja às mensagens da turma.', key: 'r', unit: 'n', tiers: [10, 50, 200, 600, 1500], titles: ['Gostei', 'Mão Aberta', 'Tri Legal', 'Tri Demais', 'Tchê Reação'] },
  { id: 'gaita', emoji: '🪗', name: 'Gaiteiro', desc: 'Toque sons no soundboard durante a chamada.', key: 'p', unit: 'n', tiers: [5, 30, 100, 300, 1000], titles: ['Assobiador', 'Gaitinha', 'Gaiteiro', 'Maestro', 'Gaiteiro Master'] },
  { id: 'churras', emoji: '🥩', name: 'Churrasco', desc: 'Fique em chamada quando tem 4 ou mais pessoas: resenha cheia!', key: 'g', unit: 'min', tiers: [30, 120, 600, 1500, 3000], titles: ['Fogo de Chão', 'Espeto Corrido', 'Assador', 'Churrasqueiro', 'Mestre do Braseiro'] },
  { id: 'coruja', emoji: '🦉', name: 'Coruja', desc: 'Fique em chamada de madrugada (da meia-noite às 5h).', key: 'n', unit: 'min', tiers: [30, 120, 300, 900, 1800], titles: ['Olho Aberto', 'Insone', 'Coruja', 'Coruja Raiz', 'Guardião da Noite'] },
  { id: 'madruga', emoji: '🌅', name: 'Madrugador', desc: 'Fique em chamada cedinho (das 5h às 8h).', key: 'e', unit: 'min', tiers: [15, 60, 180, 600, 1200], titles: ['Cedo Levantado', 'Mateando Cedo', 'Madrugador', 'Galo de Estância', 'Sol Nascente'] },
  // emblemas EXCLUSIVOS (special): não contam uso, contam o progresso nos outros emblemas
  { id: 'colecao', emoji: '🏆', name: 'Colecionador', desc: 'Exclusivo: some os níveis de todos os outros emblemas.', key: 'tl', unit: 'niv', special: 1, tiers: [5, 15, 30, 45, 55], titles: ['Primeiras Medalhas', 'Vitrine Cheia', 'Colecionador', 'Grande Colecionador', 'Museu dos Pampas'] },
  { id: 'lenda', emoji: '👑', name: 'Lenda do Pampa', desc: 'Exclusivo: leve emblemas até o nível máximo (nível 5).', key: 'mx', unit: 'emb', special: 1, tiers: [1, 3, 5, 8, 11], titles: ['Promessa', 'Fenômeno', 'Ídolo', 'Mito', 'Lenda do Pampa'] },
  // emblema SÓ DE ADM: ninguém ganha por uso (a chave 'admx' nunca sobe); o ADM recebe no máximo automaticamente (ver lvOf)
  { id: 'adm', emoji: '🛡️', name: 'Administrador', desc: 'Exclusivo de ADM: só quem é administrador do servidor tem.', key: 'admx', unit: 'n', special: 1, adm: 1, tiers: [1, 1, 1, 1, 1], titles: ['Administrador', 'Administrador', 'Administrador', 'Administrador', 'Administrador'] },
];
const STATS = new Map();   // cid -> { v, s, c, m, r, p, g, n, e, d, sk, bs, ld, lv: { emblema: nível }, pick: [ids] | null }
const BRT = () => new Date(Date.now() - 3 * 3600e3);   // horário de Brasília (getUTC* dessa data = hora daqui)
const dayKey = d => d.toISOString().slice(0, 10);
function stOf(cid) {
  let s = STATS.get(cid);
  if (!s) { s = { v: 0, s: 0, c: 0, m: 0, r: 0, p: 0, g: 0, n: 0, e: 0, d: 0, sk: 0, bs: 0, ld: '', lv: {}, pick: null }; STATS.set(cid, s); }
  return s;
}
const lvlOf = (def, v) => def.tiers.filter(t => v >= t).length;
// os até 5 emblemas que aparecem no cartão: os que a pessoa escolheu, ou (sem escolha) os de maior nível
const lvOf = (cid, s) => isAdmCid(cid) ? Object.fromEntries(DEFS.map(d => [d.id, d.tiers.length])) : s.lv;   // níveis (ADM: tudo no máximo)
function showcase(cid) {
  const s0 = cid && STATS.get(cid); if (!s0) return [];
  const s = { ...s0, lv: lvOf(cid, s0) };
  const have = DEFS.filter(d => (s.lv[d.id] || 0) > 0);
  let ids = Array.isArray(s.pick) ? s.pick.filter(id => have.some(d => d.id === id)) : have.map((d, i) => ({ d, i })).sort((a, b) => (b.d.adm ? 1 : 0) - (a.d.adm ? 1 : 0) || s.lv[b.d.id] - s.lv[a.d.id] || a.i - b.i).map(x => x.d.id);
  return ids.slice(0, 5).map(id => ({ id, lvl: s.lv[id] }));
}
const achPayload = ws => {
  const s = stOf(ws.cid || ''), vals = {};
  derive(s);
  DEFS.forEach(d => vals[d.id] = isAdmCid(ws.cid) ? Math.max(s[d.key] || 0, d.tiers[d.tiers.length - 1]) : s[d.key] || 0);
  return { type: 'ach', defs: DEFS.map(d => ({ id: d.id, emoji: d.emoji, name: d.name, desc: d.desc, unit: d.unit, tiers: d.tiers, titles: d.titles, special: !!d.special, adm: !!d.adm })), frames: Object.entries(FRAME_REQ).map(([id, r]) => ({ id, b: r.b, l: r.l, open: frameOpen(ws.cid, id) })), vals, lv: lvOf(ws.cid, s), pick: s.pick, sk: s.sk, adm: isAdmCid(ws.cid) };
};
const tellProfile = ws => clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) }));
// confere se algum emblema subiu de nível; se sim, avisa a pessoa e atualiza o cartão dela para a turma
function derive(s) {   // contadores dos emblemas exclusivos: tl = soma dos níveis, mx = quantos estão no nível máximo
  const base = DEFS.filter(d => !d.special);
  s.tl = base.reduce((n, d) => n + (s.lv[d.id] || 0), 0);
  s.mx = base.filter(d => (s.lv[d.id] || 0) >= d.tiers.length).length;
}
function checkLv(ws) {
  if (!ws.cid) return;
  const s = stOf(ws.cid), ups = [];
  for (let k = 0; k < 2; k++) {   // 2 voltas: o exclusivo pode subir por causa de um emblema que acabou de subir
    derive(s);
    DEFS.forEach(d => { const l = lvlOf(d, s[d.key] || 0); if (l > (s.lv[d.id] || 0)) { s.lv[d.id] = l; ups.push({ id: d.id, lvl: l }); } });
  }
  s.fr = s.fr || {};
  const fr = Object.keys(FRAME_REQ).filter(f => !s.fr[f] && frameOpen(ws.cid, f));
  fr.forEach(f => s.fr[f] = 1);
  if (fr.length) ups.push(...fr.map(f => ({ frame: f })));
  if (!ups.length) return;
  markDirty('\0st');
  ups.forEach(u => send(ws, u.frame ? { type: 'unlock-fr', id: u.frame } : { type: 'unlock', ...u }));
  send(ws, achPayload(ws));
  tellProfile(ws);
}
function bump(ws, key, n = 1) {
  if (!ws.cid) return;
  const s = stOf(ws.cid); s[key] = (s[key] || 0) + n;
  markDirty('\0st'); checkLv(ws);
}
// conta 1 dia novo (e a sequência de dias seguidos) na primeira vez que a pessoa aparece no dia
function touchDay(ws) {
  if (!ws.cid) return;
  const s = stOf(ws.cid), now = BRT(), t = dayKey(now);
  if (s.ld === t) return;
  s.sk = s.ld === dayKey(new Date(now - 864e5)) ? s.sk + 1 : 1;
  s.d++; s.ld = t; s.bs = Math.max(s.bs || 0, s.sk);
  markDirty('\0st'); checkLv(ws);
}
// a cada minuto: quem está em chamada COM mais alguém ganha tempo (sozinho na sala não conta, para não dar para "farmar")
setInterval(() => {
  const h = BRT().getUTCHours();
  rooms.forEach(set => {
    if (set.size < 2) return;
    set.forEach(ws => {
      if (!ws.cid || !ws.nick) return;
      const s = stOf(ws.cid);
      s.v++; if (ws.vs && ws.vs.screen) s.s++; if (ws.vs && ws.vs.cam) s.c++;
      if (set.size >= 4) s.g++;
      if (h < 5) s.n++; else if (h < 8) s.e++;
      markDirty('\0st'); checkLv(ws);
    });
  });
  clients.forEach(c => c.nick && touchDay(c));
}, 60000);

const pj = c => ({ id: c.id, name: c.nick, prof: c.prof || {}, bd: showcase(c.cid), adm: !!c.admin });

// ---------- membros que já entraram (aparecem como OFFLINE na lista da direita) ----------
// pid -> { cid, name, prof, seen }. Fica salvo no Upstash (uma chave por pessoa). GIF muito grande não é guardado (a pessoa fica só com a letra/cor).
const MEMB = new Map(), MEMB_MAX = 80, KEEP_AV = 200000, KEEP_BN = 300000;
function slimMemb(m) {
  const pr = { ...(m.prof || {}) };
  if ((pr.avatar || '').length > KEEP_AV) pr.avatar = '';
  if ((pr.banner || '').length > KEEP_BN) pr.banner = '';
  return { cid: m.cid, name: m.name, prof: pr, seen: m.seen };
}
const isOnlinePid = pid => [...clients].some(c => c.nick && c.cid && pidOf(c.cid) === pid);
function rememberMember(ws) {
  if (!ws.cid || !ws.nick) return;
  const pid = pidOf(ws.cid);
  MEMB.set(pid, { cid: ws.cid, name: ws.nick, prof: ws.prof || {}, seen: Date.now() });
  markDirty('\0mb:' + pid);
  if (MEMB.size > MEMB_MAX) {   // passou do limite: tira quem ficou mais tempo sem aparecer
    const old = [...MEMB].filter(([k]) => k !== pid && !isOnlinePid(k)).sort((a, b) => a[1].seen - b[1].seen)[0];
    if (old) { MEMB.delete(old[0]); markDirty('\0mb:' + old[0]); }
  }
  markDirty('\0mbl');
}
const offPj = pid => { const m = MEMB.get(pid); return m ? { type: 'profile', id: 'o:' + pid, name: m.name, prof: m.prof || {}, bd: showcase(m.cid), adm: isAdmCid(m.cid) } : null; };
const offList = () => { const on = new Set([...clients].filter(c => c.nick && c.cid).map(c => pidOf(c.cid))); return [...MEMB].filter(([k]) => !on.has(k)).sort((a, b) => b[1].seen - a[1].seen).map(([k, m]) => ({ id: 'o:' + k, pid: k, name: m.name, seen: m.seen })); };

function state() {
  const users = [...clients].filter(c => c.nick).map(c => ({ id: c.id, name: c.nick, pid: pidOf(c.cid), room: c.room || null, vs: c.vs || {}, act: c.act || null, jt: c.room ? (c.jt || null) : null }));
  const now = Date.now();   // hora do servidor: o app usa para contar o tempo de chamada sem depender do relógio do PC
  const off = offList();
  clients.forEach(c => c.nick && send(c, { type: 'state', channels: CH, users, off, now }));
}
function leave(ws) {
  const set = rooms.get(ws.room);
  if (!set) return;
  set.delete(ws.id);
  set.forEach(p => send(p, { type: 'peer-leave', id: ws.id }));
  if (!set.size) rooms.delete(ws.room);
  ws.room = null; ws.jt = null;
  if (ws.vs) ws.vs = { ...ws.vs, cam: false, screen: false };
  state();
}

wss.on('connection', (ws, req) => {
  ws.id = String(next++);
  ws.seen = Date.now();   // última vez que esta conexão deu sinal de vida (o app manda um ping a cada 4 s)
  ws.ip = ipOf(req);
  clients.add(ws);
  ws.on('pong', () => { ws.seen = Date.now(); });   // o navegador responde ao ping do protocolo sozinho, mesmo com o app minimizado/na bandeja (timers do JS congelados)
  ws.on('error', e => console.log('Erro de conexão (' + (ws.nick || ws.id) + '): ' + e.message));
  ws.on('message', raw => {
    ws.seen = Date.now();
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'hello') {
      if (SENHA && !ws.nick) {   // senha da turma: sem ela certa, a pessoa nem aparece na lista
        if (blocked(ws.ip)) { send(ws, { type: 'bad-pass', wait: true }); return ws.close(); }
        if (!passOk(String(m.pass || ''))) { failed(ws.ip); send(ws, { type: 'bad-pass' }); return ws.close(); }
      }
      ws.nick = String(m.name || 'Guri').slice(0, 24);
      ws.cid = String(m.cid || '').slice(0, 64);   // identidade fixa deste aparelho (nunca é enviada aos outros): é ela que prova que a mensagem é sua para editar
      // mesma pessoa/aparelho já conectada (conexão "fantasma" ou outra aba): derruba a antiga para não aparecer duplicado
      if (ws.cid) [...clients].filter(c => c !== ws && c.nick && c.cid === ws.cid).forEach(old => {
        console.log('Duplicada: ' + ws.nick + ' entrou de novo, derrubando a conexão antiga.');
        send(old, { type: 'replaced' });
        old.nick = '';
        leave(old);
        setTimeout(() => { try { old.terminate(); } catch {} }, 200);
      });
      setProf(ws, m.prof);
      rememberMember(ws);
      send(ws, { type: 'hello-ok', id: ws.id, v: VER });
      sendSb(ws);
      musHello(ws);
      [...clients].filter(c => c.nick && c !== ws).forEach(c => send(ws, { type: 'profile', ...pj(c) })); // um por um: GIFs grandes não cabem num pacote só
      offList().forEach(o => { const j = offPj(o.pid); if (j) send(ws, j); });   // perfis de quem está offline (um por um)
      clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) }));
      ws.admin = !!ADMIN_SENHA && !!ws.cid && ADMINS.has(ws.cid);
      send(ws, { type: 'admin', on: ws.admin, enabled: !!ADMIN_SENHA });
      send(ws, achPayload(ws)); touchDay(ws);
      state();
    } else if (m.type === 'profile' && ws.nick) {
      ws.nick = String(m.name || ws.nick).slice(0, 24);
      setProf(ws, m.prof);
      rememberMember(ws);
      clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) }));
      state();
    } else if (!ws.nick) {
      return;
    } else if (m.type === 'ach-get') {
      send(ws, achPayload(ws));
    } else if (m.type === 'badge-pick') {   // escolher (até 5) emblemas para o cartão; ids = null volta para o automático
      if (!ws.cid) return;
      const s = stOf(ws.cid);
      s.pick = Array.isArray(m.ids) ? [...new Set(m.ids.map(String))].filter(id => (lvOf(ws.cid, s)[id] || 0) > 0).slice(0, 5) : null;
      markDirty('\0st'); tellProfile(ws); send(ws, achPayload(ws));
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
    } else if (m.type === 'admin-login') {   // vira ADM digitando a senha (o servidor confere; no máx. 5 tentativas por minuto)
      if (!ADMIN_SENHA || !ws.cid) return send(ws, { type: 'admin', on: false, enabled: !!ADMIN_SENHA, err: ADMIN_SENHA ? 'sem aparelho' : 'A senha de ADM ainda não foi criada no Render (variável ADMIN_SENHA).' });
      const now = Date.now(); ws.admT = (ws.admT || []).filter(t => now - t < 60000);
      if (ws.admT.length >= 5) return send(ws, { type: 'admin', on: false, enabled: true, err: 'Muitas tentativas. Espere 1 minuto.' });
      ws.admT.push(now);
      if (!crypto.timingSafeEqual(sha(m.senha || ''), sha(ADMIN_SENHA))) return send(ws, { type: 'admin', on: false, enabled: true, err: 'Senha de ADM errada.' });
      ws.admin = true; ADMINS.add(ws.cid); markDirty('\0adm');
      send(ws, { type: 'admin', on: true, enabled: true }); tellProfile(ws); send(ws, achPayload(ws));
    } else if (m.type === 'admin-logout') {
      ws.admin = false; ADMINS.delete(ws.cid); markDirty('\0adm');
      if (ws.prof && !frameOpen(ws.cid, ws.prof.frame)) { ws.prof.frame = ''; clients.forEach(c => c !== ws && c.nick && send(c, { type: 'profile', ...pj(ws) })); }   // saiu do ADM: perde a borda trancada
      send(ws, { type: 'admin', on: false, enabled: !!ADMIN_SENHA }); tellProfile(ws); send(ws, achPayload(ws));
    } else if (m.type === 'kick') {
      if (!ws.admin) return;   // só ADM expulsa
      const t = [...clients].find(c => c.id === String(m.id) && c !== ws);
      if (!t) return;
      send(t, { type: 'kicked', by: ws.nick });
      setTimeout(() => t.close(), 200);
    } else if (m.type === 'history') {
      const hh = hist.get(m.channel) || []; fixMids(hh);
      send(ws, { type: 'history', channel: m.channel, msgs: hh.map(x => pub(x, ws)) });
    } else if (m.type === 'msg') {
      if (!CH.some(c => c.id === m.channel && c.kind === 'text')) return;
      const att = (Array.isArray(m.att) ? m.att : []).slice(0, 4)
        .filter(a => a && typeof a.data === 'string' && a.data.startsWith('data:') && a.data.length < 4.3e6)
        .map(a => ({ name: String(a.name).slice(0, 100), type: String(a.type).slice(0, 60), size: +a.size || 0, data: a.data }));
      const st = Number.isInteger(m.st) ? m.st : null;
      const text = String(m.text || '').slice(0, 2000);
      if (!text && !att.length && st === null) return;
      const h = hist.get(m.channel) || [];
      fixMids(h);
      const msg = { mid: mkMid(), cid: ws.cid || '', uid: ws.id, from: ws.nick, text, att, st, t: Date.now() };
      const rep = typeof m.re === 'string' ? h.find(x => x.mid === m.re) : null;   // resposta: o servidor confere a mensagem original
      if (rep) msg.re = { mid: rep.mid, from: rep.from, text: snip(rep) };
      h.push(msg); if (h.length > 40) h.shift();
      hist.set(m.channel, h);
      markDirty(m.channel);
      clients.forEach(c => c.nick && send(c, { type: 'msg', channel: m.channel, msg: pub(msg, c) }));
      if (Date.now() - (ws.mAt || 0) >= 3000) { ws.mAt = Date.now(); bump(ws, 'm'); }   // no máx. 1 mensagem a cada 3 s conta (anti-spam)
    } else if (m.type === 'msg-edit') {
      const x = (hist.get(m.channel) || []).find(y => y.mid === m.mid);
      if (!x || !ws.cid || x.cid !== ws.cid) return;   // só o dono edita
      const text = String(m.text || '').slice(0, 2000);
      if (text === x.text || (!text && !(x.att && x.att.length) && x.st == null)) return;
      x.text = text; x.edited = Date.now();
      markDirty(m.channel);
      clients.forEach(c => c.nick && send(c, { type: 'msg-edit', channel: m.channel, mid: x.mid, text, edited: x.edited }));
    } else if (m.type === 'msg-del') {
      const h = hist.get(m.channel) || [], i = h.findIndex(y => y.mid === m.mid);
      if (i < 0 || !ws.cid || (h[i].cid !== ws.cid && !ws.admin)) return;   // só o dono apaga (ou um ADM)
      h.splice(i, 1);
      markDirty(m.channel);
      clients.forEach(c => c.nick && send(c, { type: 'msg-del', channel: m.channel, mid: m.mid }));
    } else if (m.type === 'react') {
      const x = (hist.get(m.channel) || []).find(y => y.mid === m.mid), e = m.emoji;
      if (!x || !ws.cid || !okEmoji(e)) return;
      const rx = x.rx || (x.rx = {});
      let a = rx[e];
      if (!a) { if (Object.keys(rx).length >= 20) return; a = rx[e] = []; }
      const i = a.findIndex(y => y.c === ws.cid);   // clicou de novo na mesma reação: tira a sua
      if (i >= 0) a.splice(i, 1); else { a.push({ c: ws.cid, n: ws.nick }); if (Date.now() - (ws.rAt || 0) >= 2000) { ws.rAt = Date.now(); bump(ws, 'r'); } }
      if (!a.length) delete rx[e];
      if (!Object.keys(rx).length) delete x.rx;
      markDirty(m.channel);
      clients.forEach(c => c.nick && send(c, { type: 'react', channel: m.channel, mid: x.mid, rx: rxPub(x.rx, c) }));
    } else if (m.type === 'sb-add') {
      const name = String(m.name || '').trim().slice(0, 24), data = String(m.data || '');
      const emoji = okEmoji(String(m.emoji || '')) ? String(m.emoji) : '🔊';
      if (!ws.cid || !name || SB.length >= 30) return send(ws, { type: 'sb-err', msg: SB.length >= 30 ? 'O soundboard já tem 30 sons (o máximo). Apague algum.' : 'Faltou o nome do som.' });
      if (data.length > 700000 || !/^data:audio\/[a-z0-9.+-]+(;[a-z0-9=.+-]+)*;base64,/i.test(data)) return send(ws, { type: 'sb-err', msg: 'Esse arquivo de áudio não serve (grande demais ou formato estranho).' });
      const id = mkMid();
      SB.push({ id, name, emoji, by: ws.nick, cid: ws.cid, data });
      markDirty('\0sb:' + id); markDirty('\0sbl');
      sbAll();
    } else if (m.type === 'sb-del') {
      const i = SB.findIndex(s => s.id === m.id);
      if (i < 0 || !ws.cid || SB[i].cid !== ws.cid) return;   // só quem adicionou o som apaga
      SB.splice(i, 1);
      markDirty('\0sb:' + m.id); markDirty('\0sbl');
      sbAll();
    } else if (m.type === 'sb-play') {
      const id = String(m.id || '');
      if (!ws.room || !(/^b:[a-z]{1,16}$/.test(id) || SB.some(s => s.id === id))) return;   // só toca quem está numa chamada
      const now = Date.now(); if (now - (ws.sbAt || 0) < 1000) return; ws.sbAt = now;        // 1 som por segundo, por pessoa
      (rooms.get(ws.room) || new Map()).forEach(p => send(p, { type: 'sb-play', id, from: ws.id, name: ws.nick }));
      bump(ws, 'p');
    } else if (typeof m.type === 'string' && m.type.startsWith('mus-')) {
      musMsg(ws, m);
    } else if (m.type === 'join') {
      const c = CH.find(c => c.id === m.room && c.kind === 'voice');
      if (!c || ws.room === c.id) return;
      const set = rooms.get(c.id) || new Map();
      if (set.size >= MAX) return send(ws, { type: 'full' });
      if (ws.room) leave(ws);
      ws.room = c.id; ws.jt = Date.now();
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
  ws.on('close', (code) => {
    if (ws.nick) console.log('Saiu: ' + ws.nick + ' (código ' + code + ')');
    const wasNick = ws.nick, wasCid = ws.cid;
    leave(ws); clients.delete(ws);
    if (wasNick && wasCid) {   // guarda a última vez visto e avisa os outros do perfil dele como offline (se não entrou de novo em outro lugar)
      rememberMember(ws);
      const pid = pidOf(wasCid);
      if (!isOnlinePid(pid)) { const j = offPj(pid); if (j) clients.forEach(c => c.nick && send(c, j)); }
    }
    musIdle(); state();
  });
});

// a cada 4 s manda para todo mundo o ping de cada pessoa (medido por ela mesma até o servidor)
setInterval(() => {
  const p = {}; clients.forEach(c => { if (c.nick && c.ping !== undefined) p[c.id] = c.ping; });
  const mem = { used: Math.round(process.memoryUsage().rss / 1048576), limit: +process.env.MEM_LIMIT_MB || 512 };   // plano grátis do Render = 512 MB
  clients.forEach(c => c.nick && send(c, { type: 'pings', p, mem }));
}, 4000);

// a cada 20 s manda um ping do protocolo WebSocket (o navegador responde sozinho). Só derruba a conexão que não deu NENHUM sinal
// (nem mensagem nem pong) por 90 s: aí é queda de verdade (internet caiu, celular dormiu). O 'close' tira da lista.
setInterval(() => {
  const now = Date.now();
  clients.forEach(c => {
    if (now - c.seen > 90000) { console.log('Sem sinal há 90 s: derrubando ' + (c.nick || c.id)); c.terminate(); return; }
    try { c.ping(); } catch {}
  });
}, 20000);

setInterval(prune, 3600e3);   // limpeza das mensagens/anexos antigos, de hora em hora

// o Render avisa (SIGTERM) antes de desligar: grava o que faltar
process.on('uncaughtException', e => console.error('ERRO NÃO TRATADO (servidor continua):', e));
process.on('unhandledRejection', e => console.error('PROMESSA REJEITADA (servidor continua):', e));
process.on('SIGTERM', async () => { clearTimeout(flushTimer); await flush().catch(() => {}); process.exit(0); });

Promise.race([loadSaved(), new Promise(r => setTimeout(r, 10000))]).finally(() => srv.listen(PORT, () => console.log('Discord dos Guri em http://localhost:' + PORT)));
