const { app, BrowserWindow, globalShortcut, ipcMain, session, desktopCapturer, shell, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
let autoUpdater = null;
try { ({ autoUpdater } = require('electron-updater')); } catch { /* sem atualizador (ex.: rodando em modo dev sem npm install) */ }

const URL_SITE = process.env.PAMPAS_URL || 'https://discord-dos-pampas.onrender.com/';
let win, tray = null, quitting = false;   // quitting = true só quando a pessoa escolhe Sair de verdade
let splash = null, shown = false;          // janelinha de abertura / janela principal já apareceu?
const TB = 32;
const startHidden = process.argv.includes('--hidden');   // aberto junto com o Windows: fica escondido perto do relógio, sem a janelinha de abertura                             // altura da faixa de cima (onde ficam minimizar, maximizar e fechar)

// Com o jogo em tela cheia por cima, o Chromium acha que a janela está "escondida" e
// congela timers (indicador de quem está falando, redução de eco...). Desligamos isso.
app.commandLine.appendSwitch('disable-features', 'CalculateNativeWinOcclusion');
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
app.setAppUserModelId('br.pampas.discord');

if (!app.requestSingleInstanceLock()) app.quit();
function showWin() { if (!win || win.isDestroyed()) return; if (!shown) { if (splash && !splash.isDestroyed()) splash.focus(); return; } if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
app.on('second-instance', showWin);

function load() {
  win.loadURL(URL_SITE).catch(() => {});
}

// ---------- seletor de tela / janela ----------
let pending = null;
function waitPick() {   // espera a escolha da pessoa (ou ela cancelar)
  return new Promise(resolve => {
    const t = setTimeout(() => { pending = null; resolve(null); }, 120000);
    pending = r => { clearTimeout(t); pending = null; resolve(r); };
  });
}
ipcMain.on('pick-result', (e, r) => { if (pending) pending(r && typeof r.id === 'string' ? { id: r.id, audio: !!r.audio } : null); });

// ---------- atualização automática ----------
let lastUpd = { s: 'idle' };
const canUpdate = !!autoUpdater && app.isPackaged;
function upd(m) { lastUpd = m; if (win && !win.isDestroyed()) win.webContents.send('upd', m); }
function setupUpdater() {
  if (!canUpdate) return;
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on('checking-for-update', () => upd({ s: 'checking' }));
  autoUpdater.on('update-available', i => upd({ s: 'downloading', v: i.version, pct: 0 }));
  autoUpdater.on('update-not-available', () => upd({ s: 'none' }));
  autoUpdater.on('download-progress', p => upd({ s: 'downloading', v: lastUpd.v, pct: Math.round(p.percent) }));
  autoUpdater.on('update-downloaded', i => upd({ s: 'ready', v: i.version }));
  autoUpdater.on('error', e => upd({ s: 'error', m: String((e && e.message) || e).slice(0, 160) }));
  const check = () => autoUpdater.checkForUpdates().catch(() => {});
  setTimeout(check, 8000);
  setInterval(() => { if (lastUpd.s !== 'ready' && lastUpd.s !== 'downloading') check(); }, 30 * 60 * 1000);
  ipcMain.handle('upd-check', () => { if (lastUpd.s !== 'downloading') check(); });
}
if (!canUpdate) ipcMain.handle('upd-check', () => upd({ s: 'dev' }));
ipcMain.handle('upd-state', () => lastUpd);
ipcMain.handle('upd-install', () => { if (canUpdate && lastUpd.s === 'ready') { quitting = true; autoUpdater.quitAndInstall(false, true); } });
ipcMain.handle('app-version', () => app.getVersion());


// ---------- atividade: jogo aberto e música tocando (só Windows) ----------
const { execFile } = require('child_process');
const PS_SCRIPT = [
  "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
  "$ErrorActionPreference='SilentlyContinue'",
  "$r=@{procs=@();paths=@();java='';media=$null}",
  "$ps=Get-Process",
  "$r.procs=@($ps|Select-Object -ExpandProperty ProcessName -Unique)",
  "$r.paths=@($ps|Where-Object{$p=$_.Path; $p -and (($p -like '*steamapps\\common\\*') -or ($p -like '*\\Epic Games\\*') -or ($p -like '*\\GOG Galaxy\\Games\\*') -or ($p -like '*\\GOG Games\\*') -or ($p -like '*\\Riot Games\\*') -or ($p -like '*\\XboxGames\\*') -or ($p -like '*\\Ubisoft Game Launcher\\games\\*') -or ($p -like '*\\EA Games\\*'))}|ForEach-Object{[string]$_.Path}|Select-Object -Unique)",
  "$r.java=[string](($ps|Where-Object{$_.ProcessName -like 'javaw*' -and $_.MainWindowTitle}|Select-Object -First 1).MainWindowTitle)",
  "try{",
  "Add-Type -AssemblyName System.Runtime.WindowsRuntime",
  "$asTask=([System.WindowsRuntimeSystemExtensions].GetMethods()|Where-Object{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation*'})[0]",
  "function Await($t,$rt){$m=$asTask.MakeGenericMethod($rt);$n=$m.Invoke($null,@($t));$n.Wait(-1)|Out-Null;$n.Result}",
  "$mt=[Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager,Windows.Media.Control,ContentType=WindowsRuntime]",
  "$pt=[Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties,Windows.Media.Control,ContentType=WindowsRuntime]",
  "$mgr=Await ($mt::RequestAsync()) $mt",
  "foreach($s in $mgr.GetSessions()){ if([int]$s.GetPlaybackInfo().PlaybackStatus -eq 4){ $p=Await ($s.TryGetMediaPropertiesAsync()) $pt; $r.media=@{title=[string]$p.Title;artist=[string]$p.Artist;app=[string]$s.SourceAppUserModelId}; break } }",
  "}catch{}",
  "$r|ConvertTo-Json -Compress -Depth 4",
].join('\n');
const PS_ENC = Buffer.from(PS_SCRIPT, 'utf16le').toString('base64');
let actOn = false, actBusy = false;
function pollActivity() {
  if (!actOn || actBusy || process.platform !== 'win32' || !win || win.isDestroyed()) return;
  actBusy = true;
  execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', PS_ENC],
    { windowsHide: true, timeout: 20000, maxBuffer: 4 * 1024 * 1024 }, (err, out) => {
      actBusy = false;
      if (err || !out || !win || win.isDestroyed()) return;
      try { const j = JSON.parse(out.trim().split('\n').pop()); win.webContents.send('act', { procs: j.procs || [], paths: [].concat(j.paths || []), java: j.java || '', media: j.media || null }); } catch {}
    });
}
ipcMain.handle('act-enable', (e, on) => { actOn = !!on; if (actOn) pollActivity(); return process.platform === 'win32'; });
setInterval(pollActivity, 20000);

// ---------- janelinha de abertura (pequena, sem moldura, cantos arredondados) ----------
const splashAt = Date.now();
const SPLASH_MIN_MS = 4500;   // milissegundos que a abertura fica na tela, no mínimo
function openSplash() {
  splash = new BrowserWindow({
    width: 440, height: 520, frame: false, transparent: true, hasShadow: false, resizable: false,
    minimizable: false, maximizable: false, fullscreenable: false, show: false, center: true,
    backgroundColor: '#00000000', title: 'Pampa Chat', icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  splash.removeMenu();
  splash.loadFile(path.join(__dirname, 'splash.html')).catch(() => {});
  splash.once('ready-to-show', () => { if (splash && !splash.isDestroyed()) splash.show(); });
  splash.on('closed', () => { splash = null; if (!shown) { quitting = true; app.quit(); } });   // fechou a abertura antes de abrir: sai do app
}
function revealMain() {   // a página já está pronta: mostra a janela grande e some com a abertura
  if (shown || !win || win.isDestroyed()) return; shown = true;
  win.show(); win.focus(); setTimeout(syncBar, 700);
  if (splash && !splash.isDestroyed()) {
    splash.webContents.executeJavaScript("document.getElementById('splash').classList.add('out')").catch(() => {});
    setTimeout(() => { if (splash && !splash.isDestroyed()) splash.close(); }, 850);
  }
}
let siteLoaded = false;
function waitPage() {   // espera a animação de entrada do próprio site terminar (ou a tela de login aparecer)
  const t0 = Date.now();
  const iv = setInterval(async () => {
    if (shown || !win || win.isDestroyed()) return clearInterval(iv);
    const giveUp = Date.now() - t0 > 90000;
    if (!siteLoaded && !giveUp) return;
    const ok = giveUp || await win.webContents.executeJavaScript("document.readyState !== 'loading' && !document.documentElement.classList.contains('spl')").catch(() => false);
    if (!ok) return;
    clearInterval(iv);
    setTimeout(revealMain, Math.max(0, SPLASH_MIN_MS - (Date.now() - splashAt)));   // tempo mínimo da animação de abertura (mude SPLASH_MIN_MS para mais ou menos)
  }, 300);
}

// ---------- faixa de cima: sem barra cinza e sem nome, só os 3 botões na cor do app ----------
const BAR_CSS = `html{--tb:${TB}px}
body{padding-top:var(--tb)!important}
body.mod #app{padding-top:0!important}
html::before{content:"";position:fixed;left:0;top:0;right:0;height:var(--tb);-webkit-app-region:drag;z-index:2147483000}
/* telas que cobrem a janela inteira: descem a altura da faixa para não ficar por baixo dos botões do Windows */
#cfg{padding-top:var(--tb)!important}
#cfgx{top:calc(22px + var(--tb))!important}
#updbar{top:var(--tb)!important}
#lbx{padding-top:calc(68px + var(--tb))!important}
#lbx .lbb{top:calc(16px + var(--tb))!important}
body>div[style*="top:14px"]{top:calc(14px + var(--tb))!important}`;
let lastBar = '';
async function syncBar() {   // pinta o fundo dos botões com a cor real do app naquele canto (acompanha o tema)
  try {
    if (!win || win.isDestroyed() || typeof win.setTitleBarOverlay !== 'function' || !win.isVisible() || win.isMinimized()) return;
    const [w] = win.getContentSize();
    const img = await win.webContents.capturePage({ x: Math.max(0, w - 90), y: 6, width: 1, height: 1 });
    const bm = img.toBitmap(); if (!bm || bm.length < 4) return;
    const r = bm[2], g = bm[1], b = bm[0];
    const hex = '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
    if (hex === lastBar) return; lastBar = hex;
    win.setTitleBarOverlay({ color: hex, symbolColor: (0.299 * r + 0.587 * g + 0.114 * b) > 150 ? '#1e1f22' : '#dbdee1', height: TB });
  } catch {}
}
setInterval(syncBar, 4000);

app.whenReady().then(() => {
  if (startHidden) shown = true; else openSplash();   // escondido: sem abertura; o ícone do relógio abre a janela
  win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 700, minHeight: 500, show: false,
    title: 'Pampa Chat', backgroundColor: '#0d0a14', autoHideMenuBar: true,
    titleBarStyle: 'hidden', titleBarOverlay: { color: '#0d0a14', symbolColor: '#dbdee1', height: TB },
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, backgroundThrottling: false },
  });
  win.removeMenu();

  // ícone perto do relógio: fechar no X só esconde a janela, o app (voz, atalho do microfone) continua rodando
  try {
    const img = nativeImage.createFromPath(path.join(__dirname, 'build', 'icon.png'));
    if (!img.isEmpty()) {
      tray = new Tray(img.resize({ width: 32, height: 32 }));
      tray.setToolTip('Pampa Chat');
      tray.setContextMenu(Menu.buildFromTemplate([
        { label: 'Abrir o Pampa Chat', click: showWin },
        { type: 'separator' },
        { label: 'Sair', click: () => { quitting = true; app.quit(); } },
      ]));
      tray.on('click', showWin);
      let avisou = false;
      win.on('close', e => {
        if (quitting) return;
        e.preventDefault(); win.hide();
        if (!avisou) { avisou = true; try { tray.displayBalloon({ title: 'Pampa Chat', content: 'Continua rodando aqui. Clique no ícone para abrir, ou botão direito > Sair.' }); } catch {} }
      });
    }
  } catch {}

  if (startHidden && !tray) { win.show(); }   // sem ícone perto do relógio ninguém conseguiria abrir a janela: mostra

  // microfone, câmera e tela liberados só para o site da turma
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(['media', 'display-capture', 'fullscreen'].includes(perm)));

  // compartilhar tela: a página mostra o seletor (telas e janelas) e devolve a escolha
  session.defaultSession.setDisplayMediaRequestHandler(async (req, cb) => {
    try {
      const ready = await win.webContents.executeJavaScript('!!window.__pickerReady').catch(() => false);
      const TYPES = ['screen', 'window'];
      if (!ready) { // página antiga sem seletor: tela principal, como antes
        const all = await desktopCapturer.getSources({ types: TYPES, thumbnailSize: { width: 320, height: 180 }, fetchWindowIcons: true });
        if (!all.length) return cb({});
        const scr = all.find(s => s.id.startsWith('screen:')) || all[0];
        return cb({ video: scr, audio: 'loopback' });
      }
      if (pending) return cb({});   // já tem um seletor aberto: ignora pedido repetido
      const res = waitPick();
      const FULL = { types: TYPES, thumbnailSize: { width: 320, height: 180 }, fetchWindowIcons: true };
      // 1) lista rápida (miniatura mínima, sem ícones): o seletor mostra os nomes na hora
      let quick = null, usedFull = false;
      try { quick = await desktopCapturer.getSources({ types: TYPES, thumbnailSize: { width: 1, height: 1 }, fetchWindowIcons: false }); } catch (e) { console.error('lista rápida falhou:', e && e.message); }
      if (!pending) return cb({});   // a pessoa cancelou enquanto procurava
      if (!quick || !quick.length) { quick = await desktopCapturer.getSources(FULL); usedFull = true; }   // plano B: lista completa (mais lenta)
      if (!pending) return cb({});
      if (!quick.length) { pending(null); await res; return cb({}); }
      const toList = srcs => srcs.map(s => ({
        id: s.id, name: s.name, screen: s.id.startsWith('screen:'),
        thumb: s.thumbnail && !s.thumbnail.isEmpty() && s.thumbnail.getSize().width > 8 ? s.thumbnail.toDataURL() : '',
        icon: s.appIcon && !s.appIcon.isEmpty() ? s.appIcon.toDataURL() : '',
      }));
      let all = quick;
      win.webContents.send('pick-sources', toList(quick));
      // 2) miniaturas e ícones (demora uns segundos): chegam depois, sem travar o seletor
      if (!usedFull) desktopCapturer.getSources(FULL).then(full => {
        if (!pending || !full.length) return;
        all = full; win.webContents.send('pick-sources', toList(full));
      }).catch(() => {});
      const pick = await res;
      const src = pick && (all.find(s => s.id === pick.id) || quick.find(s => s.id === pick.id));
      if (!src) return cb({});
      cb(pick.audio ? { video: src, audio: 'loopback' } : { video: src });
    } catch (e) {
      console.error('compartilhar tela:', e);
      if (pending) pending(null);
      win.webContents.executeJavaScript('window.__pkErr&&window.__pkErr(' + JSON.stringify(String((e && e.message) || e).slice(0, 120)) + ')').catch(() => {});   // mostra o motivo no aviso do app
      cb({});
    }
  });

  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
  // o Render grátis dorme: se o site ainda estiver acordando, tenta de novo
  win.webContents.on('did-fail-load', (e, code, desc, url, main) => { if (main && code !== -3) setTimeout(load, 5000); });
  win.webContents.on('page-title-updated', e => e.preventDefault());
  win.webContents.on('dom-ready', () => {
    win.webContents.insertCSS(BAR_CSS).catch(() => {});
    try { if (win.webContents.getURL().startsWith(new URL(URL_SITE).origin)) siteLoaded = true; } catch {}   // página de erro do Chromium não conta
    setTimeout(syncBar, 900);
  });
  // tela cheia da janela: sem faixa em cima
  const tb = on => win.webContents.executeJavaScript(on ? "document.documentElement.style.removeProperty('--tb')" : "document.documentElement.style.setProperty('--tb','0px')").catch(() => {});
  ['enter-full-screen', 'enter-html-full-screen'].forEach(ev => win.on(ev, () => tb(false)));   // tela cheia (da janela ou de um vídeo): sem faixa
  ['leave-full-screen', 'leave-html-full-screen'].forEach(ev => win.on(ev, () => tb(true)));
  if (!startHidden) waitPage();
  load();
  setupUpdater();
});

// ---------- iniciar com o Windows ----------
const canAuto = () => app.isPackaged && process.platform === 'win32';   // só no app instalado (no modo de teste registraria o Electron solto)
const autoOn = () => { const s = app.getLoginItemSettings({ args: ['--hidden'] }); return !!s.openAtLogin && s.executableWillLaunchAtLogin !== false; };
ipcMain.handle('autostart-get', () => canAuto() ? autoOn() : null);
ipcMain.handle('autostart-set', (e, on) => {
  if (!canAuto()) return null;
  try { app.setLoginItemSettings({ openAtLogin: !!on, path: process.execPath, args: ['--hidden'] }); } catch {}
  return autoOn();
});

// atalho global: funciona mesmo com o jogo em foco
ipcMain.handle('mute-key', (e, acc) => {
  globalShortcut.unregisterAll();
  if (!acc) return true;
  try { return globalShortcut.register(acc, () => win && win.webContents.send('mute')); } catch { return false; }
});

// vários atalhos globais: { mute, deaf, leave } -> devolve a lista dos que não foram registrados
ipcMain.handle('set-keys', (e, map) => {
  globalShortcut.unregisterAll();
  const bad = [];
  for (const [name, acc] of Object.entries(map || {})) {
    if (!acc || !['mute', 'deaf', 'leave'].includes(name)) continue;
    let ok = false;
    try { ok = globalShortcut.register(acc, () => win && win.webContents.send('key', name)); } catch {}
    if (!ok) bad.push(name);
  }
  return bad;
});

app.on('before-quit', () => { quitting = true; });
app.on('will-quit', () => globalShortcut.unregisterAll());
app.on('window-all-closed', () => { if (quitting) app.quit(); });
