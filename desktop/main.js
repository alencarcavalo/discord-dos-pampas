const { app, BrowserWindow, globalShortcut, ipcMain, session, desktopCapturer, shell } = require('electron');
const path = require('path');
let autoUpdater = null;
try { ({ autoUpdater } = require('electron-updater')); } catch { /* sem atualizador (ex.: rodando em modo dev sem npm install) */ }

const URL_SITE = process.env.PAMPAS_URL || 'https://discord-dos-pampas.onrender.com/';
let win;

// Com o jogo em tela cheia por cima, o Chromium acha que a janela está "escondida" e
// congela timers (indicador de quem está falando, redução de eco...). Desligamos isso.
app.commandLine.appendSwitch('disable-features', 'CalculateNativeWinOcclusion');
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
app.setAppUserModelId('br.pampas.discord');

if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

function load() {
  win.loadURL(URL_SITE).catch(() => {});
}

// ---------- seletor de tela / janela ----------
let pending = null;
function askPicker(list) {
  return new Promise(resolve => {
    if (pending) pending(null);
    const t = setTimeout(() => { pending = null; resolve(null); }, 120000);
    pending = r => { clearTimeout(t); pending = null; resolve(r); };
    win.webContents.send('pick-sources', list);
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
ipcMain.handle('upd-install', () => { if (canUpdate && lastUpd.s === 'ready') autoUpdater.quitAndInstall(false, true); });
ipcMain.handle('app-version', () => app.getVersion());


// ---------- atividade: jogo aberto e música tocando (só Windows) ----------
const { execFile } = require('child_process');
const PS_SCRIPT = [
  "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
  "$ErrorActionPreference='SilentlyContinue'",
  "$r=@{procs=@();java='';media=$null}",
  "$ps=Get-Process",
  "$r.procs=@($ps|Select-Object -ExpandProperty ProcessName -Unique)",
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
      try { const j = JSON.parse(out.trim().split('\n').pop()); win.webContents.send('act', { procs: j.procs || [], java: j.java || '', media: j.media || null }); } catch {}
    });
}
ipcMain.handle('act-enable', (e, on) => { actOn = !!on; if (actOn) pollActivity(); return process.platform === 'win32'; });
setInterval(pollActivity, 20000);

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 700, minHeight: 500,
    title: 'Discord dos Guri', backgroundColor: '#1e1f22', autoHideMenuBar: true,
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, backgroundThrottling: false },
  });
  win.removeMenu();

  // microfone, câmera e tela liberados só para o site da turma
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(['media', 'display-capture', 'fullscreen'].includes(perm)));

  // compartilhar tela: a página mostra o seletor (telas e janelas) e devolve a escolha
  session.defaultSession.setDisplayMediaRequestHandler(async (req, cb) => {
    try {
      const ready = await win.webContents.executeJavaScript('!!window.__pickerReady').catch(() => false);
      const sources = await desktopCapturer.getSources({
        types: ['screen', 'window'], thumbnailSize: { width: 320, height: 180 }, fetchWindowIcons: true,
      });
      if (!sources.length) return cb({});
      if (!ready) { // página antiga sem seletor: tela principal, como antes
        const scr = sources.find(s => s.id.startsWith('screen:')) || sources[0];
        return cb({ video: scr, audio: 'loopback' });
      }
      const list = sources.map(s => ({
        id: s.id, name: s.name, screen: s.id.startsWith('screen:'),
        thumb: s.thumbnail && !s.thumbnail.isEmpty() ? s.thumbnail.toDataURL() : '',
        icon: s.appIcon && !s.appIcon.isEmpty() ? s.appIcon.toDataURL() : '',
      }));
      const pick = await askPicker(list);
      const src = pick && sources.find(s => s.id === pick.id);
      if (!src) return cb({});
      cb(pick.audio ? { video: src, audio: 'loopback' } : { video: src });
    } catch { cb({}); }
  });

  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
  // o Render grátis dorme: se o site ainda estiver acordando, tenta de novo
  win.webContents.on('did-fail-load', (e, code, desc, url, main) => { if (main && code !== -3) setTimeout(load, 5000); });
  win.webContents.on('page-title-updated', e => e.preventDefault());
  load();
  setupUpdater();
});

// atalho global: funciona mesmo com o jogo em foco
ipcMain.handle('mute-key', (e, acc) => {
  globalShortcut.unregisterAll();
  if (!acc) return true;
  try { return globalShortcut.register(acc, () => win && win.webContents.send('mute')); } catch { return false; }
});

app.on('will-quit', () => globalShortcut.unregisterAll());
app.on('window-all-closed', () => app.quit());
