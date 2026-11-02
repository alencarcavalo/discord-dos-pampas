const { app, BrowserWindow, globalShortcut, ipcMain, session, desktopCapturer, shell } = require('electron');
const path = require('path');

const URL_SITE = process.env.PAMPAS_URL || 'https://discord-dos-pampas.onrender.com/';
let win;

if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

function load() {
  win.loadURL(URL_SITE).catch(() => {});
}

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 700, minHeight: 500,
    title: 'Discord dos Pampas', backgroundColor: '#1e1f22', autoHideMenuBar: true,
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
  });
  win.removeMenu();

  // microfone, câmera e tela liberados só para o site da turma
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(['media', 'display-capture', 'fullscreen'].includes(perm)));
  // compartilhar tela: pega a tela principal (com o som do computador)
  session.defaultSession.setDisplayMediaRequestHandler((req, cb) => {
    desktopCapturer.getSources({ types: ['screen'] }).then(src => cb({ video: src[0], audio: 'loopback' })).catch(() => cb({}));
  });

  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
  // o Render grátis dorme: se o site ainda estiver acordando, tenta de novo
  win.webContents.on('did-fail-load', (e, code, desc, url, main) => { if (main && code !== -3) setTimeout(load, 5000); });
  win.webContents.on('page-title-updated', e => e.preventDefault());
  load();
});

// atalho global: funciona mesmo com o jogo em foco
ipcMain.handle('mute-key', (e, acc) => {
  globalShortcut.unregisterAll();
  if (!acc) return true;
  try { return globalShortcut.register(acc, () => win && win.webContents.send('mute')); } catch { return false; }
});

app.on('will-quit', () => globalShortcut.unregisterAll());
app.on('window-all-closed', () => app.quit());
