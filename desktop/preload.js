const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('pampas', {
  setMute: acc => ipcRenderer.invoke('mute-key', acc),
  onMute: cb => ipcRenderer.on('mute', () => cb()),
  // seletor de tela/janela
  onPick: cb => ipcRenderer.on('pick-sources', (e, list) => cb(list)),
  pickResult: r => ipcRenderer.send('pick-result', r),
  // versão e atualização automática
  version: () => ipcRenderer.invoke('app-version'),
  updState: () => ipcRenderer.invoke('upd-state'),
  onUpdate: cb => ipcRenderer.on('upd', (e, m) => cb(m)),
  checkUpdate: () => ipcRenderer.invoke('upd-check'),
  installUpdate: () => ipcRenderer.invoke('upd-install'),
});
