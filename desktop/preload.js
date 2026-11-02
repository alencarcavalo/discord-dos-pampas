const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('pampas', {
  setMute: acc => ipcRenderer.invoke('mute-key', acc),
  onMute: cb => ipcRenderer.on('mute', () => cb()),
});
