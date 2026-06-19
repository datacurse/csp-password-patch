// Read decrypted bytes at traced RVAs before applying patches.
'use strict';

const mod = Process.getModuleByName('CLIPStudioPaint.exe');
const base = mod.base;

const RVAS = [0x5c2d861, 0x5c2db5d, 0x5c2dd5d, 0x5c82ab3];

function readSite(rva) {
  const addr = base.add(rva);
  const bytes = addr.readByteArray(16);
  return {
    rva: '0x' + rva.toString(16),
    bytes: Array.from(new Uint8Array(bytes)),
  };
}

setTimeout(function () {
  const samples = RVAS.map(readSite);
  send({ type: 'memory_samples', samples: samples });
}, 8000);

send({ type: 'ready' });
