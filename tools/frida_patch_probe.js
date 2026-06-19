// Probe in-memory patches at traced itzmx RVAs (validation path).
'use strict';

function getExport(moduleName, exportName) {
  return Process.getModuleByName(moduleName).getExportByName(exportName);
}

function readWideString(ptr) {
  if (ptr.isNull()) {
    return '';
  }
  try {
    return ptr.readUtf16String();
  } catch (_) {
    return '';
  }
}

const mod = Process.getModuleByName('CLIPStudioPaint.exe');
const base = mod.base;

// Traced from CreateFileW key validation backtrace.
const PATCH_SITES = [
  { rva: 0x5c2d861, feature: 'startup_gate', bytes: [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3] }, // mov eax,1; ret
  { rva: 0x5c2db5d, feature: 'key_validate_call', bytes: [0x90, 0x90, 0x90, 0x90, 0x90, 0x90] },
  { rva: 0x5c2dd5d, feature: 'key_validate_branch', bytes: [0x90, 0x90, 0x90, 0x90, 0x90, 0x90] },
];

const applied = [];
for (let i = 0; i < PATCH_SITES.length; i++) {
  const site = PATCH_SITES[i];
  const addr = base.add(site.rva);
  const original = addr.readByteArray(site.bytes.length);
  Memory.protect(addr, site.bytes.length, 'rwx');
  addr.writeByteArray(site.bytes);
  applied.push({
    feature: site.feature,
    rva: '0x' + site.rva.toString(16),
    original: Array.from(new Uint8Array(original)),
    patched: site.bytes,
  });
}

Interceptor.attach(getExport('user32.dll', 'SetWindowTextW'), {
  onEnter(args) {
    const text = readWideString(args[1]);
    if (text.toLowerCase().indexOf('password') !== -1) {
      send({ type: 'password_dialog_seen', text: text });
    }
  },
});

Interceptor.attach(getExport('kernel32.dll', 'Sleep'), {
  onEnter(args) {
    const ms = args[0].toInt32();
    if (ms >= 3000 && ms <= 4000) {
      args[0] = ptr(0);
      send({ type: 'splash_sleep_zeroed', ms: ms });
    }
  },
});

send({ type: 'patches_applied', sites: applied });
