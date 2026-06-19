// Recon: find the itzmx daily-auth persistence + clock checks, and detect the
// password dialog. Run via spawn (frida injected post-loader, which itzmx tolerates).
'use strict';

function W(p) { try { return p.isNull() ? '' : p.readUtf16String(); } catch (e) { return ''; } }
function A(p) { try { return p.isNull() ? '' : p.readAnsiString(); } catch (e) { return ''; } }

function exp(mod, name) {
  try { return Process.getModuleByName(mod).getExportByName(name); } catch (e) { return null; }
}

function hook(mod, name, onEnter, onLeave) {
  const a = exp(mod, name);
  if (!a) return;
  Interceptor.attach(a, { onEnter: onEnter, onLeave: onLeave });
}

// ---- Registry ----
const HKEYS = {};
function keyName(h) { return HKEYS[h.toString()] || h.toString(); }

hook('advapi32.dll', 'RegOpenKeyExW', function (args) {
  this.sub = W(args[1]);
  this.out = args[4];
}, function (ret) {
  if (ret.toInt32() === 0 && !this.out.isNull()) {
    const nh = this.out.readPointer();
    HKEYS[nh.toString()] = this.sub;
  }
});
hook('advapi32.dll', 'RegCreateKeyExW', function (args) {
  this.sub = W(args[1]);
  this.out = args[7];
}, function (ret) {
  if (ret.toInt32() === 0 && !this.out.isNull()) {
    const nh = this.out.readPointer();
    HKEYS[nh.toString()] = this.sub;
  }
});

function readRegData(type, pData, pcb) {
  try {
    if (pData.isNull()) return '';
    const t = type.isNull() ? -1 : type.readU32();
    if (t === 1 || t === 2) return 'SZ:' + W(pData);
    const cb = pcb && !pcb.isNull() ? pcb.readU32() : 8;
    return 'HEX:' + pData.readByteArray(Math.min(cb, 32));
  } catch (e) { return '?'; }
}

hook('advapi32.dll', 'RegQueryValueExW', function (args) {
  this.key = keyName(args[0]); this.val = W(args[1]);
  this.type = args[3]; this.data = args[4]; this.cb = args[5];
}, function (ret) {
  if (ret.toInt32() === 0) {
    send({ t: 'reg_query', key: this.key, val: this.val, data: readRegData(this.type, this.data, this.cb) });
  }
});
hook('advapi32.dll', 'RegGetValueW', function (args) {
  this.key = keyName(args[0]); this.sub = W(args[1]); this.val = W(args[2]);
  this.type = args[4]; this.data = args[5]; this.cb = args[6];
}, function (ret) {
  if (ret.toInt32() === 0) {
    send({ t: 'reg_getvalue', key: this.key, sub: this.sub, val: this.val, data: readRegData(this.type, this.data, this.cb) });
  }
});
hook('advapi32.dll', 'RegSetValueExW', function (args) {
  const t = args[3].toInt32();
  let data = '';
  try { data = (t === 1 || t === 2) ? 'SZ:' + W(args[4]) : 'HEX:' + args[4].readByteArray(Math.min(args[5].toInt32(), 32)); } catch (e) {}
  send({ t: 'reg_set', key: keyName(args[0]), val: W(args[1]), data: data });
});

// ---- Files (filter to app/appdata, skip system) ----
function interesting(path) {
  if (!path) return false;
  const l = path.toLowerCase();
  if (l.indexOf('\\windows\\') !== -1) return false;
  if (l.indexOf('\\program files') !== -1 && l.indexOf('clip studio') === -1) return false;
  return l.indexOf('clip') !== -1 || l.indexOf('celsys') !== -1 || l.indexOf('itzmx') !== -1 ||
         l.indexOf('appdata') !== -1 || l.indexOf('.dat') !== -1 || l.indexOf('.ini') !== -1 ||
         l.indexOf('.cfg') !== -1 || l.indexOf('.txt') !== -1;
}
hook('kernel32.dll', 'CreateFileW', function (args) {
  const p = W(args[0]);
  if (interesting(p)) send({ t: 'file_open', path: p });
});

// ---- Clock ----
hook('kernel32.dll', 'GetLocalTime', null, function () {});
hook('kernel32.dll', 'GetSystemTime', null, function () {});
['GetLocalTime', 'GetSystemTime'].forEach(function (n) {
  hook('kernel32.dll', n, function (args) { this.p = args[0]; }, function () {
    try {
      const y = this.p.readU16(); const mo = this.p.add(2).readU16(); const da = this.p.add(6).readU16();
      send({ t: 'clock', api: n, date: y + '-' + mo + '-' + da });
    } catch (e) {}
  });
});

// ---- Password dialog detection ----
hook('user32.dll', 'CreateWindowExW', function (args) {
  const cls = W(args[1]); const title = W(args[2]);
  if (title && (title.indexOf('password') !== -1 || title.indexOf('Application requires') !== -1)) {
    send({ t: 'password_window', cls: cls, title: title });
  }
});

send({ t: 'recon_ready' });
