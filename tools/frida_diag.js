// Diagnostic: enumerate top-level windows of this process and probe the password dialog.
'use strict';

function getExport(m, n) {
  return Process.getModuleByName(m).getExportByName(n);
}

const FindWindowW = new NativeFunction(getExport('user32.dll', 'FindWindowW'), 'pointer', [
  'pointer',
  'pointer',
]);
const FindWindowExW = new NativeFunction(getExport('user32.dll', 'FindWindowExW'), 'pointer', [
  'pointer',
  'pointer',
  'pointer',
  'pointer',
]);
const GetWindowTextW = new NativeFunction(getExport('user32.dll', 'GetWindowTextW'), 'int', [
  'pointer',
  'pointer',
  'int',
]);
const GetClassNameW = new NativeFunction(getExport('user32.dll', 'GetClassNameW'), 'int', [
  'pointer',
  'pointer',
  'int',
]);
const GetWindowThreadProcessId = new NativeFunction(
  getExport('user32.dll', 'GetWindowThreadProcessId'),
  'uint',
  ['pointer', 'pointer']
);
const EnumWindows = new NativeFunction(getExport('user32.dll', 'EnumWindows'), 'int', [
  'pointer',
  'pointer',
]);
const GetCurrentProcessId = new NativeFunction(
  getExport('kernel32.dll', 'GetCurrentProcessId'),
  'uint',
  []
);
const IsWindowVisible = new NativeFunction(getExport('user32.dll', 'IsWindowVisible'), 'int', [
  'pointer',
]);

const myPid = GetCurrentProcessId();

function winText(hwnd) {
  const buf = Memory.alloc(512);
  GetWindowTextW(hwnd, buf, 256);
  return buf.readUtf16String();
}
function winClass(hwnd) {
  const buf = Memory.alloc(512);
  GetClassNameW(hwnd, buf, 256);
  return buf.readUtf16String();
}

function dumpChildren(hwnd, depth) {
  const out = [];
  let child = FindWindowExW(hwnd, ptr(0), ptr(0), ptr(0));
  let guard = 0;
  while (!child.isNull() && guard < 50) {
    out.push({ class: winClass(child), text: winText(child).slice(0, 60), hwnd: child.toString() });
    child = FindWindowExW(hwnd, child, ptr(0), ptr(0));
    guard += 1;
  }
  return out;
}

const enumCb = new NativeCallback(
  function (hwnd, lparam) {
    const pidBuf = Memory.alloc(8);
    GetWindowThreadProcessId(hwnd, pidBuf);
    const wp = pidBuf.readU32();
    if (wp === myPid && IsWindowVisible(hwnd) !== 0) {
      const t = winText(hwnd);
      const c = winClass(hwnd);
      if (t && t.length > 0) {
        send({
          type: 'window',
          hwnd: hwnd.toString(),
          class: c,
          text: t.slice(0, 80),
          children: dumpChildren(hwnd, 0),
        });
      }
    }
    return 1;
  },
  'int',
  ['pointer', 'pointer']
);

const EnumChildWindows = new NativeFunction(
  getExport('user32.dll', 'EnumChildWindows'),
  'int',
  ['pointer', 'pointer', 'pointer']
);

const descendants = [];
const childCb = new NativeCallback(
  function (hwnd, lparam) {
    descendants.push({
      hwnd: hwnd.toString(),
      class: winClass(hwnd),
      text: winText(hwnd).slice(0, 60),
      visible: IsWindowVisible(hwnd),
    });
    return 1;
  },
  'int',
  ['pointer', 'pointer']
);

let done = false;
const t = setInterval(function () {
  const titleBuf = Memory.allocUtf16String('Application requires password to start');
  const hwnd = FindWindowW(ptr(0), titleBuf);
  if (hwnd.isNull()) {
    return;
  }
  if (done) {
    return;
  }
  done = true;
  descendants.length = 0;
  EnumChildWindows(hwnd, childCb, ptr(0));
  send({ type: 'all_descendants', dialog: hwnd.toString(), items: descendants });
  clearInterval(t);
}, 500);

send({ type: 'ready_diag', pid: myPid });
