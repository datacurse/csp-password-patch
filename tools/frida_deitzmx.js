// De-itzmx runtime bypass: UI hooks only (memory patches trigger language-file warning).
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

function shouldBypass(text) {
  if (!text) {
    return false;
  }
  const lower = text.toLowerCase();
  if (
    lower.indexOf('password') !== -1 ||
    lower.indexOf('application requires') !== -1 ||
    lower.indexOf('itzmx') !== -1 ||
    lower.indexOf('anti-resale') !== -1
  ) {
    return true;
  }
  if (
    text.indexOf('警告') !== -1 ||
    text.indexOf('语言文件') !== -1 ||
    text.indexOf('篡改') !== -1 ||
    text.indexOf('串改') !== -1 ||
    text.indexOf('出处') !== -1 ||
    text.indexOf('完全免费') !== -1 ||
    text.indexOf('防倒卖') !== -1 ||
    text.indexOf('bbs.itzmx') !== -1
  ) {
    return true;
  }
  return false;
}

function readDialogTitle(templatePtr) {
  if (templatePtr.isNull()) {
    return '';
  }
  try {
    return templatePtr.add(18).readUtf16String();
  } catch (_) {
    return '';
  }
}

function hookDialogApi(name) {
  let addr;
  try {
    addr = getExport('user32.dll', name);
  } catch (e) {
    return;
  }
  Interceptor.attach(addr, {
    onEnter(args) {
      this.bypass = false;
      const title = readDialogTitle(args[1]);
      if (shouldBypass(title)) {
        this.bypass = true;
        send({ type: 'bypass_dialog', api: name, title: title });
      }
    },
    onLeave(retval) {
      if (this.bypass) {
        retval.replace(1);
      }
    },
  });
}

['DialogBoxParamW', 'DialogBoxIndirectParamW', 'CreateDialogParamW', 'CreateDialogIndirectParamW'].forEach(
  hookDialogApi
);

function hookMessageBox(name, wide) {
  Interceptor.attach(getExport('user32.dll', name), {
    onEnter(args) {
      let text = '';
      let caption = '';
      try {
        if (wide) {
          text = readWideString(args[1]);
          caption = readWideString(args[2]);
        } else {
          text = args[1].readAnsiString() || '';
          caption = args[2].readAnsiString() || '';
        }
      } catch (_) {
        return;
      }
      this.bypass = shouldBypass(text) || shouldBypass(caption);
      if (this.bypass) {
        send({ type: 'bypass_messagebox', api: name, caption: caption, text: text.slice(0, 200) });
      }
    },
    onLeave(retval) {
      if (this.bypass) {
        retval.replace(1);
      }
    },
  });
}

hookMessageBox('MessageBoxW', true);
hookMessageBox('MessageBoxA', false);

Interceptor.attach(getExport('kernel32.dll', 'Sleep'), {
  onEnter(args) {
    const ms = args[0].toInt32();
    if (ms >= 3000 && ms <= 4000) {
      send({ type: 'bypass_splash_sleep', ms: ms });
      args[0] = ptr(0);
    }
  },
});

Interceptor.attach(getExport('shell32.dll', 'ShellExecuteW'), {
  onEnter(args) {
    const file = readWideString(args[2]);
    if (shouldBypass(file)) {
      send({ type: 'blocked_shell_execute', file: file });
      args[2].writeUtf16String('');
    }
  },
});

const PASSWORD =
  'lai2 zi4 bbs.itzmx.com mian3 fei4 fen1 xiang3 fa1 xian4 fan4 mai4 ju3 bao4 cha4 ping2 tui4 kuan3 bbs.itzmx.com Always Free';

// Frida getExportByName returns a NativePointer; functions must be wrapped in
// NativeFunction before they can be called from JS.
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
const EnumChildWindows = new NativeFunction(getExport('user32.dll', 'EnumChildWindows'), 'int', [
  'pointer',
  'pointer',
  'pointer',
]);
const GetClassNameW = new NativeFunction(getExport('user32.dll', 'GetClassNameW'), 'int', [
  'pointer',
  'pointer',
  'int',
]);
const GetWindowTextW = new NativeFunction(getExport('user32.dll', 'GetWindowTextW'), 'int', [
  'pointer',
  'pointer',
  'int',
]);
const SendMessageW = new NativeFunction(getExport('user32.dll', 'SendMessageW'), 'long', [
  'pointer',
  'uint',
  'pointer',
  'pointer',
]);
const PostMessageW = new NativeFunction(getExport('user32.dll', 'PostMessageW'), 'int', [
  'pointer',
  'uint',
  'pointer',
  'pointer',
]);
const SetForegroundWindow = new NativeFunction(
  getExport('user32.dll', 'SetForegroundWindow'),
  'int',
  ['pointer']
);
const GetWindowTextLengthW = new NativeFunction(
  getExport('user32.dll', 'GetWindowTextLengthW'),
  'int',
  ['pointer']
);

const OpenClipboard = new NativeFunction(getExport('user32.dll', 'OpenClipboard'), 'int', [
  'pointer',
]);
const EmptyClipboard = new NativeFunction(getExport('user32.dll', 'EmptyClipboard'), 'int', []);
const SetClipboardData = new NativeFunction(
  getExport('user32.dll', 'SetClipboardData'),
  'pointer',
  ['uint', 'pointer']
);
const CloseClipboard = new NativeFunction(getExport('user32.dll', 'CloseClipboard'), 'int', []);
const GlobalAlloc = new NativeFunction(getExport('kernel32.dll', 'GlobalAlloc'), 'pointer', [
  'uint',
  'uint64',
]);
const GlobalLock = new NativeFunction(getExport('kernel32.dll', 'GlobalLock'), 'pointer', [
  'pointer',
]);
const GlobalUnlock = new NativeFunction(getExport('kernel32.dll', 'GlobalUnlock'), 'int', [
  'pointer',
]);

const CF_UNICODETEXT = 13;
const GMEM_MOVEABLE = 0x0002;
const WM_PASTE = 0x0302;
const BM_CLICK = 0x00f5;

function setClipboardUnicode(text) {
  // Allocate a movable global buffer with the UTF-16 string + null terminator.
  const bytes = (text.length + 1) * 2;
  const hMem = GlobalAlloc(GMEM_MOVEABLE, uint64(bytes));
  if (hMem.isNull()) {
    return false;
  }
  const dst = GlobalLock(hMem);
  if (dst.isNull()) {
    return false;
  }
  dst.writeUtf16String(text);
  GlobalUnlock(hMem);

  if (OpenClipboard(ptr(0)) === 0) {
    return false;
  }
  EmptyClipboard();
  const ok = !SetClipboardData(CF_UNICODETEXT, hMem).isNull();
  CloseClipboard();
  return ok;
}

function getClass(hwnd) {
  const buf = Memory.alloc(256 * 2);
  GetClassNameW(hwnd, buf, 256);
  return buf.readUtf16String();
}

function getText(hwnd) {
  const buf = Memory.alloc(512 * 2);
  GetWindowTextW(hwnd, buf, 512);
  return buf.readUtf16String();
}

// The password input is a nested Edit control (not a direct child); the dialog also
// has a "&OK" Button. Both are only reachable via recursive EnumChildWindows.
function findDialogControls(dialog) {
  const found = { edit: ptr(0), ok: ptr(0) };
  const cb = new NativeCallback(
    function (hwnd, lparam) {
      const cls = getClass(hwnd);
      if (cls === 'Edit' && found.edit.isNull()) {
        found.edit = hwnd;
      } else if (cls === 'Button') {
        const txt = getText(hwnd);
        if (txt.indexOf('OK') !== -1 || txt.indexOf('确定') !== -1) {
          found.ok = hwnd;
        }
      }
      return 1;
    },
    'int',
    ['pointer', 'pointer']
  );
  EnumChildWindows(dialog, cb, ptr(0));
  return found;
}

let submitted = false;

function autoSubmitPassword() {
  const titleBuf = Memory.allocUtf16String('Application requires password to start');
  const hwnd = FindWindowW(ptr(0), titleBuf);
  if (hwnd.isNull()) {
    return false;
  }

  const controls = findDialogControls(hwnd);
  if (controls.edit.isNull()) {
    return false;
  }
  const edit = controls.edit;

  if (GetWindowTextLengthW(edit) < PASSWORD.length) {
    if (!setClipboardUnicode(PASSWORD)) {
      send({ type: 'clipboard_set_failed' });
      return false;
    }
    SetForegroundWindow(hwnd);
    // Author-sanctioned safe method: simulate a paste rather than WM_SETTEXT
    // (update #33 only penalizes auto fast-input via SetText-style APIs).
    SendMessageW(edit, WM_PASTE, ptr(0), ptr(0));
    send({ type: 'password_pasted', hwnd: hwnd.toString(), edit: edit.toString() });
  }

  if (GetWindowTextLengthW(edit) < PASSWORD.length) {
    // Paste didn't take yet; try again next tick.
    return false;
  }

  if (!controls.ok.isNull()) {
    SendMessageW(controls.ok, BM_CLICK, ptr(0), ptr(0));
    send({ type: 'auto_submitted_password', via: 'ok_button', hwnd: hwnd.toString() });
  } else {
    PostMessageW(edit, 0x0100, ptr(0x0d), ptr(0));
    PostMessageW(edit, 0x0101, ptr(0x0d), ptr(0));
    send({ type: 'auto_submitted_password', via: 'enter', hwnd: hwnd.toString() });
  }
  submitted = true;
  return true;
}

const submitTimer = setInterval(function () {
  try {
    if (submitted) {
      // Confirm the dialog is gone; if it reappeared, allow another submit.
      const titleBuf = Memory.allocUtf16String('Application requires password to start');
      if (FindWindowW(ptr(0), titleBuf).isNull()) {
        return;
      }
      submitted = false;
    }
    autoSubmitPassword();
  } catch (e) {
    send({ type: 'auto_submit_error', error: String(e) });
  }
}, 250);

send({ type: 'ready' });
