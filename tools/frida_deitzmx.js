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

// Build-time placeholder. tools/build_proxy.py substitutes the per-version itzmx
// password (the daily phrase differs by word order between CSP builds).
const PASSWORD = '__DEITZMX_PASSWORD__';

const SW_HIDE = 0;
const SWP_SHOWWINDOW = 0x0040;
const ITZMX_POPUP_SUFFIX = '6571ddc4-b3aa-45e4-9d35-57c0c1e90ad5';
const CF_UNICODETEXT = 13;
const GMEM_MOVEABLE = 0x0002;
const WM_PASTE = 0x0302;
const BM_CLICK = 0x00f5;
const WM_GETTEXT = 0x000d;
const SMTO_ABORTIFHUNG = 0x0002;
const GETTEXT_TIMEOUT_MS = 200;
// GUITHREADINFO.flags bits that mean "a menu is currently being tracked".
const GUI_INMENUMODE = 0x00000004;
const GUI_POPUPMENUMODE = 0x00000010;
const GUI_SYSTEMMENUMODE = 0x00000020;
// sizeof(GUITHREADINFO) on x64: cbSize(4)+flags(4)+6*HWND(48)+RECT(16).
const GUITHREADINFO_SIZE = 72;

const FindWindowW = new NativeFunction(getExport('user32.dll', 'FindWindowW'), 'pointer', [
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
// Timeout-bounded variant so reading a window's text can never block the
// Frida thread on a busy/hung CSP UI thread (the cause of the menu/freeze hang).
const SendMessageTimeoutW = new NativeFunction(
  getExport('user32.dll', 'SendMessageTimeoutW'),
  'long',
  ['pointer', 'uint', 'pointer', 'pointer', 'uint', 'uint', 'pointer']
);
const GetGUIThreadInfo = new NativeFunction(
  getExport('user32.dll', 'GetGUIThreadInfo'),
  'int',
  ['uint', 'pointer']
);

// True while the user has a menu open. Polling/cross-thread messaging during a
// menu's modal tracking loop dismisses the dropdown, so we stand down that tick.
function menuIsOpen() {
  const info = Memory.alloc(80);
  info.writeU32(GUITHREADINFO_SIZE);
  if (GetGUIThreadInfo(0, info) === 0) {
    return false;
  }
  const flags = info.add(4).readU32();
  return (flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE)) !== 0;
}
const ShowWindow = new NativeFunction(getExport('user32.dll', 'ShowWindow'), 'int', [
  'pointer',
  'int',
]);
const IsWindowVisible = new NativeFunction(getExport('user32.dll', 'IsWindowVisible'), 'int', [
  'pointer',
]);
const GetWindowTextLengthW = new NativeFunction(
  getExport('user32.dll', 'GetWindowTextLengthW'),
  'int',
  ['pointer']
);
const GetWindowThreadProcessId = new NativeFunction(
  getExport('user32.dll', 'GetWindowThreadProcessId'),
  'uint',
  ['pointer', 'pointer']
);
const EnumWindows = new NativeFunction(getExport('user32.dll', 'EnumWindows'), 'int', [
  'pointer',
  'pointer',
]);
const GetWindowRect = new NativeFunction(getExport('user32.dll', 'GetWindowRect'), 'int', [
  'pointer',
  'pointer',
]);
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

function getClass(hwnd) {
  const buf = Memory.alloc(256 * 2);
  GetClassNameW(hwnd, buf, 256);
  return buf.readUtf16String();
}

function getText(hwnd) {
  const buf = Memory.alloc(512 * 2);
  // WM_GETTEXT (wParam = buffer chars, lParam = buffer). ABORTIFHUNG + short
  // timeout means a stalled UI thread returns immediately instead of pinning us.
  const result = Memory.alloc(Process.pointerSize);
  SendMessageTimeoutW(hwnd, WM_GETTEXT, ptr(512), buf, SMTO_ABORTIFHUNG, GETTEXT_TIMEOUT_MS, result);
  return buf.readUtf16String();
}

function getRect(hwnd) {
  const rect = Memory.alloc(16);
  if (GetWindowRect(hwnd, rect) === 0) {
    return { w: 0, h: 0 };
  }
  const left = rect.readS32();
  const top = rect.add(4).readS32();
  const right = rect.add(8).readS32();
  const bottom = rect.add(12).readS32();
  return { w: right - left, h: bottom - top };
}

function shouldHideWindow(className, title, hwnd) {
  const cls = (className || '').toLowerCase();
  const ttl = title || '';
  const lower = ttl.toLowerCase();

  if (cls === 'internet explorer_server' || cls.indexOf('shell embedding') !== -1) {
    return true;
  }

  // itzmx full-screen splash: untitled "Window" class at ~1024x576.
  if (cls === 'window' && ttl.trim() === '' && hwnd && !hwnd.isNull()) {
    const rect = getRect(hwnd);
    if (rect.w >= 900 && rect.h >= 500) {
      return true;
    }
  }

  // itzmx marketing overlay (512x314), not generic CSP internals.
  if (cls.indexOf(ITZMX_POPUP_SUFFIX) !== -1) {
    return true;
  }

  if (
    lower.indexOf('password') !== -1 ||
    lower.indexOf('application requires') !== -1 ||
    lower.indexOf('itzmx') !== -1 ||
    lower.indexOf('anti-resale') !== -1
  ) {
    return true;
  }
  return shouldBypass(ttl);
}

function hideWindow(hwnd, reason) {
  if (hwnd.isNull() || IsWindowVisible(hwnd) === 0) {
    return false;
  }
  ShowWindow(hwnd, SW_HIDE);
  send({ type: 'hide_window', reason: reason, class: getClass(hwnd), title: getText(hwnd) });
  return true;
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

// Kept as a named listener so it can be removed the instant the splash phase
// ends — a lingering global Sleep() override is what risks freezing the live app.
const sleepHook = Interceptor.attach(getExport('kernel32.dll', 'Sleep'), {
  onEnter(args) {
    const ms = args[0].toInt32();
    if (ms >= 1000 && ms <= 6000) {
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

Interceptor.attach(getExport('user32.dll', 'ShowWindow'), {
  onEnter(args) {
    const cmd = args[1].toInt32();
    if (cmd === SW_HIDE) {
      return;
    }
    const hwnd = args[0];
    const cls = getClass(hwnd);
    const title = getText(hwnd);
    if (shouldHideWindow(cls, title, hwnd)) {
      args[1] = ptr(SW_HIDE);
      send({ type: 'block_show_window', class: cls, title: title, cmd: cmd });
    }
  },
});

Interceptor.attach(getExport('user32.dll', 'SetWindowPos'), {
  onEnter(args) {
    const flags = args[7].toInt32();
    if ((flags & SWP_SHOWWINDOW) === 0) {
      return;
    }
    const hwnd = args[0];
    const cls = getClass(hwnd);
    const title = getText(hwnd);
    if (shouldHideWindow(cls, title, hwnd)) {
      args[7] = ptr(flags & ~SWP_SHOWWINDOW);
      send({ type: 'block_setwindowpos_show', class: cls, title: title });
    }
  },
});

Interceptor.attach(getExport('user32.dll', 'SetForegroundWindow'), {
  onEnter(args) {
    const hwnd = args[0];
    if (shouldHideWindow(getClass(hwnd), getText(hwnd), hwnd)) {
      this.block = true;
    }
  },
  onLeave(retval) {
    if (this.block) {
      retval.replace(1);
    }
  },
});

function setClipboardUnicode(text) {
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

function sweepHiddenWindows() {
  const selfPid = Process.id;
  const pidBuf = Memory.alloc(4);
  const cb = new NativeCallback(
    function (hwnd, lparam) {
      GetWindowThreadProcessId(hwnd, pidBuf);
      if (pidBuf.readU32() !== selfPid || IsWindowVisible(hwnd) === 0) {
        return 1;
      }
      const cls = getClass(hwnd);
      const title = getText(hwnd);
      if (shouldHideWindow(cls, title, hwnd)) {
        hideWindow(hwnd, 'sweep');
      }
      return 1;
    },
    'int',
    ['pointer', 'pointer']
  );
  EnumWindows(cb, ptr(0));
}

let submitted = false;

function autoSubmitPassword() {
  const titleBuf = Memory.allocUtf16String('Application requires password to start');
  const hwnd = FindWindowW(ptr(0), titleBuf);
  if (hwnd.isNull()) {
    return false;
  }

  hideWindow(hwnd, 'password_dialog');

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
    SendMessageW(edit, WM_PASTE, ptr(0), ptr(0));
    send({ type: 'password_pasted', hwnd: hwnd.toString(), edit: edit.toString() });
  }

  if (GetWindowTextLengthW(edit) < PASSWORD.length) {
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

// --- Lifecycle ------------------------------------------------------------
// These hooks + polling are STARTUP-ONLY: they exist to skip the splash and
// auto-fill the password. Leaving them running for the whole session is what
// made the menu bar unclickable and caused random freezes (perpetual EnumWindows
// + cross-thread messages, plus a permanent Sleep() override).
//
// Fastest safe handoff to the live app:
//   1. The moment CSP's main window is visible (canvas up) we STOP POLLING and
//      drop the Sleep override — that's the part that fights the menu bar.
//   2. The cheap event-driven window hooks linger a few more seconds to swallow
//      any late itzmx popup, then fully detach. They don't poll, so they don't
//      touch the menus.
// Don't honor the main-window signal before this — guards against a transient
// big window appearing before the password gate is handled. The splash sleep is
// zeroed and the password shows within ~1s, so this stays safely small.
const MAIN_READY_MIN_MS = 900;
const POST_SUBMIT_GRACE_MS = 1000; // fallback: stop this long after a submit
const NO_DIALOG_TEARDOWN_MS = 5000; // fallback: no password dialog ever appeared
const HARD_CAP_MS = 90000; // absolute upper bound — never hook a live session
const EVENT_HOOK_LINGER_MS = 750; // keep event hooks briefly after polling stops
const PW_TITLE = 'Application requires password to start';
const MAIN_WIN_MIN_W = 700;
const MAIN_WIN_MIN_H = 400;

const startedAt = Date.now();
let submittedAt = 0;
let pollingStopped = false;
let tornDown = false;

function passwordWindowPresent() {
  const titleBuf = Memory.allocUtf16String(PW_TITLE);
  return !FindWindowW(ptr(0), titleBuf).isNull();
}

// Reused across ticks to avoid reallocating the callback every 100ms.
const mainWinState = { pid: Process.id, pidBuf: Memory.alloc(4), found: false };
const mainWinCb = new NativeCallback(
  function (hwnd, lparam) {
    GetWindowThreadProcessId(hwnd, mainWinState.pidBuf);
    if (mainWinState.pidBuf.readU32() !== mainWinState.pid || IsWindowVisible(hwnd) === 0) {
      return 1;
    }
    // Class + rect are read locally and never block on the (busy) UI thread,
    // unlike WM_GETTEXT — so this fires the moment the canvas is on screen.
    const cls = (getClass(hwnd) || '').toLowerCase();
    if (
      cls === 'internet explorer_server' ||
      cls.indexOf('shell embedding') !== -1 ||
      cls.indexOf(ITZMX_POPUP_SUFFIX) !== -1
    ) {
      return 1;
    }
    const r = getRect(hwnd);
    if (r.w >= MAIN_WIN_MIN_W && r.h >= MAIN_WIN_MIN_H) {
      mainWinState.found = true;
      return 0;
    }
    return 1;
  },
  'int',
  ['pointer', 'pointer']
);

// A large, visible, non-itzmx top-level window in our process = the canvas. The
// fullscreen splash is the same size class, but it has no title so the sweep
// (which runs earlier in the same tick) hides it first; the real canvas window
// carries a title, so it survives and is the only large visible window left.
function mainWindowReady() {
  mainWinState.found = false;
  EnumWindows(mainWinCb, ptr(0));
  return mainWinState.found;
}

function fullTeardown(reason) {
  if (tornDown) {
    return;
  }
  tornDown = true;
  try {
    Interceptor.detachAll();
  } catch (_) {}
  send({ type: 'teardown', reason: reason });
}

function stopPolling(reason) {
  if (pollingStopped) {
    return;
  }
  pollingStopped = true;
  try {
    clearInterval(submitTimer);
  } catch (_) {}
  try {
    clearInterval(sweepTimer);
  } catch (_) {}
  // Remove the global Sleep override right away (freeze risk); the event-driven
  // window hooks are cheap and menu-safe, so let them linger a moment longer.
  try {
    sleepHook.detach();
  } catch (_) {}
  send({ type: 'stop_polling', reason: reason });
  setTimeout(function () {
    fullTeardown('linger_done');
  }, EVENT_HOOK_LINGER_MS);
}

const submitTimer = setInterval(function () {
  if (pollingStopped) {
    return;
  }
  // Never poke the UI thread while a menu is being tracked — it would cancel it.
  if (menuIsOpen()) {
    return;
  }
  const now = Date.now();
  try {
    sweepHiddenWindows();

    if (passwordWindowPresent()) {
      submitted = false;
      autoSubmitPassword();
      if (submitted) {
        submittedAt = Date.now();
      }
      return;
    }

    // Password is gone (handled, or bypassed at the dialog-API level). The main
    // window being visible is the definitive "we're done" signal.
    if (now - startedAt >= MAIN_READY_MIN_MS && mainWindowReady()) {
      stopPolling('main_window_ready');
      return;
    }

    if (submittedAt !== 0 && now - submittedAt > POST_SUBMIT_GRACE_MS) {
      stopPolling('password_handled');
      return;
    }
    if (submittedAt === 0 && now - startedAt > NO_DIALOG_TEARDOWN_MS) {
      stopPolling('no_dialog');
      return;
    }
    if (now - startedAt > HARD_CAP_MS) {
      stopPolling('hard_cap');
    }
  } catch (e) {
    send({ type: 'auto_submit_error', error: String(e) });
  }
}, 100);

// Faster early sweep to catch the splash; self-limits after ~12s.
let sweepTicks = 0;
const sweepTimer = setInterval(function () {
  if (pollingStopped) {
    return;
  }
  if (menuIsOpen()) {
    return;
  }
  sweepTicks += 1;
  try {
    sweepHiddenWindows();
  } catch (e) {
    send({ type: 'sweep_error', error: String(e) });
  }
  if (sweepTicks >= 120) {
    try {
      clearInterval(sweepTimer);
    } catch (_) {}
  }
}, 100);

send({ type: 'ready' });
