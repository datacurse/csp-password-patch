// Frida script: trace itzmx anti-resale call sites and optionally bypass UI.
'use strict';

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

function getExport(moduleName, exportName) {
  return Process.getModuleByName(moduleName).getExportByName(exportName);
}

function moduleOffset(addr) {
  const mod = Process.findModuleByAddress(addr);
  if (!mod) {
    return addr.toString();
  }
  return mod.name + '+0x' + addr.sub(mod.base).toString(16);
}

function shouldBypass(text) {
  if (!text) {
    return false;
  }
  const lower = text.toLowerCase();
  return (
    lower.indexOf('password') !== -1 ||
    lower.indexOf('application requires') !== -1 ||
    lower.indexOf('itzmx') !== -1 ||
    lower.indexOf('anti-resale') !== -1
  );
}

function logBacktrace(tag, ctx) {
  const frames = Thread.backtrace(ctx.context, Backtracer.ACCURATE)
    .slice(0, 12)
    .map(moduleOffset);
  send({ type: 'backtrace', tag: tag, frames: frames });
}

const user32 = Process.getModuleByName('user32.dll');

Interceptor.attach(getExport('user32.dll', 'SetWindowTextW'), {
  onEnter(args) {
    const text = readWideString(args[1]);
    if (shouldBypass(text)) {
      this.hwnd = args[0];
      this.text = text;
      logBacktrace('SetWindowTextW', this);
      send({ type: 'password_title', text: text, hwnd: args[0].toString() });
    }
  },
  onLeave(retval) {
    if (this.hwnd) {
      // Force success path: hide dialog and mark as accepted.
      const WM_CLOSE = 0x0010;
      getExport('user32.dll', 'PostMessageW')(this.hwnd, WM_CLOSE, ptr(0), ptr(0));
      send({ type: 'closed_password_window', hwnd: this.hwnd.toString() });
    }
  },
});

Interceptor.attach(getExport('user32.dll', 'DialogBoxParamW'), {
  onEnter(args) {
    this.template = args[1];
    logBacktrace('DialogBoxParamW', this);
  },
  onLeave(retval) {
    send({ type: 'dialogbox_return', value: retval.toInt32() });
  },
});

Interceptor.attach(getExport('kernel32.dll', 'CreateFileW'), {
  onEnter(args) {
    const path = readWideString(args[0]);
    if (path.indexOf('Anti-Resale') !== -1 || path.indexOf('itzmx') !== -1) {
      logBacktrace('CreateFileW', this);
      send({ type: 'key_file_open', path: path });
    }
  },
});

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

send({ type: 'ready' });
