// Frida script: hook itzmx anti-resale APIs in CLIPStudioPaint.
'use strict';

const PASSWORD_TITLE = 'Application requires password to start';
const PASSWORD_TEXT =
  'lai2 zi4 bbs.itzmx.com mian3 fei4 fen1 xiang3 fa1 xian4 fan4 mai4 ju3 bao4 cha4 ping2 tui4 kuan3 bbs.itzmx.com Always Free';

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

function hookUser32() {
  const dialogBox = Module.findExportByName('user32.dll', 'DialogBoxParamW');
  if (dialogBox) {
    Interceptor.attach(dialogBox, {
      onEnter(args) {
        this.skip = false;
        const template = args[1];
        // Dialog template pointer may not expose title directly; also check later APIs.
        this.template = template;
      },
      onLeave(retval) {
        if (this.skip) {
          retval.replace(1); // IDOK
        }
      },
    });
  }

  const createWindow = Module.findExportByName('user32.dll', 'CreateWindowExW');
  if (createWindow) {
    Interceptor.attach(createWindow, {
      onEnter(args) {
        const title = readWideString(args[2]);
        if (title.indexOf('password') !== -1 || title.indexOf(PASSWORD_TITLE) !== -1) {
          send({ type: 'skip_window', api: 'CreateWindowExW', title: title });
          args[2].writeUtf16String('__deitzmx_hidden__');
        }
      },
    });
  }

  const messageBox = Module.findExportByName('user32.dll', 'MessageBoxW');
  if (messageBox) {
    Interceptor.attach(messageBox, {
      onEnter(args) {
        const text = readWideString(args[1]);
        const caption = readWideString(args[2]);
        if (
          (caption && caption.indexOf('password') !== -1) ||
          (text && text.indexOf('password') !== -1) ||
          (text && text.indexOf('itzmx') !== -1)
        ) {
          send({ type: 'skip_messagebox', caption: caption, text: text.slice(0, 120) });
          this.skip = true;
        }
      },
      onLeave(retval) {
        if (this.skip) {
          retval.replace(1); // IDOK
        }
      },
    });
  }

  const setWindowText = Module.findExportByName('user32.dll', 'SetWindowTextW');
  if (setWindowText) {
    Interceptor.attach(setWindowText, {
      onEnter(args) {
        const text = readWideString(args[1]);
        if (text.indexOf(PASSWORD_TITLE) !== -1) {
          send({ type: 'dialog_title_seen', api: 'SetWindowTextW' });
        }
      },
    });
  }

  const findWindow = Module.findExportByName('user32.dll', 'FindWindowW');
  if (findWindow) {
    Interceptor.attach(findWindow, {
      onEnter(args) {
        this.title = readWideString(args[1]);
      },
      onLeave(retval) {
        if (this.title && this.title.indexOf('password') !== -1) {
          send({ type: 'find_window_password', title: this.title, hwnd: retval.toString() });
        }
      },
    });
  }
}

function hookSleep() {
  const sleep = Module.findExportByName('kernel32.dll', 'Sleep');
  if (!sleep) {
    return;
  }
  Interceptor.attach(sleep, {
    onEnter(args) {
      const ms = args[0].toInt32();
      if (ms >= 3000 && ms <= 4000) {
        send({ type: 'skip_splash_sleep', ms: ms });
        args[0] = ptr(0);
      }
    },
  });
}

function hookFileIO() {
  const createFile = Module.findExportByName('kernel32.dll', 'CreateFileW');
  if (!createFile) {
    return;
  }
  Interceptor.attach(createFile, {
    onEnter(args) {
      const path = readWideString(args[0]);
      if (path.indexOf('itzmx') !== -1 || path.indexOf('Anti-Resale') !== -1) {
        send({ type: 'key_file_open', path: path });
      }
    },
  });
}

hookUser32();
hookSleep();
hookFileIO();
send({ type: 'ready' });
