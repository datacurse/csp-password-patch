# De-itzmx patch — how it works (success write-up)

This document describes the **working baked-in patch** for CLIP Studio Paint v4.2.0
Patch1 (itzmx build). After deploy, you launch CSP normally — desktop icon, Start
menu, double-click the exe — and land on the canvas without the daily password,
without the itzmx splash, and without tamper/marketing pop-ups.

For build/deploy commands see [tools/README.md](tools/README.md). For the old
pywinauto launcher see [README.md](README.md).

---

## What you get

| Before patch | After patch |
|--------------|-------------|
| Daily password dialog (`Application requires password to start`) | Auto-filled invisibly in the background |
| Full-screen itzmx splash (anime + `BBS.ITZMX.COM` banner) | Hidden before you notice it |
| Chinese tamper / anti-resale message boxes | Auto-dismissed |
| Random itzmx document pop-ups via `ShellExecuteW` | Blocked |
| External Python launcher each time | Not needed |

The password and splash are **once per calendar day** on an unpatched install. On
days when CSP would not prompt, the patch is effectively invisible — it just
starts faster and cleaner.

---

## Architecture (30-second version)

```
CLIPStudioPaint.exe          ← never modified (protector checks exe integrity)
  │
  └─► SHFolder.dll           ← tiny proxy dropped in the CSP install folder
        ├─ forwards SHGetFolderPathA/W → SHFolder_orig.dll (real System32 DLL)
        └─ DllMain → worker thread (250 ms delay)
              └─ LoadLibrary("deitzmx.dll")     ← frida-gadget, renamed
                    └─ reads deitzmx.config
                          └─ runs deitzmx_hook.js  ← copy of tools/frida_deitzmx.js
```

**Why this shape:** the itzmx protector exits immediately (code 1) if you edit
`CLIPStudioPaint.exe` or inject into it too early. Shadowing an early-loaded
system DLL (`SHFolder.dll`, not in Windows KnownDLLs) lets us load Frida ~350 ms
after process start — early enough for the password (~2.2 s) and splash (~0.6 s),
late enough to avoid tripping anti-tamper.

---

## What the hook script does

Source: `tools/frida_deitzmx.js` → deployed as `deitzmx_hook.js`.

All changes are **Win32 UI hooks only**. Memory patches inside the encrypted exe
were tried and consistently triggered the Chinese “do not tamper with language
files” warning.

### 1. Daily password

On prompt days, itzmx shows a dialog titled `Application requires password to start`.

The hook:

1. Finds the dialog by title (`FindWindowW`).
2. **Hides it** with `ShowWindow(SW_HIDE)` — never brings it to the foreground.
3. Recursively finds the nested `Edit` control (`EnumChildWindows`).
4. Pastes the daily password via clipboard + `WM_PASTE` (the method the patch
   author expects; fast `WM_SETTEXT` is penalized in itzmx update #33).
5. Clicks OK (`BM_CLICK`) or sends Enter.

**The password is per-version.** The phrase differs by word order between builds
(e.g. 4.2.0 swaps `tui4 kuan3` and `ju3 bao4 cha4 ping2` vs 5.0.0). A wrong
password yields itzmx's `启动密码错误！` ("startup password error") popup. The hook
ships a placeholder (`__DEITZMX_PASSWORD__`); `tools/build_proxy.py --csp-version`
substitutes the correct one per version at build time (`PASSWORDS` dict there).

A 100 ms timer retries until the dialog is gone.

### 2. Splash screen

The itzmx splash is **not** a normal IE window. Measured at runtime it is:

| Window | Class | Title | Size (typical) |
|--------|-------|-------|----------------|
| Full-screen splash | `Window` | *(empty)* | ~1024×576 |
| Marketing overlay | `742DEA58-…-6571DDC4-…` | *(empty)* | ~512×314 |

The hook hides these by intercepting:

- `ShowWindow` — redirect show → `SW_HIDE` for matching windows
- `SetWindowPos` — strip `SWP_SHOWWINDOW` for matching windows
- `SetForegroundWindow` — block for matching windows
- A startup `EnumWindows` sweep as a safety net

It also zeroes `Sleep(1000–6000)` calls so the splash timer does not stall startup.

**Important:** we only **hide** splash windows. Sending `WM_CLOSE` to them was
tested and **breaks launch** — itzmx treats that as aborting startup.

**The sweep, the `Sleep` override, and all hooks are startup-only and tear
themselves down the moment the canvas is up** — see [Lifecycle / teardown](#lifecycle--teardown-startup-only-suppression) below. Leaving them
running for the whole session made CSP unusable.

### 3. Tamper warnings and marketing

- `MessageBoxW/A`, `DialogBox*`, `CreateDialog*` — return `IDOK` when title/text
  matches itzmx / Chinese tamper strings.
- `ShellExecuteW` — blank out paths that match itzmx marketing URLs.

### Lifecycle / teardown (startup-only suppression)

Every mechanism above exists **only to get past startup**. None of it must
survive into the live session — and originally all of it did, which made the
patched app unusable (see [Debugging notes](#patch-left-the-ui-unresponsive--randomly-frozen-hooks-never-tore-down)).

The script now self-terminates in two stages:

1. **`stopPolling()`** — fired the instant CSP's main window is on screen. Clears
   the 100 ms timers (the part that fights the menu bar) and **detaches the
   global `Sleep` override immediately** (the part that caused freezes).
2. **`fullTeardown()`** — `Interceptor.detachAll()` after a short linger
   (`EVENT_HOOK_LINGER_MS`, 750 ms) so the cheap event hooks can still swallow a
   late marketing popup, then every hook is gone.

Main-window detection is deliberately **message-free**: it matches a large
(≥700×400), visible, non-itzmx top-level window via `GetClassNameW` +
`GetWindowRect` only. It never calls `GetWindowText`/`WM_GETTEXT`, because during
heavy startup the UI thread is too busy to answer a cross-thread message — which
would stall detection and delay teardown.

Tuning knobs (top of the lifecycle block in `tools/frida_deitzmx.js`):

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAIN_READY_MIN_MS` | 900 | Floor before the main-window signal is honored (guards a transient early window before the password gate). |
| `MAIN_WIN_MIN_W/H` | 700 / 400 | Min size counted as "the canvas". Keep `H` below the splash height but at/under your real window height. |
| `POST_SUBMIT_GRACE_MS` | 1000 | Fallback: stop this long after a password submit. |
| `NO_DIALOG_TEARDOWN_MS` | 5000 | Fallback: stop this long in if no main window is ever detected. |
| `EVENT_HOOK_LINGER_MS` | 750 | Gap between `stopPolling` and `fullTeardown`. |
| `HARD_CAP_MS` | 90000 | Absolute upper bound — never hook a live session past this. |

Each lifecycle transition emits a Frida `send()` event (`ready`, `stop_polling`,
`teardown`) visible to a connected Frida client if you ever need to trace timing.
During development a temporary file logger (`%LOCALAPPDATA%\deitzmx-patch\hook.log`)
recorded ms-since-start timestamps; a healthy launch measured:

```
ready            @ ~0 ms
stop_polling     @ ~1.8 s   (main_window_ready; canvas visible)
teardown         @ ~2.6 s   (all hooks detached)
```

That file logger was removed for the release build to avoid writing to disk every
launch — re-add a `send()` listener or a small `File` write if you need to
re-measure.

---

## Files in the CSP install folder

All five are required. If any are missing, behavior degrades silently or obviously:

| File | Required | Role |
|------|----------|------|
| `SHFolder.dll` | yes | Proxy; loads the gadget after 250 ms |
| `SHFolder_orig.dll` | yes | Real System32 SHFolder (forward target) |
| `deitzmx.dll` | yes | frida-gadget (~23 MB) |
| `deitzmx.config` | **yes** | Points gadget at the hook script |
| `deitzmx_hook.js` | **yes** | Runtime suppression logic |

**Common failure:** deploy copies `deitzmx.dll` and `SHFolder.dll` but skips
`deitzmx.config` and `deitzmx_hook.js` when CSP is still running and DLLs are
locked. The gadget loads but **runs no hooks** — you see the full password +
splash exactly as in an unpatched session.

`deploy_proxy.ps1` now kills CSP first, deploys the hook payload before the
proxy DLLs, and reports `DEPLOY INCOMPLETE` if required files are missing.

---

## GUI installer (recommended for end users)

One exe bundles the five patch files and a Russian CustomTkinter UI (same style as
[csp-lang-switch](https://github.com/datacurse/csp-lang-switch)):

- **Version combo** — `5.0.0` and `4.2.0` (only versions with bundled payloads)
- **Установить патч** / **Удалить патч** — install or remove the proxy payload
- **Status** — detects CSP install, shows whether the patch is active
- **Saved state** — `%LOCALAPPDATA%\deitzmx-patch\state.json` and `settings.json`

Build the installer:

```powershell
pip install -r requirements.txt
build_installer.bat
```

Output: `dist\csp-password-patch.exe`. Run once; confirm UAC when prompted.

Dev run without building exe:

```powershell
python tools\stage_version_payload.py --rebuild
python src\main.py
```

---

## Deploy manually (elevated)

Close CSP completely (including system tray), then:

```powershell
pip install lief
python tools\build_proxy.py --target SHFolder --source-dir C:\Windows\System32 --csp-version 4.2.0
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\deploy_proxy.ps1 -Stem SHFolder
```

`--csp-version` selects the per-version itzmx password baked into the hook (the
daily phrase differs by word order between builds; see `PASSWORDS` in
`tools/build_proxy.py`). Use the version matching the target install.

Verify all five files exist under:

`C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\`

If deploy warns about locked files, quit CSP, reboot if needed, and re-run deploy.

### Hook-only update

After editing `tools/frida_deitzmx.js`:

```powershell
python tools\build_proxy.py --target SHFolder --source-dir C:\Windows\System32 --csp-version 4.2.0
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\_deploy_hook.ps1
```

Or re-run full `deploy_proxy.ps1`.

### Uninstall

Virgin itzmx CSP **does not ship `SHFolder.dll`** in the install folder — our patch is
purely additive (five new files). Uninstall must **delete** those files entirely;
copying System32 `SHFolder.dll` into the folder or leaving the proxy behind breaks
CSP startup. Inspect baseline with `tools\probe_install.ps1`.

```powershell
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\restore_proxy.ps1 -Stem SHFolder
```

CSP returns to stock itzmx behavior (password + splash).

---

## Verify it works

On a day when you already authenticated, you will not see the password dialog.
To force a prompt day (elevated — advances system clock +1 day, then restores it):

```powershell
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\verify_clock.ps1
```

Check `tools/output/verify_timeline.txt`. Success looks like:

```
+2545 ms  APPEAR  742DEA58-…|CLIP STUDIO PAINT
proc_alive=True
```

No `Application requires password to start`, no `Window|` splash line.

Window timeline probe (optional):

```powershell
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\probe_splash.ps1
```

Output: `tools/output/splash_probe.txt`

---

## Debugging notes (what we learned the hard way)

### Patch left the UI unresponsive / randomly frozen (hooks never tore down)

Symptom: after a patched launch CSP would open, but for several seconds the
**top menu bar / toolbar buttons would not open their dropdowns**, and during
normal use the app would **intermittently freeze**.

Root cause: the suppression logic in `frida_deitzmx.js` was **startup-only by
intent but ran for the entire session**:

| Mechanism | Why it broke the live app |
|-----------|---------------------------|
| 100 ms `submitTimer` (never cleared) | Ran `EnumWindows` + **synchronous cross-thread** `GetWindowTextW`/`SendMessageW` against the UI thread forever. While a menu is open the UI thread is in a modal tracking loop; hammering it with sent messages cancels the dropdown — so menus "wouldn't open". |
| Global `Sleep(1000–6000) → 0` override (never detached) | Meant only to skip the splash sleep, but left permanent it turned every background back-off in that range into a busy-spin, starving the UI thread → random freezes. |

Fix (see [Lifecycle / teardown](#lifecycle--teardown-startup-only-suppression)):

1. **Self-terminating lifecycle** — `stopPolling()` (clears timers + detaches the
   `Sleep` hook) the moment the main window is visible, then `fullTeardown()`
   (`Interceptor.detachAll()`) after a 750 ms linger. Nothing survives into the
   live session.
2. **Non-blocking text reads** — `getText` uses `SendMessageTimeoutW`
   (`SMTO_ABORTIFHUNG`, 200 ms) instead of `GetWindowTextW`, so the Frida thread
   can never pin a busy UI thread.
3. **Menu-aware back-off** — each tick checks `GetGUIThreadInfo`
   (`GUI_INMENUMODE`/popup/system) and skips its work while a menu is being
   tracked, so it can never cancel an open dropdown.
4. **Message-free main-window detection** — class + size via `GetClassNameW` /
   `GetWindowRect`, no `WM_GETTEXT`, so detection fires immediately even while the
   UI thread is busy (an earlier title-based check stalled and fell through to a
   5 s fallback timer — the original "~5 s lag").
5. **Short event-hook linger** — keeping `ShowWindow`/`SetWindowPos` hooks alive
   only 750 ms after the canvas appears removes their per-window overhead during
   CSP's heavy init, which was the last source of perceptible lag.

Net result: hooks detach ~2.5 s after launch (right as the canvas paints) and
the live session runs completely unhooked.

### Wrong password on 4.2.0 → `启动密码错误！` popup (passwords are per-version)

Symptom: on a **4.2.0** install the patch loaded fine, but instead of the canvas
itzmx showed a custom popup titled `启动密码错误！` ("startup password error") — an
anti-resale rant ("this is pirated, demand a refund…") with a countdown — and CSP
never opened.

Diagnosis: a **non-destructive live window probe** (enumerate every CSP-owned
window, visible or hidden, plus child-control text, during a normal patched
launch — no clock change, no unpatch) showed:

```
TOP vis=False rect=342x118 text=[Application requires password to start]   ← dialog WAS found + hidden
TOP vis=False rect=1024x576 text=[]                                        ← splash hidden
TOP vis=True  rect=345x152 text=[??????!]  child text=[5]                  ← 启动密码错误！ + countdown
```

So title matching and hiding worked — the **password we pasted was simply wrong
for the 4.2.0 build**. The daily itzmx phrase differs by **word order** between
builds:

| Version | …fan4 mai4 **…** bbs.itzmx.com Always Free |
|---------|--------------------------------------------|
| 5.0.0 | `tui4 kuan3 ju3 bao4 cha4 ping2` |
| 4.2.0 | `ju3 bao4 cha4 ping2 tui4 kuan3` |

Fix: passwords are now **per-version, baked at build time**.
`tools/frida_deitzmx.js` carries a `__DEITZMX_PASSWORD__` placeholder;
`tools/build_proxy.py` holds a `PASSWORDS` dict and a `--csp-version` flag that
substitutes the right phrase; `tools/stage_version_payload.py` rebuilds each
version with its own password. The installer (`build_installer.bat`) stages both
4.2.0 and 5.0.0, so the GUI ships the correct password for whichever version the
user selects.

Note: a wrong password **cannot** be recovered by hiding the error popup — the
gate isn't satisfied, so CSP stays locked. Password *correctness* is the fix; do
not "suppress" `启动密码错误！`.

### Partial deploy → hooks never run

Symptom: password dialog and splash visible; patch files “look” installed.

Cause: `deitzmx.config` / `deitzmx_hook.js` missing while `deitzmx.dll` present.

Fix: ensure all five files; redeploy with CSP fully quit.

### CSP exits immediately (code 1)

Causes we hit:

| Change | Result |
|--------|--------|
| `WM_CLOSE` on splash windows | Process aborts — do not use |
| Hiding all GUID-suffixed CSP internal windows | Breaks Qt init — only hide the known popup suffix |
| Hiding every untitled `Window` class | Too broad — restrict to large splash (~900×500+) |
| `LOAD_DELAY_MS = 0` | Occasionally tripped protector — keep **250 ms** |

Stable rule: **hide, never close** splash; **narrow** window matching; **250 ms**
gadget delay.

### Visible password autofill

Early versions called `SetForegroundWindow` before paste, flashing the dialog.
Current hook hides the dialog first and never foregrounds it.

### Splash mistaken for IE

README originally described an embedded IE browser + 3–4 s sleep. Sleep bypass
helps, but the visible splash is a native `Window` class fullscreen surface.
IE-class hooks alone are not enough.

---

## Target build

| Item | Value |
|------|-------|
| Exe | `CLIPStudioPaint.exe` |
| SHA256 | `868BBC5637563E68BD98220AD1D4EE3A5B7FDEADDCED1C368E7141014C3653CB` |
| Install path | `C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\` |

---

## Repo map

| Path | Purpose |
|------|---------|
| `tools/frida_deitzmx.js` | Hook source |
| `tools/native/deitzmx_helper.c` | Proxy DLL source |
| `tools/build_proxy.py` | Build + stage payload |
| `tools/deploy_proxy.ps1` | Install patch (elevated) |
| `tools/restore_proxy.ps1` | Remove patch |
| `tools/verify_clock.ps1` | Force password day test |
| `tools/probe_splash.ps1` | Window timeline during startup |
| `src/main.py` | GUI installer entry (CustomTkinter, Russian) |
| `deitzmx-patch.spec` | PyInstaller spec for `dist/csp-password-patch.exe` |
| `build_installer.bat` | Stage payload + build installer exe |

---

## Caveats

- **CSP reinstall/update** may delete patch files — re-run deploy.
- **Antivirus** may flag DLL shadowing or frida-gadget.
- **Do not edit `CLIPStudioPaint.exe`** — integrity check kills the process.
- **Fallback proxy targets** if `SHFolder` conflicts: `msimg32`, `uxtheme`,
  `dwmapi` (same `build_proxy.py --target …`).
