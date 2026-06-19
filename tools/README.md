# De-itzmx patch — remove the itzmx anti-resale layer (v4.2.0 Patch1)

Double-click the **normal** CLIP Studio Paint icon and it starts straight into
the canvas: no daily password, no website splash, no Chinese tamper warning, no
random document pop-ups — and **no external launcher process**.

This document explains what the itzmx layer is, what we tried, what finally
worked, and how to build or remove the patch.

## Target build

| Item | Value |
|------|-------|
| Exe | `CLIPStudioPaint.exe` |
| SHA256 | `868BBC5637563E68BD98220AD1D4EE3A5B7FDEADDCED1C368E7141014C3653CB` |
| Install path (typical) | `C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\` |

The password/splash are **daily-gated** (once per calendar day). On an already-authed day nothing appears either way.

---

## What itzmx does

The redistributed CSP build wraps the real executable in a **VM-based protector**
(similar in spirit to Themida/VMProtect):

- Hijacks the PE entry point into encrypted sections (`sec8`, `sec9`).
- Decrypts the original code at runtime and virtualizes ~22 critical API imports.
- Shows a daily **password dialog** (`Application requires password to start`).
- Shows a **website/splash** (embedded browser — sets `FEATURE_BROWSER_EMULATION`
  for `CLIPStudioPaint.exe`, loads `winhttp`/`ole32`, sleeps 3–4 s).
- Runs **anti-tamper**: byte-patching the protector or exe triggers
  `警告！禁止擅自串改语言文件！` (“Do not tamper with language files!”).
- Validates the **exe import table / PE integrity** — any edit to the exe itself
  aborts with exit code 1.

Two `.txt` key files in the install folder are required; deleting them breaks launch.

---

## What we tried (and why it failed)

| Approach | Outcome |
|----------|---------|
| pywinauto / `WM_SETTEXT` auto-fill | Works intermittently; update #33 penalizes fast auto-input |
| Disk patch / NOP gates in decrypted memory | Triggers tamper warning |
| Full unpack + rebuild (OEP dump, IAT reconstruction) | 22 VM-virtualized imports unresolved → crash in `sec8` |
| Import-table inject `frida-gadget` into exe | Exit code 1 — protector rejects **any exe modification** |
| Import inject tiny helper DLL into exe | Same — even a no-op helper import kills the process |
| Proxy `ailia_blas.dll` (loads ~3.3 s) | Process survives, hooks run — but **too late** for the password (~2.2 s) |

The breakthrough: **never touch the exe**. Load our code via **DLL search-order
shadowing** of a system DLL that CSP loads **before** the password dialog.

---

## Final design (what works)

```
CLIPStudioPaint.exe          ← byte-identical original, never modified
  │
  └─► SHFolder.dll           ← our proxy (added to install folder)
        ├─► SHGetFolderPathA/W  forwarded to SHFolder_orig.dll
        └─► DllMain → CreateThread(worker)
              └─► Sleep(250ms)   ← wait until loader lock is done
                    └─► LoadLibrary("deitzmx.dll")   ← frida-gadget, renamed
                          └─► deitzmx.config (script mode)
                                └─► deitzmx_hook.js  ← frida_deitzmx.js
```

### Why `SHFolder.dll`

CSP loads these **non-KnownDLL** system DLLs by name very early (~100 ms):

- `SHFolder.dll` — **2 exports**, ideal to forward
- `msimg32.dll`, `uxtheme.dll`, `dwmapi.dll`, … — also early, usable as fallbacks

`SHFolder` is **not** in the Windows KnownDLLs list, so placing a copy in the
install folder shadows `C:\Windows\System32\SHFolder.dll` (app dir wins in
search order). Nothing existing in the install folder is modified — the shadow
is purely **additive**.

Load timing (prompt day, measured via `LdrLoadDll` hooks):

| Time | Event |
|------|-------|
| ~100 ms | `SHFolder.dll` loaded → our proxy runs |
| ~250 ms | worker thread loads `deitzmx.dll` + hooks |
| ~2250 ms | password dialog would appear → **suppressed at creation** |
| ~3300 ms | `ailia_blas.dll` (too late to catch password) |

### Why deferred load

Loading frida-gadget **during the loader lock** (static import or early
`LoadLibrary` from `DllMain`) caused immediate exit code 1. The proxy's
`DllMain` only calls `CreateThread`; the worker waits 250 ms then loads the
gadget. This matches the safe timing of `frida.spawn` (late injection), which
we validated first.

### What the hook script does

`frida_deitzmx.js` — **UI hooks only** (no memory patches; those trip tamper).
See **[docs.md](../docs.md)** for the current behavior (splash window classes,
password hiding, deploy pitfalls). Summary:

1. **Password** — hide dialog, paste via clipboard + `WM_PASTE`, click OK.
2. **Splash** — hide native `Window` class fullscreen splash + itzmx marketing
   overlay; skip long `Sleep(1000–6000)` calls.
3. **Tamper/marketing** — auto-dismiss matching `MessageBoxW/A` and dialog APIs.
4. **Random doc popup** — block matching `ShellExecuteW` targets.

---

## Files in this repo

| Path | Role |
|------|------|
| `native/deitzmx_helper.c` | Proxy DLL source (forward exports + deferred gadget loader) |
| `frida_deitzmx.js` | Suppression hooks (copied to install dir as `deitzmx_hook.js`) |
| `bin/frida-gadget.dll` | Upstream frida-gadget (renamed to `deitzmx.dll` at deploy) |
| `build_proxy.py` | Build proxy + stage payload under `output/proxy/` |
| `deploy_proxy.ps1` | Copy staged files into CSP install dir (elevated) |
| `restore_proxy.ps1` | Remove patch files (elevated) |
| `_deploy_hook.ps1` | Redeploy hook script only after editing `frida_deitzmx.js` |
| `verify_clock.ps1` | Dev test: advance clock +1 day, launch, restore (elevated) |

Build output goes to `tools/output/proxy/` (gitignored).

---

## Build & deploy

**Requirements:** Python 3 with `lief`, MinGW gcc (`gcc` on PATH or at
`C:\ProgramData\mingw64\mingw64\bin\gcc.exe`).

```powershell
pip install lief

# 1. Build proxy + stage payload (--csp-version picks the per-version password)
python tools\build_proxy.py --target SHFolder --source-dir C:\Windows\System32 --csp-version 4.2.0

# 2. Deploy (elevated — close CSP first)
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\deploy_proxy.ps1 -Stem SHFolder
```

Then use CSP normally (desktop icon, Start menu, etc.).

### Files added to the install folder

| File | Size (approx) | Purpose |
|------|---------------|---------|
| `SHFolder.dll` | 4.6 KB | Proxy |
| `SHFolder_orig.dll` | 28 KB | Real System32 SHFolder |
| `deitzmx.dll` | 23 MB | frida-gadget |
| `deitzmx.config` | tiny | Gadget script path |
| `deitzmx_hook.js` | ~9 KB | Suppression hooks |

---

## Uninstall

```powershell
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\restore_proxy.ps1 -Stem SHFolder
```

Deletes the five files above. CSP returns to original (annoying) behavior.

---

## Update hook only

After editing `frida_deitzmx.js`:

```powershell
python tools\build_proxy.py --target SHFolder --source-dir C:\Windows\System32 --csp-version 4.2.0
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\_deploy_hook.ps1
```

---

## Verify (optional)

On an authed day you will not see the password. To force a prompt:

```powershell
powershell -Verb RunAs -ExecutionPolicy Bypass -File tools\verify_clock.ps1
```

Check `tools/output/verify_timeline.txt`: success = no
`Application requires password to start` window, CSP main window appears,
`proc_alive=True`.

---

## Caveats

- **CSP reinstall/update** may wipe the folder — re-run deploy.
- **Antivirus** may flag DLL shadowing or frida-gadget; allow if needed.
- **Fallback targets** if `SHFolder` ever conflicts: `msimg32`, `uxtheme`,
  `dwmapi` (all early, non-KnownDLL) — same `build_proxy.py --target …`.
- **Do not modify `CLIPStudioPaint.exe`** — integrity check will kill it.
