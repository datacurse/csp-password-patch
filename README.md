# CLIP Studio Paint Auto Password Tool

A tool that automatically enters the CLIP Studio Paint password. It can replace the original CLIPStudioPaint.exe launcher.

## Features

- Automatically enters the password with no manual input
- Supports launching via shortcuts
- Supports custom program icons
- Detects whether CLIP Studio Paint is already running
- Saves the install path so you only need to configure it once

## Usage

1. Place `CSP_auto_Psw.exe` in the CLIP Studio Paint install directory
2. Create a desktop shortcut (optional)
3. Double-click to run the program

## Custom Icon

To change the program icon, name your image `icon.jpg` or `icon.png` and place it in the same directory as `auto_password.exe`.

## Notes

- On first use, if the program is not in the install directory, you will need to enter the CLIP Studio Paint install path manually
- It is recommended to place the program in the CLIP Studio Paint install directory so it can detect the location automatically
- If you run into problems, save the error output as `error.txt` and report it

## How It Works

1. On startup, the program checks whether it is in the CLIP Studio Paint install directory
2. If not, it tries to read the install path from the config file
3. If no config file exists, it prompts you to enter the install path
4. It launches CLIP Studio Paint
5. If a password window is detected, it enters the password automatically
6. If no password window is detected, CLIP Studio Paint is already running and the tool exits

---

# De-itzmx baked-in patch (no external launcher)

This is the preferred solution. You double-click the **normal** CLIP Studio Paint
icon and it starts straight into the canvas: no daily password prompt, no website
splash image, no "language file tampering" warning, no random pop-ups — and there
is **no separate launcher process**. The fix lives entirely inside CSP's own
install folder and the suppression runs *inside* the CSP process.

## Why it is built this way

The itzmx redistribution wraps `CLIPStudioPaint.exe` in a VM-based protector
(encrypted sections, hijacked entry point, virtualized API calls) that also
performs anti-tamper checks. Two things were proven during reverse engineering:

- **The exe cannot be modified.** Editing its import table (even to add one
  harmless DLL) makes the protector abort with exit code 1. So the exe is left
  **byte-identical**.
- **The protector does not validate the other DLLs in its folder, nor the loaded
  module list.** Frida injected *after* process init suppresses every annoyance
  reliably, and the protector never notices.

So instead of patching the exe, we get our code to run inside the process via
**DLL search-order shadowing** of a system DLL that CSP loads very early.

## Architecture

```
CLIPStudioPaint.exe   (untouched, original)
  └─ loads SHFolder.dll  ──►  our proxy (added to the install folder)
        ├─ forwards SHGetFolderPathA/W ──► SHFolder_orig.dll (the real one)
        └─ DllMain spawns a worker thread that, AFTER the loader lock,
             LoadLibrary("deitzmx.dll")  (frida-gadget, renamed)
               └─ reads deitzmx.config (script mode)
                    └─ runs deitzmx_hook.js  (the suppression hooks)
```

Key design points:

- **`SHFolder.dll` is the shadow target** because it is *not* a Windows
  "KnownDLL", it has only 2 exports (trivial to forward), and CSP loads it at
  ~100 ms — **before** the protector shows the password (~2.2 s). Targets that
  load later (e.g. `ailia_blas.dll` at ~3.3 s) load *after* the password and are
  therefore too late.
- **Deferred load is essential.** The proxy's `DllMain` only schedules a thread;
  it does *not* touch the Frida engine during the loader lock. That early
  presence is exactly what crashed an earlier `frida-gadget`-as-static-import
  attempt. Loading the engine from the worker thread reproduces the safe,
  proven "late injection" timing.
- **The suppression script** (`tools/frida_deitzmx.js`) hooks the dialog/
  messagebox APIs to drop the password and warning dialogs, auto-pastes the
  password via the author-sanctioned clipboard+`WM_PASTE` method, zeroes the
  splash `Sleep`, and blocks the website `ShellExecuteW`.

## Files placed in the install folder

Purely **additive** — no existing file is modified or replaced:

| File                | What it is                                            |
|---------------------|-------------------------------------------------------|
| `SHFolder.dll`      | the proxy (forwards + deferred loader, ~4.6 KB)       |
| `SHFolder_orig.dll` | a copy of the real `C:\Windows\System32\SHFolder.dll` |
| `deitzmx.dll`       | frida-gadget, renamed                                 |
| `deitzmx.config`    | gadget config (script mode → `deitzmx_hook.js`)       |
| `deitzmx_hook.js`   | the suppression hooks                                 |

## Build & deploy

Requirements: Python with `lief` + `frida`, and MinGW gcc (used at
`C:\ProgramData\mingw64\mingw64\bin\gcc.exe`).

```powershell
# 1. Build the proxy + stage the payload (reads the real System32 SHFolder.dll)
python tools\build_proxy.py --target SHFolder --source-dir C:\Windows\System32

# 2. Deploy into the install folder (elevated; UAC prompt). Exe is untouched.
#    Close CSP first.
powershell -Verb RunAs -File tools\deploy_proxy.ps1 -Stem SHFolder
```

Then just double-click CLIP Studio Paint as usual.

## Uninstall / restore

```powershell
powershell -Verb RunAs -File tools\restore_proxy.ps1 -Stem SHFolder
```

This deletes the 5 added files. Because nothing existing was modified, CSP
returns to its original (annoying) behavior.

## Verifying it works

The password/splash are **daily-gated**, so on an already-authed day nothing
appears either way. To force a prompt for testing, `tools\verify_clock.ps1`
(elevated) advances the clock one day, launches CSP via the plain double-click
path, records a window timeline, then restores the clock. A successful run shows
the password window never appearing and CSP going straight to its main window.

## Caveats

- A CSP/patch reinstall or update may overwrite the folder — just re-run deploy.
- Some antivirus tools flag app-folder shadowing of a system DLL name; allow it
  if needed (it only forwards `SHFolder` and loads the local gadget).
- If CELSYS ever ships a real `SHFolder.dll` in the install folder, switch the
  shadow target (e.g. `msimg32`, `dwmapi`, `uxtheme` are other early non-KnownDLL
  loaders) via the same `build_proxy.py --target ... --source-dir C:\Windows\System32`.
